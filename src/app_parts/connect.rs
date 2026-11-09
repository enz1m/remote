//! Session connect and ready settlement.

use super::*;

impl App {
    pub(crate) fn connect_saved_requests(&mut self) -> Task<Message> {
        let settled: Vec<_> = self
            .pending_save_connects
            .iter()
            .filter_map(|(pid, request)| {
                let Some(op) = self.profile_ops.get(pid) else {
                    return Some((*pid, false));
                };
                if op.generation != request.generation {
                    return Some((*pid, false));
                }
                if op.password_pending || op.tunnel_pending {
                    return None;
                }
                let accepted = !request.failed
                    && self.profiles.iter().any(|profile| {
                        profile.id == *pid
                            && profile.has_keyring_password == request.password
                            && profile
                                .ssh_tunnel
                                .as_ref()
                                .is_some_and(|tunnel| tunnel.has_tunnel_password)
                                == request.tunnel_password
                    });
                Some((*pid, accepted))
            })
            .collect();
        let mut tasks = Vec::new();
        for (pid, accepted) in settled {
            self.pending_save_connects.remove(&pid);
            if accepted
                && matches!(
                    self.session_status_for(pid),
                    SessionStatus::Disconnected | SessionStatus::Error
                )
            {
                tasks.push(self.drive_session(pid));
            }
        }
        Task::batch(tasks)
    }

    /// Drive the session state machine for a profile according to the action label
    /// the button was showing.
    ///
    /// A connect runs the backend call off-thread via `Task::perform`;
    /// `SessionEvent::Connect` is applied immediately and the outcome arrives later as
    /// `Message::ConnectResult`.
    pub(crate) fn drive_session(&mut self, pid: Uuid) -> Task<Message> {
        let status = self.session_status_for(pid);
        if matches!(status, SessionStatus::Disconnected | SessionStatus::Error)
            && self.credentials_pending(pid)
        {
            return Task::none();
        }

        // Refuse a connect edge for a protocol with no backend before anything
        // observable moves. No control offers it, so an arrival here is a stale
        // accessibility action, capture argument or late context-menu activation.
        // Both `Connect` and `Reconnect` are guarded; teardowns never are.
        if matches!(status, SessionStatus::Disconnected | SessionStatus::Error)
            && let Some(prof) = self.profiles.iter().find(|p| p.id == pid)
            && !self.backends.available(prof.protocol)
        {
            return Task::none();
        }

        // Also refuse while a severed VNC transport's join is uncollected: a second dial
        // would add a second owner of the reader, writer and socket. SSH is not gated
        // here because its backend returns a typed refusal; RDP does the same.
        if matches!(status, SessionStatus::Disconnected | SessionStatus::Error)
            && self.backends.vnc_closing(pid)
        {
            return Task::none();
        }

        // Ensure a session exists for the profile being driven.
        if !self.sessions.iter().any(|s| s.profile_id == pid)
            && let Some(prof) = self.profiles.iter().find(|p| p.id == pid)
        {
            self.sessions.push(Session::new(prof.clone()));
        }

        match status {
            SessionStatus::Disconnected => self.begin_connect(pid, &SessionEvent::Connect),
            SessionStatus::Error => {
                // The user asked for this attempt, so it supersedes whatever
                // the policy had scheduled: the armed deadline is cancelled
                // and the policy's spent attempts go back to zero.
                self.abandon_connect(pid);
                self.reconnect.cancel(pid);
                self.begin_connect(pid, &SessionEvent::Reconnect)
            }
            SessionStatus::Connecting | SessionStatus::Connected => {
                self.abandon_connect(pid);
                // A user Disconnect withdraws the policy: nothing this app
                // reconnects was reconnected because the user asked for it.
                self.reconnect.cancel(pid);
                self.apply_session_event(pid, SessionEvent::Disconnect);
                Task::none()
            }
        }
    }

    /// Retire the credential fetch and the dispatched backend call for `pid`.
    ///
    /// The fetch's next poll resolves to `Cancelled`, which reverts the amber
    /// dot with no error surface; the dispatched call cannot be cancelled at
    /// all, so dropping its entry is what refuses its answer when it lands.
    pub(crate) fn abandon_connect(&mut self, pid: Uuid) {
        if let Some((_, handle)) = self.pending_connects.remove(&pid) {
            handle.cancel();
        }
        self.dispatched_connects.remove(&pid);
    }

    /// Take `edge` into the session and dispatch the connect behind it.
    ///
    /// The edge moves the dot immediately. The stored password is fetched
    /// asynchronously, because a locked keyring can prompt through the desktop
    /// portal; the backend call is dispatched in `on_password_fetched`.
    ///
    /// The generation is checked so a wrapped value cannot match an abandoned dial;
    /// exhaustion withdraws the profile's reconnect policy.
    pub(crate) fn begin_connect(&mut self, pid: Uuid, edge: &SessionEvent) -> Task<Message> {
        let Some(profile) = self
            .profiles
            .iter()
            .find(|profile| profile.id == pid)
            .cloned()
        else {
            return Task::none();
        };
        if let Some(session) = self
            .sessions
            .iter_mut()
            .find(|session| session.profile_id == pid)
        {
            if session.profile_snapshot.dial_identity() != profile.dial_identity()
                || session.profile_snapshot.view_only != profile.view_only
            {
                *session = Session::new(profile);
            } else {
                session.profile_snapshot = profile;
            }
        } else {
            self.sessions.push(Session::new(profile));
        }
        if let Some(session) = self.sessions.iter_mut().find(|s| s.profile_id == pid)
            && let Ok((next, msg)) = transition(session.status, edge)
        {
            session.status = next;
            if let Some(m) = msg {
                session.last_message = m;
            }
        }

        let Some(generation) = self.connect_generation.checked_add(1) else {
            self.reconnect.cancel(pid);
            return Task::none();
        };
        self.connect_generation = generation;
        let op = self.credentials.get(profile_password_key(pid));
        self.pending_connects
            .insert(pid, (generation, op.cancel_handle()));
        Task::future(op)
            .map(move |o| Message::PasswordFetched(pid, generation, CredResult::from_outcome(o)))
    }

    /// Second half of the async connect: the stored password resolved.
    ///
    /// * A value, `NotFound` or `Unavailable` dispatches the backend connect;
    ///   `Unavailable` connects without a stored password and writes it nowhere else.
    /// * `UnlockCancelled` (unlock prompt dismissed) or `Cancelled` reverts the dot to
    ///   disconnected with no error surface.
    /// * `Denied` / `Failed` drives the session to `Error`.
    pub(crate) fn on_password_fetched(
        &mut self,
        pid: Uuid,
        generation: u64,
        result: CredResult,
    ) -> Task<Message> {
        // Act only while this op is still the pending connect; a cancelled or
        // superseded op must not revert a replacement connect.
        match self.pending_connects.get(&pid) {
            Some((g, _)) if *g == generation => {
                self.pending_connects.remove(&pid);
            }
            _ => return Task::none(),
        }

        let password = match result {
            CredResult::Retrieved(pw) => Some(pw),
            // No stored password; there is no plaintext fallback.
            CredResult::NotFound | CredResult::Unavailable => None,
            // The user said no. Revert to disconnected, quietly.
            CredResult::UnlockCancelled | CredResult::Cancelled => {
                // A dismissed unlock prompt is the user declining this
                // connection, so nothing may dial it again unasked.
                self.reconnect.cancel(pid);
                self.apply_session_event(pid, SessionEvent::Disconnect);
                return Task::none();
            }
            // A real failure. Drive to Error with a truthful message.
            CredResult::Denied => {
                // A credential the store will not release is identical on the
                // next attempt, so the schedule is withdrawn rather than
                // spending attempts to be denied again.
                self.reconnect.cancel(pid);
                self.apply_session_event(
                    pid,
                    SessionEvent::Fail(
                        "the system keyring refused to release the password".to_string(),
                    ),
                );
                return Task::none();
            }
            CredResult::Failed(reason) => {
                self.reconnect.cancel(pid);
                self.apply_session_event(
                    pid,
                    SessionEvent::Fail(format!("could not read the stored password: {reason}")),
                );
                return Task::none();
            }
            // A get never yields these, but be total.
            CredResult::Stored | CredResult::Deleted => None,
        };

        let profile = match self.profiles.iter().find(|p| p.id == pid) {
            Some(p) => p.clone(),
            None => return Task::none(),
        };
        let backend = match self.backends.get(profile.protocol) {
            Some(b) => b,
            None => return Task::none(),
        };
        // `Task::perform` cannot be cancelled, so this entry tells this dial's answer
        // from an abandoned one. The identity is read from the `profile` handed to the
        // backend, so success credits what was dialled, not a later edit.
        self.dispatched_connects.insert(
            pid,
            crate::app_state::DispatchedConnect {
                generation,
                candidate: profile.dial_identity(),
            },
        );
        Task::perform(
            dial_off_executor(backend, profile, password),
            move |result| {
                let (events_result, stream) = match result {
                    Ok((events, stream)) => (Ok(events), stream),
                    Err(e) => (Err(e), None),
                };
                Message::ConnectResult(
                    pid,
                    generation,
                    events_result,
                    Arc::new(std::sync::Mutex::new(stream)),
                )
            },
        )
    }

    /// Settle an authoritative Ready: the policy's attempts go back to zero
    /// and this connection's time is recorded.
    ///
    /// Reached only from the `Connecting -> Connected` edge of a dial whose
    /// generation the reducer has already matched, which is the point the
    /// backend has authenticated, opened its subsystem and established every
    /// forward the profile asked for.
    pub(crate) fn settle_authoritative_ready(
        &mut self,
        pid: Uuid,
        dialled: Option<&crate::model::DialIdentity>,
        ready_at: chrono::DateTime<chrono::Utc>,
        admitted: bool,
    ) {
        self.reconnect.settle_ready(pid);
        self.adopt_last_connected(pid, dialled, ready_at, admitted);
    }

    /// Record the wall-clock time this profile's transport reached Ready, paired
    /// with the history row for the endpoint it reached.
    ///
    /// Both go to [`ProfileDb::record_ready`] in one transaction, and nothing in
    /// memory is promoted until it commits, so sorting reads durable values only.
    ///
    /// Pairing is refused when the launch keeps no history, the session is no longer
    /// `Connected`, an SSH channel is gone, [`ConnectionProfile::dial_identity`] no
    /// longer matches, or the reading would not advance recency. The admitted history
    /// row is still written on its own in those cases.
    fn adopt_last_connected(
        &mut self,
        pid: Uuid,
        dialled: Option<&crate::model::DialIdentity>,
        ready_at: chrono::DateTime<chrono::Utc>,
        admitted: bool,
    ) {
        if !self.records_history {
            return;
        }
        // Rebuilt from the dial identity and the single settlement reading, so the
        // stored entry matches what the admitting edge displayed.
        let entry = match (dialled, admitted) {
            (Some(identity), true) => Some(identity.recent_at(ready_at)),
            _ => None,
        };
        let Some(dialled) = dialled else {
            self.settle_recent_only(entry.as_ref());
            return;
        };
        if self.session_status_for(pid) != SessionStatus::Connected {
            self.settle_recent_only(entry.as_ref());
            return;
        }
        // Read out as owned values, so the gates below can write the history
        // row on their own without holding a borrow of the library.
        let Some((_protocol, present, adopted)) =
            self.profiles.iter().find(|p| p.id == pid).map(|profile| {
                (
                    profile.protocol,
                    profile.dial_identity(),
                    profile.last_connected,
                )
            })
        else {
            self.settle_recent_only(entry.as_ref());
            return;
        };
        // The profile must still dial what reached Ready, compared via
        // `ConnectionProfile::dial_identity`: renames, notes or colour depth still adopt;
        // changes to destination or authentication do not.
        if &present != dialled {
            self.settle_recent_only(entry.as_ref());
            return;
        }
        // Strictly-newer rule on the settlement's own reading, so a backwards clock
        // cannot reorder two connections.
        let Some(stamp) = crate::reconnect::bounded_stamp(ready_at, adopted) else {
            self.settle_recent_only(entry.as_ref());
            return;
        };
        let Some(reservation) = self.reconnect.reserve_recency(pid) else {
            // No publication order, so no write: the structural bound on
            // tracked profiles and the token counter are both refusals to
            // publish, not permission to publish unordered.
            self.owe_recency(pid, dialled.clone(), stamp, entry.as_ref());
            return;
        };
        if !self.reconnect.holds_reservation(reservation) {
            self.reconnect.release_recency(reservation);
            self.settle_recent_only(entry.as_ref());
            return;
        }
        self.settle_ready_pair(pid, dialled.clone(), stamp, entry);
        self.reconnect.release_recency(reservation);
    }

    /// Commit one Ready settlement, or record exactly what it owes.
    ///
    /// The only writer of an adopted `last_connected`. Memory follows the
    /// transaction: on commit the profile takes the reading and the history row loses
    /// its unsaved mark; on a refused store both stay unchanged and one paired debt is
    /// recorded.
    ///
    /// A declined pairing (profile gone or now a different dial) is not a debt: the
    /// reading is dropped and the reached endpoint is written on its own.
    pub(crate) fn settle_ready_pair(
        &mut self,
        pid: Uuid,
        dialled: crate::model::DialIdentity,
        stamp: chrono::DateTime<chrono::Utc>,
        entry: Option<crate::quick_connect::RecentConnection>,
    ) {
        let outcome = self.db.record_ready(
            pid,
            &dialled,
            stamp,
            entry.as_ref(),
            crate::quick_connect::RECENT_CAP,
        );
        match outcome {
            Ok(crate::db::ReadyRecord::Committed) => {
                if let Some(profile) = self.profiles.iter_mut().find(|p| p.id == pid) {
                    profile.last_connected = Some(stamp);
                }
                if let Some(entry) = &entry {
                    let identity = entry.key();
                    self.unsaved_recents.retain(|k| *k != identity);
                }
                self.recency_debt.retain(|debt| debt.profile_id != pid);
                self.clear_recent_write_notice();
            }
            Ok(crate::db::ReadyRecord::Declined(_)) => {
                self.recency_debt.retain(|debt| debt.profile_id != pid);
                self.settle_recent_only(entry.as_ref());
            }
            Err(err) => {
                let cause = crate::error_boundary::DbWriteFailure::classify(&err);
                self.owe_recency(pid, dialled, stamp, entry.as_ref());
                // A settlement carrying a history row is disclosed as a history write, since
                // that connection will be missing after a restart.
                match &entry {
                    Some(entry) => {
                        self.credential_notice = Some(CredentialNotice::write_refused(
                            cause,
                            crate::error_boundary::DbWriteOperation::RecordRecent,
                            &entry.endpoint(),
                        ));
                    }
                    None => self.disclose_marker_refusal(
                        pid,
                        cause,
                        crate::error_boundary::DbWriteOperation::Save,
                    ),
                }
            }
        }
    }

    /// Record one paired debt, replacing any older one for this profile.
    ///
    /// At most one per profile: a debt is what the *next* launch will not
    /// know, and only the newest refused settlement can still be true about
    /// that. The history row stays marked unsaved by the same refusal, so the
    /// two disclosures cannot disagree.
    fn owe_recency(
        &mut self,
        pid: Uuid,
        dialled: crate::model::DialIdentity,
        stamp: chrono::DateTime<chrono::Utc>,
        entry: Option<&crate::quick_connect::RecentConnection>,
    ) {
        if let Some(entry) = entry {
            let identity = entry.key();
            if !self.unsaved_recents.contains(&identity) {
                self.unsaved_recents.push(identity);
            }
        }
        self.recency_debt.retain(|debt| debt.profile_id != pid);
        self.recency_debt.push(crate::reconnect::RecencyDebt {
            profile_id: pid,
            identity: dialled,
            stamp,
            recent_identity: entry.map(crate::quick_connect::RecentConnection::key),
        });
        self.prune_unsaved_recents();
    }
}

/// Live dials at once; a stalled handshake cannot hold every one.
const DIAL_WORKERS: std::num::NonZeroUsize = std::num::NonZeroUsize::new(4).unwrap();
/// Dials admitted behind the live ones; further dials wait for a slot.
const DIAL_QUEUE: std::num::NonZeroUsize = std::num::NonZeroUsize::new(8).unwrap();

/// The dial owner, cached only once it has started (see `import_source::owner`
/// for why a failed start is retried rather than stored).
fn dial_owner() -> Option<&'static enzui_iced_core::blocking_task::BlockingTaskOwner> {
    use enzui_iced_core::blocking_task::BlockingTaskOwner;
    static OWNER: std::sync::OnceLock<BlockingTaskOwner> = std::sync::OnceLock::new();
    if let Some(started) = OWNER.get() {
        return Some(started);
    }
    let started = BlockingTaskOwner::new("remote-dial", DIAL_WORKERS, DIAL_QUEUE).ok()?;
    let _ = OWNER.set(started);
    OWNER.get()
}

type DialResult = Result<
    (
        Vec<crate::state_machine::SessionEvent>,
        Option<crate::protocol::SessionStream>,
    ),
    crate::protocol::ProtocolError,
>;

/// Run a backend dial on the dial owner.
///
/// SSH dials block on a process and SFTP handshake, VNC on TCP and RFB, so they
/// must not hold an executor worker. A dial waits for a slot; one the owner cannot
/// settle is refused with a sentence the reconnect policy does not retry. Without
/// an owner the dial runs where it is awaited.
fn dial_off_executor(
    backend: std::sync::Arc<dyn crate::protocol::RemoteProtocol>,
    profile: crate::model::ConnectionProfile,
    password: Option<String>,
) -> impl std::future::Future<Output = DialResult> + Send + 'static {
    let dial = move || backend.connect(&profile, password.as_deref());
    let job = match dial_owner() {
        Some(owner) => Ok(owner.submit_waiting(0, move |_| dial())),
        None => Err(dial),
    };
    async move {
        match job {
            Ok(job) => job.await.into_result().unwrap_or_else(|_| {
                Err(crate::protocol::ProtocolError::Refused(
                    "The connection attempt stopped before it finished.".to_owned(),
                ))
            }),
            Err(dial) => dial(),
        }
    }
}

#[cfg(test)]
mod dial_tests {}
