//! Recency debt and retry scheduling.

use super::*;

impl App {
    /// Persist an admitted history row on its own, with no connection time.
    ///
    /// The endpoint was reached, so the row is written, but the profile is not
    /// credited because the pairing conditions failed. A refusal marks the row
    /// unsaved like any other refused history write.
    pub(crate) fn settle_recent_only(
        &mut self,
        entry: Option<&crate::quick_connect::RecentConnection>,
    ) {
        if let Some(entry) = entry {
            self.settle_recent_write(entry);
        }
    }

    /// Schedule, or refuse to schedule, another attempt for `pid`.
    ///
    /// Only a transport failure is retried. Everything else — an unknown host
    /// key, a refused key, a credential the store would not release, a forward
    /// the server prohibits, a profile this build will not dial, a cancelled
    /// dial and an exhausted generation counter — withdraws the schedule,
    /// because the next identical attempt has the same answer.
    pub(crate) fn settle_failed_attempt(
        &mut self,
        pid: Uuid,
        disposition: crate::reconnect::RetryDisposition,
    ) {
        let Some(policy) = self
            .profiles
            .iter()
            .find(|p| p.id == pid)
            .map(|profile| profile.reconnect)
        else {
            self.reconnect.cancel(pid);
            return;
        };
        let refusal = self.reconnect.schedule(
            pid,
            policy,
            disposition,
            std::time::Instant::now(),
            crate::reconnect::draw_jitter(),
        );
        if let Err(crate::reconnect::ScheduleRefusal::GenerationsExhausted) = refusal {
            // No later wake could be told from an older one, so the policy is
            // withdrawn for every profile rather than acting on an ambiguous
            // identity.
            self.reconnect.cancel_all();
        }
    }

    /// Run every attempt whose deadline has passed.
    ///
    /// The wake names one profile and one generation; a wake that is no longer
    /// that profile's current schedule starts nothing. Every other profile
    /// that is also due is collected in the same turn, so one deadline
    /// subscription serves the whole library.
    pub(crate) fn run_due_retries(
        &mut self,
        pid: Uuid,
        generation: u64,
        now: std::time::Instant,
    ) -> Task<Message> {
        if !self.reconnect.is_due(pid, generation, now) {
            return Task::none();
        }
        // Refresh close debt first: an attempt for a profile whose previous child is
        // still being reaped would be refused and spend an attempt.
        self.refresh_close_notices();
        let due = self.reconnect.due(&self.profiles, now);
        let tasks: Vec<Task<Message>> = due
            .into_iter()
            .map(|(profile_id, generation)| {
                self.start_scheduled_attempt(profile_id, generation, now)
            })
            .collect();
        Task::batch(tasks)
    }

    /// Start one scheduled attempt, or re-arm it while its profile's previous
    /// connection is still retiring.
    fn start_scheduled_attempt(
        &mut self,
        pid: Uuid,
        generation: u64,
        now: std::time::Instant,
    ) -> Task<Message> {
        if self.desktop_close_notices.contains(&pid) || self.backends.vnc_closing(pid) {
            let _ = self
                .reconnect
                .defer(pid, now, crate::reconnect::RETIREMENT_DEFER);
            return Task::none();
        }
        let edge = match self.session_status_for(pid) {
            SessionStatus::Error => SessionEvent::Reconnect,
            SessionStatus::Disconnected => SessionEvent::Connect,
            // A session that is already dialling or up needs no attempt, and
            // taking one would spend the policy's budget on a connection it
            // did not make.
            SessionStatus::Connecting | SessionStatus::Connected => return Task::none(),
        };
        if self
            .profiles
            .iter()
            .find(|p| p.id == pid)
            .is_none_or(|profile| !self.backends.available(profile.protocol))
        {
            self.reconnect.cancel(pid);
            return Task::none();
        }
        if self.reconnect.begin_attempt(pid, generation).is_none() {
            return Task::none();
        }
        self.abandon_connect(pid);
        self.begin_connect(pid, &edge)
    }

    /// What the session surface says about `pid`'s reconnect policy, or
    /// `None` when there is no policy state to report.
    ///
    /// An idle policy reports only that a live connection is being watched;
    /// with no transport up, the surface's own copy is what says the session
    /// is not connected, and a profile that never opted in says nothing at
    /// all.
    #[must_use]
    pub fn reconnect_presentation(&self, pid: Uuid) -> Option<crate::reconnect::RetryPresentation> {
        let status = self.session_status_for(pid);
        let phase = self.reconnect.phase(pid);
        let watching = status == SessionStatus::Connected
            && self
                .profiles
                .iter()
                .find(|profile| profile.id == pid)
                .is_some_and(|profile| profile.reconnect.normalized().enabled);
        if matches!(phase, crate::reconnect::RetryPhase::Idle) && !watching {
            return None;
        }
        Some(crate::reconnect::presentation(status, phase))
    }

    /// The recency reading this profile earned and the store refused, if any.
    #[must_use]
    pub fn recency_debt_for(&self, pid: Uuid) -> Option<&crate::reconnect::RecencyDebt> {
        self.recency_debt.iter().find(|debt| debt.profile_id == pid)
    }

    /// Put one recent on screen for a settlement that has not committed yet.
    ///
    /// The same gates and the same list as `Self::admit_recent`, and no
    /// store write: the row is durable only when the paired transaction in
    /// [`Self::settle_ready_pair`] commits it, so until then it carries the
    /// unsaved mark every unwritten row carries. Returns whether the row was
    /// admitted, which is what tells the settlement there is history to pair.
    pub(crate) fn admit_recent_pending(
        &mut self,
        entry: crate::quick_connect::RecentConnection,
    ) -> bool {
        if !self.records_history {
            return false;
        }
        if !self.backends.available(entry.protocol) {
            return false;
        }
        if entry.host.is_empty() {
            return false;
        }
        let identity = entry.key();
        crate::quick_connect::record(&mut self.recents, entry);
        if !self.unsaved_recents.contains(&identity) {
            self.unsaved_recents.push(identity);
        }
        self.prune_unsaved_recents();
        true
    }

    /// Write one recent to the store and disclose a refusal.
    ///
    /// Returns whether the row reached disk. A refusal raises the `credential_notice`
    /// banner with a bounded [`crate::error_boundary::DbWriteFailure`] class; the raw
    /// `rusqlite::Error`, which carries the statement and database path, never
    /// reaches the banner.
    fn settle_recent_write(&mut self, entry: &crate::quick_connect::RecentConnection) -> bool {
        match self
            .db
            .record_recent(entry, crate::quick_connect::RECENT_CAP)
        {
            Ok(()) => {
                let identity = entry.key();
                self.unsaved_recents.retain(|k| *k != identity);
                true
            }
            Err(err) => {
                let identity = entry.key();
                if !self.unsaved_recents.contains(&identity) {
                    self.unsaved_recents.push(identity);
                }
                self.credential_notice = Some(CredentialNotice::write_refused(
                    crate::error_boundary::DbWriteFailure::classify(&err),
                    crate::error_boundary::DbWriteOperation::RecordRecent,
                    &entry.endpoint(),
                ));
                false
            }
        }
    }

    /// Retry one refused history write, paired with its connection time when
    /// that is what was refused.
    ///
    /// A paired debt is retried as the same transaction at the same reading; nothing
    /// reads the clock. If the profile now describes a different dial (edited or
    /// deleted), the endpoint is written alone and the profile is not credited.
    /// Either way the debt is discharged.
    pub(crate) fn retry_recency_debt(&mut self, entry: &crate::quick_connect::RecentConnection) {
        let identity = entry.key();
        let Some(debt) = self
            .recency_debt
            .iter()
            .find(|debt| debt.recent_identity.as_deref() == Some(identity.as_str()))
            .cloned()
        else {
            self.settle_recent_write(entry);
            return;
        };
        let still_ours = self
            .profiles
            .iter()
            .find(|p| p.id == debt.profile_id)
            .is_some_and(|profile| profile.dial_identity() == debt.identity);
        if !still_ours {
            if self.settle_recent_write(entry) {
                self.recency_debt
                    .retain(|d| d.profile_id != debt.profile_id);
            }
            return;
        }
        // Rebuilt from the debt rather than taken from the list: the
        // endpoint and the reading then come from one value, so the pair
        // cannot be retried with two different times.
        let paired = debt.identity.recent_at(debt.stamp);
        self.settle_ready_pair(debt.profile_id, debt.identity, debt.stamp, Some(paired));
    }

    /// Drop unsaved marks for endpoints no longer in the list.
    ///
    /// The cap evicts the oldest row on every admission; without pruning, marks would
    /// grow without bound and retain endpoints the app no longer shows.
    pub(crate) fn prune_unsaved_recents(&mut self) {
        let live: Vec<String> = self.recents.iter().map(|r| r.key()).collect();
        self.unsaved_recents.retain(|k| live.contains(k));
        // A paired debt is retried through its row. Once the cap has evicted
        // that row there is no route left, so the debt goes with it rather
        // than accumulating one entry per endpoint ever dialled.
        self.recency_debt
            .retain(|debt| match &debt.recent_identity {
                Some(identity) => live.contains(identity),
                None => true,
            });
    }
}
