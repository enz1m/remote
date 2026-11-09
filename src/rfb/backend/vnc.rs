//! VNC backend: sessions, close debt, and dial admission.

use super::*;

/// The VNC backend [`crate::protocol::BackendRegistry::production`] registers.
///
/// Every connection this holds is reachable by profile id for retirement, in
/// each of its three phases: reserved while dialling, live, and severed while
/// its workers leave. A session that could not be reached in one of them would
/// be a socket to a remote desktop that no surface can end.
#[derive(Debug)]
pub struct RfbBackend {
    sessions: Mutex<Vec<RfbSession>>,
    /// Dials that have been admitted but have not registered a session yet.
    dialling: Mutex<Vec<Reservation>>,
    /// Severed transports whose workers have still to leave their loops. Their
    /// sockets are already shut down, so what is outstanding is the join, and
    /// while an entry is here the connection is closing rather than closed.
    retiring: Mutex<Vec<Retiring>>,
    generation: AtomicU64,
    admitting: AtomicBool,
    /// Set when a close was abandoned, cleared when admission actually
    /// reopens. Admission waits for the close debt to reach zero, so a
    /// resumed app never dials a profile whose previous owner is still alive.
    resume_owed: AtomicBool,
    /// Set only by a test, so the window between severing a transport and
    /// collecting its join can be observed rather than raced. Production has
    /// no writer and the field does not exist outside a test build.
    #[cfg(test)]
    holds_closes: AtomicBool,
}

impl Default for RfbBackend {
    fn default() -> Self {
        Self {
            sessions: Mutex::default(),
            dialling: Mutex::default(),
            retiring: Mutex::default(),
            generation: AtomicU64::new(0),
            admitting: AtomicBool::new(true),
            resume_owed: AtomicBool::new(false),
            #[cfg(test)]
            holds_closes: AtomicBool::new(false),
        }
    }
}

impl RfbBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stop opening new connections, for an app that is closing.
    pub fn stop_admission(&self) {
        self.admitting.store(false, Ordering::SeqCst);
    }

    /// Ask to open connections again after a close was abandoned.
    ///
    /// Admission reopens only once every severed transport from that close has been
    /// joined; returns whether it reopened now. A close of
    /// [`VncCloseProgress::Unknown`] fate never lets it reopen.
    pub fn resume_admission(&self) -> bool {
        self.resume_owed.store(true, Ordering::SeqCst);
        self.settle_closes();
        self.admits()
    }

    fn try_resume(&self) {
        if !self.resume_owed.load(Ordering::SeqCst) {
            return;
        }
        if self.with_retiring(|retiring| !retiring.is_empty()) {
            return;
        }
        self.resume_owed.store(false, Ordering::SeqCst);
        self.admitting.store(true, Ordering::SeqCst);
    }

    /// Whether this backend would open a new connection.
    #[must_use]
    pub fn admits(&self) -> bool {
        self.admitting.load(Ordering::SeqCst)
    }

    /// Run `read` against the reservation list, recovering a poisoned lock.
    ///
    /// A retirement that treated a poisoned list as empty would leave a dial
    /// free to register a socket nothing can close.
    fn with_dialling<T>(&self, read: impl FnOnce(&mut Vec<Reservation>) -> T) -> T {
        let mut dialling = self.dialling.lock().unwrap_or_else(PoisonError::into_inner);
        read(&mut dialling)
    }

    /// Run `read` against the retirement list, recovering a poisoned lock.
    fn with_retiring<T>(&self, read: impl FnOnce(&mut Vec<Retiring>) -> T) -> T {
        let mut retiring = self.retiring.lock().unwrap_or_else(PoisonError::into_inner);
        read(&mut retiring)
    }

    /// Sever this profile's transport without waiting for its workers.
    ///
    /// Reports whether a live session or an in-flight dial was retired; a dial is
    /// cancelled inside its handshake and closes its own socket. A live session's
    /// socket is shut down before return, so no screen or input byte crosses it
    /// afterwards. Never blocks, so it is safe from the reducer.
    pub fn begin_retire(&self, pid: Uuid) -> bool {
        let withdrawn = self.with_dialling(|dialling| {
            let mut cancelled = Vec::new();
            dialling.retain(|reservation| {
                if reservation.profile_id == pid {
                    cancelled.push(Arc::clone(&reservation.dial));
                    return false;
                }
                true
            });
            for dial in &cancelled {
                dial.cancel();
            }
            !cancelled.is_empty()
        });
        let severed = self.take_sessions(|session| session.profile_id == pid);
        let retired = withdrawn || !severed.is_empty();
        self.park(severed);
        retired
    }

    /// Sever every transport this backend holds, reporting the profiles.
    ///
    /// Includes dials in flight, so an app that is closing cannot acquire a
    /// connection after the surfaces that could end it are gone.
    pub fn retire_all(&self) -> Vec<Uuid> {
        let mut retired = self.with_dialling(|dialling| {
            let pids: Vec<Uuid> = dialling
                .iter()
                .map(|reservation| reservation.profile_id)
                .collect();
            for reservation in dialling.iter() {
                reservation.dial.cancel();
            }
            dialling.clear();
            pids
        });
        let severed = self.take_sessions(|_| true);
        retired.extend(severed.iter().map(|session| session.profile_id));
        self.park(severed);
        retired.sort_unstable();
        retired.dedup();
        retired
    }

    /// Remove and sever every live session `wanted` selects.
    fn take_sessions(&self, wanted: impl Fn(&RfbSession) -> bool) -> Vec<RfbSession> {
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        let mut severed = Vec::new();
        let mut index = 0;
        while index < sessions.len() {
            if wanted(&sessions[index]) {
                let mut session = sessions.remove(index);
                session.sever();
                severed.push(session);
            } else {
                index += 1;
            }
        }
        severed
    }

    /// Take ownership of severed transports as close debt and start joining
    /// them off the reducer.
    ///
    /// Each entry keeps a socket that is already shut down in both directions
    /// and two thread handles. A thread per entry does the waiting; this
    /// returns as soon as they are dispatched.
    fn park(&self, severed: Vec<RfbSession>) {
        if !severed.is_empty() {
            let mut entries: Vec<Retiring> = severed.into_iter().map(Retiring::new).collect();
            for entry in &mut entries {
                entry.dispatch();
            }
            self.with_retiring(|retiring| retiring.extend(entries));
        }
        self.settle_closes();
    }

    /// Collect finished joins, start the ones still owed, and report how many
    /// closes are outstanding.
    ///
    /// Non-blocking, so the reducer may call it: a join is only collected once
    /// its thread has finished. An entry whose join was lost stays here as
    /// [`VncCloseProgress::Unknown`] and is never discharged.
    pub fn settle_closes(&self) -> usize {
        if self.collection_held() {
            return self.with_retiring(|retiring| retiring.len());
        }
        let outstanding = self.with_retiring(|retiring| {
            for entry in retiring.iter_mut() {
                entry.collect();
                entry.dispatch();
            }
            retiring.retain(|entry| !entry.settled);
            retiring.len()
        });
        self.try_resume();
        outstanding
    }

    /// Every outstanding close, for the app's close authorization.
    pub fn close_report(&self) -> Vec<VncCloseDebt> {
        self.settle_closes();
        self.with_retiring(|retiring| retiring.iter().map(Retiring::debt).collect())
    }

    /// Whether an outstanding close can still advance on its own.
    ///
    /// False once no entry has a join running or an attempt left: an
    /// [`VncCloseProgress::Unknown`] one never will, and one that has spent
    /// [`CLOSE_ATTEMPTS`] waits for the user rather than for another wake.
    pub fn close_work_pending(&self) -> bool {
        self.with_retiring(|retiring| retiring.iter().any(Retiring::advancing))
    }

    /// How far this profile's close has got, if it is closing.
    ///
    /// Side-effect free, so a view may call it every frame.
    /// [`VncCloseProgress::Unknown`] dominates, so a worker of unknown fate is never
    /// reported as an ordinary close.
    pub fn close_progress(&self, pid: Uuid) -> Option<VncCloseProgress> {
        self.with_retiring(|retiring| {
            retiring
                .iter()
                .filter(|entry| entry.profile_id == pid)
                .map(|entry| entry.progress)
                .reduce(|left, right| {
                    if left == VncCloseProgress::Unknown || right == VncCloseProgress::Unknown {
                        VncCloseProgress::Unknown
                    } else {
                        VncCloseProgress::Closing
                    }
                })
        })
    }

    /// Whether this profile's previous transport is still closing.
    pub fn closing(&self, pid: Uuid) -> bool {
        self.close_progress(pid).is_some()
    }

    #[cfg(not(test))]
    fn collection_held(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn collection_held(&self) -> bool {
        self.holds_closes.load(Ordering::SeqCst)
    }

    /// Give every close that ran out of attempts its attempts back, for a user
    /// who asked to try again, and report what is still outstanding.
    ///
    /// A [`VncCloseProgress::Unknown`] entry is not retried: its transport was
    /// consumed by the join that lost it, so there is nothing left to close
    /// and nothing a retry could learn.
    pub fn retry_closes(&self) -> usize {
        self.with_retiring(|retiring| {
            for entry in retiring.iter_mut() {
                if entry.owed() && entry.task.is_none() {
                    entry.attempts = 0;
                    entry.dispatch();
                }
            }
            retiring.len()
        })
    }

    /// Wait for one profile's severed transports to finish closing.
    ///
    /// Bounded by [`SETTLE_DEADLINE`] and called from a dial's own worker
    /// thread, never the reducer. The joins themselves still happen on the
    /// retirement threads; this only waits for them to be collected.
    fn settle_profile(&self, pid: Uuid) -> bool {
        let deadline = Instant::now() + SETTLE_DEADLINE;
        loop {
            self.settle_closes();
            if !self.closing(pid) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(SETTLE_POLL);
        }
    }

    /// Reserve this profile's dial before a socket exists.
    ///
    /// Retires whatever the profile holds and waits for the severed workers, so one
    /// profile never holds two sockets.
    ///
    /// # Errors
    ///
    /// [`RfbFailure::AdmissionClosed`] while the app is closing, and
    /// [`RfbFailure::ClosePending`] when the previous transport for this
    /// profile could not be shown to have gone.
    fn admit(&self, pid: Uuid) -> Result<Reserved<'_>, RfbFailure> {
        if !self.admits() {
            return Err(RfbFailure::AdmissionClosed);
        }
        self.begin_retire(pid);
        if !self.settle_profile(pid) {
            return Err(RfbFailure::ClosePending);
        }
        let dial = Arc::new(DialHandle::new());
        // Admission is decided under the lock that publishes the reservation, and a
        // close stops admission before sweeping it, so a dial is either cancelled by the
        // sweep or opens no socket. The generation is taken here so a refused dial
        // consumes none.
        let reserved = self.with_dialling(|dialling| {
            if !self.admits() {
                return None;
            }
            let generation = self
                .generation
                .fetch_add(1, Ordering::SeqCst)
                .wrapping_add(1);
            dialling.push(Reservation {
                profile_id: pid,
                generation,
                dial: Arc::clone(&dial),
            });
            Some(generation)
        });
        let Some(generation) = reserved else {
            return Err(RfbFailure::AdmissionClosed);
        };
        Ok(Reserved {
            backend: self,
            profile_id: pid,
            generation,
            dial,
            committed: false,
        })
    }

    /// Encode and enqueue an input against the one live session.
    ///
    /// Refuses rather than guesses when zero or several are live — see the
    /// module docs.
    fn route_input(&self, input: RemoteInput) -> Result<(), ProtocolError> {
        let sessions = self.sessions.lock().map_err(|_| poisoned())?;
        match sessions.len() {
            0 => Err(no_session()),
            1 => {
                let session = &sessions[0];
                let bytes = session.encode(input);
                session.enqueue(bytes)
            }
            n => Err(ProtocolError::Transport(format!(
                "{n} VNC sessions are open and this build cannot tell which one to send to"
            ))),
        }
    }
}

/// One admitted dial's claim on a profile, held for as long as it is opening.
///
/// Dropping it uncommitted withdraws the reservation, so a dial that failed
/// releases the profile for the next attempt.
struct Reserved<'a> {
    backend: &'a RfbBackend,
    profile_id: Uuid,
    generation: u64,
    dial: Arc<DialHandle>,
    committed: bool,
}

impl Reserved<'_> {
    fn generation(&self) -> u64 {
        self.generation
    }

    /// What the dial hands its handshake, so a retirement can end it there.
    fn dial(&self) -> &DialHandle {
        &self.dial
    }

    /// Register the opened session against this reservation.
    ///
    /// # Errors
    ///
    /// [`RfbFailure::Cancelled`] when the profile was retired while the session was
    /// opening; the session is closed here so an abandoned dial never becomes a live
    /// socket.
    fn commit(mut self, session: RfbSession) -> Result<(), RfbFailure> {
        let (profile_id, generation) = (self.profile_id, self.generation);
        let reserved = self.backend.with_dialling(|dialling| {
            let Some(index) = dialling.iter().position(|reservation| {
                reservation.profile_id == profile_id && reservation.generation == generation
            }) else {
                return false;
            };
            dialling.remove(index);
            true
        });
        if !reserved {
            session.close();
            return Err(RfbFailure::Cancelled);
        }
        self.committed = true;
        match self.backend.sessions.lock() {
            Ok(mut sessions) => {
                sessions.push(session);
                Ok(())
            }
            Err(_) => {
                session.close();
                Err(RfbFailure::Io {
                    phase: "registering the session",
                    reason: "the connection state is poisoned".to_string(),
                })
            }
        }
    }
}

impl Drop for Reserved<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let (profile_id, generation) = (self.profile_id, self.generation);
        self.backend.with_dialling(|dialling| {
            dialling.retain(|reservation| {
                !(reservation.profile_id == profile_id && reservation.generation == generation)
            });
        });
    }
}

fn poisoned() -> ProtocolError {
    ProtocolError::Transport("the connection state is poisoned".to_string())
}

fn no_session() -> ProtocolError {
    ProtocolError::Transport("no VNC session is open".to_string())
}

impl RemoteProtocol for RfbBackend {
    fn input_capture_for(&self, id: Uuid) -> Option<Arc<AtomicBool>> {
        let sessions = self.sessions.lock().ok()?;
        sessions
            .iter()
            .find(|s| s.profile_id == id && !s.severed)
            .map(|s| Arc::clone(&s.clipboard.capture))
    }
    fn clipboard_enabled_for(&self, id: Uuid, enabled: bool) {
        if let Ok(sessions) = self.sessions.lock()
            && let Some(session) = sessions.iter().find(|s| s.profile_id == id && !s.severed)
        {
            session.clipboard.enable(enabled);
        }
    }
    fn share_clipboard_for(&self, id: Uuid, text: &str) -> Result<(), ProtocolError> {
        let sessions = self.sessions.lock().map_err(|_| poisoned())?;
        let session = sessions
            .iter()
            .find(|s| s.profile_id == id && !s.severed)
            .ok_or_else(no_session)?;
        let bytes = session
            .clipboard
            .local(text)
            .map_err(ProtocolError::Refused)?;
        session.enqueue(bytes)
    }

    fn protocol(&self) -> Protocol {
        Protocol::Vnc
    }

    /// Open one session, under a reservation taken before the socket exists.
    ///
    /// The reservation is what a retirement reaches a dial through: this build
    /// cannot cancel a `Task::perform`, so a Disconnect pressed while a
    /// handshake is running withdraws the claim instead, and the dial then
    /// closes its own socket rather than registering one the user has already
    /// ended.
    fn connect(
        &self,
        profile: &ConnectionProfile,
        password: Option<&str>,
    ) -> Result<(Vec<SessionEvent>, Option<SessionStream>), ProtocolError> {
        let reserved = self
            .admit(profile.id)
            .map_err(RfbFailure::into_protocol_error)?;
        let (session, _established, events, stream) =
            open_on_with_password(profile, reserved.generation(), reserved.dial(), password)
                .map_err(RfbFailure::into_protocol_error)?;
        reserved
            .commit(session)
            .map_err(RfbFailure::into_protocol_error)?;
        Ok((events, Some(stream)))
    }

    fn send_input(&self, input: RemoteInput) -> Result<(), ProtocolError> {
        self.route_input(input)
    }

    fn send_input_for(&self, profile_id: Uuid, input: RemoteInput) -> Result<(), ProtocolError> {
        let sessions = self.sessions.lock().map_err(|_| poisoned())?;
        let session = sessions
            .iter()
            .find(|session| session.profile_id == profile_id)
            .ok_or_else(no_session)?;
        session.enqueue(session.encode(input))
    }

    fn send_inputs_for(
        &self,
        profile_id: Uuid,
        inputs: &[RemoteInput],
    ) -> Result<(), ProtocolError> {
        if inputs.len() > 8192 {
            return Err(ProtocolError::Refused("Input batch is too large".into()));
        }
        let sessions = self.sessions.lock().map_err(|_| poisoned())?;
        let session = sessions
            .iter()
            .find(|session| session.profile_id == profile_id)
            .ok_or_else(no_session)?;
        let bytes = inputs
            .iter()
            .flat_map(|input| session.encode(*input))
            .collect();
        session.enqueue(bytes)
    }

    /// Ask the server to repaint the whole desktop.
    ///
    /// The local size is not forwarded: changing the remote size needs
    /// `ExtendedDesktopSize`, which this build does not implement. A resize needs a
    /// non-incremental update for the newly exposed area, requested for the
    /// geometry being decoded. Remote geometry changes arrive as `DesktopSize`.
    fn resize_for(&self, profile_id: Uuid, _size: (u32, u32)) -> Result<(), ProtocolError> {
        let sessions = self.sessions.lock().map_err(|_| poisoned())?;
        let session = sessions
            .iter()
            .find(|session| session.profile_id == profile_id)
            .ok_or_else(no_session)?;
        let (width, height) = session.geometry();
        session.enqueue(wire::framebuffer_update_request(false, width, height).to_vec())
    }
}

#[cfg(test)]
impl RfbBackend {
    // This test helper waits for joins; the reducer retires sessions without blocking.
}
