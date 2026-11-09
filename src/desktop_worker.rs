//! Bounded desktop-transport workers with profile-owned cancellation and close debt.

use std::collections::HashMap;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::model::{ConnectionProfile, Protocol};
use crate::protocol::{
    ProtocolError, RemoteInput, RemoteProtocol, SessionStream, SessionStreamSender,
};
use crate::state_machine::SessionEvent;

const INPUT_BATCH_LIMIT: usize = 4096;

pub(crate) trait Transport: Send + Sync + std::fmt::Debug + 'static {
    const PROTOCOL: Protocol;
    const MAX_SESSIONS: usize = 8;
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    const NATIVE_CLIPBOARD: bool = false;
    fn interrupt() {}
    fn run(
        profile: &ConnectionProfile,
        password: &str,
        control: &Arc<Control>,
        inputs: mpsc::Receiver<Vec<RemoteInput>>,
        ready: SyncSender<Result<(), ProtocolError>>,
    );
}

impl<T: Transport> Default for DesktopBackend<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
            transport: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
use crate::rdp::RdpBackend;

#[derive(Debug)]
pub(crate) struct Control {
    pub(crate) route: Mutex<Option<Arc<crate::tunnel::Route>>>,
    pub(crate) cancelled: AtomicBool,
    pub(crate) input_failed: AtomicBool,
    pub(crate) active: AtomicBool,
    pub(crate) input_capture: Arc<AtomicBool>,
    pub(crate) clipboard: crate::native_clipboard::Clipboard,
    pub(crate) requested_size: std::sync::atomic::AtomicU64,
    pub(crate) dynamic_resize: AtomicBool,
    pub(crate) resize_available: AtomicBool,
    pub(crate) socket: Mutex<Option<TcpStream>>,
    pub(crate) events: SessionStreamSender,
}

impl Control {
    pub(crate) fn route(&self) -> Option<Arc<crate::tunnel::Route>> {
        lock(&self.route).clone()
    }
    pub(crate) fn sever_socket(&self) {
        self.clipboard.enable(false);
        self.input_capture.store(false, Ordering::SeqCst);
        self.active.store(false, Ordering::SeqCst);
        self.resize_available.store(false, Ordering::SeqCst);
        if let Some(socket) = lock(&self.socket).as_ref() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    pub(crate) fn receive_clipboard(&self, text: &str) {
        if self.active.load(Ordering::SeqCst)
            && !self.cancelled.load(Ordering::SeqCst)
            && self.clipboard.sharing(&self.input_capture)
            && let Ok(text) = crate::native_clipboard::normalize(text)
        {
            let _ = self
                .events
                .send(SessionEvent::Clipboard(crate::native_clipboard::Text(
                    Arc::new(text),
                )));
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.events.close();
        self.sever_socket();
    }

    pub(crate) fn fail_input(&self) {
        self.input_failed.store(true, Ordering::SeqCst);
        self.cancelled.store(true, Ordering::SeqCst);
        self.sever_socket();
    }

    pub(crate) fn adopt(&self, socket: &TcpStream) -> std::io::Result<()> {
        let mut registered = lock(&self.socket);
        *registered = Some(socket.try_clone()?);
        if self.cancelled.load(Ordering::SeqCst) {
            let _ = socket.shutdown(Shutdown::Both);
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Session {
    control: Arc<Control>,
    inputs: SyncSender<Vec<RemoteInput>>,
    worker: JoinHandle<()>,
    view_only: bool,
}

#[derive(Debug, Default)]
struct State {
    stopped: bool,
    resume_pending: bool,
    sessions: HashMap<Uuid, Session>,
}

#[derive(Debug)]
pub(crate) struct DesktopBackend<T: Transport> {
    transport: std::marker::PhantomData<T>,
    state: Mutex<State>,
}

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<T: Transport> DesktopBackend<T> {
    fn collect(state: &mut State) {
        let finished: Vec<_> = state
            .sessions
            .iter()
            .filter_map(|(id, session)| session.worker.is_finished().then_some(*id))
            .collect();
        for id in finished {
            if let Some(session) = state.sessions.remove(&id) {
                let _ = session.worker.join();
            }
        }
        if state.resume_pending && state.sessions.is_empty() {
            state.stopped = false;
            state.resume_pending = false;
        }
    }

    fn retire_if_current(&self, id: Uuid, control: &Arc<Control>) {
        let mut state = lock(&self.state);
        if let Some(session) = state.sessions.get(&id)
            && Arc::ptr_eq(&session.control, control)
        {
            session.control.cancel();
            T::interrupt();
        }
        Self::collect(&mut state);
    }

    pub fn retire(&self, id: Uuid) {
        let mut state = lock(&self.state);
        if let Some(session) = state.sessions.get(&id) {
            session.control.cancel();
            T::interrupt();
        }
        Self::collect(&mut state);
    }

    pub fn stop(&self) {
        let mut state = lock(&self.state);
        state.stopped = true;
        state.resume_pending = false;
        for session in state.sessions.values() {
            session.control.cancel();
            T::interrupt();
        }
        Self::collect(&mut state);
    }

    pub fn resume(&self) {
        let mut state = lock(&self.state);
        state.resume_pending = true;
        Self::collect(&mut state);
    }

    pub fn closing(&self) -> Vec<Uuid> {
        let mut state = lock(&self.state);
        Self::collect(&mut state);
        state
            .sessions
            .iter()
            .filter_map(|(id, session)| {
                session
                    .control
                    .cancelled
                    .load(Ordering::SeqCst)
                    .then_some(*id)
            })
            .collect()
    }
}

impl<T: Transport> RemoteProtocol for DesktopBackend<T> {
    fn resize_for(&self, id: Uuid, size: (u32, u32)) -> Result<(), ProtocolError> {
        if !matches!(T::PROTOCOL, Protocol::Rdp | Protocol::Spice) {
            return Err(ProtocolError::Refused(
                "This transport changes display size when reconnecting.".into(),
            ));
        }
        let state = lock(&self.state);
        let session = state
            .sessions
            .get(&id)
            .filter(|session| session.control.active.load(Ordering::SeqCst))
            .ok_or_else(|| {
                ProtocolError::Refused("The remote display is no longer active.".into())
            })?;
        if session.view_only || !session.control.dynamic_resize.load(Ordering::SeqCst) {
            return Err(ProtocolError::Refused(
                "Dynamic display resizing is disabled for this session.".into(),
            ));
        }
        let width = size.0.clamp(200, 3840) & !1;
        let height = size.1.clamp(200, 2160);
        session.control.requested_size.store(
            (u64::from(width) << 32) | u64::from(height),
            Ordering::SeqCst,
        );
        Ok(())
    }

    fn set_dynamic_resize_for(&self, id: Uuid, enabled: bool) -> Result<(), ProtocolError> {
        if !matches!(T::PROTOCOL, Protocol::Rdp | Protocol::Spice) {
            return Err(ProtocolError::Refused(
                "This transport cannot resize the guest display during a session.".into(),
            ));
        }
        let state = lock(&self.state);
        let session = state
            .sessions
            .get(&id)
            .filter(|s| {
                s.control.active.load(Ordering::SeqCst)
                    && !s.control.cancelled.load(Ordering::SeqCst)
            })
            .ok_or_else(|| {
                ProtocolError::Refused("The remote display is no longer active.".into())
            })?;
        if session.view_only {
            return Err(ProtocolError::Refused(
                "Guest display resizing is unavailable in view-only sessions.".into(),
            ));
        }
        if enabled && !session.control.resize_available.load(Ordering::SeqCst) {
            return Err(ProtocolError::Refused("The host has not enabled display resizing. RDP needs DisplayControl; SPICE needs its display agent.".into()));
        }
        session
            .control
            .dynamic_resize
            .store(enabled, Ordering::SeqCst);
        if !enabled {
            session.control.requested_size.store(0, Ordering::SeqCst);
        }
        Ok(())
    }

    fn input_capture_for(&self, id: Uuid) -> Option<Arc<AtomicBool>> {
        let state = lock(&self.state);
        let session = state.sessions.get(&id)?;
        (!session.view_only && session.control.active.load(Ordering::SeqCst))
            .then(|| Arc::clone(&session.control.input_capture))
    }

    fn clipboard_enabled_for(&self, id: Uuid, enabled: bool) {
        if let Some(session) = lock(&self.state).sessions.get(&id) {
            session
                .control
                .clipboard
                .enable(enabled && T::NATIVE_CLIPBOARD && !session.view_only);
        }
    }

    fn share_clipboard_for(&self, id: Uuid, text: &str) -> Result<(), ProtocolError> {
        let state = lock(&self.state);
        let session = state
            .sessions
            .get(&id)
            .filter(|s| {
                T::NATIVE_CLIPBOARD
                    && !s.view_only
                    && s.control.active.load(Ordering::SeqCst)
                    && !s.control.cancelled.load(Ordering::SeqCst)
            })
            .ok_or_else(|| {
                ProtocolError::Refused(
                    "Native text clipboard sharing is unavailable for this session.".into(),
                )
            })?;
        session
            .control
            .clipboard
            .queue(&session.control.input_capture, text)
            .map_err(ProtocolError::Refused)
    }

    fn protocol(&self) -> Protocol {
        T::PROTOCOL
    }

    fn connect(
        &self,
        profile: &ConnectionProfile,
        password: Option<&str>,
    ) -> Result<(Vec<SessionEvent>, Option<SessionStream>), ProtocolError> {
        if profile.protocol != T::PROTOCOL
            || (T::PROTOCOL == Protocol::Rdp && profile.username.trim().is_empty())
        {
            return Err(ProtocolError::Refused(
                "The profile does not meet the transport requirements.".into(),
            ));
        }
        let settle_deadline = Instant::now() + Duration::from_secs(5);
        let mut state = lock(&self.state);
        loop {
            Self::collect(&mut state);
            let retiring = state
                .sessions
                .get(&profile.id)
                .is_some_and(|session| session.control.cancelled.load(Ordering::SeqCst));
            if !retiring || state.stopped || Instant::now() >= settle_deadline {
                break;
            }
            drop(state);
            std::thread::sleep(Duration::from_millis(5));
            state = lock(&self.state);
        }
        if state.stopped || state.sessions.contains_key(&profile.id) {
            return Err(ProtocolError::Refused(format!(
                "{} is waiting for the previous connection to finish closing.",
                T::PROTOCOL.label()
            )));
        }
        if state.sessions.len() >= T::MAX_SESSIONS {
            return Err(ProtocolError::Refused(format!(
                "The {} connection limit has been reached.",
                T::PROTOCOL.label()
            )));
        }
        let (events, stream) = SessionStream::channel();
        let control = Arc::new(Control {
            route: std::sync::Mutex::new(None),
            cancelled: AtomicBool::new(false),
            input_failed: AtomicBool::new(false),
            active: AtomicBool::new(false),
            input_capture: Arc::new(AtomicBool::new(false)),
            clipboard: crate::native_clipboard::Clipboard::new(
                !profile.disable_clipboard && !profile.view_only,
            ),
            requested_size: std::sync::atomic::AtomicU64::new(0),
            dynamic_resize: AtomicBool::new(
                !profile.view_only
                    && profile
                        .extra
                        .get("remote.display.dynamic-resize")
                        .is_some_and(|value| value == "true"),
            ),
            resize_available: AtomicBool::new(false),
            socket: Mutex::new(None),
            events,
        });
        let (inputs, input_rx) = mpsc::sync_channel(64);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker_control = Arc::clone(&control);
        let worker_profile = profile.clone();
        let password = zeroize::Zeroizing::new(password.unwrap_or_default().to_owned());
        let worker = std::thread::Builder::new()
            .name(format!("remote-{}", T::PROTOCOL.key()))
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match crate::tunnel::Route::prepare(&worker_profile, &worker_control.cancelled)
                    {
                        Ok(route) => *lock(&worker_control.route) = route,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error));
                            return;
                        }
                    }
                    T::run(
                        &worker_profile,
                        &password,
                        &worker_control,
                        input_rx,
                        ready_tx,
                    );
                }));
                let route = lock(&worker_control.route).take();
                drop(route);
                worker_control.sever_socket();
                if outcome.is_err() && !worker_control.cancelled.load(Ordering::SeqCst) {
                    let _ = worker_control.events.send(SessionEvent::Drop(format!(
                        "The {} worker stopped unexpectedly.",
                        T::PROTOCOL.label()
                    )));
                }
                worker_control.cancel();
            })
            .map_err(|_| {
                ProtocolError::Transport(format!(
                    "{} could not start its connection worker.",
                    T::PROTOCOL.label()
                ))
            })?;
        state.sessions.insert(
            profile.id,
            Session {
                control: Arc::clone(&control),
                inputs,
                worker,
                view_only: profile.view_only,
            },
        );
        drop(state);
        let timeout = T::CONNECT_TIMEOUT
            + if profile.ssh_tunnel.is_some() {
                crate::tunnel::SETUP_TIMEOUT
            } else {
                Duration::ZERO
            };
        match ready_rx.recv_timeout(timeout) {
            Ok(Ok(())) if !control.cancelled.load(Ordering::SeqCst) => {
                Ok((vec![SessionEvent::Ready], Some(stream)))
            }
            Ok(Err(error)) => {
                self.retire_if_current(profile.id, &control);
                Err(error)
            }
            _ => {
                self.retire_if_current(profile.id, &control);
                Err(ProtocolError::Refused(format!(
                    "The {} connection was cancelled or exceeded its connection deadline.",
                    T::PROTOCOL.label()
                )))
            }
        }
    }

    fn send_input(&self, _input: RemoteInput) -> Result<(), ProtocolError> {
        Err(ProtocolError::Refused(format!(
            "{} input requires an explicit connection identity.",
            T::PROTOCOL.label()
        )))
    }

    fn send_input_for(&self, id: Uuid, input: RemoteInput) -> Result<(), ProtocolError> {
        self.send_inputs_for(id, &[input])
    }

    fn send_inputs_for(&self, id: Uuid, inputs: &[RemoteInput]) -> Result<(), ProtocolError> {
        let state = lock(&self.state);
        let session = state
            .sessions
            .get(&id)
            .filter(|session| {
                session.control.active.load(Ordering::SeqCst)
                    && !session.control.cancelled.load(Ordering::SeqCst)
            })
            .ok_or_else(|| {
                ProtocolError::Refused(format!(
                    "The {} connection is no longer active.",
                    T::PROTOCOL.label()
                ))
            })?;
        if session.view_only || inputs.len() > INPUT_BATCH_LIMIT {
            return Err(ProtocolError::Refused(format!(
                "{} input was refused by the session's input policy.",
                T::PROTOCOL.label()
            )));
        }
        session.inputs.try_send(inputs.to_vec()).map_err(|_| {
            session.control.fail_input();
            T::interrupt();
            ProtocolError::Transport(
                "RDP input could not be queued; the connection was closed to release held input."
                    .into(),
            )
        })
    }
}

impl<T: Transport> Drop for DesktopBackend<T> {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
#[path = "rdp/tests.rs"]
mod tests;
