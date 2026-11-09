//! `RemoteProtocol`, the trait every protocol backend implements, and
//! [`BackendRegistry`], the single authority for which protocols this build can
//! dial.
//!
//! # What this build ships
//!
//! [`BackendRegistry::production`] registers VNC/RFB, embedded RDP with
//! system-trusted TLS, SPICE, RustDesk and Moonlight. OpenSSH carries optional TCP tunnels. Legacy SSH has no desktop input
//! or framebuffer resize capability.
//!
//! A protocol with no registered slot is not offered: [`BackendRegistry::choices`]
//! omits it from the form's picker and Quick Connect refuses its URI. It stays
//! visible: existing saved or imported profiles remain listed, editable,
//! exportable and deletable, render [`NOT_IN_THIS_BUILD`] where a Connect control
//! would go, and the reducer refuses their connect edge. Stored protocols are
//! never rewritten. Every control derives its offer from the registered slots, so
//! registering a backend in `production()` restores all of them.
//!
//! # Contract
//!
//! - `connect(profile, password)` performs the transport setup (TCP, TLS, auth)
//!   and returns immediate `SessionEvent`s (typically `Ready`) plus an optional
//!   [`SessionStream`] for frames, drops and input rejections after the
//!   handshake. The reducer runs it via `Task::perform`, after applying
//!   `SessionEvent::Connect` itself.
//! - `send_input` forwards keyboard/mouse input to the remote.
//! - `resize` requests a new framebuffer size (best-effort; some protocols
//!   ignore it).
//! - `disconnect` is idempotent.
//!
//! `StubBackend` fails every connect and is a fixture for the demo library only.
//! `FakeStreamingBackend` is a test fixture that drives the full streaming
//! boundary.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use crate::model::{ConnectionProfile, Protocol, QUALITY_LABELS, quality_index};
use crate::state_machine::SessionEvent;

// ---------------------------------------------------------------------------
// Session stream
// ---------------------------------------------------------------------------

/// How many events may wait for the app at once.
///
/// Small on purpose. A framebuffer protocol's events are whole desktops, and
/// the point of the bound is that a producer cannot run ahead of the reducer:
/// the depth only has to cover a terminal event sitting behind the frame that
/// is already being presented.
pub const MAX_QUEUED_EVENTS: usize = 4;

/// The most pixel and diagnostic bytes the queue may hold at once.
///
/// Equal to the single-frame ceiling in
/// [`crate::framebuffer::REMOTE_FRAME_LIMITS`], so the largest accepted desktop is
/// queued alone. A session's worst case is this plus
/// `crate::framebuffer::MAX_RETAINED_BYTES`.
pub const MAX_QUEUED_BYTES: usize = 32 * 1024 * 1024;

/// What one queued event costs against [`MAX_QUEUED_BYTES`].
///
/// A frame costs its pixels: `width * height * 4` is exactly the buffer
/// length [`crate::framebuffer::admit`] will accept for that geometry, so the
/// accounting cannot drift from the allocation it is bounding. Everything
/// else costs its own diagnostic text.
fn event_cost(event: &SessionEvent) -> usize {
    match event {
        SessionEvent::Frame { width, height, .. } => (*width as usize)
            .saturating_mul(*height as usize)
            .saturating_mul(4),
        SessionEvent::Fail(text) | SessionEvent::Drop(text) | SessionEvent::InputRejected(text) => {
            text.len()
        }
        SessionEvent::Clipboard(text) => text.0.len(),
        _ => 0,
    }
}

/// Why a send did not queue an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionStreamClosed;

impl std::fmt::Display for SessionStreamClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the session's event stream is closed")
    }
}

impl std::error::Error for SessionStreamClosed {}

struct Queued {
    event: SessionEvent,
    cost: usize,
}

#[derive(Default)]
struct QueueState {
    items: VecDeque<Queued>,
    bytes: usize,
    senders: usize,
    closed: bool,
    waker: Option<Waker>,
}

/// The bounded handoff between a backend's threads and the reducer.
///
/// Two bounds ([`MAX_QUEUED_EVENTS`] and [`MAX_QUEUED_BYTES`]) and a blocking
/// sender: a producer at either bound waits rather than allocating. An empty
/// queue always admits, so one oversized frame is delivered rather than
/// deadlocked. A waiting sender is released by [`Self::close`], by the receiver
/// being dropped, or by the app taking an event.
struct EventQueue {
    state: Mutex<QueueState>,
    capacity: Condvar,
}

impl EventQueue {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState {
                senders: 1,
                ..QueueState::default()
            }),
            capacity: Condvar::new(),
        })
    }

    /// The queue state, recovering a poisoned lock.
    ///
    /// A panic elsewhere must not turn this into a queue that refuses every
    /// send: a sender that could not report a drop, and a receiver that never
    /// ended, are both worse than continuing with the state as it stands.
    fn lock(&self) -> MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queue one event, waiting while the queue is at either bound.
    ///
    /// # Errors
    ///
    /// [`SessionStreamClosed`] once the stream is closed or the receiver is
    /// gone, which is also what wakes a sender that is already waiting.
    fn send(&self, event: SessionEvent) -> Result<(), SessionStreamClosed> {
        let cost = event_cost(&event);
        let mut state = self.lock();
        while !state.closed
            && !state.items.is_empty()
            && (state.items.len() >= MAX_QUEUED_EVENTS
                || state.bytes.saturating_add(cost) > MAX_QUEUED_BYTES)
        {
            state = self
                .capacity
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        if state.closed {
            return Err(SessionStreamClosed);
        }
        state.bytes = state.bytes.saturating_add(cost);
        state.items.push_back(Queued { event, cost });
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }

    /// Refuse further sends and release every waiting one.
    fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        let waker = state.waker.take();
        drop(state);
        self.capacity.notify_all();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn poll_next(&self, cx: &mut Context<'_>) -> Poll<Option<SessionEvent>> {
        let mut state = self.lock();
        if let Some(queued) = state.items.pop_front() {
            state.bytes = state.bytes.saturating_sub(queued.cost);
            drop(state);
            self.capacity.notify_all();
            return Poll::Ready(Some(queued.event));
        }
        if state.closed || state.senders == 0 {
            return Poll::Ready(None);
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn add_sender(&self) {
        self.lock().senders += 1;
    }

    fn drop_sender(&self) {
        let mut state = self.lock();
        state.senders = state.senders.saturating_sub(1);
        if state.senders > 0 {
            return;
        }
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// The events and bytes waiting for the app right now.
    fn queued(&self) -> (usize, usize) {
        let state = self.lock();
        (state.items.len(), state.bytes)
    }
}

/// A stream of [`SessionEvent`]s delivered asynchronously after the initial
/// handshake.
///
/// The backend owns the send half; the app's polling task owns this one. The
/// stream ends when every sender is gone or the queue is closed, and dropping
/// it releases any sender waiting for capacity, so retiring a session cannot
/// leave a worker parked on a queue nobody reads.
pub struct SessionStream {
    queue: Arc<EventQueue>,
}

impl SessionStream {
    /// Create a `(sender, stream)` pair. The sender goes to the backend; the
    /// stream goes to the app.
    pub fn channel() -> (SessionStreamSender, Self) {
        let queue = EventQueue::new();
        (
            SessionStreamSender {
                queue: Arc::clone(&queue),
            },
            Self { queue },
        )
    }

    /// Receive the next event, returning `None` when the stream has ended.
    pub async fn recv(&mut self) -> Option<SessionEvent> {
        let queue = Arc::clone(&self.queue);
        std::future::poll_fn(move |cx| queue.poll_next(cx)).await
    }

    #[cfg(test)]
    pub fn queued(&self) -> (usize, usize) {
        self.queue.queued()
    }
}

impl std::fmt::Debug for SessionStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStream").finish_non_exhaustive()
    }
}

/// A dropped receiver ends the stream and releases every waiting sender.
impl Drop for SessionStream {
    fn drop(&mut self) {
        self.queue.close();
    }
}

/// Convert a [`SessionStream`] into a `futures::Stream` for use with
/// `Task::run`. Each item is a [`SessionEvent`]; the stream ends when the last
/// sender is dropped or the queue is closed, after whatever was already
/// queued has been delivered.
pub fn session_stream_to_futures_stream(
    stream: SessionStream,
) -> impl iced::futures::Stream<Item = SessionEvent> {
    iced::futures::stream::unfold(stream, |mut s| async move {
        let event = s.recv().await?;
        Some((event, s))
    })
}

/// The send half of a [`SessionStream`] channel.
///
/// Cloneable so a backend can hand copies to its decoder thread, its
/// keep-alive thread, etc. The stream ends when the last clone is dropped.
pub struct SessionStreamSender {
    queue: Arc<EventQueue>,
}

impl SessionStreamSender {
    /// Queue an event for the app, waiting while the queue is full.
    ///
    /// This backpressure paces a framebuffer reader by the reducer, so a remote
    /// cannot make this build hold more than [`MAX_QUEUED_BYTES`].
    ///
    /// # Errors
    ///
    /// [`SessionStreamClosed`] when the stream has been closed or the app has
    /// dropped the receiver.
    pub fn send(&self, event: SessionEvent) -> Result<(), SessionStreamClosed> {
        self.queue.send(event)
    }

    /// Refuse further sends and release a sender waiting for capacity.
    ///
    /// Called by a session's own teardown, before it waits for its workers: a
    /// worker parked on a full queue would otherwise only leave when the app
    /// next drained one, which is not something a close may depend on.
    pub fn close(&self) {
        self.queue.close();
    }
}

impl Clone for SessionStreamSender {
    fn clone(&self) -> Self {
        self.queue.add_sender();
        Self {
            queue: Arc::clone(&self.queue),
        }
    }
}

impl Drop for SessionStreamSender {
    fn drop(&mut self) {
        self.queue.drop_sender();
    }
}

impl std::fmt::Debug for SessionStreamSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (events, bytes) = self.queue.queued();
        f.debug_struct("SessionStreamSender")
            .field("queued_events", &events)
            .field("queued_bytes", &bytes)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Connection parameters
// ---------------------------------------------------------------------------

/// The picture parameters a session was actually opened with.
///
/// The profile's `quality` and `color_depth` are captured here at connect time
/// and passed through `RemoteProtocol::negotiate`; the session surface renders the
/// negotiated result, pinned by
/// `render_tests::the_session_surface_reports_the_negotiated_quality`. A protocol
/// that cannot carry a parameter reports `None` for it rather than echoing the
/// request (SSH has no picture; Moonlight is fixed 32-bit).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ConnectParams {
    /// The requested picture quality on the profile's `0..=9` scale, or `None`
    /// for a protocol with no picture at all.
    ///
    /// `None` and `Some(0)` are different: `Some(0)` is "the worst picture
    /// this protocol offers", `None` is "this protocol has no picture".
    /// Collapsing them would make an SSH session claim it is rendering at
    /// `Poor`.
    pub quality: Option<u8>,
    /// The requested colour depth in bits, or `None` for a protocol that has
    /// no colour depth to choose.
    pub color_depth: Option<u8>,
    /// Whether the session was opened read-only.
    pub view_only: bool,
}

impl ConnectParams {
    /// The parameters a profile asks for, before any backend has clamped them.
    pub fn from_profile(p: &ConnectionProfile) -> Self {
        Self {
            quality: Some(p.quality),
            color_depth: Some(p.color_depth),
            view_only: p.view_only,
        }
    }

    /// The rendered quality name (`Poor`…`Best`), or `None` when the protocol
    /// carries no picture.
    ///
    /// Uses the same `quality_index` rung mapping the form's picker selects
    /// with, so the string under the surface is the string the picker showed
    /// and the two cannot drift.
    pub fn quality_label(&self) -> Option<&'static str> {
        let q = self.quality?;
        Some(QUALITY_LABELS[quality_index(q)])
    }

    /// The one-line "what this session negotiated" summary the surface renders.
    ///
    /// A protocol with no picture says so explicitly rather than omitting the
    /// line: a missing line reads as "nobody looked", while `No picture
    /// parameters` reads as the deliberate answer it is.
    pub fn summary(&self) -> String {
        match (self.quality_label(), self.color_depth) {
            (Some(q), Some(d)) => format!("Quality: {q} · {d}-bit"),
            (Some(q), None) => format!("Quality: {q}"),
            (None, Some(d)) => format!("{d}-bit"),
            (None, None) => "No picture parameters".to_string(),
        }
    }
}

/// A keyboard or mouse event to forward to the remote.
///
/// `PartialEq` so a test can state the exact sequence a gesture produced:
/// "the remote received a move to (10, 10), then a left press" is the claim,
/// and a set-membership check would pass for a route that sent the button
/// without positioning it first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteInput {
    KeyDown(u32),
    KeyUp(u32),
    /// Absolute (x, y) in remote framebuffer pixels.
    PointerMove(i32, i32),
    PointerButton {
        button: PointerButton,
        pressed: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PointerButton {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
    WheelLeft,
    WheelRight,
}

#[derive(Clone, Debug)]
pub enum ProtocolError {
    /// The protocol is defined but its backend is not compiled into this build.
    NotSupported(Protocol),
    /// Underlying transport failed to establish.
    Transport(String),
    /// Authentication was refused.
    Auth(String),
    /// The attempt was refused by policy, configuration or the user, so the
    /// next identical attempt has the same answer.
    ///
    /// Covers unestablishable forwards, undialable profiles, an exhausted generation
    /// counter and cancellation. The message is a complete sentence, rendered
    /// without a prefix.
    Refused(String),
}

impl ProtocolError {
    /// Whether another attempt could differ on its own.
    ///
    /// The reconnect policy consults this before scheduling: only a transport
    /// failure may be retried, and everything else waits for the user.
    #[must_use]
    pub fn retry_disposition(&self) -> crate::reconnect::RetryDisposition {
        match self {
            Self::Transport(_) => crate::reconnect::RetryDisposition::Transient,
            Self::NotSupported(_) | Self::Auth(_) | Self::Refused(_) => {
                crate::reconnect::RetryDisposition::RequiresUser
            }
        }
    }
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSupported(p) => {
                write!(f, "protocol {} has no backend in this build", p.label())
            }
            Self::Transport(msg) => write!(f, "transport failed: {msg}"),
            Self::Auth(msg) => write!(f, "authentication failed: {msg}"),
            Self::Refused(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// A trait every protocol backend implements.
///
/// `Send + Sync` because the reducer holds backends behind
/// `Arc<dyn RemoteProtocol>` and hands them to worker tasks without cloning.
pub trait RemoteProtocol: Send + Sync + std::fmt::Debug {
    fn input_capture_for(&self, _id: uuid::Uuid) -> Option<Arc<std::sync::atomic::AtomicBool>> {
        None
    }

    /// Updates the session's permission to exchange native clipboard text.
    fn clipboard_enabled_for(&self, _id: uuid::Uuid, _enabled: bool) {}

    /// Queues bounded text for the named session, refusing unsupported or inactive sharing.
    fn share_clipboard_for(&self, _id: uuid::Uuid, _text: &str) -> Result<(), ProtocolError> {
        Err(ProtocolError::Refused(
            "Native text clipboard sharing is unavailable for this protocol.".into(),
        ))
    }

    /// Which protocol enum variant this backend serves.
    fn protocol(&self) -> Protocol;

    /// Perform the connection handshake and return immediate events plus an
    /// optional [`SessionStream`] for ongoing delivery.
    ///
    /// The caller (`drive_session`) applies `SessionEvent::Connect` first and runs
    /// this via `Task::perform`, so it may block; the returned events are the
    /// outcome (`Ready` or `Fail(msg)`). `Some(stream)` means more events follow and
    /// the app's subscription routes them through the reducer; `None` is one-shot.
    ///
    /// # Password
    ///
    /// Fetched beforehand by the reducer through the async
    /// `enzui_services::credential_store` seam, because unlocking a keyring can
    /// prompt and take arbitrarily long. `None` means nothing is stored, the store is
    /// unavailable, or the profile authenticates by other means.
    fn connect(
        &self,
        profile: &ConnectionProfile,
        password: Option<&str>,
    ) -> Result<(Vec<SessionEvent>, Option<SessionStream>), ProtocolError>;

    /// Send an input event upstream. `NotSupported` for `StubBackend`.
    fn send_input(&self, input: RemoteInput) -> Result<(), ProtocolError>;

    /// Send input to the session owned by this profile.
    fn send_input_for(
        &self,
        _profile_id: uuid::Uuid,
        input: RemoteInput,
    ) -> Result<(), ProtocolError> {
        self.send_input(input)
    }

    /// Queue one complete chord or paste without splitting a key pair.
    fn send_inputs_for(
        &self,
        profile_id: uuid::Uuid,
        inputs: &[RemoteInput],
    ) -> Result<(), ProtocolError> {
        for input in inputs {
            self.send_input_for(profile_id, *input)?;
        }
        Ok(())
    }

    /// Enable guest display changes for this interactive session.
    ///
    /// Returns a refusal when the transport or negotiated host cannot resize.
    fn set_dynamic_resize_for(
        &self,
        _profile_id: uuid::Uuid,
        _enabled: bool,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::Refused(
            "This transport cannot resize the guest display during a session.".into(),
        ))
    }

    /// Request a framebuffer resize. Best-effort.
    fn resize_for(&self, _profile_id: uuid::Uuid, size: (u32, u32)) -> Result<(), ProtocolError>;
}

// ---------------------------------------------------------------------------
// Fake streaming backend
// ---------------------------------------------------------------------------

/// The disclosure every surface shows in place of a Connect affordance for a
/// protocol this build has no backend for.
///
/// One constant so the sidebar row, the context menu, the connection form and
/// the Quick Connect sheet cannot drift into four different sentences, and so
/// a render test names the string it expects rather than re-deriving it.
pub const NOT_IN_THIS_BUILD: &str = "Not available in this build";

#[path = "protocol/registry.rs"]
mod registry;

pub use registry::BackendRegistry;

/// A placeholder backend that fails every connect and refuses every operation.
///
/// A fixture reachable only through [`BackendRegistry::with_stubs`], alongside
/// the demo library, so session paths can be driven end to end. Launches never
/// register one.
#[derive(Debug)]

pub struct StubBackend {
    protocol: Protocol,
}

impl StubBackend {
    pub fn new(protocol: Protocol) -> Self {
        Self { protocol }
    }
}

/// What a protocol can carry of a requested [`ConnectParams`].
///
/// * SSH has no framebuffer, so quality and colour depth are both `None`.
/// * Moonlight and RustDesk retain quality preferences and use 32-bit output.
/// * This VNC transport uses lossless Raw/CopyRect/ZRLE updates at 32-bit depth.
///
/// `view_only` is honoured everywhere because it is enforced locally by not
/// sending input.
pub fn negotiate_for(protocol: Protocol, requested: ConnectParams) -> ConnectParams {
    match protocol {
        Protocol::Ssh => ConnectParams {
            quality: None,
            color_depth: None,
            view_only: requested.view_only,
        },
        Protocol::Moonlight | Protocol::RustDesk => ConnectParams {
            color_depth: Some(32),
            ..requested
        },
        Protocol::Vnc | Protocol::Rdp | Protocol::Spice => ConnectParams {
            quality: None,
            color_depth: Some(32),
            view_only: requested.view_only,
        },
    }
}

impl RemoteProtocol for StubBackend {
    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn connect(
        &self,
        _profile: &ConnectionProfile,
        _password: Option<&str>,
    ) -> Result<(Vec<SessionEvent>, Option<SessionStream>), ProtocolError> {
        // One-shot: the caller already applied `Connect`, so only the terminal `Fail`
        // is reported.
        Ok((
            vec![SessionEvent::Fail(format!(
                "protocol {} has no backend compiled into this build",
                self.protocol.label()
            ))],
            None,
        ))
    }

    fn send_input(&self, _input: RemoteInput) -> Result<(), ProtocolError> {
        Err(ProtocolError::NotSupported(self.protocol))
    }

    fn resize_for(&self, _profile_id: uuid::Uuid, _size: (u32, u32)) -> Result<(), ProtocolError> {
        Err(ProtocolError::NotSupported(self.protocol))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
