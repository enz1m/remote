//! The VNC backend this build registers, and the two worker threads one live
//! connection owns.
//!
//! # Threads, and who owns what
//!
//! One connect produces one [`RfbSession`] owning a reader and writer. Plain
//! sockets use separate handles; TLS workers share serialized record state:
//!
//! * the reader ([`super::reader::read_loop`]) decodes and hands
//!   [`SessionEvent`]s to the app's bounded
//!   [`crate::protocol::SessionStreamSender`], waiting there when the app is
//!   behind;
//! * the writer drains a bounded channel onto the socket.
//!
//! The reducer never touches a socket: [`RemoteProtocol::send_input`] and
//! [`RemoteProtocol::resize_for`] only `try_send` to the writer, because a full
//! send buffer blocks for as long as the peer is unresponsive.
//!
//! # Retirement is close debt, and none of it waits on the reducer
//!
//! A connection is reachable by profile id while reserved (dialling), live,
//! and retiring (workers being joined). [`RfbBackend::begin_retire`] waits for
//! nothing: it stops the transport, cancels a handshaking dial through its
//! [`DialHandle`], and hands reader, writer and socket to a joining thread.
//! Until that join is collected the connection is closing, recorded as
//! [`VncCloseDebt`] and reported by [`RfbBackend::close_report`].
//!
//! A lost join (a panicked worker, or no signal inside [`JOIN_DEADLINE`])
//! becomes [`VncCloseProgress::Unknown`] permanently, and
//! [`RfbBackend::resume_admission`] never opens again: admitting beside an
//! owner of unknown fate lets two readers hold one profile's socket.
//! Admission is decided under the reservation lock, so a dial cannot publish
//! behind a close that already swept it.
//!
//! The handshake runs on the caller's `Task::perform` worker and finishes
//! before `connect` returns: `Ready` may not be reported before `ServerInit`
//! has named a desktop this build can hold.
//!
//! App input carries a profile identity; the legacy anonymous input route
//! refuses to guess when more than one session is live.

use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::handshake::{self, HANDSHAKE_DEADLINE, Handshake, RfbFailure};
use super::io::Stream as NetworkStream;
use super::policy::Exposure;
use super::reader::{self, READ_TIMEOUT};
use super::wire;
use crate::model::{ConnectionProfile, Protocol};
use crate::protocol::{
    ProtocolError, RemoteInput, RemoteProtocol, SessionStream, SessionStreamSender,
};
use crate::state_machine::SessionEvent;

/// The per-write timeout the writer thread runs under.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`RfbSession::close`] waits for each worker to leave its loop.
///
/// `close` shuts the socket down and drops the write channel before waiting,
/// so both workers' blocking calls return at once. A worker that misses the
/// deadline is dropped unjoined and reported as [`JoinOutcome::TimedOut`];
/// the closed socket means it can move no bytes.
pub const JOIN_DEADLINE: Duration = Duration::from_secs(2);

/// How many times a severed transport's join is attempted before its fate is
/// reported as unknown.
pub const CLOSE_ATTEMPTS: u32 = 3;

/// How long a dial waits for its own profile's previous transport to finish
/// closing before refusing to open a second one.
///
/// Spent on a dial's worker thread, never the reducer. Longer than
/// [`JOIN_DEADLINE`] so an ordinary join is never the reason a reconnect is
/// refused.
pub const SETTLE_DEADLINE: Duration = Duration::from_secs(5);

/// How long that wait sleeps between harvests.
const SETTLE_POLL: Duration = Duration::from_millis(5);

/// How many client messages may wait for the writer thread.
///
/// Small on purpose. Pointer moves arrive at motion-event rate and are worth
/// nothing once a newer one exists, so a deep queue would deliver a trail of
/// stale positions after a stall instead of dropping them. Overflow is a typed
/// refusal, never silently absorbed.
pub const WRITE_QUEUE_DEPTH: usize = 64;

/// Why [`RfbSession::close`] returned when it did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinOutcome {
    /// Both workers signalled and were joined.
    Joined,
    /// A worker did not signal within [`JOIN_DEADLINE`]; its handle was
    /// dropped rather than joined.
    TimedOut,
}

// ---------------------------------------------------------------------------
// Dial cancellation
// ---------------------------------------------------------------------------

/// The cancellation surface of one dial in flight.
///
/// A dispatched `Task::perform` cannot be cancelled, so a retirement reaches a
/// running handshake through the flag every bounded read re-checks and a
/// second handle on the dial's socket. Shutting that socket down returns the
/// parked read at once instead of holding a plaintext connection open until
/// [`HANDSHAKE_DEADLINE`].
#[derive(Debug, Default)]
pub struct DialHandle {
    cancelled: AtomicBool,
    socket: Mutex<Option<TcpStream>>,
}

impl DialHandle {
    pub fn new() -> Self {
        Self::default()
    }

    /// The flag the handshake's bounded reads re-check.
    pub fn cancel_flag(&self) -> &AtomicBool {
        &self.cancelled
    }

    fn socket(&self) -> std::sync::MutexGuard<'_, Option<TcpStream>> {
        self.socket.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Register the dial's socket so a retirement can shut it down.
    ///
    /// A `try_clone` that fails leaves the handle with no socket: the dial is
    /// then cancelled by its flag alone, which is the behaviour without this
    /// registration rather than a new failure.
    fn adopt(&self, socket: &TcpStream) {
        if let Ok(handle) = socket.try_clone() {
            *self.socket() = Some(handle);
        }
    }

    /// Release the registered handle once the handshake is over, so the
    /// session's own socket is the only one a close has to reach.
    fn release(&self) {
        *self.socket() = None;
    }

    /// Cancel this dial: store the flag, then shut its socket down.
    ///
    /// Same order [`RfbSession::sever`] uses and for the same reason — a read
    /// that wakes to an end of file caused by this call always observes the
    /// flag, so it reports cancellation rather than a server that hung up.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Some(socket) = self.socket().as_ref() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

// ---------------------------------------------------------------------------
// Pointer state
// ---------------------------------------------------------------------------

/// The button mask and position RFB requires on every pointer message.
///
/// RFB has no "button down" event: every `PointerEvent` carries the full mask
/// and a position, and [`RemoteInput`] carries neither. Without this state a
/// move during a drag would send a cleared mask and release the button.
///
/// Per session: two connections have two cursors.
#[derive(Clone, Copy, Debug, Default)]
struct PointerState {
    mask: u8,
    x: i32,
    y: i32,
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// One live RFB connection: the socket, its two workers, and their controls.
pub struct RfbSession {
    _route: Option<Arc<crate::tunnel::Route>>,
    profile_id: Uuid,
    /// The connect identity this session was opened under.
    ///
    /// Monotonic per backend; the transport-side counterpart of the app's
    /// stream generation, which tests read to prove a reconnect built a new
    /// session.
    generation: u64,
    socket: TcpStream,
    cancelled: Arc<AtomicBool>,
    /// `Option` only so `close` can drop it before waiting: the writer parks
    /// on an empty channel, and it wakes when the last sender goes away.
    writes: Option<SyncSender<Vec<u8>>>,
    exits: Receiver<()>,
    workers: Vec<std::thread::JoinHandle<()>>,
    /// A sender on the app's bounded event queue, kept so the teardown can
    /// close it. A reader parked on a full queue would otherwise leave only
    /// when the app next took an event, and a close may not depend on that.
    events: SessionStreamSender,
    /// The desktop geometry the reader is currently decoding, which the
    /// reader updates on a `DesktopSize` change.
    geometry: Arc<Mutex<(u32, u32)>>,
    pointer: Mutex<PointerState>,
    clipboard: Arc<super::clipboard::Clipboard>,
    exposure: Exposure,
    /// Whether the socket has already been shut down and the write channel
    /// dropped, so the ordered teardown runs once however often it is asked
    /// for.
    severed: bool,
    /// Worker exit signals already taken off [`Self::exits`], so a signal
    /// collected without blocking is not waited for a second time.
    exited: usize,
}

impl std::fmt::Debug for RfbSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RfbSession")
            .field("profile_id", &self.profile_id)
            .field("generation", &self.generation)
            .field("exposure", &self.exposure)
            .finish_non_exhaustive()
    }
}

impl RfbSession {
    /// The geometry the reader is currently decoding.
    pub fn geometry(&self) -> (u32, u32) {
        self.geometry.lock().map(|g| *g).unwrap_or((0, 0))
    }

    /// Enqueue one client message, never blocking the caller.
    fn enqueue(&self, bytes: Vec<u8>) -> Result<(), ProtocolError> {
        let Some(writes) = self.writes.as_ref() else {
            return Err(ProtocolError::Transport(
                "the connection is closed".to_string(),
            ));
        };
        match writes.try_send(bytes) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(ProtocolError::Transport(
                "the connection is not keeping up with input".to_string(),
            )),
            Err(TrySendError::Disconnected(_)) => Err(ProtocolError::Transport(
                "the connection is closed".to_string(),
            )),
        }
    }

    /// Turn one [`RemoteInput`] into the bytes RFB carries it as.
    ///
    /// The mask-and-position bookkeeping lives here because this is the only
    /// place that knows both halves.
    fn encode(&self, input: RemoteInput) -> Vec<u8> {
        let mut state = match self.pointer.lock() {
            Ok(guard) => guard,
            // A poisoned pointer lock means a previous encode panicked. The
            // keysym path does not need it, and a pointer message from a
            // cleared state is a cursor jump, not a wrong host.
            Err(poisoned) => poisoned.into_inner(),
        };
        match input {
            RemoteInput::PointerMove(x, y) => {
                state.x = x;
                state.y = y;
                wire::pointer_event(state.mask, x, y).to_vec()
            }
            RemoteInput::PointerButton { button, pressed } => {
                let bit = wire::button_bit(button);
                if pressed {
                    state.mask |= bit;
                } else {
                    state.mask &= !bit;
                }
                wire::pointer_event(state.mask, state.x, state.y).to_vec()
            }
            RemoteInput::KeyDown(keysym) => wire::key_event(true, keysym).to_vec(),
            RemoteInput::KeyUp(keysym) => wire::key_event(false, keysym).to_vec(),
        }
    }

    /// Stop the transport now, without waiting for either worker.
    ///
    /// On return the socket is shut down both ways and both workers' blocking
    /// calls have returned; the join is left to the session's owner. Idempotent.
    ///
    /// # Ordering contract
    ///
    /// 1. Store the cancellation flag (`SeqCst`) before the syscall that wakes
    ///    either worker, so an EOF or error caused by this close is always seen
    ///    with the flag set and a peer hang-up is not.
    /// 2. Shut the socket down, returning the reader's parked `read` instead of
    ///    waiting out [`super::reader::READ_TIMEOUT`].
    /// 3. Drop the write sender, returning the writer's parked `recv`. The reader
    ///    holds its own clone, so both exits are awaited.
    ///
    /// Reversing 1 and 2 would let the reader publish `SessionEvent::Drop` and
    /// show a requested close as a failed session.
    fn sever(&mut self) {
        if self.severed {
            return;
        }
        self.severed = true;
        self.clipboard.capture.store(false, Ordering::SeqCst);
        self.clipboard.enable(false);
        self.cancelled.store(true, Ordering::SeqCst);
        // Releases the other place a worker can park, the app's bounded event queue.
        // Already queued events are still delivered.
        self.events.close();
        let _ = self.socket.shutdown(Shutdown::Both);
        drop(self.writes.take());
    }

    /// Take whatever worker exit signals have already arrived, without
    /// blocking.
    fn collect_exits(&mut self) {
        while self.exited < self.workers.len() {
            if self.exits.try_recv().is_err() {
                return;
            }
            self.exited += 1;
        }
    }

    /// Sever the transport, then wait for both workers and join them.
    ///
    /// Bounded by [`JOIN_DEADLINE`] per worker and never blocked on I/O, since
    /// [`Self::sever`] has already returned both workers' blocking calls.
    /// Idempotent, so [`Drop`] and an explicit [`Self::close`] can share it.
    fn shutdown(&mut self) -> JoinOutcome {
        if self.workers.is_empty() {
            return JoinOutcome::Joined;
        }
        self.sever();
        self.collect_exits();

        let mut outcome = JoinOutcome::Joined;
        while self.exited < self.workers.len() {
            if self.exits.recv_timeout(JOIN_DEADLINE).is_err() {
                outcome = JoinOutcome::TimedOut;
                break;
            }
            self.exited += 1;
        }
        if outcome == JoinOutcome::Joined {
            for worker in self.workers.drain(..) {
                let _ = worker.join();
            }
        } else {
            // Detached rather than joined: the socket is shut down, so a
            // straggler can move no bytes. Clearing the handles keeps
            // `shutdown` idempotent.
            self.workers.clear();
        }
        outcome
    }

    /// Retire this session and report how the wait ended.
    pub fn close(mut self) -> JoinOutcome {
        self.shutdown()
    }
}

/// A dropped session closes its socket and joins its workers.
///
/// Dropping `RfbSession::socket` alone closes nothing, because the workers
/// hold their own handles; without this the reader would keep a live socket
/// open for up to [`super::reader::READ_TIMEOUT`]. Call `close` explicitly
/// where the outcome matters.
impl Drop for RfbSession {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(test)]
pub fn open(
    profile: &ConnectionProfile,
    generation: u64,
) -> Result<(RfbSession, Handshake, Vec<SessionEvent>, SessionStream), RfbFailure> {
    open_on(profile, generation, &DialHandle::new())
}

/// Open one RFB session: policy, socket, handshake, then the two workers.
///
/// The returned events contain `Ready` only because [`handshake::handshake`]
/// returned; a socket that merely connected never reaches `Ready`.
///
/// `dial` owns cancellation until the session is built: its flag is
/// re-checked by handshake reads and the socket is registered with it at
/// once, so a retirement ends the dial within one read.
#[cfg(test)]
pub fn open_on(
    profile: &ConnectionProfile,
    generation: u64,
    dial: &DialHandle,
) -> Result<(RfbSession, Handshake, Vec<SessionEvent>, SessionStream), RfbFailure> {
    open_on_with_password(profile, generation, dial, None)
}

pub(super) fn open_on_with_password(
    profile: &ConnectionProfile,
    generation: u64,
    dial: &DialHandle,
    password: Option<&str>,
) -> Result<(RfbSession, Handshake, Vec<SessionEvent>, SessionStream), RfbFailure> {
    let tls = handshake::VerifiedTls::for_profile(profile)?;
    let route =
        crate::tunnel::Route::prepare(profile, dial.cancel_flag()).map_err(|e| RfbFailure::Io {
            phase: "opening SSH tunnel",
            reason: e.to_string(),
        })?;
    let destination = if route.is_some() {
        super::policy::Destination {
            address: std::net::SocketAddr::from(([127, 0, 0, 1], profile.port)),
            exposure: super::policy::Exposure::Loopback,
        }
    } else {
        handshake::resolve(profile)?
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let socket = if let Some(route) = &route {
        route.connect(&profile.host, profile.port)
    } else {
        TcpStream::connect_timeout(&destination.address, HANDSHAKE_DEADLINE)
    }
    .map_err(|e| RfbFailure::Io {
        phase: "connecting",
        reason: e.to_string(),
    })?;
    dial.adopt(&socket);
    // Nagle would delay the small input messages behind an ACK, landing the
    // cursor a round trip late.
    let _ = socket.set_nodelay(true);

    let mut transport = NetworkStream::new(try_clone_tcp(&socket, "preparing VNC transport")?);
    let established = handshake::negotiate(
        &mut transport,
        destination,
        dial.cancel_flag(),
        password,
        tls,
    );
    dial.release();
    let established = established?;

    let reader_socket = clone_transport(&transport, "preparing the reader")?;
    let writer_socket = clone_transport(&transport, "preparing the writer")?;
    reader_socket
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|e| RfbFailure::Io {
            phase: "preparing the reader",
            reason: e.to_string(),
        })?;
    writer_socket
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|e| RfbFailure::Io {
            phase: "preparing the writer",
            reason: e.to_string(),
        })?;

    let (sender, stream) = SessionStream::channel();
    let (writes, write_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(WRITE_QUEUE_DEPTH);
    let (exit_tx, exits) = std::sync::mpsc::channel::<()>();
    let geometry = Arc::new(Mutex::new((established.width, established.height)));

    let clipboard = Arc::new(super::clipboard::Clipboard::new(
        !profile.disable_clipboard && !profile.view_only,
    ));
    let reader = spawn_reader(
        reader_socket,
        &established,
        &sender,
        &writes,
        reader::Shared {
            geometry: Arc::clone(&geometry),
            clipboard: Arc::clone(&clipboard),
        },
        &cancelled,
        exit_tx.clone(),
    )?;
    let writer = spawn_writer(writer_socket, write_rx, &sender, &cancelled, exit_tx)?;

    Ok((
        RfbSession {
            _route: route,
            profile_id: profile.id,
            generation,
            socket,
            cancelled,
            writes: Some(writes),
            exits,
            workers: vec![reader, writer],
            events: sender,
            geometry,
            pointer: Mutex::new(PointerState::default()),
            clipboard,
            exposure: established.exposure,
            severed: false,
            exited: 0,
        },
        established.clone(),
        vec![SessionEvent::Ready],
        stream,
    ))
}

fn try_clone_tcp(socket: &TcpStream, phase: &'static str) -> Result<TcpStream, RfbFailure> {
    socket.try_clone().map_err(|e| RfbFailure::Io {
        phase,
        reason: e.to_string(),
    })
}

fn clone_transport(
    socket: &NetworkStream,
    phase: &'static str,
) -> Result<NetworkStream, RfbFailure> {
    socket.try_clone().map_err(|error| RfbFailure::Io {
        phase,
        reason: error.to_string(),
    })
}

type Worker = std::thread::JoinHandle<()>;

fn spawn_reader(
    mut socket: NetworkStream,
    established: &Handshake,
    sender: &SessionStreamSender,
    writes: &SyncSender<Vec<u8>>,
    shared: reader::Shared,
    cancelled: &Arc<AtomicBool>,
    exit_tx: std::sync::mpsc::Sender<()>,
) -> Result<Worker, RfbFailure> {
    let (width, height) = (established.width, established.height);
    let sender = sender.clone();
    let writes = writes.clone();
    let cancelled = Arc::clone(cancelled);
    std::thread::Builder::new()
        .name("rfb-reader".to_string())
        .spawn(move || {
            let reason = reader::read_loop(
                &mut socket,
                width,
                height,
                &sender,
                &writes,
                &shared,
                &cancelled,
            );
            // A reason is a server-side end and becomes `Drop`. Cancellation stays
            // silent: the reducer already applied `Disconnect`.
            if let Some(reason) = reason {
                let _ = sender.send(SessionEvent::Drop(reason));
            }
            let _ = exit_tx.send(());
        })
        .map_err(|e| RfbFailure::Io {
            phase: "starting the reader",
            reason: e.to_string(),
        })
}

fn spawn_writer(
    mut socket: NetworkStream,
    write_rx: Receiver<Vec<u8>>,
    sender: &SessionStreamSender,
    cancelled: &Arc<AtomicBool>,
    exit_tx: std::sync::mpsc::Sender<()>,
) -> Result<Worker, RfbFailure> {
    let sender = sender.clone();
    let cancelled = Arc::clone(cancelled);
    std::thread::Builder::new()
        .name("rfb-writer".to_string())
        .spawn(move || {
            while let Ok(message) = write_rx.recv() {
                if cancelled.load(Ordering::SeqCst) {
                    break;
                }
                if let Err(e) = socket.write_all(&message) {
                    // `shutdown` stores the flag before breaking this write, so a set
                    // flag means a local teardown; a clear one means the remote stopped
                    // accepting input and belongs on the status line.
                    if !cancelled.load(Ordering::SeqCst) {
                        let _ = sender.send(SessionEvent::InputRejected(e.to_string()));
                    }
                    break;
                }
            }
            let _ = exit_tx.send(());
        })
        .map_err(|e| RfbFailure::Io {
            phase: "starting the writer",
            reason: e.to_string(),
        })
}

// ---------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------

/// One dial in flight: the profile it is for and the generation it will
/// register under.
///
/// Reserved before a socket exists so a retirement can reach a connection
/// that is still being opened. The generation tells two dials for one profile
/// apart, so withdrawing the older reservation cannot retire the newer dial.
#[derive(Debug)]
struct Reservation {
    profile_id: Uuid,
    generation: u64,
    /// What a retirement cancels this dial through while it is still
    /// handshaking.
    dial: Arc<DialHandle>,
}
#[path = "backend/vnc.rs"]
mod vnc;

pub use vnc::RfbBackend;

/// How far one severed transport has got in closing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VncCloseProgress {
    /// The workers are being joined, or another attempt is owed.
    Closing,
    /// The join was lost: a worker never signalled inside [`JOIN_DEADLINE`],
    /// or the thread waiting for it panicked. Permanent — the transport was
    /// consumed by that attempt, so nothing is left to close and nothing can
    /// prove those threads are gone.
    Unknown,
}

/// One profile's outstanding close, for a surface that must not report a
/// connection settled while its workers are still alive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VncCloseDebt {
    /// The profile whose transport is closing.
    pub profile_id: Uuid,
    /// How far that close has got.
    pub progress: VncCloseProgress,
}

/// A severed transport whose reader, writer and socket are still owned by a
/// join that has not been collected.
#[derive(Debug)]
struct Retiring {
    profile_id: Uuid,
    /// The session, held here whenever no join owns it.
    ///
    /// Behind a lock so a failed thread spawn leaves the transport here for a
    /// retry, instead of running [`RfbSession`]'s joining `Drop` on the reducer.
    session: Arc<Mutex<Option<RfbSession>>>,
    task: Option<std::thread::JoinHandle<JoinOutcome>>,
    attempts: u32,
    settled: bool,
    progress: VncCloseProgress,
}

impl Retiring {
    fn new(session: RfbSession) -> Self {
        Self {
            profile_id: session.profile_id,
            session: Arc::new(Mutex::new(Some(session))),
            task: None,
            attempts: 0,
            settled: false,
            progress: VncCloseProgress::Closing,
        }
    }

    fn debt(&self) -> VncCloseDebt {
        VncCloseDebt {
            profile_id: self.profile_id,
            progress: self.progress,
        }
    }

    /// Whether a join is owed and one is still allowed.
    fn owed(&self) -> bool {
        !self.settled && self.progress == VncCloseProgress::Closing
    }

    /// Whether this close can still advance without the user being asked.
    ///
    /// False once a join is running nowhere and every allowed attempt has
    /// been spent, which is what stops a retry wake from running against work
    /// that will not move until the user asks for it again.
    fn advancing(&self) -> bool {
        self.owed() && (self.task.is_some() || self.attempts < CLOSE_ATTEMPTS)
    }

    /// Start a join on its own thread, if one is owed and allowed.
    ///
    /// Off the reducer by construction: the wait for the workers happens on
    /// the spawned thread, and the caller only ever holds the handle.
    fn dispatch(&mut self) {
        // `owed` first: an entry whose join was lost has had its transport
        // consumed, and starting a second "join" for it would discharge a debt
        // nothing settled.
        if !self.owed() || self.task.is_some() || self.attempts >= CLOSE_ATTEMPTS {
            return;
        }
        self.attempts += 1;
        let slot = Arc::clone(&self.session);
        let spawned = std::thread::Builder::new()
            .name("rfb-retire".to_string())
            .spawn(move || {
                let session = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
                match session {
                    Some(session) => session.close(),
                    // Nothing to close: an earlier attempt already took it.
                    None => JoinOutcome::Joined,
                }
            });
        // A thread that could not be spawned dropped the closure without
        // taking the session, so the transport is still here for the next
        // attempt rather than joined on this thread.
        if let Ok(task) = spawned {
            self.task = Some(task);
        }
    }

    /// Collect a finished join, if there is one.
    ///
    /// An entry that is settled or [`VncCloseProgress::Unknown`] is final:
    /// nothing collected afterwards may discharge it, because the attempt that
    /// lost its join is the one that consumed the transport.
    fn collect(&mut self) {
        if !self.owed() {
            return;
        }
        if !self
            .task
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
        {
            return;
        }
        match self.task.take().map(std::thread::JoinHandle::join) {
            Some(Ok(JoinOutcome::Joined)) => self.settled = true,
            // A detached worker and a panicked joiner are the same fact: the
            // transport is shut down, and a thread that was holding it is
            // unaccounted for.
            _ => self.progress = VncCloseProgress::Unknown,
        }
    }
}

#[cfg(test)]
impl RfbSession {
    pub fn generation(&self) -> u64 {
        self.generation
    }
}
