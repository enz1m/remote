//! A generated RFB server, bound to `127.0.0.1:0`, that the production parser
//! and worker connect to for real.
//!
//! # Why a socket and not a mocked reader
//!
//! Byte layouts and blocking discipline are what an RFB client most likely
//! gets wrong, and a fake `Read` cannot produce a half-written message, a
//! mid-rectangle close, a stall, or a `shutdown` that must unblock a parked
//! thread. Every test drives [`super::backend::open`] (the real connect,
//! handshake and worker threads) against scripted bytes on an ephemeral
//! loopback port.
//!
//! No external host is contacted, and nothing here reads configuration or
//! environment variables.
//!
//! # Scripted, not simulated
//!
//! A [`ServerScript`] is a list of [`Step`]s performed in order, which makes
//! hostile cases reachable: `Step::Raw` writes arbitrary bytes, `Step::Stall`
//! waits silently, and `Step::CloseAbruptly` hangs up anywhere.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::wire;

/// Every fixture read and write is bounded so a defect in the code under test
/// fails a test instead of hanging the suite.
///
/// Longer than any deadline a test waits on (the pump's ten seconds, the
/// drain's five), so the test's assertion reports the failure; a fixture
/// timing out first would surface as a server-side drop and point at the
/// wrong half of the system.
pub const FIXTURE_TIMEOUT: Duration = Duration::from_secs(20);

/// How long [`ScriptedServer`]'s drop waits for its script thread to leave.
///
/// The owner's session is dropped first (drop order is reverse of
/// declaration, and the app outlives nothing here), which closes the socket
/// and makes every fixture read return at once, so the only thing left to
/// wait out is a trailing [`Step::Stall`]. Bounded, and detaching on timeout:
/// the socket is gone, so a straggler can move no bytes.
const SCRIPT_JOIN_DEADLINE: Duration = Duration::from_millis(2500);

/// How long a `Stall` step waits — long enough to exceed a deadline under
/// test, short enough that a test which reaches it still finishes.
pub const STALL: Duration = Duration::from_millis(1500);

/// One thing the scripted server does.
#[derive(Clone, Debug)]
pub enum Step {
    /// Write the RFB 3.8 version greeting.
    Version,
    /// Write an arbitrary version string, for the unsupported-version case.
    VersionRaw(&'static [u8]),
    /// Read the client's 12-byte version.
    ExpectVersion,
    /// Offer these security types.
    Security(Vec<u8>),
    /// Offer no security types, then this refusal reason.
    SecurityRefused(String),
    /// Read the client's one-byte security choice.
    ExpectSecurityChoice,
    /// Write `SecurityResult`: `0` for success, anything else followed by a
    /// reason.
    SecurityResult { code: u32, reason: String },
    /// Read `ClientInit`.
    ExpectClientInit,
    /// Write `ServerInit` with this geometry and name.
    ServerInit {
        width: u16,
        height: u16,
        name: String,
    },
    /// Write a `ServerInit` whose name-length prefix claims this many bytes
    /// without sending them, for the oversized-length case.
    ServerInitOverlongName { claimed: u32 },
    /// Read `SetPixelFormat`, `SetEncodings` and the first
    /// `FramebufferUpdateRequest`, recording each for assertion.
    ExpectClientSetup,
    /// Write a `FramebufferUpdate` carrying one Raw rectangle filled with this
    /// colour, given as `(r, g, b)`.
    RawRect {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        colour: (u8, u8, u8),
    },
    /// Write a `FramebufferUpdate` carrying a `DesktopSize` pseudo-rectangle.

    /// Write a rectangle header with this encoding and no data, for the
    /// unsupported-encoding case.
    RectWithEncoding {
        width: u16,
        height: u16,
        encoding: i32,
    },
    /// Write a rectangle header whose geometry runs outside the framebuffer.
    RectOutOfBounds {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    },
    /// Write a Raw rectangle header and then fewer pixel bytes than it
    /// promises, then close.
    TruncatedRect { width: u16, height: u16 },
    /// Read one client message of this length and record it.
    ExpectClientMessage { bytes: usize },
    /// Write arbitrary bytes.
    Raw(Vec<u8>),
    /// Write nothing and wait, so a deadline under test can expire.
    Stall,
    /// Hang up.
    CloseAbruptly,
    /// Signal the test that the script reached this point.
    Checkpoint(&'static str),
}

/// What the server observed, for assertions about what the client sent.
#[derive(Debug, Default)]
pub struct Observed {
    pub client_version: Option<Vec<u8>>,
    pub security_choice: Option<u8>,
    pub client_init: Option<u8>,
    pub set_pixel_format: Option<Vec<u8>>,
    pub set_encodings: Option<Vec<u8>>,
    /// Every `FramebufferUpdateRequest` and input message, in arrival order.
    pub messages: Vec<Vec<u8>>,
}

/// A running scripted server.
pub struct ScriptedServer {
    /// Minted once, in [`Self::start`].
    ///
    /// A fresh profile per call would carry a fresh `Uuid`, and id-keyed lookups
    /// (`close_profile`, a reducer's session list) would silently miss.
    profile: crate::model::ConnectionProfile,
    observed: Arc<Mutex<Observed>>,
    checkpoints: Receiver<&'static str>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl ScriptedServer {
    /// Bind `127.0.0.1:0`, accept one connection, and run `script` against it.
    pub fn start(script: Vec<Step>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback bind");
        let address = listener.local_addr().expect("assigned port");
        let observed = Arc::new(Mutex::new(Observed::default()));
        let (checkpoint_tx, checkpoints) = std::sync::mpsc::channel();

        let worker = {
            let observed = Arc::clone(&observed);
            std::thread::Builder::new()
                .name("rfb-fixture".to_string())
                .spawn(move || {
                    let Ok((mut socket, _)) = listener.accept() else {
                        return;
                    };
                    let _ = socket.set_read_timeout(Some(FIXTURE_TIMEOUT));
                    let _ = socket.set_write_timeout(Some(FIXTURE_TIMEOUT));
                    run_script(&mut socket, script, &observed, &checkpoint_tx);
                })
                .expect("fixture thread")
        };

        let mut profile = crate::model::ConnectionProfile::new(
            "fixture",
            crate::model::Protocol::Vnc,
            address.ip().to_string(),
        );
        profile.port = address.port();

        Self {
            profile,
            observed,
            checkpoints,
            worker: Some(worker),
        }
    }

    /// The profile that dials this server, with no plaintext acknowledgement.
    ///
    /// The address is loopback, so [`super::policy`] admits it without one —
    /// which is the whole point of the loopback rule and is what lets these
    /// tests exist without recording consent to anything.
    ///
    /// The same profile, and therefore the same id, on every call.
    pub fn profile(&self) -> crate::model::ConnectionProfile {
        self.profile.clone()
    }

    /// Wait for the next checkpoint, bounded.
    ///
    /// Returns `None` on timeout so a caller states the failure itself rather
    /// than letting the suite hang.
    pub fn checkpoint(&self) -> Option<&'static str> {
        self.checkpoints.recv_timeout(FIXTURE_TIMEOUT).ok()
    }

    pub fn observed(&self) -> std::sync::MutexGuard<'_, Observed> {
        match self.observed.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Join the script thread, bounded. Called by `Drop`, so no test has to
    /// remember it.
    ///
    /// Waiting matters: without it every fixture thread in the suite outlives
    /// the test that created it, and a dozen of them competing for the CPU is
    /// enough to starve the reader thread the *next* test is waiting on. A
    /// bounded wait that detaches on expiry cannot itself hang a test.
    fn finish(&mut self) {
        let Some(worker) = self.worker.take() else {
            return;
        };
        let deadline = std::time::Instant::now() + SCRIPT_JOIN_DEADLINE;
        while !worker.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if worker.is_finished() {
            let _ = worker.join();
        }
    }
}

impl Drop for ScriptedServer {
    fn drop(&mut self) {
        self.finish();
    }
}

fn run_script(
    socket: &mut TcpStream,
    script: Vec<Step>,
    observed: &Arc<Mutex<Observed>>,
    checkpoints: &Sender<&'static str>,
) {
    for step in script {
        let ok = perform(socket, step, observed, checkpoints);
        if !ok {
            return;
        }
    }
    // Leave the socket open until the fixture is dropped, so a test that
    // expects no drop event does not receive one from the script simply
    // ending.
    std::thread::sleep(Duration::from_millis(50));
}

fn record<F: FnOnce(&mut Observed)>(observed: &Arc<Mutex<Observed>>, f: F) {
    match observed.lock() {
        Ok(mut guard) => f(&mut guard),
        Err(poisoned) => f(&mut poisoned.into_inner()),
    }
}

fn read_exact(socket: &mut TcpStream, buf: &mut [u8]) -> bool {
    socket.read_exact(buf).is_ok()
}

#[allow(clippy::too_many_lines)] // One arm per Step; splitting it hides the table.
fn perform(
    socket: &mut TcpStream,
    step: Step,
    observed: &Arc<Mutex<Observed>>,
    checkpoints: &Sender<&'static str>,
) -> bool {
    match step {
        Step::Version => socket.write_all(wire::RFB_003_008).is_ok(),
        Step::VersionRaw(bytes) => socket.write_all(bytes).is_ok(),
        Step::ExpectVersion => {
            let mut buf = [0u8; 12];
            if !read_exact(socket, &mut buf) {
                return false;
            }
            record(observed, |o| o.client_version = Some(buf.to_vec()));
            true
        }
        Step::Security(types) => {
            let mut out = vec![types.len() as u8];
            out.extend_from_slice(&types);
            socket.write_all(&out).is_ok()
        }
        Step::SecurityRefused(reason) => {
            let mut out = vec![0u8];
            out.extend_from_slice(&(reason.len() as u32).to_be_bytes());
            out.extend_from_slice(reason.as_bytes());
            socket.write_all(&out).is_ok()
        }
        Step::ExpectSecurityChoice => {
            let mut buf = [0u8; 1];
            if !read_exact(socket, &mut buf) {
                return false;
            }
            record(observed, |o| o.security_choice = Some(buf[0]));
            true
        }
        Step::SecurityResult { code, reason } => {
            let mut out = code.to_be_bytes().to_vec();
            if code != 0 {
                out.extend_from_slice(&(reason.len() as u32).to_be_bytes());
                out.extend_from_slice(reason.as_bytes());
            }
            socket.write_all(&out).is_ok()
        }
        Step::ExpectClientInit => {
            let mut buf = [0u8; 1];
            if !read_exact(socket, &mut buf) {
                return false;
            }
            record(observed, |o| o.client_init = Some(buf[0]));
            true
        }
        Step::ServerInit {
            width,
            height,
            name,
        } => {
            let mut out = Vec::new();
            out.extend_from_slice(&width.to_be_bytes());
            out.extend_from_slice(&height.to_be_bytes());
            // The format the *server* offers. Deliberately not the client's:
            // this build imposes its own and must not depend on the server
            // having happened to offer a matching one.
            out.extend_from_slice(
                &wire::PixelFormat {
                    bits_per_pixel: 32,
                    depth: 24,
                    big_endian: true,
                    true_colour: true,
                    red_max: 255,
                    green_max: 255,
                    blue_max: 255,
                    red_shift: 0,
                    green_shift: 8,
                    blue_shift: 16,
                }
                .to_bytes(),
            );
            out.extend_from_slice(&(name.len() as u32).to_be_bytes());
            out.extend_from_slice(name.as_bytes());
            socket.write_all(&out).is_ok()
        }
        Step::ServerInitOverlongName { claimed } => {
            let mut out = Vec::new();
            out.extend_from_slice(&64u16.to_be_bytes());
            out.extend_from_slice(&64u16.to_be_bytes());
            out.extend_from_slice(&wire::CLIENT_PIXEL_FORMAT.to_bytes());
            out.extend_from_slice(&claimed.to_be_bytes());
            socket.write_all(&out).is_ok()
        }
        Step::ExpectClientSetup => {
            let mut pixel_format = [0u8; 20];
            if !read_exact(socket, &mut pixel_format) {
                return false;
            }
            let mut encodings_head = [0u8; 4];
            if !read_exact(socket, &mut encodings_head) {
                return false;
            }
            let count = u16::from_be_bytes([encodings_head[2], encodings_head[3]]) as usize;
            let mut encodings = vec![0u8; count * 4];
            if !encodings.is_empty() && !read_exact(socket, &mut encodings) {
                return false;
            }
            let mut request = [0u8; 10];
            if !read_exact(socket, &mut request) {
                return false;
            }
            record(observed, |o| {
                o.set_pixel_format = Some(pixel_format.to_vec());
                let mut all = encodings_head.to_vec();
                all.extend_from_slice(&encodings);
                o.set_encodings = Some(all);
                o.messages.push(request.to_vec());
            });
            true
        }
        Step::RawRect {
            x,
            y,
            width,
            height,
            colour,
        } => {
            let mut out = update_head(1);
            out.extend_from_slice(&rect_header(x, y, width, height, wire::ENCODING_RAW));
            let (r, g, b) = colour;
            // The wire order for this client's imposed format: little-endian
            // 32-bit with redShift 16, which in memory is [B, G, R, X].
            for _ in 0..(width as usize * height as usize) {
                out.extend_from_slice(&[b, g, r, 0x00]);
            }
            socket.write_all(&out).is_ok()
        }

        Step::RectWithEncoding {
            width,
            height,
            encoding,
        } => {
            let mut out = update_head(1);
            out.extend_from_slice(&rect_header(0, 0, width, height, encoding));
            socket.write_all(&out).is_ok()
        }
        Step::RectOutOfBounds {
            x,
            y,
            width,
            height,
        } => {
            let mut out = update_head(1);
            out.extend_from_slice(&rect_header(x, y, width, height, wire::ENCODING_RAW));
            socket.write_all(&out).is_ok()
        }
        Step::TruncatedRect { width, height } => {
            let mut out = update_head(1);
            out.extend_from_slice(&rect_header(0, 0, width, height, wire::ENCODING_RAW));
            // One row where the header promised `height` of them.
            out.extend(std::iter::repeat_n(0u8, width as usize * 4));
            let _ = socket.write_all(&out);
            false
        }
        Step::ExpectClientMessage { bytes } => {
            let mut buf = vec![0u8; bytes];
            if !read_exact(socket, &mut buf) {
                return false;
            }
            record(observed, |o| o.messages.push(buf));
            true
        }
        Step::Raw(bytes) => socket.write_all(&bytes).is_ok(),

        Step::Stall => {
            std::thread::sleep(STALL);
            true
        }
        Step::CloseAbruptly => false,
        Step::Checkpoint(name) => checkpoints.send(name).is_ok(),
    }
}

fn update_head(rectangles: u16) -> Vec<u8> {
    let mut out = vec![wire::MSG_FRAMEBUFFER_UPDATE, 0];
    out.extend_from_slice(&rectangles.to_be_bytes());
    out
}

fn rect_header(x: u16, y: u16, width: u16, height: u16, encoding: i32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..2].copy_from_slice(&x.to_be_bytes());
    out[2..4].copy_from_slice(&y.to_be_bytes());
    out[4..6].copy_from_slice(&width.to_be_bytes());
    out[6..8].copy_from_slice(&height.to_be_bytes());
    out[8..12].copy_from_slice(&encoding.to_be_bytes());
    out
}

/// The eight steps every successful handshake needs, so a script that is only
/// interested in what happens *after* connecting does not restate them.
pub fn handshake_steps(width: u16, height: u16) -> Vec<Step> {
    vec![
        Step::Version,
        Step::ExpectVersion,
        Step::Security(vec![wire::SecurityType::None.number()]),
        Step::ExpectSecurityChoice,
        Step::SecurityResult {
            code: 0,
            reason: String::new(),
        },
        Step::ExpectClientInit,
        Step::ServerInit {
            width,
            height,
            name: "fixture desktop".to_string(),
        },
        Step::ExpectClientSetup,
    ]
}
