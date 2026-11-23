//! The RFB 3.8 handshake, and the deadline discipline every byte of it runs
//! under.
//!
//! Decides whether a session may exist: version, security type, plaintext
//! policy, and a `ServerInit` naming a desktop this build can hold.
//! `SessionEvent::Ready` is reachable only from the end of [`handshake`], so a
//! green row means a framebuffer exists, not just a TCP connection. Runs on the
//! `Task::perform` worker, never the reducer.

use std::io::{Read, Write};
#[cfg(test)]
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::policy::{self, Destination, Exposure};
use super::wire::{self, WireError};
use crate::model::ConnectionProfile;
use crate::protocol::ProtocolError;

/// How long the whole handshake may take, from TCP connect through
/// `ServerInit`.
///
/// One budget for the sequence, not one per read. A peer that answers every
/// individual read just inside a per-read timeout would otherwise hold the
/// connect open indefinitely while never exceeding any single limit — the
/// slow-drip shape a per-call timeout does not bound.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
const VENCRYPT: u8 = 19;
const X509_NONE: u32 = 260;
const X509_VNC: u32 = 261;
const X509_PLAIN: u32 = 262;
const MAX_CREDENTIAL_BYTES: usize = 4096;

// ---------------------------------------------------------------------------
// Failure
// ---------------------------------------------------------------------------

/// Everything the RFB transport can fail with, as one typed ladder.
///
/// No variant is a catch-all string at the top level: the string inside `Io`
/// is the operating system's, and every protocol-level refusal keeps its
/// structure in [`WireError`] so a test can name the exact rule it expects.
#[derive(Clone, Debug)]
pub enum RfbFailure {
    /// The destination was refused before a socket existed.
    Policy(policy::PolicyRefusal),
    /// The socket could not be opened, or died mid-handshake.
    Io {
        phase: &'static str,
        reason: String,
    },
    /// The handshake did not survive the parser.
    Wire(WireError),
    /// The handshake budget expired.
    Timeout,
    Tls(String),
    /// The session was cancelled while connecting, or retired before the
    /// connection it opened could be registered.
    Cancelled,
    /// The backend is not opening connections, because the app is closing.
    AdmissionClosed,
    /// This profile's previous transport has not finished closing, so opening
    /// a second one would put two owners on the same connection.
    ClosePending,
    /// A security type this build recognises and does not perform.
    ///
    /// Separate from [`WireError::NoSupportedSecurity`] so a
    /// password-protected server reports as a missing capability rather than
    /// as an unrecognised number: the first is something to fix, the second is
    /// something to investigate.
    SecurityUnsupported(wire::SecurityType),
}

impl std::fmt::Display for RfbFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(r) => write!(f, "{r}"),
            Self::Io { phase, reason } => write!(f, "{phase}: {reason}"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::Tls(reason) => write!(f, "VNC TLS: {reason}"),
            Self::Timeout => write!(f, "the server did not finish the VNC handshake in time"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::AdmissionClosed => write!(
                f,
                "this app is closing and is not opening new VNC connections"
            ),
            Self::ClosePending => write!(
                f,
                "the previous VNC connection for this profile is still closing"
            ),
            Self::SecurityUnsupported(t) => {
                write!(f, "{} {}", t.label(), super::SECURITY_UNSUPPORTED)
            }
        }
    }
}

impl From<WireError> for RfbFailure {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

impl RfbFailure {
    /// The `ProtocolError` arm this failure reaches the reducer as.
    ///
    /// Authentication refusals map to `Auth` so the credential surfaces can
    /// tell them apart from a dead network; a policy refusal and a cancelled
    /// handshake map to `Refused`, which the reconnect policy does not retry;
    /// everything else is `Transport`.
    pub fn into_protocol_error(self) -> ProtocolError {
        match &self {
            Self::Tls(_)
            | Self::SecurityUnsupported(_)
            | Self::Wire(WireError::SecurityFailed { .. })
            | Self::Wire(WireError::NoSupportedSecurity { .. }) => {
                ProtocolError::Auth(self.to_string())
            }
            Self::Policy(_) | Self::Cancelled | Self::AdmissionClosed | Self::ClosePending => {
                ProtocolError::Refused(self.to_string())
            }
            _ => ProtocolError::Transport(self.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Deadline-aware reads
// ---------------------------------------------------------------------------

/// A borrowed socket plus one overall deadline and one cancellation flag.
///
/// `TcpStream::set_read_timeout` bounds a single `read` call, which is not the
/// same as bounding a sequence of them. This re-arms the per-read timeout from
/// the *remaining* budget before every read, so what is bounded is the total,
/// and it checks the cancel flag at the same point so a Cancel pressed during
/// a handshake is answered within one read rather than at the deadline.
struct Deadlined<'a> {
    stream: &'a mut super::io::Stream,
    deadline: Instant,
    cancelled: &'a AtomicBool,
}

impl<'a> Deadlined<'a> {
    pub fn new(
        stream: &'a mut super::io::Stream,
        cancelled: &'a AtomicBool,
    ) -> Result<Self, RfbFailure> {
        let deadline = enzui_iced_core::monotonic_ms::checked_instant_deadline(
            Instant::now(),
            HANDSHAKE_DEADLINE,
            enzui_iced_core::monotonic_ms::Policy::Expire,
        )
        .ok_or(RfbFailure::Timeout)?;
        Ok(Self {
            stream,
            deadline,
            cancelled,
        })
    }

    /// [`RfbFailure::Cancelled`] once this dial has been cancelled.
    ///
    /// Consulted after a failed read as well as before one, because the
    /// failure may well be the cancellation itself arriving as a reset or an
    /// end of file.
    fn cancelled(&self) -> Result<(), RfbFailure> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(RfbFailure::Cancelled);
        }
        Ok(())
    }

    /// The budget left, or the reason there is none.
    fn remaining(&self) -> Result<Duration, RfbFailure> {
        self.cancelled()?;
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(RfbFailure::Timeout);
        }
        Ok(left)
    }

    pub fn read_exact(&mut self, buf: &mut [u8], phase: &'static str) -> Result<(), RfbFailure> {
        let mut filled = 0;
        while filled < buf.len() {
            let left = self.remaining()?;
            self.stream
                .set_read_timeout(Some(left))
                .map_err(|e| RfbFailure::Io {
                    phase,
                    reason: e.to_string(),
                })?;
            let source = &mut self.stream;
            match source.read(&mut buf[filled..]) {
                // A cancel shuts the socket down, so end of file may be ours; re-checking the
                // flag keeps a cancelled dial from being reported and retried as a hang-up.
                Ok(0) => {
                    self.cancelled()?;
                    return Err(RfbFailure::Io {
                        phase,
                        reason: "the server closed the connection".to_string(),
                    });
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    self.cancelled()?;
                    return Err(RfbFailure::Timeout);
                }
                Err(e) => {
                    self.cancelled()?;
                    return Err(RfbFailure::Io {
                        phase,
                        reason: e.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Read a `u32`-prefixed reason string, checking the prefix before reserving
    /// anything.
    ///
    /// Bounded by [`wire::MAX_DESKTOP_NAME_BYTES`], since a reason is a sentence.
    fn read_reason(&mut self, phase: &'static str) -> Result<String, RfbFailure> {
        let mut len = [0u8; 4];
        self.read_exact(&mut len, phase)?;
        let claimed = u64::from(u32::from_be_bytes(len));
        if claimed > u64::from(wire::MAX_DESKTOP_NAME_BYTES) {
            return Err(WireError::LengthTooLarge {
                field: "refusal reason",
                claimed,
            }
            .into());
        }
        let mut body = vec![0u8; claimed as usize];
        self.read_exact(&mut body, phase)?;
        Ok(wire::sanitise(&body, 160))
    }

    pub fn write_all(&mut self, bytes: &[u8], phase: &'static str) -> Result<(), RfbFailure> {
        let left = self.remaining()?;
        self.stream
            .set_write_timeout(Some(left))
            .map_err(|e| RfbFailure::Io {
                phase,
                reason: e.to_string(),
            })?;
        let sink = &mut self.stream;
        sink.write_all(bytes).map_err(|e| RfbFailure::Io {
            phase,
            reason: e.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// The handshake
// ---------------------------------------------------------------------------

/// What the handshake established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub width: u32,
    pub height: u32,
    /// The desktop name, bounded and sanitised.
    pub name: String,
    /// Whether the admitted destination was loopback or the network.
    pub exposure: Exposure,
}

/// Resolve a profile's host and apply [`policy::admit`].
///
/// Resolution is DNS and blocks, so it belongs on this thread and not on the
/// reducer. The admitted [`Destination`] carries the exact `SocketAddr` the
/// caller then dials, so the address the policy approved is the address the
/// socket reaches — a second resolver answer cannot slip in between.
pub fn resolve(profile: &ConnectionProfile) -> Result<Destination, RfbFailure> {
    let addresses: Vec<_> = (profile.host.as_str(), profile.port)
        .to_socket_addrs()
        .map(Iterator::collect)
        .unwrap_or_default();
    policy::admit(profile, &addresses).map_err(RfbFailure::Policy)
}

/// Run the handshake to completion on an already-connected socket.
///
/// The order is the protocol's, and every step is bounded:
///
/// 1. the server's version, checked by [`wire::check_version`];
/// 2. the client's version;
/// 3. the security list (a `u8` count; an empty list is RFB 3.8's refusal, whose
///    reason is read under the length check);
/// 4. the chosen type, from [`wire::choose_security`];
/// 5. `SecurityResult`;
/// 6. `ClientInit`;
/// 7. `ServerInit`, whose dimensions must pass [`wire::check_dimensions`] and
///    whose name length is checked before the name is read;
/// 8. `SetPixelFormat`, `SetEncodings`, and the first full framebuffer request.
///
/// The plaintext policy is not re-decided here; [`resolve`] already admitted the
/// destination.
#[cfg(test)]
pub fn handshake(
    stream: &TcpStream,
    destination: Destination,
    cancelled: &AtomicBool,
) -> Result<Handshake, RfbFailure> {
    handshake_with_password(stream, destination, cancelled, None)
}

#[cfg(test)]
pub fn handshake_with_password(
    stream: &TcpStream,
    destination: Destination,
    cancelled: &AtomicBool,
    password: Option<&str>,
) -> Result<Handshake, RfbFailure> {
    let mut stream =
        super::io::Stream::new(stream.try_clone().map_err(|error| RfbFailure::Io {
            phase: "preparing VNC",
            reason: error.to_string(),
        })?);
    negotiate(&mut stream, destination, cancelled, password, None)
}

pub(super) struct VerifiedTls<'a> {
    host: &'a str,
    fingerprint: Option<policy::Fingerprint>,
    username: &'a str,
}

impl<'a> VerifiedTls<'a> {
    pub(super) fn for_profile(profile: &'a ConnectionProfile) -> Result<Option<Self>, RfbFailure> {
        if !policy::requires_tls(profile) {
            return Ok(None);
        }
        let fingerprint = profile
            .extra
            .get(policy::FINGERPRINT_KEY)
            .map(|value| {
                policy::parse_fingerprint(value).ok_or_else(|| {
                    RfbFailure::Tls("The saved SHA-256 certificate fingerprint is invalid".into())
                })
            })
            .transpose()?;
        Ok(Some(Self {
            host: &profile.host,
            fingerprint,
            username: &profile.username,
        }))
    }
}

fn negotiate_vencrypt(
    io: &mut Deadlined<'_>,
    tls: VerifiedTls<'_>,
    password: Option<&str>,
) -> Result<u32, RfbFailure> {
    let mut version = [0; 2];
    io.read_exact(&mut version, "reading VeNCrypt version")?;
    if version != [0, 2] {
        return Err(RfbFailure::Tls("The host must support VeNCrypt 0.2".into()));
    }
    io.write_all(&[0, 2], "selecting VeNCrypt version")?;
    let mut accepted = [0];
    io.read_exact(&mut accepted, "reading VeNCrypt version acceptance")?;
    if accepted != [0] {
        return Err(RfbFailure::Tls("The host refused VeNCrypt 0.2".into()));
    }
    let mut count = [0];
    io.read_exact(&mut count, "reading VeNCrypt subtypes")?;
    let mut supported = Vec::with_capacity(usize::from(count[0]));
    for _ in 0..count[0] {
        let mut subtype = [0; 4];
        io.read_exact(&mut subtype, "reading VeNCrypt subtypes")?;
        supported.push(u32::from_be_bytes(subtype));
    }

    let plain = password.filter(|password| !password.is_empty() && !tls.username.is_empty());
    let selected = if plain.is_some() && supported.contains(&X509_PLAIN) {
        X509_PLAIN
    } else if password.is_some() && supported.contains(&X509_VNC) {
        X509_VNC
    } else if supported.contains(&X509_NONE) {
        X509_NONE
    } else if supported.contains(&X509_PLAIN) {
        return Err(RfbFailure::Tls(
            "The host requires a VNC sharing username and password. Enter them in the connection’s credentials.".into(),
        ));
    } else {
        return Err(RfbFailure::Tls(
            "The host must offer X509Plain, X509Vnc or X509None".into(),
        ));
    };

    io.write_all(&selected.to_be_bytes(), "selecting verified VNC TLS")?;
    io.read_exact(&mut accepted, "reading VeNCrypt subtype acceptance")?;
    if accepted != [1] {
        return Err(RfbFailure::Tls(
            "The host refused the verified TLS subtype".into(),
        ));
    }
    io.stream
        .enable_tls(tls.host, tls.fingerprint, io.deadline)
        .map_err(|error| RfbFailure::Tls(error.into()))?;
    if let Some(password) = plain.filter(|_| selected == X509_PLAIN) {
        write_plain_credentials(io, tls.username, password)?;
    }
    Ok(selected)
}

fn write_plain_credentials(
    io: &mut Deadlined<'_>,
    username: &str,
    password: &str,
) -> Result<(), RfbFailure> {
    if [username, password]
        .into_iter()
        .any(|value| value.len() > MAX_CREDENTIAL_BYTES || value.as_bytes().contains(&0))
    {
        return Err(RfbFailure::Tls(
            "The VNC sharing username and password must each fit within 4096 bytes and contain no NUL bytes".into(),
        ));
    }
    let phase = "sending VNC sharing credentials";
    let mut lengths = [0; 8];
    lengths[..4].copy_from_slice(&(username.len() as u32).to_be_bytes());
    lengths[4..].copy_from_slice(&(password.len() as u32).to_be_bytes());
    io.write_all(&lengths, phase)?;
    io.write_all(username.as_bytes(), phase)?;
    io.write_all(password.as_bytes(), phase)
}

pub(super) fn negotiate(
    stream: &mut super::io::Stream,
    destination: Destination,
    cancelled: &AtomicBool,
    password: Option<&str>,
    tls: Option<VerifiedTls<'_>>,
) -> Result<Handshake, RfbFailure> {
    let mut io = Deadlined::new(stream, cancelled)?;

    let mut version = [0u8; 12];
    io.read_exact(&mut version, "reading the server's version")?;
    wire::check_version(&version)?;
    io.write_all(wire::RFB_003_008, "sending the client version")?;

    let mut count = [0u8; 1];
    io.read_exact(&mut count, "reading the security types")?;
    let mut offered = vec![0u8; usize::from(count[0])];
    if !offered.is_empty() {
        io.read_exact(&mut offered, "reading the security types")?;
    }
    let chosen = match if tls.is_some() {
        if !offered.contains(&VENCRYPT) {
            return Err(RfbFailure::Tls("The host does not offer required VeNCrypt security; plaintext downgrade was refused".into()));
        }
        Ok(wire::SecurityType::Other(VENCRYPT))
    } else if password.is_some() && offered.contains(&2) {
        Ok(wire::SecurityType::VncAuth)
    } else {
        wire::choose_security(&offered)
    } {
        Ok(t) => t,
        Err(WireError::ServerRefused { .. }) => {
            let reason = io.read_reason("reading the server's refusal")?;
            return Err(WireError::ServerRefused { reason }.into());
        }
        Err(e) => {
            // Name the one type this build could plausibly have performed, so
            // a password-protected server reports a missing capability rather
            // than an opaque list of numbers.
            if let Some(known) = offered
                .iter()
                .copied()
                .map(wire::SecurityType::from_number)
                .find(|t| *t == wire::SecurityType::VncAuth)
            {
                return Err(RfbFailure::SecurityUnsupported(known));
            }
            return Err(e.into());
        }
    };
    io.write_all(&[chosen.number()], "choosing a security type")?;

    let subtype = tls
        .map(|tls| negotiate_vencrypt(&mut io, tls, password))
        .transpose()?;
    let vnc_auth = subtype == Some(X509_VNC) || chosen == wire::SecurityType::VncAuth;
    if vnc_auth {
        use des::cipher::{BlockEncrypt, KeyInit};
        use zeroize::Zeroize;
        let password =
            password.ok_or(RfbFailure::SecurityUnsupported(wire::SecurityType::VncAuth))?;
        let mut key = [0u8; 8];
        for (out, byte) in key.iter_mut().zip(password.bytes()) {
            *out = byte.reverse_bits();
        }
        let cipher = des::Des::new((&key).into());
        key.zeroize();
        let mut challenge = [0u8; 16];
        io.read_exact(&mut challenge, "reading the authentication challenge")?;
        for block in challenge.as_chunks_mut::<8>().0 {
            let mut encrypted = des::cipher::Block::<des::Des>::default();
            encrypted.copy_from_slice(block);
            cipher.encrypt_block(&mut encrypted);
            block.copy_from_slice(&encrypted);
        }
        io.write_all(&challenge, "answering the authentication challenge")?;
        challenge.zeroize();
    }
    let mut result = [0u8; 4];
    io.read_exact(&mut result, "reading the security result")?;
    if u32::from_be_bytes(result) != 0 {
        let reason = if subtype == Some(X509_PLAIN) {
            // The host's refusal text can echo the credentials it just received.
            "The host rejected the VNC sharing username or password".into()
        } else {
            io.read_reason("reading the security failure")?
        };
        return Err(WireError::SecurityFailed { reason }.into());
    }

    io.write_all(&wire::client_init(), "sending ClientInit")?;

    let mut prefix = [0u8; wire::SERVER_INIT_PREFIX_BYTES];
    io.read_exact(&mut prefix, "reading ServerInit")?;
    let (width, height, _offered_format, name_len) = wire::parse_server_init_prefix(&prefix)?;
    let mut name_bytes = vec![0u8; name_len as usize];
    if !name_bytes.is_empty() {
        io.read_exact(&mut name_bytes, "reading the desktop name")?;
    }

    io.write_all(&wire::set_pixel_format(), "sending SetPixelFormat")?;
    io.write_all(&wire::set_encodings(), "sending SetEncodings")?;
    io.write_all(
        &wire::framebuffer_update_request(false, width, height),
        "requesting the first frame",
    )?;

    Ok(Handshake {
        width,
        height,
        name: wire::sanitise(&name_bytes, 64),
        exposure: destination.exposure,
    })
}
