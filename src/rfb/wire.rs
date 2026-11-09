//! Bounded RFB 3.8 messages and rectangle admission.
//!
//! The client requests a fixed 32-bit BGRX format and decodes Raw, CopyRect
//! and ZRLE rectangles, with DesktopSize and LastRect control encodings.
//! Authentication and transport ownership live in the handshake and backend.

use enzui_iced_core::media::preflight_rgba8;

use crate::framebuffer::REMOTE_FRAME_LIMITS;

/// The only protocol version this build speaks, as it appears on the wire.
pub const RFB_003_008: &[u8; 12] = b"RFB 003.008\n";

/// The largest single server message body this build will read.
///
/// Every peer length is checked against this before a buffer is reserved. It
/// matches [`crate::framebuffer::REMOTE_FRAME_LIMITS`], since the largest
/// legitimate message is a full-screen Raw rectangle.
pub const MAX_MESSAGE_BYTES: u64 = 32 * 1024 * 1024;

/// The largest desktop name this build will read from `ServerInit`.
///
/// The name is a label under the session surface, not a document. A server
/// offering more than this is refused rather than truncated: a truncated name
/// is indistinguishable from a real one and would hide the anomaly.
pub const MAX_DESKTOP_NAME_BYTES: u32 = 4096;

/// The fixed pixel format this client requires, in `SetPixelFormat` order.
///
/// 32 bits per pixel, little-endian, true colour, `redShift = 16`,
/// `greenShift = 8`, `blueShift = 0`: `[B, G, R, X]` on the wire, converted by
/// [`raw_bgrx_to_rgba`]. RFB obliges the server to convert to a client-imposed
/// format, so only one layout needs decoding.
pub const CLIENT_PIXEL_FORMAT: PixelFormat = PixelFormat {
    bits_per_pixel: 32,
    depth: 24,
    big_endian: false,
    true_colour: true,
    red_max: 255,
    green_max: 255,
    blue_max: 255,
    red_shift: 16,
    green_shift: 8,
    blue_shift: 0,
};

/// A `PixelFormat` occupies exactly this many bytes in every RFB message that
/// carries one.
pub const PIXEL_FORMAT_BYTES: usize = 16;

/// `ServerInit`'s fixed prefix: two `u16` dimensions, a pixel format and a
/// `u32` name length. The name follows, and is read separately once its length
/// has been checked.
pub const SERVER_INIT_PREFIX_BYTES: usize = 2 + 2 + PIXEL_FORMAT_BYTES + 4;

/// Bytes per pixel in the client format, and therefore in every decoded frame.
pub const BYTES_PER_PIXEL: u64 = 4;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A refusal decided by the bytes alone.
///
/// Every variant names what was expected and what arrived, because these
/// reach a session's status line through
/// `super::RfbFailure` and "the server said something wrong" is not an
/// actionable sentence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The greeting was not `RFB 003.008`.
    ///
    /// Carries a sanitised rendering of what arrived, never the raw bytes: the
    /// greeting is the first thing an arbitrary TCP peer sends, so it may be
    /// an HTTP response, a TLS alert or a binary blob, and it must not be able
    /// to inject control characters into a status line.
    UnsupportedVersion { offered: String },
    /// The server offered no security types at all, which RFB 3.8 defines as
    /// "connection refused", with a reason string.
    ServerRefused { reason: String },
    /// The server offered security types, but none of them is supported here.
    NoSupportedSecurity { offered: Vec<u8> },
    /// The server rejected the security handshake.
    SecurityFailed { reason: String },
    /// A length prefix exceeded [`MAX_MESSAGE_BYTES`] or
    /// [`MAX_DESKTOP_NAME_BYTES`].
    ///
    /// Reported before any buffer is reserved, which is the whole point of
    /// having it as a distinct variant.
    LengthTooLarge { field: &'static str, claimed: u64 },
    /// A message was shorter than its own fixed layout requires.
    Truncated {
        message: &'static str,
        need: usize,
        got: usize,
    },
    /// `ServerInit` announced a framebuffer this build will not hold, or one
    /// with no area.
    UnusableDimensions { width: u32, height: u32 },
    /// A rectangle was not contained by the framebuffer it claims to update.
    RectangleOutOfBounds {
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        fb_width: u32,
        fb_height: u32,
    },
    /// A rectangle's own geometry is unusable — zero area, or a pixel count
    /// whose byte length passes no bound.
    UnusableRectangle { width: u32, height: u32 },
    /// The server used an encoding this build did not ask for and cannot
    /// decode.
    ///
    /// Refused rather than skipped: an unknown encoding's length is not derivable,
    /// so the stream position is lost from that rectangle on.
    UnsupportedEncoding { encoding: i32 },
    /// A server-to-client message type this build does not handle.
    ///
    /// Also unrecoverable, for the same reason: the message's length is not
    /// knowable without knowing its type.
    UnknownMessageType { message_type: u8 },
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { offered } => write!(
                f,
                "the server speaks {offered}, and this build speaks RFB 3.8 only"
            ),
            Self::ServerRefused { reason } => {
                write!(f, "the server refused the connection: {reason}")
            }
            Self::NoSupportedSecurity { offered } => write!(
                f,
                "the server offers security types {offered:?}, with no supported plaintext method; enable verified TLS for VeNCrypt"
            ),
            Self::SecurityFailed { reason } => {
                write!(f, "the server rejected the handshake: {reason}")
            }
            Self::LengthTooLarge { field, claimed } => write!(
                f,
                "the server claimed a {field} of {claimed} bytes, past this build's limit"
            ),
            Self::Truncated { message, need, got } => write!(
                f,
                "the server's {message} needs {need} bytes and carried {got}"
            ),
            Self::UnusableDimensions { width, height } => write!(
                f,
                "the server announced a {width}x{height} desktop, which this build cannot hold"
            ),
            Self::RectangleOutOfBounds {
                x,
                y,
                width,
                height,
                fb_width,
                fb_height,
            } => write!(
                f,
                "a {width}x{height} update at ({x}, {y}) runs outside the {fb_width}x{fb_height} desktop"
            ),
            Self::UnusableRectangle { width, height } => {
                write!(f, "a {width}x{height} update has no usable geometry")
            }
            Self::UnsupportedEncoding { encoding } => write!(
                f,
                "the server used encoding {encoding}, which this build did not request and cannot skip"
            ),
            Self::UnknownMessageType { message_type } => write!(
                f,
                "the server sent message type {message_type}, whose length this build cannot determine"
            ),
        }
    }
}

impl std::error::Error for WireError {}

// ---------------------------------------------------------------------------
// Pixel format
// ---------------------------------------------------------------------------

/// An RFB pixel format, in the layout every message that carries one uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl PixelFormat {
    /// The 16 bytes this format occupies on the wire, including its three pad
    /// bytes.
    pub fn to_bytes(self) -> [u8; PIXEL_FORMAT_BYTES] {
        let mut out = [0u8; PIXEL_FORMAT_BYTES];
        out[0] = self.bits_per_pixel;
        out[1] = self.depth;
        out[2] = u8::from(self.big_endian);
        out[3] = u8::from(self.true_colour);
        out[4..6].copy_from_slice(&self.red_max.to_be_bytes());
        out[6..8].copy_from_slice(&self.green_max.to_be_bytes());
        out[8..10].copy_from_slice(&self.blue_max.to_be_bytes());
        out[10] = self.red_shift;
        out[11] = self.green_shift;
        out[12] = self.blue_shift;
        out
    }

    /// Read a format out of exactly 16 bytes.
    ///
    /// Total: every field is fixed-width at a fixed offset. The parsed value is only
    /// reported; the client always imposes [`CLIENT_PIXEL_FORMAT`].
    pub fn from_bytes(bytes: &[u8; PIXEL_FORMAT_BYTES]) -> Self {
        Self {
            bits_per_pixel: bytes[0],
            depth: bytes[1],
            big_endian: bytes[2] != 0,
            true_colour: bytes[3] != 0,
            red_max: u16::from_be_bytes([bytes[4], bytes[5]]),
            green_max: u16::from_be_bytes([bytes[6], bytes[7]]),
            blue_max: u16::from_be_bytes([bytes[8], bytes[9]]),
            red_shift: bytes[10],
            green_shift: bytes[11],
            blue_shift: bytes[12],
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// The security types this build recognises by number.
///
/// Only [`Self::None`] is usable, and even that is subject to
/// [`super::policy`]'s loopback rule. The others exist so a refusal can name
/// what the server wanted instead of reporting an opaque number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityType {
    /// Type 1: no authentication and no encryption.
    None,
    /// Type 2: the classic 16-byte DES challenge.
    ///
    /// Recognised, never performed. This build carries no DES implementation,
    /// and the honest consequence is a named refusal — see
    /// [`super::SECURITY_UNSUPPORTED`].
    VncAuth,
    /// Anything else the server offered.
    Other(u8),
}

impl SecurityType {
    pub fn from_number(n: u8) -> Self {
        match n {
            1 => Self::None,
            2 => Self::VncAuth,
            other => Self::Other(other),
        }
    }

    pub fn number(self) -> u8 {
        match self {
            Self::None => 1,
            Self::VncAuth => 2,
            Self::Other(n) => n,
        }
    }

    /// The name a refusal uses.
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::VncAuth => "VNC password",
            Self::Other(_) => "an unrecognised security type",
        }
    }
}

/// Check the server's 12-byte greeting.
///
/// Only the exact `RFB 003.008` string is accepted. Negotiating *down* to 3.3
/// or 3.7 is deliberately not implemented: the three versions differ in the
/// security handshake, and supporting all of them would triple the number of
/// hostile paths for servers this build has no way to test against.
pub fn check_version(offered: &[u8]) -> Result<(), WireError> {
    if offered == RFB_003_008 {
        return Ok(());
    }
    Err(WireError::UnsupportedVersion {
        offered: sanitise(offered, 24),
    })
}

/// Choose a security type from the list the server offered.
///
/// An empty list is RFB 3.8's "connection refused" signal, and its reason
/// string is read by the caller (the length prefix has to be checked against
/// [`MAX_MESSAGE_BYTES`] first), so this reports the empty case and leaves the
/// reason to be filled in.
pub fn choose_security(offered: &[u8]) -> Result<SecurityType, WireError> {
    if offered.is_empty() {
        return Err(WireError::ServerRefused {
            reason: String::new(),
        });
    }
    if offered.contains(&SecurityType::None.number()) {
        return Ok(SecurityType::None);
    }
    Err(WireError::NoSupportedSecurity {
        offered: offered.to_vec(),
    })
}

/// Parse `ServerInit`'s fixed prefix and report the name length still to read.
///
/// Split in two because the name's length is peer-chosen: it is checked
/// against [`MAX_DESKTOP_NAME_BYTES`] here, so the caller reserves a bounded
/// buffer or does not reserve one at all.
pub fn parse_server_init_prefix(bytes: &[u8]) -> Result<(u32, u32, PixelFormat, u32), WireError> {
    if bytes.len() < SERVER_INIT_PREFIX_BYTES {
        return Err(WireError::Truncated {
            message: "ServerInit",
            need: SERVER_INIT_PREFIX_BYTES,
            got: bytes.len(),
        });
    }
    let width = u32::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    let height = u32::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    let mut format = [0u8; PIXEL_FORMAT_BYTES];
    format.copy_from_slice(&bytes[4..4 + PIXEL_FORMAT_BYTES]);
    let name_len = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    if name_len > MAX_DESKTOP_NAME_BYTES {
        return Err(WireError::LengthTooLarge {
            field: "desktop name",
            claimed: u64::from(name_len),
        });
    }
    check_dimensions(width, height)?;
    Ok((width, height, PixelFormat::from_bytes(&format), name_len))
}

/// Admit a framebuffer geometry against this build's ceilings.
///
/// Gates `ServerInit` before `SessionEvent::Ready`, using
/// [`crate::framebuffer::REMOTE_FRAME_LIMITS`] so a connected session can always
/// paint.
pub fn check_dimensions(width: u32, height: u32) -> Result<(), WireError> {
    use enzui_iced_core::decode_limits::DecodeVerdict;

    match REMOTE_FRAME_LIMITS.check_decoded(width, height) {
        DecodeVerdict::Allow => Ok(()),
        _ => Err(WireError::UnusableDimensions { width, height }),
    }
}

// ---------------------------------------------------------------------------
// Framebuffer updates
// ---------------------------------------------------------------------------

/// Server-to-client message numbers this build recognises.
pub const MSG_FRAMEBUFFER_UPDATE: u8 = 0;
pub const MSG_SET_COLOUR_MAP: u8 = 1;
pub const MSG_BELL: u8 = 2;
pub const MSG_SERVER_CUT_TEXT: u8 = 3;

/// Encoding numbers this build requests.
pub const ENCODING_RAW: i32 = 0;
pub const ENCODING_COPY_RECT: i32 = 1;
pub const ENCODING_ZRLE: i32 = 16;
pub const ENCODING_LAST_RECT: i32 = -224;
pub const ENCODING_DESKTOP_SIZE: i32 = -223;
pub const ENCODING_EXTENDED_CLIPBOARD: i32 = 0xc0a1_e5ceu32 as i32;

pub const REQUESTED_ENCODINGS: [i32; 6] = [
    ENCODING_ZRLE,
    ENCODING_COPY_RECT,
    ENCODING_RAW,
    ENCODING_DESKTOP_SIZE,
    ENCODING_LAST_RECT,
    ENCODING_EXTENDED_CLIPBOARD,
];

/// One rectangle header from a `FramebufferUpdate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RectangleHeader {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub encoding: i32,
}

/// The twelve bytes a rectangle header occupies.
pub const RECTANGLE_HEADER_BYTES: usize = 12;

impl RectangleHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < RECTANGLE_HEADER_BYTES {
            return Err(WireError::Truncated {
                message: "rectangle header",
                need: RECTANGLE_HEADER_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self {
            x: u32::from(u16::from_be_bytes([bytes[0], bytes[1]])),
            y: u32::from(u16::from_be_bytes([bytes[2], bytes[3]])),
            width: u32::from(u16::from_be_bytes([bytes[4], bytes[5]])),
            height: u32::from(u16::from_be_bytes([bytes[6], bytes[7]])),
            encoding: i32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        })
    }
}

/// What a rectangle header asks the reader to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RectanglePlan {
    /// Read exactly this many bytes of `Raw` pixel data into the region.
    Raw {
        bytes: usize,
    },
    Zrle {
        bytes: usize,
    },
    CopyRect,
    Last,
    /// The desktop changed size to these dimensions. No pixel data follows.
    DesktopSize {
        width: u32,
        height: u32,
    },
}

/// Decide what a rectangle header means, refusing every geometry that does not
/// fit the framebuffer it claims to update.
///
/// 1. Encoding: an unrequested encoding cannot be skipped, since its length is
///    not derivable from the header.
/// 2. Containment: `x + width <= fb_width` and `y + height <= fb_height`, in
///    `u64`, so no write can leave the destination buffer.
/// 3. Geometry and byte length, through
///    [`enzui_iced_core::media::preflight_rgba8`], proving pixel count, stride and
///    total length are representable and bounded before reading.
/// 4. Zero area: an empty rectangle would let a server loop the reader without
///    progress.
///
/// `DesktopSize` carries no pixels and is exempt from containment, but not from
/// [`check_dimensions`].
pub fn plan_rectangle(
    header: RectangleHeader,
    fb_width: u32,
    fb_height: u32,
) -> Result<RectanglePlan, WireError> {
    if header.encoding == ENCODING_DESKTOP_SIZE {
        check_dimensions(header.width, header.height)?;
        return Ok(RectanglePlan::DesktopSize {
            width: header.width,
            height: header.height,
        });
    }
    if header.encoding == ENCODING_LAST_RECT {
        return Ok(RectanglePlan::Last);
    }
    if ![ENCODING_RAW, ENCODING_ZRLE, ENCODING_COPY_RECT].contains(&header.encoding) {
        return Err(WireError::UnsupportedEncoding {
            encoding: header.encoding,
        });
    }
    if u64::from(header.x) + u64::from(header.width) > u64::from(fb_width)
        || u64::from(header.y) + u64::from(header.height) > u64::from(fb_height)
    {
        return Err(WireError::RectangleOutOfBounds {
            x: header.x,
            y: header.y,
            width: header.width,
            height: header.height,
            fb_width,
            fb_height,
        });
    }
    let stride = u64::from(header.width) * BYTES_PER_PIXEL;
    let geometry = preflight_rgba8(header.width, header.height, stride, &REMOTE_FRAME_LIMITS)
        .map_err(|_| WireError::UnusableRectangle {
            width: header.width,
            height: header.height,
        })?;
    let tight = geometry.tight_len();
    if tight == 0 {
        return Err(WireError::UnusableRectangle {
            width: header.width,
            height: header.height,
        });
    }
    if tight as u64 > MAX_MESSAGE_BYTES {
        return Err(WireError::LengthTooLarge {
            field: "rectangle",
            claimed: tight as u64,
        });
    }
    Ok(match header.encoding {
        ENCODING_COPY_RECT => RectanglePlan::CopyRect,
        ENCODING_ZRLE => RectanglePlan::Zrle { bytes: tight },
        _ => RectanglePlan::Raw { bytes: tight },
    })
}

/// Convert one `Raw` rectangle from the wire's `[B, G, R, X]` to `[R, G, B, A]`
/// in place, forcing full opacity.
///
/// The X byte is padding, not alpha, and may hold anything. Returns the number of
/// pixels converted so the caller can detect a slice that is not a multiple of
/// four.
pub fn raw_bgrx_to_rgba(pixels: &mut [u8]) -> usize {
    let mut converted = 0;
    for chunk in pixels.as_chunks_mut::<4>().0 {
        chunk.swap(0, 2);
        chunk[3] = 0xFF;
        converted += 1;
    }
    converted
}

/// Copy a converted rectangle into the session's framebuffer.
///
/// A per-row copy at a row offset. Returns `false` when the rectangle does not
/// fit; this is an independent bounds check beside [`plan_rectangle`] because
/// this function performs the writes.
pub fn blit(
    frame: &mut [u8],
    fb_width: u32,
    fb_height: u32,
    header: RectangleHeader,
    pixels: &[u8],
) -> bool {
    let bpp = BYTES_PER_PIXEL as usize;
    let row_bytes = header.width as usize * bpp;
    if u64::from(header.x) + u64::from(header.width) > u64::from(fb_width)
        || u64::from(header.y) + u64::from(header.height) > u64::from(fb_height)
    {
        return false;
    }
    if pixels.len() != row_bytes * header.height as usize {
        return false;
    }
    if frame.len() != fb_width as usize * fb_height as usize * bpp {
        return false;
    }
    for row in 0..header.height as usize {
        let dst_start = ((header.y as usize + row) * fb_width as usize + header.x as usize) * bpp;
        let src_start = row * row_bytes;
        frame[dst_start..dst_start + row_bytes]
            .copy_from_slice(&pixels[src_start..src_start + row_bytes]);
    }
    true
}

// ---------------------------------------------------------------------------
// Client messages
// ---------------------------------------------------------------------------

/// `ClientInit`: one byte, the shared-desktop flag.
///
/// Always shared (`1`). A non-shared connect asks the server to disconnect
/// every other client, which is a destructive side effect on a machine
/// somebody else may be using, and nothing in this app's UI asks for it.
pub fn client_init() -> [u8; 1] {
    [1]
}

/// `SetPixelFormat` carrying [`CLIENT_PIXEL_FORMAT`].
pub fn set_pixel_format() -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0] = 0;
    out[4..].copy_from_slice(&CLIENT_PIXEL_FORMAT.to_bytes());
    out
}

/// `SetEncodings` carrying [`REQUESTED_ENCODINGS`].
pub fn set_encodings() -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + REQUESTED_ENCODINGS.len() * 4);
    out.push(2);
    out.push(0);
    out.extend_from_slice(&(REQUESTED_ENCODINGS.len() as u16).to_be_bytes());
    for encoding in REQUESTED_ENCODINGS {
        out.extend_from_slice(&encoding.to_be_bytes());
    }
    out
}

/// `FramebufferUpdateRequest` for the whole desktop.
///
/// `incremental = false` asks for every pixel and is what the first request
/// and a re-expose need; `true` asks only for what changed and is what the
/// steady-state loop sends after each update. RFB is a pull protocol: a client
/// that stops requesting stops receiving, which is also this build's
/// backpressure — see [`super::backend`].
pub fn framebuffer_update_request(incremental: bool, width: u32, height: u32) -> [u8; 10] {
    let mut out = [0u8; 10];
    out[0] = 3;
    out[1] = u8::from(incremental);
    out[2..4].copy_from_slice(&0u16.to_be_bytes());
    out[4..6].copy_from_slice(&0u16.to_be_bytes());
    out[6..8].copy_from_slice(&(width.min(u32::from(u16::MAX)) as u16).to_be_bytes());
    out[8..10].copy_from_slice(&(height.min(u32::from(u16::MAX)) as u16).to_be_bytes());
    out
}

/// `PointerEvent`: a button mask and an absolute position.
///
/// The position is clamped to `u16`, which is the width of the field. A
/// coordinate outside the framebuffer is the caller's to refuse — and
/// [`crate::framebuffer::remote_pixel`] already does, by returning `None` for
/// a press in the letterbox — but clamping here means a wrong answer upstream
/// cannot become a wrapped coordinate on the wire.
pub fn pointer_event(button_mask: u8, x: i32, y: i32) -> [u8; 6] {
    let mut out = [0u8; 6];
    out[0] = 5;
    out[1] = button_mask;
    out[2..4].copy_from_slice(&(x.clamp(0, u16::MAX as i32) as u16).to_be_bytes());
    out[4..6].copy_from_slice(&(y.clamp(0, u16::MAX as i32) as u16).to_be_bytes());
    out
}

/// `KeyEvent`: a down flag and an X11 keysym.
pub fn key_event(down: bool, keysym: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = 4;
    out[1] = u8::from(down);
    out[4..8].copy_from_slice(&keysym.to_be_bytes());
    out
}

/// The RFB button mask bit for one of this app's pointer buttons.
pub fn button_bit(button: crate::protocol::PointerButton) -> u8 {
    match button {
        crate::protocol::PointerButton::Left => 0b0000_0001,
        crate::protocol::PointerButton::Middle => 0b0000_0010,
        crate::protocol::PointerButton::Right => 0b0000_0100,
        crate::protocol::PointerButton::WheelUp => 1 << 3,
        crate::protocol::PointerButton::WheelDown => 1 << 4,
        crate::protocol::PointerButton::WheelLeft => 1 << 5,
        crate::protocol::PointerButton::WheelRight => 1 << 6,
    }
}

// ---------------------------------------------------------------------------
// Sanitising
// ---------------------------------------------------------------------------

/// Render peer-supplied bytes as a short, single-line, printable string.
///
/// Used for every string this build takes from the server: the version
/// greeting, a refusal reason, a desktop name. All three reach a status line,
/// and all three are chosen by whoever is on the other end of the socket, so
/// none may carry a newline, an escape sequence or ten kilobytes of padding.
pub fn sanitise(bytes: &[u8], max_chars: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    for c in text.chars() {
        if out.chars().count() >= max_chars {
            out.push('\u{2026}');
            break;
        }
        if c.is_control() {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        "no reason given".to_string()
    } else {
        trimmed.to_string()
    }
}
