//! The reader thread's loop: decode server messages, paint the framebuffer,
//! publish a frame, ask for the next update.
//!
//! # Backpressure is the protocol's own
//!
//! RFB is a pull protocol: one `FramebufferUpdateRequest` is sent per decoded
//! update, so at most one update is in flight.
//!
//! The decoded frame is handed to the app before the next request is
//! written, and that handoff blocks while the app's queue is at its event or
//! byte bound ([`crate::protocol::MAX_QUEUED_BYTES`]). A lagging reducer
//! therefore leaves unread bytes in the kernel buffer, where TCP flow control
//! holds the server. Above the queue,
//! [`enzui_iced_core::media::BoundedFrameSink`] coalesces.
//!
//! Rectangles are incremental, so nothing here may drop or coalesce a frame;
//! blocking is the only correct backpressure, and teardown closes the queue
//! so blocking cannot outlive the session.
//!
//! # Every exit is a reason
//!
//! The loop returns `Some(reason)` for a server-side end, which becomes
//! [`SessionEvent::Drop`], and `None` for cancellation, which must stay
//! silent because the reducer already applied `Disconnect`.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::wire::{self, WireError};
use crate::framebuffer::FrameBytes;
use crate::protocol::SessionStreamSender;
use crate::state_machine::SessionEvent;

/// The per-read timeout the steady-state loop runs under.
///
/// Generous, because an untouched desktop legitimately sends nothing for a
/// long time. A timeout before a message's first byte is idle
/// ([`ReadStep::Idle`]) and the loop waits again; a timeout inside a message
/// is fatal, since the stream cannot resynchronise from a partial message.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// One decoded desktop, reused across updates.
///
/// Allocated once per geometry rather than once per frame: a 4K desktop at 30
/// updates a second would otherwise churn a gigabyte a second through the
/// allocator. The published frame is a copy, because the app owns its frames
/// independently and the next update must not mutate a buffer the UI is
/// painting.
pub struct Framebuffer {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
    zrle: super::zrle::Zrle,
}

impl Framebuffer {
    /// Allocate a desktop. The caller has already admitted the geometry
    /// through [`wire::check_dimensions`], so the product is bounded.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            pixels: vec![0u8; width as usize * height as usize * 4],
            zrle: super::zrle::Zrle::default(),
        }
    }

    /// Adopt a new geometry from a `DesktopSize` pseudo-rectangle.
    ///
    /// The old contents are dropped rather than rescaled: the server sends a
    /// full update for the new geometry next, and a stretched copy would be a
    /// picture the remote never sent.
    pub fn adopt(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
        self.pixels = vec![0; width as usize * height as usize * 4];
    }
}

/// How one bounded read ended.
pub enum ReadStep {
    Done,
    /// The timeout expired with nothing read at all. A quiet desktop, not a
    /// failure.
    Idle,
    Cancelled,
    Closed,
    Failed(String),
}

/// Fill `buf` completely, or say why not.
///
/// # Cancellation is re-read after the syscall
///
/// A reader is usually parked inside `read` when the owner closes, and wakes
/// to an EOF it did not cause. [`super::backend::RfbSession::shutdown`]
/// stores the flag (`SeqCst`) before calling `shutdown(Both)`, so a set flag
/// here means a local close and the retirement is silent; a clear flag means
/// the peer hung up, a [`ReadStep::Closed`] that owes the user a reason.
///
/// This is ordering, not timing. The same re-read guards timeouts and socket
/// errors, since `shutdown` on a parked socket can surface as `ECONNRESET` or
/// `ENOTCONN` rather than a clean EOF.
pub fn read_blocking(stream: &mut impl Read, buf: &mut [u8], cancelled: &AtomicBool) -> ReadStep {
    let mut filled = 0;
    while filled < buf.len() {
        if cancelled.load(Ordering::SeqCst) {
            return ReadStep::Cancelled;
        }
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                if cancelled.load(Ordering::SeqCst) {
                    return ReadStep::Cancelled;
                }
                return if filled == 0 {
                    ReadStep::Closed
                } else {
                    ReadStep::Failed("the server closed mid-message".to_string())
                };
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if cancelled.load(Ordering::SeqCst) {
                    return ReadStep::Cancelled;
                }
                return if filled == 0 {
                    ReadStep::Idle
                } else {
                    ReadStep::Failed("the server stalled mid-message".to_string())
                };
            }
            Err(e) => {
                if cancelled.load(Ordering::SeqCst) {
                    return ReadStep::Cancelled;
                }
                return ReadStep::Failed(e.to_string());
            }
        }
    }
    ReadStep::Done
}

pub(crate) struct Shared {
    pub(crate) geometry: Arc<Mutex<(u32, u32)>>,
    pub(crate) clipboard: Arc<super::clipboard::Clipboard>,
}

/// Read every message until the socket closes or the session is cancelled.
///
/// `geometry` is the size the owning [`super::backend::RfbSession`] publishes
/// for `resize`, updated here because this loop is the only thing that learns
/// a `DesktopSize` change.
pub(crate) fn read_loop(
    stream: &mut impl Read,
    width: u32,
    height: u32,
    events: &SessionStreamSender,
    writes: &SyncSender<Vec<u8>>,
    shared: &Shared,
    cancelled: &AtomicBool,
) -> Option<String> {
    let (geometry, clipboard) = (&shared.geometry, &shared.clipboard);
    let mut fb = Framebuffer::new(width, height);
    let mut scratch = Vec::new();

    loop {
        let mut kind = [0u8; 1];
        match read_blocking(stream, &mut kind, cancelled) {
            ReadStep::Done => {}
            ReadStep::Idle => continue,
            ReadStep::Cancelled => return None,
            ReadStep::Closed => return Some("the server closed the connection".to_string()),
            ReadStep::Failed(reason) => return Some(reason),
        }

        match kind[0] {
            wire::MSG_FRAMEBUFFER_UPDATE => {
                match read_update(stream, &mut fb, &mut scratch, cancelled) {
                    Ok(UpdateOutcome::Painted { geometry_changed }) => {
                        if geometry_changed && let Ok(mut g) = geometry.lock() {
                            *g = (fb.width, fb.height);
                        }
                        if events
                            .send(SessionEvent::Frame {
                                width: fb.width,
                                height: fb.height,
                                pixels: FrameBytes::new(fb.pixels.clone()),
                            })
                            .is_err()
                        {
                            // The queue is closed: the receiver dropped or the session was
                            // severed, so there is nobody to report to.
                            return None;
                        }
                        if writes
                            .try_send(
                                wire::framebuffer_update_request(true, fb.width, fb.height)
                                    .to_vec(),
                            )
                            .is_err()
                        {
                            // The writer is gone: silent during a close, otherwise the pull
                            // loop cannot continue.
                            return if cancelled.load(Ordering::SeqCst) {
                                None
                            } else {
                                Some("the connection stopped accepting requests".to_string())
                            };
                        }
                    }
                    Ok(UpdateOutcome::Cancelled) => return None,
                    Err(reason) => return Some(reason),
                }
            }
            // Meaningless under the imposed true-colour format, and its length
            // depends on untracked fields, so it cannot be skipped in sync.
            wire::MSG_SET_COLOUR_MAP => {
                return Some(
                    WireError::UnknownMessageType {
                        message_type: wire::MSG_SET_COLOUR_MAP,
                    }
                    .to_string(),
                );
            }
            // A remote bell does not drive local playback.
            wire::MSG_BELL => {}
            wire::MSG_SERVER_CUT_TEXT => match read_cut_text(stream, cancelled) {
                Ok(Some((length, body))) => match clipboard.receive(length, &body) {
                    Ok((text, replies)) => {
                        for reply in replies {
                            if writes.send(reply).is_err() {
                                return None;
                            }
                        }
                        if let Some(text) = text
                            && events.send(SessionEvent::Clipboard(text)).is_err()
                        {
                            return None;
                        }
                    }
                    Err(reason) => return Some(reason),
                },
                Ok(None) => return None,
                Err(reason) => return Some(reason),
            },
            other => {
                return Some(
                    WireError::UnknownMessageType {
                        message_type: other,
                    }
                    .to_string(),
                );
            }
        }
    }
}

pub enum UpdateOutcome {
    Painted { geometry_changed: bool },
    Cancelled,
}

/// Read one `FramebufferUpdate` and paint every rectangle it carries.
///
/// Each rectangle passes [`wire::plan_rectangle`] before a byte of its data is
/// read, so the length reserved into `scratch` is one this build chose rather
/// than one the peer named.
pub fn read_update(
    stream: &mut impl Read,
    fb: &mut Framebuffer,
    scratch: &mut Vec<u8>,
    cancelled: &AtomicBool,
) -> Result<UpdateOutcome, String> {
    let mut head = [0u8; 3];
    match read_blocking(stream, &mut head, cancelled) {
        ReadStep::Done => {}
        ReadStep::Cancelled => return Ok(UpdateOutcome::Cancelled),
        ReadStep::Idle | ReadStep::Closed => {
            return Err("the server closed inside a framebuffer update".to_string());
        }
        ReadStep::Failed(reason) => return Err(reason),
    }
    let rectangles = u16::from_be_bytes([head[1], head[2]]);
    let mut geometry_changed = false;

    for _ in 0..rectangles {
        let mut header_bytes = [0u8; wire::RECTANGLE_HEADER_BYTES];
        match read_blocking(stream, &mut header_bytes, cancelled) {
            ReadStep::Done => {}
            ReadStep::Cancelled => return Ok(UpdateOutcome::Cancelled),
            ReadStep::Idle | ReadStep::Closed => {
                return Err("the server closed inside a rectangle".to_string());
            }
            ReadStep::Failed(reason) => return Err(reason),
        }
        let header = wire::RectangleHeader::parse(&header_bytes).map_err(|e| e.to_string())?;
        match wire::plan_rectangle(header, fb.width, fb.height).map_err(|e| e.to_string())? {
            wire::RectanglePlan::DesktopSize { width, height } => {
                fb.adopt(width, height);
                geometry_changed = true;
            }
            wire::RectanglePlan::Last => break,
            wire::RectanglePlan::CopyRect => {
                let mut location = [0; 4];
                if !matches!(
                    read_blocking(stream, &mut location, cancelled),
                    ReadStep::Done
                ) {
                    return if cancelled.load(Ordering::SeqCst) {
                        Ok(UpdateOutcome::Cancelled)
                    } else {
                        Err("The CopyRect source is truncated.".into())
                    };
                }
                let x = u32::from(u16::from_be_bytes([location[0], location[1]]));
                let y = u32::from(u16::from_be_bytes([location[2], location[3]]));
                if x + header.width > fb.width || y + header.height > fb.height {
                    return Err("The CopyRect source exceeds the desktop.".into());
                }
                let stride = fb.width as usize * 4;
                for row in 0..header.height as usize {
                    let row = if header.y > y {
                        header.height as usize - 1 - row
                    } else {
                        row
                    };
                    let from = (y as usize + row) * stride + x as usize * 4;
                    let to = (header.y as usize + row) * stride + header.x as usize * 4;
                    fb.pixels
                        .copy_within(from..from + header.width as usize * 4, to);
                }
            }
            wire::RectanglePlan::Zrle { bytes } => {
                let mut length = [0; 4];
                if !matches!(
                    read_blocking(stream, &mut length, cancelled),
                    ReadStep::Done
                ) {
                    return if cancelled.load(Ordering::SeqCst) {
                        Ok(UpdateOutcome::Cancelled)
                    } else {
                        Err("The ZRLE length is truncated.".into())
                    };
                }
                let length = u32::from_be_bytes(length) as usize;
                if length == 0 || length as u64 > wire::MAX_MESSAGE_BYTES {
                    return Err("The ZRLE compressed input exceeds its limit.".into());
                }
                scratch.resize(length, 0);
                if !matches!(read_blocking(stream, scratch, cancelled), ReadStep::Done) {
                    return if cancelled.load(Ordering::SeqCst) {
                        Ok(UpdateOutcome::Cancelled)
                    } else {
                        Err("The ZRLE input is truncated.".into())
                    };
                }
                let pixels = fb
                    .zrle
                    .decode(scratch, header.width, header.height, bytes)?;
                if !wire::blit(&mut fb.pixels, fb.width, fb.height, header, &pixels) {
                    return Err("The ZRLE output exceeds the desktop.".into());
                }
            }
            wire::RectanglePlan::Raw { bytes } => {
                scratch.clear();
                scratch.resize(bytes, 0);
                match read_blocking(stream, scratch, cancelled) {
                    ReadStep::Done => {}
                    ReadStep::Cancelled => return Ok(UpdateOutcome::Cancelled),
                    ReadStep::Idle | ReadStep::Closed => {
                        return Err("the server closed inside rectangle pixels".to_string());
                    }
                    ReadStep::Failed(reason) => return Err(reason),
                }
                let converted = wire::raw_bgrx_to_rgba(scratch);
                if converted != header.width as usize * header.height as usize {
                    return Err(WireError::UnusableRectangle {
                        width: header.width,
                        height: header.height,
                    }
                    .to_string());
                }
                if !wire::blit(&mut fb.pixels, fb.width, fb.height, header, scratch) {
                    return Err(WireError::RectangleOutOfBounds {
                        x: header.x,
                        y: header.y,
                        width: header.width,
                        height: header.height,
                        fb_width: fb.width,
                        fb_height: fb.height,
                    }
                    .to_string());
                }
            }
        }
    }
    Ok(UpdateOutcome::Painted { geometry_changed })
}

fn read_cut_text(
    stream: &mut impl Read,
    cancelled: &AtomicBool,
) -> Result<Option<(i32, Vec<u8>)>, String> {
    let mut head = [0u8; 7];
    match read_blocking(stream, &mut head, cancelled) {
        ReadStep::Done => {}
        ReadStep::Cancelled => return Ok(None),
        _ => return Err("The server closed inside a VNC clipboard header.".into()),
    }
    let length = i32::from_be_bytes(
        head[3..7]
            .try_into()
            .map_err(|_| "Invalid VNC clipboard length.")?,
    );
    let claimed = length.unsigned_abs() as usize;
    if claimed > super::clipboard::LIMIT + 4096 {
        return Err("The VNC clipboard message exceeds the text limit.".into());
    }
    let mut body = vec![0; claimed];
    match read_blocking(stream, &mut body, cancelled) {
        ReadStep::Done => Ok(Some((length, body))),
        ReadStep::Cancelled => Ok(None),
        _ => Err("The server closed inside a VNC clipboard message.".into()),
    }
}
