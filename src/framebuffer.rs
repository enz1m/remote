//! Remote framebuffer admission, retention and coordinate policy.
//!
//! Pure decisions for frames and pointer presses, with no widget, task or `App`.
//! The reducer applies them and [`crate::session_view`] paints the result.
//!
//! Shared framework capabilities do the general work:
//!
//! * [`enzui_iced_core::media::Rgba8Frame`] validates the owned frame and its
//!   `Debug` prints a byte count rather than pixels.
//! * [`enzui_iced_core::media::BoundedFrameSink`] retains at most one displayed,
//!   one in-flight and one queued frame over
//!   [`enzui_iced_core::frame_plan::FramePlan`], coalescing newer frames and
//!   refusing stale generations and out-of-order sequences.
//! * [`enzui_iced_core::image_space::ImageProjection`] maps a pointer position to
//!   a remote pixel under a [`ContentFit`].
//!
//! This module adds the remote-desktop specifics: the admission byte ceiling, the
//! mapping from [`ScalingMode`] to a fit, and the refusal type.

use enzui_iced_core::decode_limits::{DecodeLimits, DecodeVerdict};
use enzui_iced_core::image_space::ImageProjection;
use enzui_iced_core::media::{FrameFormatError, Generation, Rgba8Frame};
use enzui_iced_core::zoom_pan::ViewTransform;
use iced::{ContentFit, Point, Rectangle, Size};

use crate::session::ScalingMode;

/// The ceilings a remote framebuffer is admitted against.
///
/// Far below [`DecodeLimits::DEFAULT`], because framebuffer dimensions are chosen
/// by the remote and the retention bound multiplies whatever is admitted.
/// 8 Mpx / 32 MiB covers a 3840×2160 desktop with a little headroom; see
/// `MAX_RETAINED_BYTES` for the per-session worst case.
pub const REMOTE_FRAME_LIMITS: DecodeLimits = DecodeLimits {
    max_encoded_bytes: 32 * 1024 * 1024,
    max_width: 8192,
    max_height: 8192,
    max_pixels: 8 * 1024 * 1024,
    max_rgba_bytes: 32 * 1024 * 1024,
};

/// The pixel bytes of one frame, in transit from a backend to the reducer.
///
/// A newtype so `Debug` prints the length instead of millions of bytes. The `Arc`
/// makes `Message` clones cheap, and [`Self::into_vec`] takes the buffer without
/// copying when the reducer holds the only reference.
#[derive(Clone)]
pub struct FrameBytes {
    pixels: std::sync::Arc<Vec<u8>>,
    consumed: Option<std::sync::Arc<FrameConsumed>>,
}

struct FrameConsumed(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for FrameConsumed {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

impl PartialEq for FrameBytes {
    fn eq(&self, other: &Self) -> bool {
        self.pixels == other.pixels
    }
}

impl Eq for FrameBytes {}

impl FrameBytes {
    pub fn new(pixels: Vec<u8>) -> Self {
        Self {
            pixels: std::sync::Arc::new(pixels),
            consumed: None,
        }
    }

    pub(crate) fn tracked(
        pixels: Vec<u8>,
        consumed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            pixels: std::sync::Arc::new(pixels),
            consumed: Some(std::sync::Arc::new(FrameConsumed(consumed))),
        }
    }

    /// The buffer, taken without copying when the reducer holds the only reference.
    pub fn into_vec(self) -> Vec<u8> {
        let Self { pixels, consumed } = self;
        if let Some(receipt) = consumed.as_ref() {
            receipt.0.store(true, std::sync::atomic::Ordering::Release);
        }
        let pixels = std::sync::Arc::try_unwrap(pixels).unwrap_or_else(|shared| (*shared).clone());
        drop(consumed);
        pixels
    }
}

impl std::fmt::Debug for FrameBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FrameBytes({} bytes)", self.pixels.len())
    }
}

/// Why a frame was not admitted.
///
/// Every arm is a refusal the reducer can meet from a *correct* transport
/// meeting a hostile or broken remote, so each is typed rather than a string:
/// the surface keeps showing the last good frame and the session is not
/// failed over a single bad one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameRefusal {
    /// The announced geometry exceeds [`REMOTE_FRAME_LIMITS`].
    OverLimit(DecodeVerdict),
    /// The geometry is unusable, or the buffer length disagrees with it.
    Malformed(FrameFormatError),
}

impl FrameRefusal {
    /// A short, bounded reason, safe to put on a session's status line.
    ///
    /// Deliberately not the `Display` of the underlying verdict: those name
    /// exact byte counts and limits, which is diagnostic detail rather than
    /// something a user of a remote desktop can act on.
    pub fn summary(self) -> &'static str {
        match self {
            Self::OverLimit(_) => "the remote offered a framebuffer larger than this build accepts",
            Self::Malformed(_) => "the remote offered a framebuffer this build cannot read",
        }
    }
}

/// Admit one frame from a backend, stamping it with the session's own
/// generation and sequence.
///
/// The generation is the app's connect identity, which a backend cannot know, so
/// the reducer stamps it here. The byte ceiling is checked before any owned
/// buffer is built, so an absurd announced geometry allocates nothing.
pub fn admit(
    generation: Generation,
    seq: enzui_iced_core::frame_plan::FrameSeq,
    width: u32,
    height: u32,
    pixels: FrameBytes,
) -> Result<Rgba8Frame, FrameRefusal> {
    match REMOTE_FRAME_LIMITS.check_decoded(width, height) {
        DecodeVerdict::Allow => {}
        refused => return Err(FrameRefusal::OverLimit(refused)),
    }
    Rgba8Frame::new(generation, seq, width, height, pixels.into_vec())
        .map_err(FrameRefusal::Malformed)
}

/// The fit the surface paints a framebuffer under.
///
/// Mapped once so painting and pointer mapping agree:
///
/// * `ScaleToFit` is [`ContentFit::Contain`]: letterboxed, aspect preserved, never
///   cropping the remote's edges.
/// * `OriginalSize` is [`ContentFit::None`]: one framebuffer pixel per surface
///   pixel from the slot's top-left, clipped by the slot.
pub fn fit_for(scaling: ScalingMode) -> ContentFit {
    match scaling {
        ScalingMode::ScaleToFit => ContentFit::Contain,
        ScalingMode::OriginalSize => ContentFit::None,
    }
}

/// Where the picture lands inside a slot of `slot` showing a `frame`-sized
/// framebuffer under `scaling`.
///
/// `None` for a degenerate slot or framebuffer, which is the honest answer
/// while a session has no frame or a pane has collapsed to nothing — there is
/// no rectangle to hit-test against.
pub fn projection(slot: Size, frame: (u32, u32), scaling: ScalingMode) -> Option<ImageProjection> {
    if slot.width <= 0.0 || slot.height <= 0.0 || frame.0 == 0 || frame.1 == 0 {
        return None;
    }
    if scaling == ScalingMode::OriginalSize {
        return ImageProjection::from_origin_scale(Point::ORIGIN, 1.0);
    }
    ImageProjection::new(
        Rectangle::new(Point::ORIGIN, slot),
        Size::new(frame.0 as f32, frame.1 as f32),
        fit_for(scaling),
        ViewTransform::IDENTITY,
    )
}

/// The remote pixel a pointer at `at` (slot coordinates, origin top-left) is over,
/// or `None` when it is over the letterbox or margin.
///
/// Coordinates are truncated, the convention framebuffer pointer events use.
pub fn remote_pixel(
    slot: Size,
    frame: (u32, u32),
    scaling: ScalingMode,
    at: Point,
) -> Option<(i32, i32)> {
    let projection = projection(slot, frame, scaling)?;
    let image = Size::new(frame.0 as f32, frame.1 as f32);
    let point = projection.display_to_image(at);
    if !projection.contains(point, image) {
        return None;
    }
    Some((point.x as i32, point.y as i32))
}

#[cfg(test)]
mod tests;

/// CPU admission-sink bound during replacement, excluding the native GPU presenter.
#[cfg(test)]
pub const MAX_RETAINED_BYTES: usize = 2 * 32 * 1024 * 1024;
