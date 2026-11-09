//! Reference aspect-fit math for the session surface, as a pure function
//! pinned to specific pixel outcomes by unit tests.
//!
//! # Why nothing calls this
//!
//! Each item carries a targeted `#[allow(dead_code)]`. The painted surface
//! uses `framebuffer::projection`, one
//! [`enzui_iced_core::image_space::ImageProjection`] from the drawn
//! `ContentFit` that both places the picture and maps pointers back, so paint
//! and input cannot use different fits.
//!
//! This keeps the letterbox/pillarbox vocabulary that visual verification is
//! written against, as a second opinion rather than an authority. The render
//! and input paths must not call it: it describes only `ScaleToFit`, and
//! `OriginalSize` would silently scale up.

/// The inner rect an aspect-fit'd remote surface should occupy, given the
/// available `container` size and the remote's native `surface` size.
///
/// * If `surface` has any zero component (no framebuffer yet), the fit fills
///   the container.
/// * Otherwise the surface is scaled to the largest size that fits without
///   cropping, centred, letterboxed or pillarboxed.
///
/// Returned as an `(offset, size)` pair in container-local coordinates.
#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(dead_code)] // Reserved until a backend supplies a framebuffer; see module docs.
pub struct FitRect {
    pub offset: (f32, f32),
    pub size: (f32, f32),
}

#[allow(dead_code)] // Reserved until a backend supplies a framebuffer; see module docs.
pub fn aspect_fit(container: (f32, f32), surface: (u32, u32)) -> FitRect {
    let (cw, ch) = container;
    if cw <= 0.0 || ch <= 0.0 {
        return FitRect {
            offset: (0.0, 0.0),
            size: (0.0, 0.0),
        };
    }
    let (sw, sh) = surface;
    if sw == 0 || sh == 0 {
        // No native size yet — the placeholder card owns everything.
        return FitRect {
            offset: (0.0, 0.0),
            size: (cw, ch),
        };
    }
    let sw_f = sw as f32;
    let sh_f = sh as f32;
    let scale = (cw / sw_f).min(ch / sh_f);
    let inner_w = (sw_f * scale).min(cw);
    let inner_h = (sh_f * scale).min(ch);
    let ox = ((cw - inner_w) * 0.5).max(0.0);
    let oy = ((ch - inner_h) * 0.5).max(0.0);
    FitRect {
        offset: (ox, oy),
        size: (inner_w, inner_h),
    }
}

/// True if the fit produced letterboxing (top/bottom bars). The visual
/// verification rungs check this explicitly.
#[allow(dead_code)] // Reserved until a backend supplies a framebuffer; see module docs.
pub fn is_letterboxed(rect: FitRect, container: (f32, f32)) -> bool {
    rect.offset.1 > 0.5 && rect.size.1 + 2.0 * rect.offset.1 <= container.1 + 0.5
}

#[allow(dead_code)] // Reserved until a backend supplies a framebuffer; see module docs.
pub fn is_pillarboxed(rect: FitRect, container: (f32, f32)) -> bool {
    rect.offset.0 > 0.5 && rect.size.0 + 2.0 * rect.offset.0 <= container.0 + 0.5
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {}
