//! Local screenshot export (R25): the remote picture the viewer shows, saved
//! as a PNG through the native Save dialog.
//!
//! The picture is captured from the session's frame sink when the command is
//! pressed, so the file holds what the user saw rather than whatever the
//! remote drew while the dialog was open. This is distinct from the Print
//! Screen keystroke macro, which asks the remote machine to take its own
//! screenshot.

use std::io::Write;

/// The picture captured for one pending save.
#[derive(Clone, Debug)]
pub struct PendingScreenshot {
    pub width: u32,
    pub height: u32,
    pub pixels: std::sync::Arc<Vec<u8>>,
}

/// The longest file-name stem the Save dialog is pre-filled with.
const MAX_STEM_CHARS: usize = 80;

/// The name the Save dialog is pre-filled with: the connection name and the
/// local capture time, with path separators and control characters removed.
#[must_use]
pub fn suggested_name(profile_name: &str, at: chrono::DateTime<chrono::Local>) -> String {
    let cleaned: String = profile_name
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect();
    let mut stem: String = cleaned
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_start_matches(['.', ' '])
        .chars()
        .take(MAX_STEM_CHARS)
        .collect();
    if stem.trim().is_empty() {
        stem = "Remote".to_string();
    }
    format!("{} {}.png", stem.trim_end(), at.format("%Y-%m-%d %H.%M.%S"))
}

/// Encode an RGBA8 picture as an opaque PNG.
///
/// The remote desktop has no meaningful transparency (VNC pads its pixels and
/// some decoders leave alpha zero), so every pixel is written fully opaque.
///
/// # Errors
///
/// A geometry that does not match the byte count, or an encoder failure.
pub fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<u8>, String> {
    let row = (width as usize)
        .checked_mul(4)
        .ok_or("the picture is too large")?;
    if width == 0 || height == 0 || row.checked_mul(height as usize) != Some(rgba.len()) {
        return Err("the picture has no valid size".to_string());
    }
    let mut encoder = flate2::write::ZlibEncoder::new(
        Vec::with_capacity(rgba.len() / 4),
        flate2::Compression::fast(),
    );
    let mut line = Vec::with_capacity(row + 1);
    for scanline in rgba.chunks_exact(row) {
        line.clear();
        // Filter type 0 (None) for every scanline.
        line.push(0);
        for pixel in scanline.as_chunks::<4>().0 {
            line.extend_from_slice(&[pixel[0], pixel[1], pixel[2], 0xFF]);
        }
        encoder
            .write_all(&line)
            .map_err(|_| "the picture could not be compressed")?;
    }
    let data = encoder
        .finish()
        .map_err(|_| "the picture could not be compressed")?;

    let mut png = Vec::with_capacity(data.len() + 64);
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    // Bit depth 8, colour type 6 (RGBA), deflate, adaptive filtering, no interlace.
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(&mut png, b"IHDR", &header)?;
    chunk(&mut png, b"IDAT", &data)?;
    chunk(&mut png, b"IEND", &[])?;
    Ok(png)
}

fn chunk(png: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) -> Result<(), String> {
    let length = u32::try_from(data.len()).map_err(|_| "the picture is too large")?;
    png.extend_from_slice(&length.to_be_bytes());
    let mut crc = flate2::Crc::new();
    crc.update(kind);
    crc.update(data);
    png.extend_from_slice(kind);
    png.extend_from_slice(data);
    png.extend_from_slice(&crc.sum().to_be_bytes());
    Ok(())
}

/// Encode and publish `shot` at `path` on a worker thread.
///
/// Uses the same atomic user-file publication as the profile export; the
/// native Save dialog has already asked before an existing file is replaced.
pub async fn save(path: std::path::PathBuf, shot: PendingScreenshot) -> Result<String, String> {
    let (reply, answer) = iced::futures::channel::oneshot::channel();
    std::thread::Builder::new()
        .name("remote-screenshot".into())
        .spawn(move || {
            let result = encode_png(shot.width, shot.height, &shot.pixels).and_then(|png| {
                enzui_iced_core::user_file::save(
                    &path,
                    enzui_iced_core::user_file::SavePolicy::ReplaceOrCreate,
                    &png,
                )
                .map(|()| path.display().to_string())
                .or_else(|error| {
                    if error.was_published() {
                        // The file is in place; only its durability is unconfirmed.
                        Ok(path.display().to_string())
                    } else {
                        Err(crate::error_boundary::TransferFailure::classify_write(
                            error.io_error(),
                        )
                        .body(crate::error_boundary::TransferOperation::Write))
                    }
                })
            });
            let _ = reply.send(result);
        })
        .map_err(|_| "the screenshot could not be saved".to_string())?;
    answer
        .await
        .map_err(|_| "the screenshot could not be saved".to_string())?
}

#[cfg(test)]
mod tests {}
