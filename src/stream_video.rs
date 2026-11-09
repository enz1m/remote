//! Bounded software video decoding into the app's RGBA frame stream.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use gstreamer::{self as gst, prelude::*};
use gstreamer_app::{AppSink, AppSrc};

use crate::desktop_worker::Control;
use crate::protocol::ProtocolError;
use crate::state_machine::SessionEvent;

pub(crate) struct VideoDecoder {
    pipeline: gst::Pipeline,
    source: AppSrc,
    sink: AppSink,
    pending: Option<Arc<AtomicBool>>,
    codec: Codec,
    vp8_keyframe: AtomicBool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Codec {
    H264,
    Vp9,
    Vp8,
    H265,
    Av1,
}

const MAX_PACKET: usize = 4 * 1024 * 1024;
const MAX_QUEUED: u64 = 8 * 1024 * 1024;

impl Codec {
    pub(crate) fn available(self) -> bool {
        if gst::init().is_err() {
            return false;
        }
        let (parser, decoder) = match self {
            Self::H264 => (
                "h264parse",
                if gst::ElementFactory::find("avdec_h264").is_some() {
                    "avdec_h264"
                } else {
                    "openh264dec"
                },
            ),
            Self::Vp9 => ("vp9parse", "vp9dec"),
            Self::Vp8 => ("identity", "vp8dec"),
            Self::H265 => ("h265parse", "avdec_h265"),
            Self::Av1 => ("av1parse", "avdec_av1"),
        };
        gst::ElementFactory::find(parser).is_some() && gst::ElementFactory::find(decoder).is_some()
    }
}

impl VideoDecoder {
    pub(crate) fn new(codec: Codec) -> Result<Self, ProtocolError> {
        gst::init().map_err(|_| error("Video services are unavailable."))?;
        let (media, parser, decoder, subtype) = match codec {
            Codec::H264 => (
                "video/x-h264,stream-format=byte-stream,alignment=au",
                "h264parse",
                if gst::ElementFactory::find("avdec_h264").is_some() {
                    "avdec_h264 max-threads=1"
                } else {
                    "openh264dec"
                },
                "h264",
            ),
            Codec::Vp9 => ("video/x-vp9", "vp9parse", "vp9dec threads=1", "vp9"),
            Codec::Vp8 => ("video/x-vp8", "identity", "vp8dec threads=1", "vp8"),
            Codec::H265 => (
                "video/x-h265,stream-format=byte-stream,alignment=au",
                "h265parse",
                "avdec_h265 max-threads=1",
                "h265",
            ),
            Codec::Av1 => (
                "video/x-av1,stream-format=obu-stream,alignment=tu",
                "av1parse",
                "avdec_av1 max-threads=1",
                "av1",
            ),
        };
        let pipeline = gst::parse::launch(&format!("appsrc name=encoded is-live=true format=time block=false max-bytes={MAX_QUEUED} ! {parser} ! video/x-{subtype},width=(int)[1,3840],height=(int)[1,2160] ! {decoder} ! videoconvert ! video/x-raw,format=RGBA ! appsink name=decoded max-buffers=1 drop=true sync=false"))
            .map_err(|_| error("The required video parser or decoder is not installed."))?
            .downcast::<gst::Pipeline>().map_err(|_| error("The video pipeline could not be created."))?;
        let source = pipeline
            .by_name("encoded")
            .and_then(|e| e.downcast::<AppSrc>().ok())
            .ok_or_else(|| error("The video source is unavailable."))?;
        let sink = pipeline
            .by_name("decoded")
            .and_then(|e| e.downcast::<AppSink>().ok())
            .ok_or_else(|| error("The video sink is unavailable."))?;
        source.set_caps(Some(
            &media
                .parse::<gst::Caps>()
                .map_err(|_| error("The encoded video format is invalid."))?,
        ));
        source.set_max_buffers(8);
        pipeline
            .set_state(gst::State::Playing)
            .map_err(|_| error("The video decoder could not start."))?;
        Ok(Self {
            pipeline,
            source,
            sink,
            pending: None,
            codec,
            vp8_keyframe: AtomicBool::new(false),
        })
    }

    pub(crate) fn push(&self, bytes: &[u8]) -> Result<(), ProtocolError> {
        if bytes.is_empty()
            || bytes.len() > MAX_PACKET
            || self
                .source
                .current_level_bytes()
                .saturating_add(bytes.len() as u64)
                > MAX_QUEUED
            || self.source.current_level_buffers() >= 8
        {
            return Err(error("The encoded video exceeds its bounded input queue."));
        }
        if self.codec == Codec::Vp8 {
            admit_vp8(bytes, &self.vp8_keyframe)?;
        }
        self.source
            .push_buffer(gst::Buffer::from_slice(bytes.to_vec()))
            .map_err(|_| error("The video decoder refused a packet."))?;
        Ok(())
    }

    pub(crate) fn publish(
        &mut self,
        control: &Control,
    ) -> Result<Option<(u32, u32)>, ProtocolError> {
        if let Some(bus) = self.pipeline.bus() {
            for message in bus.iter().take(64) {
                if matches!(message.view(), gst::MessageView::Error(_)) {
                    return Err(error("The remote video could not be decoded."));
                }
            }
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|p| !p.load(Ordering::Acquire))
        {
            return Ok(None);
        }
        let Some(sample) = self.sink.try_pull_sample(gst::ClockTime::ZERO) else {
            return Ok(None);
        };
        let caps = sample
            .caps()
            .and_then(|c| c.structure(0))
            .ok_or_else(|| error("Decoded video has no format."))?;
        let width = caps
            .get::<i32>("width")
            .map_err(|_| error("Decoded video has no width."))?;
        let height = caps
            .get::<i32>("height")
            .map_err(|_| error("Decoded video has no height."))?;
        let size = frame_size(width, height)?;
        let buffer = sample
            .buffer()
            .ok_or_else(|| error("Decoded video has no pixels."))?;
        let mapped = buffer
            .map_readable()
            .map_err(|_| error("Decoded video pixels are unavailable."))?;
        if mapped.size() != size {
            return Err(error("Decoded video has an unsupported row layout."));
        }
        let consumed = Arc::new(AtomicBool::new(false));
        control
            .events
            .send(SessionEvent::Frame {
                width: width as u32,
                height: height as u32,
                pixels: crate::framebuffer::FrameBytes::tracked(
                    mapped.as_slice().to_vec(),
                    Arc::clone(&consumed),
                ),
            })
            .map_err(|_| error("The video surface was retired."))?;
        self.pending = Some(consumed);
        Ok(Some((width as u32, height as u32)))
    }
}

impl Drop for VideoDecoder {
    fn drop(&mut self) {
        let _ = self.pipeline.set_state(gst::State::Null);
    }
}

fn error(message: &str) -> ProtocolError {
    ProtocolError::Refused(message.into())
}

fn frame_size(width: i32, height: i32) -> Result<usize, ProtocolError> {
    if !(1..=3840).contains(&width) || !(1..=2160).contains(&height) {
        return Err(error("Decoded video exceeds the desktop limits."));
    }
    (width as usize)
        .checked_mul(height as usize)
        .and_then(|n| n.checked_mul(4))
        .filter(|n| *n <= crate::protocol::MAX_QUEUED_BYTES)
        .ok_or_else(|| error("Decoded video exceeds the frame byte limit."))
}

fn admit_vp8(bytes: &[u8], keyframe: &AtomicBool) -> Result<(), ProtocolError> {
    if bytes.len() < 3 {
        return Err(error("The VP8 frame header is truncated."));
    }
    if bytes[0] & 1 != 0 {
        return if keyframe.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(error("VP8 video preceded its bounded keyframe."))
        };
    }
    if bytes.len() < 10 || bytes[3..6] != [0x9d, 0x01, 0x2a] {
        return Err(error("The VP8 keyframe is invalid."));
    }
    let width = u16::from_le_bytes([bytes[6], bytes[7]]) & 0x3fff;
    let height = u16::from_le_bytes([bytes[8], bytes[9]]) & 0x3fff;
    frame_size(i32::from(width), i32::from(height))?;
    keyframe.store(true, Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vp8_requires_a_bounded_keyframe_before_decoder_admission() {
        let admitted = AtomicBool::new(false);
        assert!(admit_vp8(&[1, 0, 0], &admitted).is_err());
        assert!(admit_vp8(&[0, 0], &admitted).is_err());
        let mut bytes = [0, 0, 0, 0x9d, 0x01, 0x2a, 0, 0, 0, 0];
        bytes[6..8].copy_from_slice(&640u16.to_le_bytes());
        bytes[8..10].copy_from_slice(&480u16.to_le_bytes());
        assert!(admit_vp8(&bytes, &admitted).is_ok());
        assert!(admit_vp8(&[1, 0, 0], &admitted).is_ok());
        for (width, height) in [(0, 480), (16383, 480), (640, 16383)] {
            bytes[6..8].copy_from_slice(&(width as u16).to_le_bytes());
            bytes[8..10].copy_from_slice(&(height as u16).to_le_bytes());
            assert!(admit_vp8(&bytes, &admitted).is_err());
        }
        bytes[3] = 0;
        assert!(admit_vp8(&bytes, &admitted).is_err());
    }
}
