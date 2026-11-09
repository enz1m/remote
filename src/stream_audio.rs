use gst::glib::value::ToSendValue;
use gstreamer::{self as gst, prelude::*};
use gstreamer_app::AppSrc;

use crate::protocol::ProtocolError;

const MAX_PACKET: usize = 64 * 1024;
const MAX_QUEUED: u64 = 512 * 1024;

pub(crate) struct AudioOutput {
    pipeline: gst::Pipeline,
    source: AppSrc,
}

impl AudioOutput {
    pub(crate) fn opus(
        rate: u32,
        channels: u32,
        streams: u32,
        coupled: u32,
        mapping: &[u8],
    ) -> Result<Self, ProtocolError> {
        if !matches!(rate, 8000 | 12000 | 16000 | 24000 | 48000)
            || !(1..=8).contains(&channels)
            || streams == 0
            || streams > channels
            || coupled > streams
            || streams + coupled > channels
            || mapping.len() != channels as usize
            || mapping
                .iter()
                .any(|&index| u32::from(index) >= streams + coupled && index != 255)
        {
            return Err(error("The remote Opus channel configuration is invalid."));
        }
        gst::init().map_err(|_| error("Audio services are unavailable."))?;
        let caps = gst::Caps::builder("audio/x-opus")
            .field("rate", rate as i32)
            .field("channels", channels as i32)
            .field("stream-count", streams as i32)
            .field("coupled-count", coupled as i32)
            .field("channel-mapping-family", 1i32)
            .field(
                "channel-mapping",
                gst::Array::from_iter(mapping.iter().map(|&n| i32::from(n).to_send_value())),
            )
            .build();
        Self::new(caps, "opusdec plc=true")
    }

    pub(crate) fn pcm(rate: u32, channels: u32) -> Result<Self, ProtocolError> {
        if !(8000..=192000).contains(&rate) || !(1..=8).contains(&channels) {
            return Err(error("The remote PCM channel configuration is invalid."));
        }
        gst::init().map_err(|_| error("Audio services are unavailable."))?;
        Self::new(
            gst::Caps::builder("audio/x-raw")
                .field("format", "S16LE")
                .field("layout", "interleaved")
                .field("rate", rate as i32)
                .field("channels", channels as i32)
                .build(),
            "identity",
        )
    }

    fn new(caps: gst::Caps, decoder: &str) -> Result<Self, ProtocolError> {
        let pipeline = gst::parse::launch(&format!(
            "appsrc name=audio is-live=true format=time do-timestamp=true block=false max-bytes={MAX_QUEUED} ! queue max-size-buffers=32 max-size-bytes={MAX_QUEUED} max-size-time=200000000 leaky=downstream ! {decoder} ! audioconvert ! audioresample ! pulsesink sync=false buffer-time=100000 latency-time=10000"
        ))
        .map_err(|_| error("Install the GStreamer audio, Opus and PulseAudio plugins to play remote audio."))?
        .downcast::<gst::Pipeline>()
        .map_err(|_| error("The audio pipeline could not be created."))?;
        let source = pipeline
            .by_name("audio")
            .and_then(|element| element.downcast::<AppSrc>().ok())
            .ok_or_else(|| error("The audio source is unavailable."))?;
        source.set_caps(Some(&caps));
        source.set_max_buffers(32);
        pipeline
            .set_state(gst::State::Playing)
            .map_err(|_| error("The desktop audio output could not start."))?;
        Ok(Self { pipeline, source })
    }

    pub(crate) fn push(&self, packet: &[u8]) -> Result<(), ProtocolError> {
        if packet.is_empty() || packet.len() > MAX_PACKET {
            return Err(error("The remote audio packet exceeds its limit."));
        }
        if let Some(bus) = self.pipeline.bus() {
            for message in bus.iter().take(64) {
                if matches!(message.view(), gst::MessageView::Error(_)) {
                    return Err(error(
                        "Remote audio playback failed. Check the desktop output or disable audio in this connection's settings.",
                    ));
                }
            }
        }
        if self
            .source
            .current_level_bytes()
            .saturating_add(packet.len() as u64)
            > MAX_QUEUED
            || self.source.current_level_buffers() >= 32
        {
            return Ok(());
        }
        self.source
            .push_buffer(gst::Buffer::from_slice(packet.to_vec()))
            .map_err(|_| error("The audio output has stopped."))?;
        Ok(())
    }
}

impl Drop for AudioOutput {
    fn drop(&mut self) {
        let _ = self.pipeline.set_state(gst::State::Null);
    }
}

fn error(message: &str) -> ProtocolError {
    ProtocolError::Refused(message.into())
}

pub(crate) const ENABLED: &str = "remote.audio.enabled";
pub(crate) fn enabled(profile: &crate::model::ConnectionProfile) -> bool {
    profile
        .extra
        .get(ENABLED)
        .is_none_or(|value| value != "false")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_peer_audio_formats_are_refused_before_output_allocation() {
        for (rate, channels) in [(0, 2), (48000, 0), (48000, 9), (192001, 1)] {
            assert!(AudioOutput::pcm(rate, channels).is_err());
        }
        for (channels, streams, coupled, mapping) in [
            (9, 1, 1, vec![0; 9]),
            (2, 0, 0, vec![0, 1]),
            (2, 1, 2, vec![0, 1]),
            (2, 1, 1, vec![0]),
            (2, 1, 1, vec![0, 2]),
        ] {
            assert!(AudioOutput::opus(48000, channels, streams, coupled, &mapping).is_err());
        }
    }
}
