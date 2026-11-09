use ironrdp_core::{Decode, ReadCursor, impl_as_any};
use ironrdp_pdu::{PduResult, gcc::ChannelName, pdu_other_err};
use ironrdp_rdpsnd::pdu::*;
use ironrdp_svc::{CompressionCondition, SvcClientProcessor, SvcMessage, SvcProcessor};

use crate::stream_audio::AudioOutput;

pub(super) struct AudioChannel {
    formats: Vec<AudioFormat>,
    output: Option<(u16, AudioOutput)>,
    pending: Option<(WaveInfoPdu, usize)>,
    ready: bool,
}

impl std::fmt::Debug for AudioChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AudioChannel")
            .field("formats", &self.formats.len())
            .finish_non_exhaustive()
    }
}

impl AudioChannel {
    pub(super) fn new() -> Self {
        Self {
            formats: Vec::new(),
            output: None,
            pending: None,
            ready: false,
        }
    }
    fn play(&mut self, index: u16, data: &[u8]) -> PduResult<()> {
        if !self.ready {
            return Err(pdu_other_err!("RDP audio preceded format negotiation"));
        }
        let format = self
            .formats
            .get(usize::from(index))
            .ok_or_else(|| pdu_other_err!("RDP audio selected an unadvertised format"))?;
        if data.is_empty()
            || data.len() > 256 * 1024
            || !data.len().is_multiple_of(usize::from(format.n_block_align))
        {
            return Err(pdu_other_err!("RDP audio exceeded its frame bounds"));
        }
        if self
            .output
            .as_ref()
            .is_none_or(|(current, _)| *current != index)
        {
            self.output = Some((
                index,
                AudioOutput::pcm(format.n_samples_per_sec, u32::from(format.n_channels))
                    .map_err(|_| pdu_other_err!("RDP audio output could not start"))?,
            ));
        }
        if let Some((_, output)) = &self.output {
            for chunk in data.chunks(65536) {
                output
                    .push(chunk)
                    .map_err(|_| pdu_other_err!("RDP audio playback failed"))?;
            }
        }
        Ok(())
    }
}

fn supported(format: &AudioFormat) -> bool {
    format.format == WaveFormat::PCM
        && matches!(format.n_channels, 1 | 2)
        && format.bits_per_sample == 16
        && (8000..=192000).contains(&format.n_samples_per_sec)
        && format.n_block_align == format.n_channels * 2
        && format.n_avg_bytes_per_sec == format.n_samples_per_sec * u32::from(format.n_block_align)
        && format.data.as_ref().is_none_or(Vec::is_empty)
}

fn legacy_data(info: &WaveInfoPdu, expected: usize, data: &[u8]) -> PduResult<Vec<u8>> {
    if !(4..=65536).contains(&expected) || data.len() != expected {
        return Err(pdu_other_err!(
            "RDP legacy audio length changed between its messages"
        ));
    }
    let mut result = Vec::with_capacity(expected);
    result.extend_from_slice(&info.data);
    result.extend_from_slice(&data[4..]);
    Ok(result)
}

impl_as_any!(AudioChannel);
impl SvcClientProcessor for AudioChannel {}
impl SvcProcessor for AudioChannel {
    fn channel_name(&self) -> ChannelName {
        ChannelName::from_static(b"rdpsnd\0\0")
    }
    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::Never
    }
    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        if let Some((info, size)) = self.pending.take() {
            let data = legacy_data(&info, size, payload)?;
            self.play(info.format_no, &data)?;
            return Ok(vec![
                ClientAudioOutputPdu::WaveConfirm(WaveConfirmPdu {
                    timestamp: info.timestamp,
                    block_no: info.block_no,
                })
                .into(),
            ]);
        }
        let pdu = ServerAudioOutputPdu::decode(&mut ReadCursor::new(payload))
            .map_err(|_| pdu_other_err!("RDP audio message is invalid"))?;
        match pdu {
            ServerAudioOutputPdu::AudioFormat(server) => {
                if server.formats.len() > 64 {
                    return Err(pdu_other_err!("RDP offered too many audio formats"));
                }
                self.formats = server.formats.into_iter().filter(supported).collect();
                self.output = None;
                // Reliable TCP hosts may send audio without an optional training exchange.
                self.ready = true;
                let mut messages = vec![
                    ClientAudioOutputPdu::AudioFormat(ClientAudioFormatPdu {
                        version: server.version,
                        flags: AudioFormatFlags::ALIVE,
                        formats: self.formats.clone(),
                        volume_left: u16::MAX,
                        volume_right: u16::MAX,
                        pitch: 0x10000,
                        dgram_port: 0,
                    })
                    .into(),
                ];
                if server.version >= Version::V6 {
                    messages.push(
                        ClientAudioOutputPdu::QualityMode(QualityModePdu {
                            quality_mode: QualityMode::High,
                        })
                        .into(),
                    );
                }
                Ok(messages)
            }
            ServerAudioOutputPdu::Training(training) => {
                if !self.ready {
                    return Err(pdu_other_err!(
                        "RDP audio training preceded format negotiation"
                    ));
                }
                let pack_size = u16::try_from(training.data.len())
                    .map_err(|_| pdu_other_err!("RDP audio training exceeded its limit"))?;
                self.ready = true;
                Ok(vec![
                    ClientAudioOutputPdu::TrainingConfirm(TrainingConfirmPdu {
                        timestamp: training.timestamp,
                        pack_size,
                    })
                    .into(),
                ])
            }
            ServerAudioOutputPdu::Wave2(wave) => {
                self.play(wave.format_no, &wave.data)?;
                Ok(vec![
                    ClientAudioOutputPdu::WaveConfirm(WaveConfirmPdu {
                        timestamp: wave.timestamp,
                        block_no: wave.block_no,
                    })
                    .into(),
                ])
            }
            ServerAudioOutputPdu::Wave(wave) => {
                if !self.ready || usize::from(wave.format_no) >= self.formats.len() {
                    return Err(pdu_other_err!(
                        "RDP legacy audio selected an unadvertised format"
                    ));
                }
                let expected = usize::from(wave.audio_length);
                let info = WaveInfoPdu {
                    timestamp: wave.timestamp,
                    format_no: wave.format_no,
                    block_no: wave.block_no,
                    data: wave.data_prefix,
                };
                // Older servers can concatenate the WaveInfo and bare audio messages.
                let header_length = 16;
                if payload.len() > header_length {
                    let data = legacy_data(&info, expected, &payload[header_length..])?;
                    self.play(info.format_no, &data)?;
                    Ok(vec![
                        ClientAudioOutputPdu::WaveConfirm(WaveConfirmPdu {
                            timestamp: info.timestamp,
                            block_no: info.block_no,
                        })
                        .into(),
                    ])
                } else {
                    if !(4..=65536).contains(&expected) {
                        return Err(pdu_other_err!("RDP legacy audio declared an invalid size"));
                    }
                    self.pending = Some((info, expected));
                    Ok(Vec::new())
                }
            }
            ServerAudioOutputPdu::Close => {
                self.output = None;
                self.pending = None;
                Ok(Vec::new())
            }
            ServerAudioOutputPdu::Volume(_) | ServerAudioOutputPdu::Pitch(_) => Ok(Vec::new()),
            _ => Err(pdu_other_err!(
                "RDP requested an unsupported audio transport"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_audio_preserves_displaced_bytes_and_refuses_changed_or_unnegotiated_frames() {
        let info = WaveInfoPdu {
            timestamp: 1,
            format_no: 0,
            block_no: 2,
            data: [1, 2, 3, 4],
        };
        assert_eq!(
            legacy_data(&info, 8, &[0, 0, 0, 0, 5, 6, 7, 8]).unwrap(),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert!(legacy_data(&info, 8, &[0; 7]).is_err());
        assert!(legacy_data(&info, 65537, &[]).is_err());
        assert!(AudioChannel::new().play(0, &[0; 4]).is_err());
        let pcm = AudioFormat {
            format: WaveFormat::PCM,
            n_channels: 2,
            n_samples_per_sec: 48000,
            n_avg_bytes_per_sec: 192000,
            n_block_align: 4,
            bits_per_sample: 16,
            data: None,
        };
        let mut unsupported = pcm.clone();
        unsupported.bits_per_sample = 24;
        let formats = ServerAudioOutputPdu::AudioFormat(ServerAudioFormatPdu {
            version: Version::V8,
            formats: vec![unsupported, pcm.clone()],
        });
        let mut channel = AudioChannel::new();
        channel
            .process(&ironrdp_core::encode_vec(&formats).unwrap())
            .unwrap();
        assert_eq!(channel.formats, vec![pcm]);
        assert!(channel.ready);
        assert!(channel.play(1, &[0; 4]).is_err());
        let info = ServerAudioOutputPdu::Wave(WavePdu {
            timestamp: 1,
            format_no: 0,
            block_no: 2,
            data_prefix: [1, 2, 3, 4],
            audio_length: 8,
        });
        assert!(
            channel
                .process(&ironrdp_core::encode_vec(&info).unwrap())
                .unwrap()
                .is_empty()
        );
        assert!(channel.pending.is_some());
        assert!(channel.process(&[0; 7]).is_err());
    }
}
