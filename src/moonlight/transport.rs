use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use moonlight_common::{
    crypto::openssl::OpenSSLCryptoBackend,
    high::std::MoonlightHost,
    http::{
        ClientIdentifier, ClientSecret, ServerIdentifier,
        pair::{PairPin, PairingCryptoBackend},
    },
    stream::{
        AesIv, AesKey, EncryptionFlags, MoonlightStreamSettings, StreamingConfig,
        audio::{AudioConfig, AudioDecoder, AudioFrame, OpusMultistreamConfig},
        c::{
            MoonlightInstance, MoonlightStream,
            bindings::{ConnectionStatus, Stage},
            connection::ConnectionListenerC,
        },
        connection::ConnectionListener,
        control::{
            ActiveGamepads, KeyAction, KeyCode, KeyModifiers, MouseButton, MouseButtonAction,
        },
        video::{
            ColorRange, ColorSpace, DecodeResult, VideoDecodeUnit,
            VideoDecoder as MoonlightDecoder, VideoFormat, VideoFormats, VideoSetup,
        },
    },
};

use super::{
    Control,
    http::{self, PinnedClient},
    identity::{Identity, Reservation},
};
use crate::model::ConnectionProfile;
use crate::protocol::{PointerButton, ProtocolError, RemoteInput};
use crate::state_machine::SessionEvent;
use crate::stream_video::{Codec, VideoDecoder};

fn error(text: &str) -> ProtocolError {
    ProtocolError::Refused(text.into())
}
fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(super) fn run(
    profile: &ConnectionProfile,
    password: &str,
    control: &Arc<Control>,
    inputs: Receiver<Vec<RemoteInput>>,
    ready: SyncSender<Result<(), ProtocolError>>,
) {
    http::bind(
        control,
        profile
            .extra
            .get(super::RESUME)
            .is_some_and(|v| v == "true"),
    );
    let result = drive(profile, password, control, inputs, &ready);
    http::unbind();
    if let Err(error) = result {
        if control.active.swap(false, Ordering::SeqCst) {
            if !control.cancelled.load(Ordering::SeqCst) {
                let _ = control.events.send(SessionEvent::Drop(error.to_string()));
            }
        } else {
            let _ = ready.send(Err(error));
        }
    }
}

fn drive(
    profile: &ConnectionProfile,
    password: &str,
    control: &Arc<Control>,
    inputs: Receiver<Vec<RemoteInput>>,
    ready: &SyncSender<Result<(), ProtocolError>>,
) -> Result<(), ProtocolError> {
    if control.cancelled.load(Ordering::SeqCst) {
        return Err(error("Moonlight connection was cancelled."));
    }
    let video_formats = supported_formats();
    if video_formats.is_empty() {
        return Err(error(
            "Install a supported GStreamer H.264, HEVC or AV1 decoder before connecting to Moonlight.",
        ));
    }
    let mut reservation = Reservation::begin(profile)?;
    let address = if profile.host.contains(':') && !profile.host.starts_with('[') {
        format!("[{}]", profile.host)
    } else {
        profile.host.clone()
    };
    let port = crate::quick_connect::effective_port(profile.port, profile.protocol)
        .checked_add(5)
        .ok_or_else(|| error("The Moonlight HTTPS port is out of range."))?;
    let client = MoonlightHost::<PinnedClient>::new(
        address,
        port,
        Some(profile.id.simple().to_string()[..16].to_owned()),
    )
    .map_err(|_| error("The Moonlight host's discovery request failed."))?;
    let crypto = Arc::new(OpenSSLCryptoBackend);
    if let Some(identity) = reservation.identity.take() {
        client
            .set_identity(
                ClientIdentifier::from_pem(
                    pem::parse(&identity.client_certificate)
                        .map_err(|_| error("The saved Moonlight identity is invalid."))?,
                ),
                ClientSecret::from_pem(
                    pem::parse(&identity.client_private_key)
                        .map_err(|_| error("The saved Moonlight identity is invalid."))?,
                ),
                ServerIdentifier::from_pem(
                    pem::parse(&identity.server_certificate)
                        .map_err(|_| error("The saved Moonlight identity is invalid."))?,
                ),
            )
            .map_err(|_| error("The saved Moonlight identity could not be verified."))?;
    } else {
        let digits = password.as_bytes();
        if digits.len() != 4 || !digits.iter().all(u8::is_ascii_digit) {
            return Err(error(
                "Enter a four-digit pairing PIN in the connection settings, then enter that PIN in the Sunshine host's pairing page.",
            ));
        }
        let pin = PairPin::from_array([
            digits[0] - b'0',
            digits[1] - b'0',
            digits[2] - b'0',
            digits[3] - b'0',
        ])
        .ok_or_else(|| error("The Moonlight pairing PIN is invalid."))?;
        let (identifier, secret) = crypto
            .generate_client_identity()
            .map_err(|_| error("The Moonlight client identity could not be generated."))?;
        client.pair(&identifier,&secret,"enzUI Remote".into(),pin,Arc::clone(&crypto)).map_err(|_| error("Moonlight pairing was refused or cancelled. Enter the same PIN on the Sunshine host."))?;
        let (identifier, secret, server) = client
            .identity()
            .ok_or_else(|| error("Moonlight pairing did not return an authenticated identity."))?;
        reservation.publish(
            Identity {
                client_certificate: identifier.to_pem().to_string(),
                client_private_key: secret.to_pem().to_string(),
                server_certificate: server.to_pem().to_string(),
            },
            control,
        )?;
    }
    if control.cancelled.load(Ordering::SeqCst) {
        return Err(error("Moonlight connection was cancelled."));
    }
    let apps = client
        .app_list()
        .map_err(|_| error("The Moonlight host certificate or app list could not be verified."))?;
    if apps.len() > 256 {
        return Err(error("The Moonlight app list exceeds its limit."));
    }
    let wanted = profile
        .extra
        .get(super::APP_ID)
        .map(|id| id.parse::<u32>())
        .transpose()
        .map_err(|_| error("The Moonlight app ID must be a positive number."))?;
    if wanted == Some(0) {
        return Err(error("The Moonlight app ID must be a positive number."));
    }
    let app=apps.iter().find(|app| wanted.map_or_else(|| app.title.eq_ignore_ascii_case("Desktop"), |id|app.id==moonlight_common::AppId(id))).ok_or_else(|| error("No Desktop app was found. Set the Sunshine desktop app ID in the connection settings."))?;
    if client
        .current_game()
        .map_err(|_| error("The Moonlight host state could not be verified."))?
        != 0
        && !profile
            .extra
            .get(super::RESUME)
            .is_some_and(|v| v == "true")
    {
        return Err(error(
            "The Moonlight host has a running app. Enable Resume running host app in this connection to join it, or stop it on the host.",
        ));
    }
    let instance = MoonlightInstance::global()
        .map_err(|_| error("Moonlight already has an active local stream."))?;
    let (width, height) = profile.resolution.unwrap_or((1280, 720));
    let mut settings = MoonlightStreamSettings {
        width: width.clamp(200, 3840),
        height: height.clamp(200, 2160),
        fps: 60,
        fps_x100: 6000,
        bitrate: 1000 + u32::from(profile.quality.min(9)) * 1000,
        packet_size: 1024,
        encryption_flags: EncryptionFlags::all(),
        streaming_remotely: StreamingConfig::Auto,
        sops: false,
        hdr: false,
        supported_video_formats: video_formats,
        color_space: ColorSpace::Rec709,
        color_range: ColorRange::Limited,
        local_audio_play_mode: false,
        audio_config: AudioConfig::STEREO,
        gamepads_attached: ActiveGamepads::empty(),
        gamepads_persist_after_disconnect: false,
        enable_mic: false,
    };
    settings
        .adjust_for_server(
            client
                .version()
                .map_err(|_| error("Moonlight host version is unavailable."))?,
            &client
                .gfe_version()
                .map_err(|_| error("Moonlight host version is unavailable."))?,
            client
                .server_codec_mode_support()
                .map_err(|_| error("Moonlight host codec information is unavailable."))?,
        )
        .map_err(|_| {
            error(
                "The Moonlight host does not support the negotiated encrypted video configuration.",
            )
        })?;
    let decoder = Arc::new(Mutex::new(None::<VideoDecoder>));
    let failed = Arc::new(AtomicBool::new(false));
    let stream_failure = Arc::new(Mutex::new(None));
    let aes_key = AesKey::new_random(&crypto)
        .map_err(|_| error("Moonlight stream-key generation failed."))?;
    let aes_iv =
        AesIv::new_random(&crypto).map_err(|_| error("Moonlight stream-key generation failed."))?;
    let mut config = client
        .start_stream(
            app.id,
            &settings,
            aes_key,
            aes_iv,
            instance.launch_query_parameters(),
        )
        .map_err(|_| error("The authenticated Moonlight desktop launch was refused."))?;
    config.address = profile
        .host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    if let Some(uri) = config.rtsp_session_url.as_mut() {
        let mut parsed = url::Url::parse(uri)
            .map_err(|_| error("The Moonlight host returned an invalid streaming endpoint."))?;
        if !matches!(parsed.scheme(), "rtsp" | "rtspenc")
            || parsed.port().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(error(
                "The Moonlight host returned an unsupported streaming endpoint.",
            ));
        }
        // Hosts behind NAT advertise their guest address; every stream stays on the chosen host.
        parsed
            .set_host(Some(&config.address))
            .map_err(|_| error("The Moonlight host address is invalid."))?;
        *uri = parsed.to_string();
    }
    if control.cancelled.load(Ordering::SeqCst) {
        return Err(error("Moonlight connection was cancelled."));
    }
    let (rumble_tx, rumble_rx) = std::sync::mpsc::sync_channel(32);
    let mut gamepads = if !profile.view_only
        && profile
            .extra
            .get(super::GAMEPADS)
            .is_some_and(|v| v == "true")
    {
        Some(super::gamepad::Gamepads::new(rumble_rx)?)
    } else {
        None
    };
    let listener = Listener {
        failed: Arc::clone(&failed),
        rumble: rumble_tx,
        failure: Arc::clone(&stream_failure),
    };
    let stream = instance
        .start_connection(
            config,
            settings,
            listener.clone(),
            listener,
            Decoder {
                video: Arc::clone(&decoder),
                failed: Arc::clone(&failed),
            },
            RemoteAudio {
                enabled: crate::stream_audio::enabled(profile),
                output: None,
                failed: Arc::clone(&failed),
                failure: Arc::clone(&stream_failure),
            },
        )
        .map_err(|_| {
            lock(&stream_failure).take().unwrap_or_else(|| {
                error("The encrypted Moonlight stream could not be established.")
            })
        })?;
    let mut keyboard = crate::desktop_scancode::KeyboardState::default();
    let mut modifiers = BTreeSet::new();
    let mut size = (width.clamp(200, 3840), height.clamp(200, 2160));
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut admitted = false;
    let result = (|| {
        while !control.cancelled.load(Ordering::SeqCst) && !failed.load(Ordering::SeqCst) {
            let published = match lock(&decoder).as_mut() {
                Some(decoder) => decoder.publish(control)?,
                None => None,
            };
            if let Some(new_size) = published {
                size = new_size;
                if !admitted {
                    admitted = true;
                    control.active.store(true, Ordering::SeqCst);
                    ready
                        .send(Ok(()))
                        .map_err(|_| error("The Moonlight dial was retired."))?;
                }
            }
            if !admitted && Instant::now() >= deadline {
                return Err(error(
                    "Moonlight did not deliver video before the desktop deadline.",
                ));
            }
            if let Some(gamepads) = gamepads.as_mut() {
                gamepads.poll(&stream, control.input_capture.load(Ordering::SeqCst))?;
            }
            for _ in 0..8 {
                let Ok(batch) = inputs.try_recv() else {
                    break;
                };
                if profile.view_only {
                    return Err(error("The Moonlight connection is read-only."));
                }
                for event in batch {
                    send_input(&stream, event, size, &mut keyboard, &mut modifiers)?;
                }
            }
            std::thread::sleep(Duration::from_millis(4));
        }
        if failed.load(Ordering::SeqCst) && !control.cancelled.load(Ordering::SeqCst) {
            return Err(lock(&stream_failure).take().unwrap_or_else(|| {
                ProtocolError::Transport("The Moonlight stream ended unexpectedly.".into())
            }));
        }
        Ok(())
    })();
    if let Some(gamepads) = gamepads.as_mut() {
        gamepads.release(&stream);
    }
    stream.stop();
    result
}

struct Decoder {
    video: Arc<Mutex<Option<VideoDecoder>>>,
    failed: Arc<AtomicBool>,
}
impl MoonlightDecoder for Decoder {
    fn setup(&mut self, setup: VideoSetup) -> i32 {
        let codec = match setup.format {
            VideoFormat::H264 | VideoFormat::H264High8_444 => Some(Codec::H264),
            VideoFormat::H265 | VideoFormat::H265Rext8_444 => Some(Codec::H265),
            VideoFormat::Av1Main8 | VideoFormat::Av1High8_444 => Some(Codec::Av1),
            _ => None,
        };
        if (1..=3840).contains(&setup.width)
            && (1..=2160).contains(&setup.height)
            && let Some(codec) = codec
            && let Ok(decoder) = VideoDecoder::new(codec)
        {
            *lock(&self.video) = Some(decoder);
            return 0;
        }
        self.failed.store(true, Ordering::SeqCst);
        -1
    }
    fn start(&mut self) {}
    fn submit_decode_unit(&mut self, unit: VideoDecodeUnit<&[u8]>) -> DecodeResult {
        let length = unit
            .buffers
            .iter()
            .try_fold(0usize, |n, b| n.checked_add(b.data.len()))
            .filter(|n| *n <= 4 * 1024 * 1024);
        let Some(length) = length else {
            self.failed.store(true, Ordering::SeqCst);
            return DecodeResult::NeedIdr;
        };
        let mut bytes = Vec::with_capacity(length);
        for buffer in unit.buffers {
            bytes.extend_from_slice(buffer.data);
        }
        if lock(&self.video)
            .as_ref()
            .is_none_or(|decoder| decoder.push(&bytes).is_err())
        {
            self.failed.store(true, Ordering::SeqCst);
            DecodeResult::NeedIdr
        } else {
            DecodeResult::Ok
        }
    }
    fn stop(&mut self) {}
    fn supported_formats(&self) -> VideoFormats {
        supported_formats()
    }
}

fn supported_formats() -> VideoFormats {
    let mut formats = VideoFormats::empty();
    if Codec::H264.available() {
        formats |= VideoFormats::H264;
        // OpenH264 is a 4:2:0 fallback; advertise 4:4:4 only with the libav decoder.
        if gstreamer::ElementFactory::find("avdec_h264").is_some() {
            formats |= VideoFormats::H264_HIGH8_444;
        }
    }
    if Codec::H265.available() {
        formats |= VideoFormats::H265 | VideoFormats::H265_REXT8_444;
    }
    if Codec::Av1.available() {
        formats |= VideoFormats::AV1_MAIN8 | VideoFormats::AV1_HIGH8_444;
    }
    formats
}

struct RemoteAudio {
    enabled: bool,
    output: Option<crate::stream_audio::AudioOutput>,
    failed: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<ProtocolError>>>,
}
impl AudioDecoder for RemoteAudio {
    fn setup(&mut self, _: AudioConfig, config: OpusMultistreamConfig) -> i32 {
        if !self.enabled {
            return 0;
        }
        if config.channel_count > 8
            || config.samples_per_frame == 0
            || config.samples_per_frame > 5760
        {
            *lock(&self.failure) = Some(error(
                "The Moonlight host supplied an invalid audio frame configuration.",
            ));
            self.failed.store(true, Ordering::SeqCst);
            return -1;
        }
        match crate::stream_audio::AudioOutput::opus(
            config.sample_rate,
            config.channel_count,
            config.streams,
            config.coupled_streams,
            &config.mapping[..config.channel_count as usize],
        ) {
            Ok(output) => {
                self.output = Some(output);
                0
            }
            Err(error) => {
                *lock(&self.failure) = Some(error);
                self.failed.store(true, Ordering::SeqCst);
                -1
            }
        }
    }
    fn start(&mut self) {}
    fn stop(&mut self) {
        self.output = None;
    }
    fn decode_and_play_sample(&mut self, frame: AudioFrame<&[u8]>) {
        if let Some(output) = self.output.as_ref()
            && let Err(error) = output.push(frame.buffer)
        {
            *lock(&self.failure) = Some(error);
            self.failed.store(true, Ordering::SeqCst);
        }
    }
    fn config(&self) -> AudioConfig {
        AudioConfig::STEREO
    }
}
#[derive(Clone)]
struct Listener {
    failed: Arc<AtomicBool>,
    rumble: SyncSender<(u16, u16, u16)>,
    failure: Arc<Mutex<Option<ProtocolError>>>,
}
impl ConnectionListener for Listener {
    fn controller_rumble(&mut self, controller: u16, low: u16, high: u16) {
        let _ = self.rumble.try_send((controller, low, high));
    }
    fn connection_terminated(&mut self, _: i32) {
        self.failed.store(true, Ordering::SeqCst);
    }
}
impl ConnectionListenerC for Listener {
    fn stage_starting(&mut self, _: Stage) {}
    fn stage_complete(&mut self, _: Stage) {}
    fn stage_failed(&mut self, stage: Stage, code: i32) {
        lock(&self.failure).get_or_insert_with(|| {
            error(&format!(
                "Moonlight failed during {} ({code}). Check the host and its streaming ports.",
                stage.name()
            ))
        });
        self.failed.store(true, Ordering::SeqCst);
    }
    fn connection_started(&mut self) {}
    fn log_message(&mut self, _: &str) {}
    fn connection_status_update(&mut self, _: ConnectionStatus) {}
}

fn send_input(
    stream: &MoonlightStream,
    event: RemoteInput,
    size: (u32, u32),
    keyboard: &mut crate::desktop_scancode::KeyboardState,
    held: &mut BTreeSet<i16>,
) -> Result<(), ProtocolError> {
    let refused = || error("Moonlight could not deliver input; reconnect to restore input safely.");
    match event {
        RemoteInput::KeyDown(key) | RemoteInput::KeyUp(key) => {
            let Some(events) = keyboard.transition(key, matches!(event, RemoteInput::KeyDown(_)))
            else {
                let character = xkeysym::Keysym::new(key)
                    .key_char()
                    .filter(|character| !character.is_control())
                    .ok_or_else(refused)?;
                if matches!(event, RemoteInput::KeyDown(_)) {
                    stream
                        .send_text(character.encode_utf8(&mut [0; 4]))
                        .map_err(|_| refused())?;
                }
                return Ok(());
            };
            for (scan, extended, down) in events {
                let vk = virtual_key(scan, extended).ok_or_else(refused)?;
                if matches!(vk, 0xa0..=0xa5 | 0x5b | 0x5c) {
                    if down {
                        held.insert(vk);
                    } else {
                        held.remove(&vk);
                    }
                }
                let mut modifiers = KeyModifiers::empty();
                if held.iter().any(|k| matches!(k, 0xa0 | 0xa1)) {
                    modifiers |= KeyModifiers::SHIFT;
                }
                if held.iter().any(|k| matches!(k, 0xa2 | 0xa3)) {
                    modifiers |= KeyModifiers::CTRL;
                }
                if held.iter().any(|k| matches!(k, 0xa4 | 0xa5)) {
                    modifiers |= KeyModifiers::ALT;
                }
                if held.iter().any(|k| matches!(k, 0x5b | 0x5c)) {
                    modifiers |= KeyModifiers::META;
                }
                if extended {
                    modifiers |= KeyModifiers::EXTENDED;
                }
                stream
                    .send_keyboard_event(
                        KeyCode(vk),
                        if down { KeyAction::Down } else { KeyAction::Up },
                        modifiers,
                    )
                    .map_err(|_| refused())?;
            }
        }
        RemoteInput::PointerMove(x, y) => stream
            .send_mouse_position(
                x.clamp(0, size.0.saturating_sub(1) as i32) as i16,
                y.clamp(0, size.1.saturating_sub(1) as i32) as i16,
                size.0 as i16,
                size.1 as i16,
            )
            .map_err(|_| refused())?,
        RemoteInput::PointerButton { button, pressed } => {
            let mapped = match button {
                PointerButton::Left => Some(MouseButton::Left),
                PointerButton::Middle => Some(MouseButton::Middle),
                PointerButton::Right => Some(MouseButton::Right),
                _ => None,
            };
            if let Some(button) = mapped {
                stream
                    .send_mouse_button(
                        if pressed {
                            MouseButtonAction::Press
                        } else {
                            MouseButtonAction::Release
                        },
                        button,
                    )
                    .map_err(|_| refused())?;
            } else if pressed {
                match button {
                    PointerButton::WheelUp => stream.send_scroll(1),
                    PointerButton::WheelDown => stream.send_scroll(-1),
                    PointerButton::WheelLeft => stream.send_horizontal_scroll(-1),
                    PointerButton::WheelRight => stream.send_horizontal_scroll(1),
                    _ => unreachable!(),
                }
                .map_err(|_| refused())?;
            }
        }
    }
    Ok(())
}
fn virtual_key(scan: u8, extended: bool) -> Option<i16> {
    if let Some(key) = (b'a'..=b'z')
        .find(|key| crate::desktop_scancode::scan_code(u32::from(*key)) == Some((scan, extended)))
    {
        return Some(i16::from(key.to_ascii_uppercase()));
    }
    Some(match scan {
        2..=10 => i16::from(scan - 2 + b'1'),
        11 => 0x30,
        0x39 => 0x20,
        0x0e => 0x08,
        0x0f => 0x09,
        0x1c => 0x0d,
        1 => 0x1b,
        0x2a => 0xa0,
        0x36 => 0xa1,
        0x1d => {
            if extended {
                0xa3
            } else {
                0xa2
            }
        }
        0x38 => {
            if extended {
                0xa5
            } else {
                0xa4
            }
        }
        0x5b | 0x5c => i16::from(scan),
        0x3b..=0x44 => i16::from(scan - 0x3b + 0x70),
        0x57 => 0x7a,
        0x58 => 0x7b,
        0x3a => 0x14,
        0x45 => 0x90,
        0x46 => 0x91,
        0x37 if extended => 0x2c,
        0x47 => 0x24,
        0x4f => 0x23,
        0x4b => 0x25,
        0x48 => 0x26,
        0x4d => 0x27,
        0x50 => 0x28,
        0x49 => 0x21,
        0x51 => 0x22,
        0x53 => 0x2e,
        0x52 => 0x2d,
        0x0c => 0xbd,
        0x0d => 0xbb,
        0x1a => 0xdb,
        0x1b => 0xdd,
        0x27 => 0xba,
        0x28 => 0xde,
        0x29 => 0xc0,
        0x2b => 0xdc,
        0x33 => 0xbc,
        0x34 => 0xbe,
        0x35 => 0xbf,
        _ => return None,
    })
}
