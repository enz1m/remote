use std::collections::BTreeSet;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, SyncSender};
use std::time::{Duration, Instant};

use base64::Engine;
use sha2::{Digest, Sha256};

use super::{
    Control, PEER_KEY,
    network::Socket,
    wire::{self, body::Body},
};
use crate::model::ConnectionProfile;
use crate::protocol::{PointerButton, ProtocolError, RemoteInput};
use crate::state_machine::SessionEvent;
use crate::stream_video::{Codec, VideoDecoder};

fn refused(message: &str) -> ProtocolError {
    ProtocolError::Refused(message.into())
}

pub(super) fn run(
    profile: &ConnectionProfile,
    password: &str,
    control: &Arc<Control>,
    inputs: Receiver<Vec<RemoteInput>>,
    ready: SyncSender<Result<(), ProtocolError>>,
) {
    let result = drive(profile, password, control, inputs, &ready);
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
    let key = profile
        .extra
        .get(PEER_KEY)
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .ok()
                .filter(|bytes| bytes.len() == 32)
                .ok_or_else(|| {
                    refused("The trusted RustDesk peer key must be 32 Base64-encoded bytes.")
                })
        })
        .transpose()?;
    sodiumoxide::init().map_err(|_| refused("RustDesk cryptography could not initialize."))?;
    let by_id = super::rendezvous::is_id(profile);
    let (mut socket, key, default_peer_id) = if by_id {
        let (socket, key) = super::rendezvous::discover(profile, control)?;
        (socket, Some(key), profile.host.clone())
    } else {
        let (tcp, peer_address) = if let Some(route) = control.route() {
            let port = crate::quick_connect::effective_port(profile.port, profile.protocol);
            let tcp = route
                .connect(&profile.host, port)
                .map_err(|_| refused("The RustDesk SSH destination could not be reached."))?;
            (tcp, format!("{}:{port}", profile.host))
        } else {
            let addresses: Vec<_> = (
                profile.host.as_str(),
                crate::quick_connect::effective_port(profile.port, profile.protocol),
            )
                .to_socket_addrs()
                .map_err(|_| refused("The RustDesk host address could not be resolved."))?
                .collect();
            let (endpoint, exposure) = crate::rfb::policy::classify(&addresses)
                .ok_or_else(|| refused("The RustDesk host has no address."))?;
            let plaintext = key.is_none();
            if plaintext
                && exposure == crate::rfb::policy::Exposure::Network
                && profile.extra.get(super::ACK_KEY).map(String::as_str)
                    != Some(crate::rfb::policy::ACK_VALUE)
            {
                return Err(refused(
                    "RustDesk direct access sends screen and input unencrypted. Explicitly allow unencrypted RustDesk to this host in connection settings, or use a protected endpoint with its trusted peer key.",
                ));
            }
            if control.cancelled.load(Ordering::SeqCst) {
                return Err(refused("RustDesk connection was cancelled."));
            }
            let tcp =
                TcpStream::connect_timeout(&endpoint, Duration::from_secs(5)).map_err(|_| {
                    ProtocolError::Transport(
                        "The RustDesk direct endpoint could not be reached.".into(),
                    )
                })?;
            (tcp, endpoint.to_string())
        };
        let socket = Socket::new(tcp, control)?;
        (socket, key, peer_address)
    };
    let deadline = Instant::now() + Duration::from_secs(25);
    let first = wait_packet(&mut socket, control, deadline)?;
    let (peer_id, challenge) = if let Some(key) = key {
        let Some(Body::Signed(signed)) = first.body else {
            return Err(refused(
                "The RustDesk peer did not provide a signed identity. Refusing plaintext downgrade.",
            ));
        };
        if signed.id.len() > 4096 {
            return Err(refused("The RustDesk signed identity is too large."));
        }
        let identity = socket.authenticate(&signed.id, &key)?;
        let expected_id = if by_id {
            &profile.host
        } else {
            &profile.username
        };
        if !expected_id.is_empty() && *expected_id != identity.id {
            return Err(refused(
                "The RustDesk host identity does not match the expected peer ID.",
            ));
        }
        let packet = wait_packet(&mut socket, control, deadline)?;
        let Some(Body::Challenge(challenge)) = packet.body else {
            return Err(refused(
                "The RustDesk peer did not issue an authentication challenge.",
            ));
        };
        (identity.id, challenge)
    } else {
        let Some(Body::Challenge(challenge)) = first.body else {
            return Err(refused(
                "The RustDesk direct peer did not issue an authentication challenge.",
            ));
        };
        let id = if profile.username.is_empty() {
            default_peer_id
        } else {
            profile.username.clone()
        };
        (id, challenge)
    };
    if challenge.salt.len() > 256 || challenge.challenge.len() > 256 {
        return Err(refused(
            "The RustDesk authentication challenge exceeds its limits.",
        ));
    }
    let mut digest = Sha256::new();
    digest.update(password.as_bytes());
    digest.update(challenge.salt.as_bytes());
    let mut response = Sha256::new();
    response.update(digest.finalize());
    response.update(challenge.challenge.as_bytes());
    socket.send(Body::Login(wire::Login {
        username: peer_id,
        password: response.finalize().to_vec(),
        my_id: profile.id.to_string(),
        my_name: "enzUI Remote".into(),
        options: Some(wire::Options {
            quality: match profile.quality {
                0..=2 => 2,
                3..=6 => 3,
                _ => 4,
            },
            disable_audio: if crate::stream_audio::enabled(profile) {
                1
            } else {
                2
            },
            disable_clipboard: if profile.disable_clipboard || profile.view_only {
                2
            } else {
                1
            },
            enable_file_transfer: 1,
            decoding: Some(wire::Decoding {
                vp9: i32::from(Codec::Vp9.available()),
                h264: i32::from(Codec::H264.available()),
                h265: i32::from(Codec::H265.available()),
                vp8: i32::from(Codec::Vp8.available()),
                av1: i32::from(Codec::Av1.available()),
                prefer: 0,
            }),
            fps: 30,
            disable_keyboard: if profile.view_only { 2 } else { 1 },
            disable_camera: 2,
        }),
        video_ack_required: false,
        session_id: profile.id.as_u128() as u64,
        version: "1.5.1".into(),
        platform: "Linux".into(),
    }))?;
    let mut audio = None::<crate::stream_audio::AudioOutput>;
    let mut keyboard_allowed = true;
    let mut audio_allowed = true;
    let mut peer = None;
    let mut decoder: Option<(Codec, VideoDecoder)> = None;
    let mut admitted = false;
    let mut modifiers = BTreeSet::new();
    let mut clipboard_enabled = !profile.disable_clipboard && !profile.view_only;
    while !control.cancelled.load(Ordering::SeqCst) {
        if peer.is_some() {
            let enabled = control.clipboard.sharing(&control.input_capture);
            if enabled != clipboard_enabled {
                socket.send(Body::Misc(wire::Misc {
                    value: Some(wire::misc::Value::Options(wire::Options {
                        disable_clipboard: if enabled { 1 } else { 2 },
                        ..Default::default()
                    })),
                }))?;
                clipboard_enabled = enabled;
            }
            if let Some(text) = control.clipboard.take(&control.input_capture) {
                socket.send(Body::Clipboard(wire::Clipboard {
                    compress: false,
                    content: text.into_bytes(),
                    format: 0,
                }))?;
            }
        }
        if !admitted && Instant::now() >= deadline {
            return Err(refused(
                "RustDesk did not deliver a desktop before the connection deadline.",
            ));
        }
        if let Some(packet) = socket.next()? {
            match packet.body {
                Some(Body::Clipboard(clipboard)) if peer.is_some() => {
                    receive_clipboard(control, clipboard)?
                }
                Some(Body::Clipboards(clipboards)) if peer.is_some() => {
                    if clipboards.clipboards.len() > 16 {
                        return Err(refused(
                            "The RustDesk clipboard format list exceeds its limit.",
                        ));
                    }
                    if let Some(text) = clipboards.clipboards.into_iter().find(|c| c.format == 0) {
                        receive_clipboard(control, text)?;
                    }
                }
                Some(Body::Accepted(wire::Accepted {
                    result: Some(wire::accepted::Result::Error(_)),
                })) => {
                    return Err(ProtocolError::Auth(
                        "RustDesk authentication or desktop access was refused.".into(),
                    ));
                }
                Some(Body::Accepted(wire::Accepted {
                    result: Some(wire::accepted::Result::Peer(info)),
                })) => {
                    if info.displays.len() > 16 {
                        return Err(refused("The RustDesk display list exceeds its limit."));
                    }
                    let index = usize::try_from(info.current_display)
                        .map_err(|_| refused("The RustDesk selected display is invalid."))?;
                    let display = info
                        .displays
                        .get(index)
                        .ok_or_else(|| refused("The RustDesk peer has no selected desktop."))?;
                    validate_display(display)?;
                    peer = Some((info.current_display, display.clone()));
                    control.clipboard.set_available(true);
                }
                Some(Body::Misc(wire::Misc {
                    value: Some(wire::misc::Value::Audio(format)),
                })) => {
                    if peer.is_none() {
                        return Err(refused(
                            "RustDesk audio arrived before desktop authorization.",
                        ));
                    }
                    if audio_allowed && crate::stream_audio::enabled(profile) {
                        if !(1..=2).contains(&format.channels) {
                            return Err(refused("The RustDesk audio channel count is invalid."));
                        }
                        audio = Some(crate::stream_audio::AudioOutput::opus(
                            format.sample_rate,
                            format.channels,
                            1,
                            format.channels - 1,
                            &[0, 1][..format.channels as usize],
                        )?);
                    }
                }
                Some(Body::Audio(frame)) => {
                    if peer.is_none() {
                        return Err(refused(
                            "RustDesk audio arrived before desktop authorization.",
                        ));
                    }
                    if let Some(audio) = audio.as_ref() {
                        audio.push(&frame.data)?;
                    }
                }
                Some(Body::Misc(wire::Misc {
                    value: Some(wire::misc::Value::Permission(permission)),
                })) => {
                    if permission.permission == 0 {
                        keyboard_allowed = permission.enabled;
                        // A denied input channel cannot reliably acknowledge held-key releases.
                        if !keyboard_allowed && !profile.view_only {
                            return Err(refused(
                                "The RustDesk host revoked keyboard access. The session was closed to release held input; reconnect in view-only mode.",
                            ));
                        }
                    }
                    if permission.permission == 3 {
                        audio_allowed = permission.enabled;
                        if !audio_allowed {
                            audio = None;
                        }
                    }
                    if permission.permission == 2 {
                        control.clipboard.set_peer_allowed(permission.enabled);
                    }
                }
                Some(Body::Misc(wire::Misc {
                    value: Some(wire::misc::Value::Closed(_)),
                })) => {
                    return Err(refused("The RustDesk host closed the session."));
                }
                Some(Body::Video(video)) => {
                    let (index, _) = peer.as_ref().ok_or_else(|| {
                        refused("RustDesk video arrived before desktop authorization.")
                    })?;
                    if video.display != *index {
                        return Err(refused("RustDesk changed to an unselected display."));
                    }
                    let (codec, frames) = match video.format {
                        Some(wire::video::Format::Vp9(frames)) => (Codec::Vp9, frames),
                        Some(wire::video::Format::H264(frames)) => (Codec::H264, frames),
                        Some(wire::video::Format::Vp8(frames)) => (Codec::Vp8, frames),
                        Some(wire::video::Format::H265(frames)) => (Codec::H265, frames),
                        Some(wire::video::Format::Av1(frames)) => (Codec::Av1, frames),
                        _ => {
                            return Err(refused(
                                "The RustDesk peer selected an unsupported codec.",
                            ));
                        }
                    };
                    if frames.frames.is_empty() || frames.frames.len() > 8 {
                        return Err(refused("The RustDesk video batch exceeds its limits."));
                    }
                    if decoder
                        .as_ref()
                        .is_some_and(|(current, _)| *current != codec)
                    {
                        decoder = None;
                    }
                    if decoder.is_none() {
                        decoder = Some((codec, VideoDecoder::new(codec)?));
                    }
                    for frame in frames.frames {
                        decoder
                            .as_ref()
                            .expect("decoder initialized")
                            .1
                            .push(&frame.data)?;
                    }
                }
                Some(Body::Delay(delay)) if !delay.from_client => {
                    socket.send(Body::Delay(delay))?
                }
                _ => {}
            }
        }
        if let Some((_, decoder)) = decoder.as_mut()
            && decoder.publish(control)?.is_some()
            && !admitted
        {
            admitted = true;
            control.active.store(true, Ordering::SeqCst);
            ready
                .send(Ok(()))
                .map_err(|_| refused("The RustDesk dial was retired."))?;
        }
        for _ in 0..8 {
            let Ok(batch) = inputs.try_recv() else {
                break;
            };
            if profile.view_only || !keyboard_allowed {
                return Err(refused("The RustDesk session is read-only."));
            }
            let (_, display) = peer
                .as_ref()
                .ok_or_else(|| refused("RustDesk has no authorized display."))?;
            for input in batch {
                socket.send(input_packet(input, display, &mut modifiers)?)?;
            }
        }
    }
    Ok(())
}

fn wait_packet(
    socket: &mut Socket,
    control: &Control,
    deadline: Instant,
) -> Result<wire::Packet, ProtocolError> {
    while !control.cancelled.load(Ordering::SeqCst) && Instant::now() < deadline {
        if let Some(packet) = socket.next()?
            && packet.body.is_some()
        {
            return Ok(packet);
        }
    }
    Err(refused(
        "The RustDesk handshake was cancelled or exceeded its deadline.",
    ))
}

fn receive_clipboard(control: &Control, clipboard: wire::Clipboard) -> Result<(), ProtocolError> {
    if clipboard.format != 0 || !control.clipboard.sharing(&control.input_capture) {
        return Ok(());
    }
    if let Some(text) = decode_clipboard(clipboard)? {
        control.receive_clipboard(&text);
    }
    Ok(())
}

fn decode_clipboard(clipboard: wire::Clipboard) -> Result<Option<String>, ProtocolError> {
    if clipboard.format != 0 {
        return Ok(None);
    }
    let bytes = if clipboard.compress {
        zstd::bulk::decompress(&clipboard.content, crate::native_clipboard::LIMIT)
            .map_err(|_| refused("Invalid or oversized RustDesk clipboard text."))?
    } else {
        clipboard.content
    };
    if bytes.len() > crate::native_clipboard::LIMIT {
        return Err(refused("RustDesk clipboard text exceeds its limit."));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| refused("Invalid UTF-8 RustDesk clipboard text."))?;
    crate::native_clipboard::normalize(text)
        .map(Some)
        .map_err(ProtocolError::Refused)
}

fn validate_display(display: &wire::Display) -> Result<(), ProtocolError> {
    if !(1..=3840).contains(&display.width)
        || !(1..=2160).contains(&display.height)
        || display.x.abs_diff(0) > 32767
        || display.y.abs_diff(0) > 32767
    {
        return Err(refused(
            "The RustDesk display geometry exceeds the supported limits.",
        ));
    }
    Ok(())
}

fn input_packet(
    input: RemoteInput,
    display: &wire::Display,
    modifiers: &mut BTreeSet<i32>,
) -> Result<Body, ProtocolError> {
    match input {
        RemoteInput::KeyDown(key) | RemoteInput::KeyUp(key) => {
            let down = matches!(input, RemoteInput::KeyDown(_));
            let value = key_value(key)
                .ok_or_else(|| refused("This key is not supported by RustDesk's keyboard mode."))?;
            if let wire::key::Value::Control(key) = value
                && matches!(key, 1 | 4 | 23 | 29 | 64 | 73 | 74 | 75)
            {
                if down {
                    modifiers.insert(key);
                } else {
                    modifiers.remove(&key);
                }
            }
            Ok(Body::Key(wire::Key {
                down,
                value: Some(value),
                modifiers: modifiers.iter().copied().collect(),
            }))
        }
        RemoteInput::PointerMove(x, y) => Ok(Body::Mouse(wire::Mouse {
            mask: 0,
            x: display.x + x.clamp(0, display.width - 1),
            y: display.y + y.clamp(0, display.height - 1),
            modifiers: modifiers.iter().copied().collect(),
        })),
        RemoteInput::PointerButton { button, pressed } => {
            let (mask, x, y) = match button {
                PointerButton::Left => ((1 << 3) | if pressed { 1 } else { 2 }, 0, 0),
                PointerButton::Right => ((2 << 3) | if pressed { 1 } else { 2 }, 0, 0),
                PointerButton::Middle => ((4 << 3) | if pressed { 1 } else { 2 }, 0, 0),
                PointerButton::WheelUp => (3, 0, if pressed { -1 } else { 0 }),
                PointerButton::WheelDown => (3, 0, if pressed { 1 } else { 0 }),
                PointerButton::WheelLeft => (3, if pressed { -1 } else { 0 }, 0),
                PointerButton::WheelRight => (3, if pressed { 1 } else { 0 }, 0),
            };
            Ok(Body::Mouse(wire::Mouse {
                mask,
                x,
                y,
                modifiers: modifiers.iter().copied().collect(),
            }))
        }
    }
}

fn key_value(key: u32) -> Option<wire::key::Value> {
    let control = match key {
        0xffe9 => 1,
        0xff08 => 2,
        0xffe5 => 3,
        0xffe3 => 4,
        0xffff => 5,
        0xff54 => 6,
        0xff57 => 7,
        0xff1b => 8,
        0xffbe => 9,
        0xffc7 => 10,
        0xffc8 => 11,
        0xffc9 => 12,
        0xffbf..=0xffc6 => (key - 0xffbf + 13) as i32,
        0xff50 => 21,
        0xff51 => 22,
        0xffeb => 23,
        0xff56 => 25,
        0xff55 => 26,
        0xff0d => 27,
        0xff53 => 28,
        0xffe1 => 29,
        0x20 => 30,
        0xff09 => 31,
        0xff52 => 32,
        0xff61 => 57,
        0xff63 => 58,
        0xff14 => 62,
        0xff7f => 63,
        0xffec => 64,
        0xffe2 => 73,
        0xffe4 => 74,
        0xffea => 75,
        _ => {
            let scalar = if key & 0xff000000 == 0x01000000 {
                key & 0xffffff
            } else {
                key
            };
            return char::from_u32(scalar)
                .filter(|c| !c.is_control())
                .map(|_| wire::key::Value::Character(scalar));
        }
    };
    Some(wire::key::Value::Control(control))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RemoteProtocol;

    #[test]
    fn compressed_clipboard_is_bounded_utf8_and_rich_formats_are_not_treated_as_text() {
        let packet = |bytes, compress, format| wire::Clipboard {
            content: bytes,
            compress,
            format,
        };
        let text = "café\r\n雪";
        assert_eq!(
            decode_clipboard(packet(
                zstd::bulk::compress(text.as_bytes(), 1).unwrap(),
                true,
                0
            ))
            .unwrap()
            .as_deref(),
            Some("café\n雪")
        );
        assert!(
            decode_clipboard(packet(
                zstd::bulk::compress(&vec![b'x'; crate::native_clipboard::LIMIT + 1], 1).unwrap(),
                true,
                0
            ))
            .is_err()
        );
        assert!(decode_clipboard(packet(vec![0xff], false, 0)).is_err());
        assert!(
            decode_clipboard(packet(vec![0xff], false, 22))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn direct_network_access_requires_its_own_acknowledgement_before_dialling() {
        let mut profile =
            ConnectionProfile::new("fixture", crate::model::Protocol::RustDesk, "203.0.113.1");
        profile.extra.insert(
            crate::rfb::policy::ACK_KEY.into(),
            crate::rfb::policy::ACK_VALUE.into(),
        );
        let error = super::super::RustDeskBackend::default()
            .connect(&profile, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unencrypted RustDesk"), "{error}");
        profile.extra.insert(PEER_KEY.into(), "invalid key".into());
        let error = super::super::RustDeskBackend::default()
            .connect(&profile, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("32 Base64-encoded bytes"), "{error}");
    }
}
