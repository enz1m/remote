use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use base64::Engine;
use prost::Message;
use sodiumoxide::crypto::sign;

use super::{
    Control,
    network::Socket,
    rendezvous_wire::{self as wire, body::Body},
};
use crate::{model::ConnectionProfile, protocol::ProtocolError};

pub(crate) const ID_MODE: &str = "remote.rustdesk.id-mode";
pub(crate) const SERVER: &str = "remote.rustdesk.server";
pub(crate) const SERVER_KEY: &str = "remote.rustdesk.server-key";
pub(crate) const RELAY: &str = "remote.rustdesk.relay";
const OFFICIAL_SERVER: &str = "rs-ny.rustdesk.com:21116";
const OFFICIAL_KEY: &str = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";

pub(crate) fn is_id(profile: &ConnectionProfile) -> bool {
    profile
        .extra
        .get(ID_MODE)
        .is_some_and(|value| value == "true")
        || (!profile.host.is_empty() && profile.host.bytes().all(|byte| byte.is_ascii_digit()))
}

fn error(message: &str) -> ProtocolError {
    ProtocolError::Refused(message.into())
}

fn address(text: &str, default_port: u16) -> Result<String, ProtocolError> {
    if text.is_empty()
        || text.len() > 512
        || text
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control() || matches!(ch, '/' | '@' | '?' | '#'))
    {
        return Err(error("The RustDesk discovery or relay address is invalid."));
    }
    let parsed = if text.parse::<std::net::IpAddr>().is_ok() {
        format!(
            "{}:{default_port}",
            if text.contains(':') {
                format!("[{text}]")
            } else {
                text.into()
            }
        )
    } else if text.contains(':') {
        text.into()
    } else {
        format!("{text}:{default_port}")
    };
    let port = parsed
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok());
    if port.is_none_or(|port| port == 0) {
        return Err(error("The RustDesk server port is invalid."));
    }
    Ok(parsed)
}

fn connect(address: &str, control: &Control) -> Result<Socket, ProtocolError> {
    if control.cancelled.load(Ordering::SeqCst) {
        return Err(error("RustDesk discovery was cancelled."));
    }
    let tcp = if let Some(route) = control.route() {
        let (host, port) = address
            .rsplit_once(':')
            .ok_or_else(|| error("The RustDesk route address is invalid."))?;
        route.connect(
            host.trim_matches(['[', ']']),
            port.parse()
                .map_err(|_| error("The RustDesk route port is invalid."))?,
        )
    } else {
        let endpoint = address
            .to_socket_addrs()
            .map_err(|_| error("The RustDesk server could not be resolved."))?
            .next()
            .ok_or_else(|| error("The RustDesk server has no address."))?;
        TcpStream::connect_timeout(&endpoint, Duration::from_secs(5))
    }
    .map_err(|_| {
        ProtocolError::Transport(
            "The RustDesk discovery or relay server could not be reached.".into(),
        )
    })?;
    Socket::new(tcp, control)
}

fn response(socket: &mut Socket, control: &Control) -> Result<Body, ProtocolError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut packets = 0;
    while Instant::now() < deadline && !control.cancelled.load(Ordering::SeqCst) {
        let Some(bytes) = socket.next_raw()? else {
            continue;
        };
        packets += 1;
        if bytes.len() > 16384 || packets > 32 {
            return Err(error("The RustDesk discovery response exceeds its limits."));
        }
        if bytes.is_empty() {
            continue;
        }
        match wire::Packet::decode(bytes.as_slice())
            .map_err(|_| error("The RustDesk discovery response is invalid."))?
            .body
        {
            Some(Body::KeyExchange(_)) | None => continue,
            Some(body) => return Ok(body),
        }
    }
    Err(ProtocolError::Transport(
        "RustDesk discovery was cancelled or timed out.".into(),
    ))
}

fn verified_peer(
    signed: &[u8],
    root: &sign::PublicKey,
    id: &str,
) -> Result<Vec<u8>, ProtocolError> {
    if signed.len() > 4096 {
        return Err(error("The RustDesk rendezvous identity exceeds its limit."));
    }
    let decoded = sign::verify(signed, root)
        .map_err(|_| error("The RustDesk server key did not verify the peer identity."))?;
    let identity = super::wire::Identity::decode(decoded.as_slice())
        .map_err(|_| error("The RustDesk rendezvous identity is invalid."))?;
    if identity.id != id || identity.key.len() != 32 {
        return Err(error(
            "The RustDesk rendezvous identity names a different peer.",
        ));
    }
    Ok(identity.key)
}

pub(super) fn discover(
    profile: &ConnectionProfile,
    control: &Control,
) -> Result<(Socket, Vec<u8>), ProtocolError> {
    if profile.host.len() > 64
        || profile.host.is_empty()
        || !profile
            .host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(error(
            "Enter a RustDesk ID containing letters, digits, hyphens or underscores.",
        ));
    }
    let configured = profile
        .extra
        .get(SERVER)
        .filter(|server| !server.trim().is_empty());
    let server = address(
        configured.map_or(OFFICIAL_SERVER, |server| server.trim()),
        21116,
    )?;
    let key = profile
        .extra
        .get(SERVER_KEY)
        .filter(|key| !key.trim().is_empty())
        .map(String::as_str)
        .or(if configured.is_none() {
            Some(OFFICIAL_KEY)
        } else {
            None
        })
        .ok_or_else(|| {
            error("A custom RustDesk ID server requires its trusted Ed25519 public key.")
        })?;
    let root = base64::engine::general_purpose::STANDARD
        .decode(key.trim())
        .ok()
        .and_then(|bytes| sign::PublicKey::from_slice(&bytes))
        .ok_or_else(|| error("The RustDesk server key must contain 32 Base64-encoded bytes."))?;
    let mut socket = connect(&server, control)?;
    socket.send_raw(
        wire::Packet {
            body: Some(Body::Punch(wire::Punch {
                id: profile.host.clone(),
                nat_type: 2,
                key: key.trim().into(),
                version: "1.5.1".into(),
                force_relay: true,
            })),
        }
        .encode_to_vec(),
    )?;
    let (uuid, advertised, signed) = match response(&mut socket, control)? {
        Body::Relay(relay) => {
            if !relay.refusal.is_empty() {
                return Err(error("The RustDesk server refused relay access."));
            }
            (relay.uuid, relay.server, relay.key)
        }
        Body::Punched(punch) => {
            if punch.address.is_empty() || !punch.reason.is_empty() {
                return Err(error(
                    "The RustDesk ID is offline, unavailable or refused by the server.",
                ));
            }
            let _ = verified_peer(&punch.key, &root, &profile.host)?;
            let uuid = uuid::Uuid::new_v4().to_string();
            socket = connect(&server, control)?;
            socket.send_raw(
                wire::Packet {
                    body: Some(Body::Request(wire::Request {
                        id: profile.host.clone(),
                        uuid: uuid.clone(),
                        relay: punch.relay.clone(),
                        secure: true,
                        key: String::new(),
                    })),
                }
                .encode_to_vec(),
            )?;
            let Body::Relay(reply) = response(&mut socket, control)? else {
                return Err(error(
                    "The RustDesk server did not grant a relay connection.",
                ));
            };
            if !reply.refusal.is_empty() {
                return Err(error("The RustDesk server refused relay access."));
            }
            (
                uuid,
                if reply.server.is_empty() {
                    punch.relay
                } else {
                    reply.server
                },
                punch.key,
            )
        }
        _ => {
            return Err(error(
                "The RustDesk server returned an unexpected discovery result.",
            ));
        }
    };
    if uuid.is_empty() || uuid.len() > 128 || uuid.chars().any(char::is_control) {
        return Err(error("The RustDesk relay session identifier is invalid."));
    }
    let peer_key = verified_peer(&signed, &root, &profile.host)?;
    if let Some(expected) = profile
        .extra
        .get(super::PEER_KEY)
        .filter(|key| !key.trim().is_empty())
    {
        let expected = base64::engine::general_purpose::STANDARD
            .decode(expected.trim())
            .map_err(|_| error("The trusted RustDesk peer key is invalid."))?;
        if expected != peer_key {
            return Err(error(
                "The RustDesk peer key changed from its pinned identity.",
            ));
        }
    }
    let relay = profile
        .extra
        .get(RELAY)
        .filter(|relay| !relay.trim().is_empty())
        .map_or(advertised.as_str(), |relay| relay.trim());
    let mut relay = connect(&address(relay, 21117)?, control)?;
    relay.send_raw(
        wire::Packet {
            body: Some(Body::Request(wire::Request {
                id: profile.host.clone(),
                uuid,
                key: key.trim().into(),
                ..Default::default()
            })),
        }
        .encode_to_vec(),
    )?;
    Ok((relay, peer_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_identity_is_bound_to_server_key_peer_id_and_signature_before_authentication() {
        sodiumoxide::init().unwrap();
        let (root, secret) = sign::gen_keypair();
        let (other, _) = sign::gen_keypair();
        let signed = sign::sign(
            &super::super::wire::Identity {
                id: "123456789".into(),
                key: vec![9; 32],
                version: 1,
            }
            .encode_to_vec(),
            &secret,
        );
        assert_eq!(verified_peer(&signed, &root, "123456789").unwrap(), [9; 32]);
        assert!(verified_peer(&signed, &root, "987654321").is_err());
        assert!(verified_peer(&signed, &other, "123456789").is_err());
        let mut forged = signed;
        forged[0] ^= 1;
        assert!(verified_peer(&forged, &root, "123456789").is_err());
        for address in [
            "",
            "https://server",
            "user@server",
            "server:0",
            "server\n:21116",
        ] {
            assert!(self::address(address, 21116).is_err());
        }
    }
}
