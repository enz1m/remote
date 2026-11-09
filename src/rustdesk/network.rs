use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use prost::Message;
use sodiumoxide::crypto::{box_, generichash, secretbox, sign};

use super::wire::{self, body::Body};
use crate::desktop_worker::Control;
use crate::protocol::ProtocolError;

const MAX_PACKET: usize = 4 * 1024 * 1024;

pub(super) struct Socket {
    pub tcp: TcpStream,
    incoming: Vec<u8>,
    send_key: Option<secretbox::Key>,
    receive_key: Option<secretbox::Key>,
    send_counter: u64,
    receive_counter: u64,
    partial_since: Option<Instant>,
}

fn error(text: &str) -> ProtocolError {
    ProtocolError::Refused(text.into())
}

impl Socket {
    pub(super) fn new(tcp: TcpStream, control: &Control) -> Result<Self, ProtocolError> {
        control
            .adopt(&tcp)
            .map_err(|_| error("RustDesk connection was cancelled."))?;
        tcp.set_read_timeout(Some(Duration::from_millis(4)))
            .map_err(|_| error("RustDesk socket setup failed."))?;
        tcp.set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| error("RustDesk socket setup failed."))?;
        tcp.set_nodelay(true)
            .map_err(|_| error("RustDesk socket setup failed."))?;
        Ok(Self {
            tcp,
            incoming: Vec::new(),
            send_key: None,
            receive_key: None,
            send_counter: 0,
            receive_counter: 0,
            partial_since: None,
        })
    }

    pub(super) fn send(&mut self, body: Body) -> Result<(), ProtocolError> {
        self.send_raw(wire::Packet { body: Some(body) }.encode_to_vec())
    }

    pub(super) fn send_raw(&mut self, mut bytes: Vec<u8>) -> Result<(), ProtocolError> {
        if let Some(key) = &self.send_key {
            self.send_counter = self
                .send_counter
                .checked_add(1)
                .ok_or_else(|| error("RustDesk transmit counter exhausted."))?;
            bytes = secretbox::seal(&bytes, &nonce(self.send_counter), key);
        }
        if bytes.len() > MAX_PACKET {
            return Err(error("RustDesk packet is too large."));
        }
        let width = header_width(bytes.len());
        let header = (((bytes.len() as u32) << 2) | (width as u32 - 1)).to_le_bytes();
        self.tcp
            .write_all(&header[..width])
            .and_then(|_| self.tcp.write_all(&bytes))
            .map_err(|_| {
                ProtocolError::Transport(
                    "RustDesk could not deliver input; the connection was closed.".into(),
                )
            })
    }

    pub(super) fn next(&mut self) -> Result<Option<wire::Packet>, ProtocolError> {
        self.next_raw()?.map(decode_packet).transpose()
    }

    pub(super) fn next_raw(&mut self) -> Result<Option<Vec<u8>>, ProtocolError> {
        if let Some(packet) = self.extract_raw()? {
            return Ok(Some(packet));
        }
        let mut bytes = [0; 8192];
        match self.tcp.read(&mut bytes) {
            Ok(0) => {
                return Err(ProtocolError::Transport(
                    "The RustDesk peer disconnected.".into(),
                ));
            }
            Ok(n) => {
                if self.incoming.len().saturating_add(n) > MAX_PACKET + 8196 {
                    return Err(error("RustDesk receive queue exceeded its limit."));
                }
                self.incoming.extend_from_slice(&bytes[..n]);
                self.partial_since.get_or_insert_with(Instant::now);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => {
                return Err(ProtocolError::Transport(
                    "The RustDesk peer connection failed.".into(),
                ));
            }
        }
        if self
            .partial_since
            .is_some_and(|t| t.elapsed() > Duration::from_secs(10))
        {
            return Err(error("A RustDesk packet exceeded its receive deadline."));
        }
        self.extract_raw()
    }

    #[cfg(test)]
    fn extract(&mut self) -> Result<Option<wire::Packet>, ProtocolError> {
        self.extract_raw()?.map(decode_packet).transpose()
    }

    fn extract_raw(&mut self) -> Result<Option<Vec<u8>>, ProtocolError> {
        let Some(first) = self.incoming.first() else {
            return Ok(None);
        };
        let width = usize::from(first & 3) + 1;
        if self.incoming.len() < width {
            return Ok(None);
        }
        let mut header = [0; 4];
        header[..width].copy_from_slice(&self.incoming[..width]);
        let length = (u32::from_le_bytes(header) >> 2) as usize;
        if length > MAX_PACKET {
            return Err(error("The RustDesk frame header exceeds its byte limit."));
        }
        if self.incoming.len() < width + length {
            return Ok(None);
        }
        let mut bytes = self.incoming[width..width + length].to_vec();
        self.incoming.drain(..width + length);
        self.partial_since = (!self.incoming.is_empty()).then(Instant::now);
        if length <= 1 {
            return Ok(Some(Vec::new()));
        }
        if let Some(key) = &self.receive_key {
            self.receive_counter = self
                .receive_counter
                .checked_add(1)
                .ok_or_else(|| error("RustDesk receive counter exhausted."))?;
            bytes = secretbox::open(&bytes, &nonce(self.receive_counter), key)
                .map_err(|_| error("RustDesk packet authentication failed."))?;
        }
        Ok(Some(bytes))
    }

    pub(super) fn authenticate(
        &mut self,
        signed: &[u8],
        peer_key: &[u8],
    ) -> Result<wire::Identity, ProtocolError> {
        let key = sign::PublicKey::from_slice(peer_key)
            .ok_or_else(|| error("RustDesk requires a 32-byte trusted peer public key."))?;
        let message = sign::verify(signed, &key)
            .map_err(|_| error("The RustDesk peer key did not verify its identity."))?;
        let identity = wire::Identity::decode(message.as_slice())
            .map_err(|_| error("The RustDesk signed identity is invalid."))?;
        if identity.version < 1 {
            return Err(error(
                "This RustDesk peer lacks version-1 directional session encryption. Update its RustDesk host.",
            ));
        }
        let peer = box_::PublicKey::from_slice(&identity.key)
            .ok_or_else(|| error("The RustDesk peer sent an invalid exchange key."))?;
        let (public, private) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let sealed = box_::seal(&key.0, &box_::Nonce([0; 24]), &peer, &private);
        self.send(Body::Exchange(wire::Exchange {
            asymmetric_value: public.0.to_vec(),
            symmetric_value: sealed,
            version: 1,
        }))?;
        self.send_key = Some(direction_key(
            &key,
            1,
            identity.version,
            &public.0,
            &peer.0,
        )?);
        self.receive_key = Some(direction_key(
            &key,
            2,
            identity.version,
            &public.0,
            &peer.0,
        )?);
        Ok(identity)
    }
}

fn decode_packet(bytes: Vec<u8>) -> Result<wire::Packet, ProtocolError> {
    if bytes.len() <= 1 {
        return Ok(wire::Packet { body: None });
    }
    wire::Packet::decode(bytes.as_slice())
        .map_err(|_| error("The RustDesk peer sent an invalid protocol message."))
}

fn nonce(counter: u64) -> secretbox::Nonce {
    let mut bytes = [0; 24];
    bytes[..8].copy_from_slice(&counter.to_le_bytes());
    secretbox::Nonce(bytes)
}
fn header_width(n: usize) -> usize {
    if n <= 0x3f {
        1
    } else if n <= 0x3fff {
        2
    } else if n <= 0x3fffff {
        3
    } else {
        4
    }
}
fn direction_key(
    key: &secretbox::Key,
    direction: u8,
    advertised: u32,
    initiator: &[u8; 32],
    responder: &[u8; 32],
) -> Result<secretbox::Key, ProtocolError> {
    let mut hash = generichash::State::new(Some(32), Some(&key.0))
        .map_err(|_| error("RustDesk key derivation failed."))?;
    for bytes in [
        b"rdkx-spl".as_slice(),
        &[direction],
        &advertised.to_le_bytes(),
        &1u32.to_le_bytes(),
        initiator,
        responder,
    ] {
        hash.update(bytes)
            .map_err(|_| error("RustDesk key derivation failed."))?;
    }
    let hash = hash
        .finalize()
        .map_err(|_| error("RustDesk key derivation failed."))?;
    secretbox::Key::from_slice(hash.as_ref())
        .ok_or_else(|| error("RustDesk key derivation failed."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Mutex, atomic::AtomicBool};

    fn sockets() -> (Socket, TcpStream) {
        let (events, _) = crate::protocol::SessionStream::channel();
        let control = Control {
            route: std::sync::Mutex::new(None),
            cancelled: AtomicBool::new(false),
            input_failed: AtomicBool::new(false),
            active: AtomicBool::new(false),
            input_capture: std::sync::Arc::new(AtomicBool::new(false)),
            clipboard: crate::native_clipboard::Clipboard::new(false),
            requested_size: std::sync::atomic::AtomicU64::new(0),
            dynamic_resize: std::sync::atomic::AtomicBool::new(false),
            resize_available: std::sync::atomic::AtomicBool::new(false),
            socket: Mutex::new(None),
            events,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        (Socket::new(client, &control).unwrap(), peer)
    }
    #[test]
    fn forged_identity_is_rejected_before_any_key_exchange_reply() {
        sodiumoxide::init().unwrap();
        let (pk, sk) = sign::gen_keypair();
        let (other, _) = sign::gen_keypair();
        let (mut socket, mut peer) = sockets();
        let bytes = sign::sign(
            &wire::Identity {
                id: "peer".into(),
                key: vec![0; 32],
                version: 1,
            }
            .encode_to_vec(),
            &sk,
        );
        assert!(socket.authenticate(&bytes, &other.0).is_err());
        let mut bad = bytes;
        bad[0] ^= 1;
        assert!(socket.authenticate(&bad, &pk.0).is_err());
        peer.set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        assert!(peer.read(&mut [0; 1]).is_err());
    }
    #[test]
    fn framing_retains_partial_data_and_rejects_oversize_or_wrong_direction_mac() {
        sodiumoxide::init().unwrap();
        let (mut socket, _) = sockets();
        let body = wire::Packet {
            body: Some(Body::Challenge(wire::Challenge {
                salt: "salt".into(),
                challenge: "nonce".into(),
            })),
        }
        .encode_to_vec();
        let mut frame = vec![(body.len() as u8) << 2];
        frame.extend_from_slice(&body);
        for &byte in &frame[..frame.len() - 1] {
            socket.incoming.push(byte);
            assert!(socket.extract().unwrap().is_none());
        }
        socket.incoming.push(*frame.last().unwrap());
        assert!(matches!(
            socket.extract().unwrap().unwrap().body,
            Some(Body::Challenge(_))
        ));
        socket.incoming = (((MAX_PACKET as u32 + 1) << 2) | 3).to_le_bytes().to_vec();
        assert!(socket.extract().is_err());
        socket.incoming.clear();
        let key = secretbox::gen_key();
        let send = direction_key(&key, 1, 1, &[1; 32], &[2; 32]).unwrap();
        let receive = direction_key(&key, 2, 1, &[1; 32], &[2; 32]).unwrap();
        assert_ne!(send.0, receive.0);
        let sealed = secretbox::seal(&body, &nonce(1), &send);
        socket.receive_key = Some(receive);
        let width = header_width(sealed.len());
        socket.incoming.extend_from_slice(
            &(((sealed.len() as u32) << 2) | (width as u32 - 1)).to_le_bytes()[..width],
        );
        socket.incoming.extend(sealed);
        assert!(socket.extract().is_err());
    }
}
