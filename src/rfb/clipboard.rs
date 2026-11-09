//! Bounded RFB text clipboard exchange; rich text and file formats are not accepted.

use std::io::{Read, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

pub(crate) const LIMIT: usize = crate::native_clipboard::LIMIT;
const UTF8: u32 = 1;
const CAPS: u32 = 1 << 24;
const REQUEST: u32 = 1 << 25;
const PEEK: u32 = 1 << 26;
const NOTIFY: u32 = 1 << 27;
const PROVIDE: u32 = 1 << 28;

pub use crate::native_clipboard::Text;

#[derive(Default)]
struct WireState {
    flags: u32,
    unsolicited_limit: usize,
    local: Option<zeroize::Zeroizing<String>>,
}

impl std::fmt::Debug for WireState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClipboardState")
            .field("flags", &self.flags)
            .field("local_bytes", &self.local.as_ref().map(|s| s.len()))
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct Clipboard {
    enabled: AtomicBool,
    pub(crate) capture: Arc<AtomicBool>,
    wire: Mutex<WireState>,
}
impl Clipboard {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            capture: Arc::new(AtomicBool::new(false)),
            wire: Mutex::default(),
        }
    }
    pub(crate) fn enable(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
        if !enabled {
            self.wire
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .local = None;
        }
    }
    pub(crate) fn sharing(&self) -> bool {
        self.enabled.load(Ordering::SeqCst) && self.capture.load(Ordering::SeqCst)
    }
    pub(crate) fn local(&self, text: &str) -> Result<Vec<u8>, String> {
        if !self.sharing() {
            return Err("Clipboard sharing requires a captured, interactive session.".into());
        }
        if text.len() > LIMIT || text.contains('\0') {
            return Err("Clipboard text is too large or contains a null character.".into());
        }
        let text = text.replace("\r\n", "\n").replace('\r', "\n");
        let mut state = self
            .wire
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.flags & (UTF8 | NOTIFY) == UTF8 | NOTIFY {
            if text.len() + text.bytes().filter(|b| *b == b'\n').count() + 1 > LIMIT {
                return Err("Clipboard text exceeds the VNC UTF-8 limit.".into());
            }
            let wire_size = text.len() + text.bytes().filter(|b| *b == b'\n').count() + 1;
            let message = if state.flags & PROVIDE != 0 && wire_size <= state.unsolicited_limit {
                provide(&text)?
            } else {
                extended(NOTIFY | UTF8, &[])
            };
            state.local = Some(zeroize::Zeroizing::new(text));
            Ok(message)
        } else {
            let bytes: Option<Vec<u8>> = text
                .chars()
                .map(|c| u8::try_from(u32::from(c)).ok())
                .collect();
            let bytes =
                bytes.ok_or("This VNC server has not negotiated UTF-8 clipboard support.")?;
            let mut out = vec![6, 0, 0, 0];
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend(bytes);
            Ok(out)
        }
    }
    pub(crate) fn receive(
        &self,
        signed_length: i32,
        body: &[u8],
    ) -> Result<(Option<Text>, Vec<Vec<u8>>), String> {
        if signed_length >= 0 {
            return Ok((
                self.sharing().then(|| {
                    Text(Arc::new(
                        body.iter()
                            .map(|b| char::from(*b))
                            .collect::<String>()
                            .replace("\r\n", "\n")
                            .replace('\r', "\n"),
                    ))
                }),
                Vec::new(),
            ));
        }
        let flags = u32::from_be_bytes(
            body.get(..4)
                .ok_or("Invalid VNC clipboard flags.")?
                .try_into()
                .map_err(|_| "Invalid VNC clipboard flags.")?,
        );
        let action = flags & 0xff00_0000;
        if action & CAPS != 0 {
            let count = (flags & 0xffff).count_ones() as usize;
            if body.len() != 4 + count * 4 {
                return Err("Invalid VNC clipboard capabilities.".into());
            }
            let mut state = self
                .wire
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.flags = flags;
            state.unsolicited_limit = if flags & UTF8 != 0 {
                u32::from_be_bytes(
                    body[4..8]
                        .try_into()
                        .map_err(|_| "Invalid VNC UTF-8 limit.")?,
                ) as usize
            } else {
                0
            };
            drop(state);
            return Ok((
                None,
                vec![extended(
                    CAPS | UTF8 | REQUEST | PEEK | NOTIFY | PROVIDE,
                    &(LIMIT as u32).to_be_bytes(),
                )],
            ));
        }
        if !self.sharing() {
            return Ok((None, Vec::new()));
        }
        match action {
            NOTIFY if flags & UTF8 != 0 => Ok((None, vec![extended(REQUEST | UTF8, &[])])),
            NOTIFY => Ok((None, Vec::new())),
            PEEK => {
                let state = self
                    .wire
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                Ok((
                    None,
                    vec![extended(
                        NOTIFY | if state.local.is_some() { UTF8 } else { 0 },
                        &[],
                    )],
                ))
            }
            REQUEST => {
                let state = self
                    .wire
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let reply = if flags & UTF8 != 0 {
                    state.local.as_deref().map(|s| provide(s)).transpose()?
                } else {
                    None
                };
                Ok((None, reply.into_iter().collect()))
            }
            PROVIDE if flags & 0xffff == UTF8 => {
                let mut decoder = flate2::read::ZlibDecoder::new(&body[4..]);
                let mut decoded = Vec::new();
                decoder
                    .by_ref()
                    .take((LIMIT + 5) as u64)
                    .read_to_end(&mut decoded)
                    .map_err(|_| "Invalid compressed VNC clipboard text.")?;
                if decoded.len() > LIMIT + 4 {
                    return Err("Decompressed VNC clipboard exceeds the text limit.".into());
                }
                let length = u32::from_be_bytes(
                    decoded
                        .get(..4)
                        .ok_or("Invalid VNC clipboard text length.")?
                        .try_into()
                        .map_err(|_| "Invalid VNC clipboard text length.")?,
                ) as usize;
                if length == 0
                    || length > LIMIT
                    || decoded.len() != length + 4
                    || decoded.last() != Some(&0)
                {
                    return Err("Invalid VNC clipboard text length or terminator.".into());
                }
                let text = std::str::from_utf8(&decoded[4..decoded.len() - 1])
                    .map_err(|_| "Invalid UTF-8 VNC clipboard text.")?;
                if text.contains('\0') {
                    return Err("Invalid VNC clipboard null character.".into());
                }
                Ok((
                    Some(Text(Arc::new(
                        text.replace("\r\n", "\n").replace('\r', "\n"),
                    ))),
                    Vec::new(),
                ))
            }
            PROVIDE => Ok((None, Vec::new())),
            _ => Err("Unsupported VNC clipboard action.".into()),
        }
    }
}
fn extended(flags: u32, body: &[u8]) -> Vec<u8> {
    let mut out = vec![6, 0, 0, 0];
    out.extend_from_slice(&(-(4 + body.len() as i32)).to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(body);
    out
}
fn provide(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.replace('\n', "\r\n").into_bytes();
    if bytes.len() + 1 > LIMIT {
        return Err("Clipboard text exceeds the VNC UTF-8 limit.".into());
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder
        .write_all(&((bytes.len() + 1) as u32).to_be_bytes())
        .and_then(|_| encoder.write_all(&bytes))
        .and_then(|_| encoder.write_all(&[0]))
        .map_err(|_| "VNC clipboard compression failed.")?;
    Ok(extended(
        PROVIDE | UTF8,
        &encoder
            .finish()
            .map_err(|_| "VNC clipboard compression failed.")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negotiated_utf8_roundtrips_and_revoked_sharing_cannot_answer_requests() {
        let clipboard = Clipboard::new(true);
        clipboard.capture.store(true, Ordering::SeqCst);
        let caps = extended(
            CAPS | UTF8 | NOTIFY | REQUEST | PROVIDE,
            &(LIMIT as u32).to_be_bytes(),
        );
        assert_eq!(clipboard.receive(-8, &caps[8..]).unwrap().1.len(), 1);
        let notify = clipboard.local("café\n🎈").unwrap();
        assert_eq!(
            u32::from_be_bytes(notify[8..12].try_into().unwrap()),
            PROVIDE | UTF8
        );
        let zero_caps = extended(
            CAPS | UTF8 | NOTIFY | REQUEST | PROVIDE,
            &0u32.to_be_bytes(),
        );
        clipboard.receive(-8, &zero_caps[8..]).unwrap();
        assert_eq!(
            u32::from_be_bytes(clipboard.local("later").unwrap()[8..12].try_into().unwrap()),
            NOTIFY | UTF8
        );
        clipboard.receive(-8, &caps[8..]).unwrap();
        clipboard.local("café\n🎈").unwrap();
        let request = extended(REQUEST | UTF8, &[]);
        let provide = clipboard.receive(-4, &request[8..]).unwrap().1.remove(0);
        let (text, _) = clipboard
            .receive(
                i32::from_be_bytes(provide[4..8].try_into().unwrap()),
                &provide[8..],
            )
            .unwrap();
        assert_eq!(text.unwrap().0.as_str(), "café\n🎈");
        clipboard.enable(false);
        assert!(clipboard.local("private").is_err());
        assert!(clipboard.receive(-4, &request[8..]).unwrap().1.is_empty());
        clipboard.enable(true);
        assert!(clipboard.receive(-4, &request[8..]).unwrap().1.is_empty());
        clipboard.capture.store(false, Ordering::SeqCst);
        assert!(clipboard.receive(6, b"secret").unwrap().0.is_none());
    }
    #[test]
    fn classic_latin1_and_bounded_sync_flushed_utf8_reject_oversized_or_malformed_data() {
        let clipboard = Clipboard::new(true);
        clipboard.capture.store(true, Ordering::SeqCst);
        assert_eq!(&clipboard.local("café").unwrap()[8..], b"caf\xe9");
        assert!(clipboard.local("🎈").is_err());
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&3u32.to_be_bytes()).unwrap();
        encoder.write_all(b"hi\0").unwrap();
        encoder.flush().unwrap();
        let packet = extended(PROVIDE | UTF8, encoder.get_ref());
        assert_eq!(
            clipboard
                .receive(-((packet.len() - 8) as i32), &packet[8..])
                .unwrap()
                .0
                .unwrap()
                .0
                .as_str(),
            "hi"
        );
        let mut bomb = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        bomb.write_all(&vec![0; LIMIT + 100]).unwrap();
        let bomb = extended(PROVIDE | UTF8, &bomb.finish().unwrap());
        assert!(
            clipboard
                .receive(-((bomb.len() - 8) as i32), &bomb[8..])
                .is_err()
        );
        let invalid = extended(PROVIDE | UTF8, b"not zlib");
        assert!(clipboard.receive(-12, &invalid[8..]).is_err());
        assert!(clipboard.local(&"x".repeat(LIMIT + 1)).is_err());
    }
}
