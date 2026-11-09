pub(crate) fn scan_code(key: u32) -> Option<(u8, bool)> {
    let code = match key {
        0x61..=0x7a | 0x41..=0x5a => b"\x1e\x30\x2e\x20\x12\x21\x22\x23\x17\x24\x25\x26\x32\x31\x18\x19\x10\x13\x1f\x14\x16\x2f\x11\x2d\x15\x2c"[(key as u8).to_ascii_lowercase().wrapping_sub(b'a') as usize],
        0x31..=0x39 => (key - 0x31 + 0x02) as u8,
        0x30 => 0x0b,
        0x20 => 0x39,
        0x2d | 0x5f => 0x0c, 0x3d | 0x2b => 0x0d,
        0x5b | 0x7b => 0x1a, 0x5d | 0x7d => 0x1b,
        0x3b | 0x3a => 0x27, 0x27 | 0x22 => 0x28,
        0x60 | 0x7e => 0x29, 0x5c | 0x7c => 0x2b,
        0x2c | 0x3c => 0x33, 0x2e | 0x3e => 0x34, 0x2f | 0x3f => 0x35,
        0xff08 => 0x0e, 0xff09 => 0x0f, 0xff0d => 0x1c, 0xff1b => 0x01,
        0xffe1 => 0x2a, 0xffe2 => 0x36, 0xffe3 => 0x1d, 0xffe9 => 0x38,
        0xffe4 => return Some((0x1d, true)), 0xffea => return Some((0x38, true)),
        0xffeb => return Some((0x5b, true)), 0xffec => return Some((0x5c, true)),
        0xffff => return Some((0x53, true)), 0xff63 => return Some((0x52, true)),
        0xff50 => return Some((0x47, true)), 0xff57 => return Some((0x4f, true)),
        0xff51 => return Some((0x4b, true)), 0xff52 => return Some((0x48, true)),
        0xff53 => return Some((0x4d, true)), 0xff54 => return Some((0x50, true)),
        0xff55 => return Some((0x49, true)), 0xff56 => return Some((0x51, true)),
        0xffbe..=0xffc7 => (key - 0xffbe + 0x3b) as u8,
        0xffc8 => 0x57, 0xffc9 => 0x58,
        0xffe5 => 0x3a, 0xff7f => 0x45, 0xff14 => 0x46,
        0xff61 => return Some((0x37, true)),
        _ => return None,
    };
    Some((code, false))
}

#[derive(Default)]
pub(crate) struct KeyboardState {
    held_shift: std::collections::BTreeSet<u32>,
    synthesized_shift: std::collections::BTreeSet<u32>,
}

pub(crate) fn needs_shift(key: u32) -> bool {
    (b'A' as u32..=b'Z' as u32).contains(&key)
        || char::from_u32(key).is_some_and(|c| "~!@#$%^&*()_+{}|:\"<>?".contains(c))
}

pub(crate) fn printable_scan(key: u32) -> Option<(u8, bool)> {
    match char::from_u32(key) {
        Some(c) if "!@#$%^&*()".contains(c) => Some((("!@#$%^&*()".find(c)? + 2) as u8, false)),
        _ => scan_code(key),
    }
}

impl KeyboardState {
    pub(crate) fn transition(&mut self, key: u32, down: bool) -> Option<Vec<(u8, bool, bool)>> {
        let (scan, extended) = printable_scan(key)?;
        let mut events = Vec::with_capacity(3);
        if matches!(key, 0xffe1 | 0xffe2) {
            if down {
                self.held_shift.insert(key);
            } else {
                self.held_shift.remove(&key);
            }
            if key != 0xffe1 || self.synthesized_shift.is_empty() {
                events.push((scan, extended, down));
            }
            return Some(events);
        }
        if down && needs_shift(key) && self.held_shift.is_empty() {
            if self.synthesized_shift.is_empty() {
                events.push((0x2a, false, true));
            }
            self.synthesized_shift.insert(key);
        }
        events.push((scan, extended, down));
        if !down
            && self.synthesized_shift.remove(&key)
            && self.synthesized_shift.is_empty()
            && !self.held_shift.contains(&0xffe1)
        {
            events.push((0x2a, false, false));
        }
        Some(events)
    }
}

#[cfg(test)]
mod tests {}
