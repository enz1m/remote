use flate2::{Decompress, FlushDecompress};

pub(super) struct Zrle(Decompress);
impl Default for Zrle {
    fn default() -> Self {
        Self(Decompress::new(true))
    }
}

struct Cursor<'a>(&'a [u8]);
impl Cursor<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], String> {
        let value = self.0.get(..count).ok_or("The ZRLE tile is truncated.")?;
        self.0 = &self.0[count..];
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn pixel(&mut self) -> Result<[u8; 4], String> {
        let pixel = self.take(3)?;
        Ok([pixel[2], pixel[1], pixel[0], 255])
    }
    fn run(&mut self, remaining: usize) -> Result<usize, String> {
        let mut length = 1;
        loop {
            let byte = self.byte()?;
            length += usize::from(byte);
            if length > remaining {
                return Err("The ZRLE run exceeds its tile.".into());
            }
            if byte != 255 {
                return Ok(length);
            }
        }
    }
}

impl Zrle {
    pub(super) fn decode(
        &mut self,
        encoded: &[u8],
        width: u32,
        height: u32,
        rgba_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        super::wire::check_dimensions(width, height).map_err(|error| error.to_string())?;
        if rgba_bytes != width as usize * height as usize * 4
            || encoded.len() as u64 > super::wire::MAX_MESSAGE_BYTES
        {
            return Err("The ZRLE geometry or input length is invalid.".into());
        }
        let tiles = width.div_ceil(64) as usize * height.div_ceil(64) as usize;
        let limit = rgba_bytes + tiles * 385;
        let mut decoded = Vec::new();
        let mut consumed = 0;
        loop {
            let mut buffer = [0; 65536];
            let before_in = self.0.total_in();
            let before_out = self.0.total_out();
            self.0
                .decompress(&encoded[consumed..], &mut buffer, FlushDecompress::Sync)
                .map_err(|_| "The ZRLE compressed stream is invalid.")?;
            let read = (self.0.total_in() - before_in) as usize;
            let written = (self.0.total_out() - before_out) as usize;
            if decoded.len().saturating_add(written) > limit {
                return Err("The ZRLE expanded data exceeds its geometry bound.".into());
            }
            decoded.extend_from_slice(&buffer[..written]);
            consumed += read;
            if consumed == encoded.len() && written < buffer.len() {
                break;
            }
            if read == 0 && written == 0 {
                return Err("The ZRLE stream did not make progress.".into());
            }
        }
        let mut input = Cursor(&decoded);
        let mut pixels = vec![0; rgba_bytes];
        for y in (0..height as usize).step_by(64) {
            for x in (0..width as usize).step_by(64) {
                let w = (width as usize - x).min(64);
                let h = (height as usize - y).min(64);
                let tile = tile(&mut input, w, h)?;
                for row in 0..h {
                    let at = ((y + row) * width as usize + x) * 4;
                    pixels[at..at + w * 4].copy_from_slice(&tile[row * w * 4..(row + 1) * w * 4]);
                }
            }
        }
        if !input.0.is_empty() {
            return Err("The ZRLE rectangle contains trailing tile data.".into());
        }
        Ok(pixels)
    }
}

fn tile(input: &mut Cursor<'_>, width: usize, height: usize) -> Result<Vec<u8>, String> {
    let mode = input.byte()?;
    let count = width * height;
    let mut pixels = Vec::with_capacity(count * 4);
    match mode {
        0 => {
            for _ in 0..count {
                pixels.extend_from_slice(&input.pixel()?);
            }
        }
        1 => {
            let color = input.pixel()?;
            for _ in 0..count {
                pixels.extend_from_slice(&color);
            }
        }
        2..=16 => {
            let palette = (0..mode)
                .map(|_| input.pixel())
                .collect::<Result<Vec<_>, _>>()?;
            let bits = if mode == 2 {
                1
            } else if mode <= 4 {
                2
            } else {
                4
            };
            for _ in 0..height {
                let row = input.take((width * bits).div_ceil(8))?;
                for x in 0..width {
                    let index = usize::from(
                        (row[x * bits / 8] >> (8 - bits - x * bits % 8)) & ((1 << bits) - 1),
                    );
                    pixels.extend_from_slice(
                        palette
                            .get(index)
                            .ok_or("The ZRLE palette index is invalid.")?,
                    );
                }
            }
        }
        128 => {
            while pixels.len() / 4 < count {
                let color = input.pixel()?;
                let length = input.run(count - pixels.len() / 4)?;
                for _ in 0..length {
                    pixels.extend_from_slice(&color);
                }
            }
        }
        130..=255 => {
            let palette = (0..mode - 128)
                .map(|_| input.pixel())
                .collect::<Result<Vec<_>, _>>()?;
            while pixels.len() / 4 < count {
                let index = input.byte()?;
                let color = palette
                    .get(usize::from(index & 127))
                    .ok_or("The ZRLE palette index is invalid.")?;
                let length = if index & 128 == 0 {
                    1
                } else {
                    input.run(count - pixels.len() / 4)?
                };
                for _ in 0..length {
                    pixels.extend_from_slice(color);
                }
            }
        }
        _ => return Err("The ZRLE tile uses a reserved encoding.".into()),
    }
    Ok(pixels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    fn compress(compressor: &mut Compress, bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(bytes.len() * 2 + 128);
        compressor
            .compress_vec(bytes, &mut output, FlushCompress::Sync)
            .unwrap();
        output
    }
    #[test]
    fn incremental_zrle_preserves_stream_state_and_rejects_tile_expansion_and_bad_palettes() {
        let mut compressor = Compress::new(Compression::fast(), true);
        let mut decoder = Zrle::default();
        let first = compress(&mut compressor, &[2, 0, 0, 255, 0, 255, 0, 0x40]);
        assert_eq!(
            decoder.decode(&first, 2, 1, 8).unwrap(),
            [255, 0, 0, 255, 0, 255, 0, 255]
        );
        let second = compress(&mut compressor, &[128, 255, 0, 0, 1]);
        assert_eq!(
            decoder.decode(&second, 2, 1, 8).unwrap(),
            [0, 0, 255, 255, 0, 0, 255, 255]
        );
        for bytes in [
            vec![128, 0, 0, 0, 255],
            vec![3, 0, 0, 0, 1, 1, 1, 2, 2, 2, 0xf0],
            vec![0; 4096],
        ] {
            let encoded = compress(&mut Compress::new(Compression::fast(), true), &bytes);
            assert!(Zrle::default().decode(&encoded, 2, 1, 8).is_err());
        }
    }
}
