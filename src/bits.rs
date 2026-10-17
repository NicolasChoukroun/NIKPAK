//! MSB-first bit writer / reader used by the audio codec.

pub struct BitWriter {
    buf: Vec<u8>,
    acc: u64,
    nacc: u32,
}

impl BitWriter {
    pub fn new() -> Self {
        BitWriter { buf: Vec::with_capacity(8192), acc: 0, nacc: 0 }
    }

    /// Write the low `n` bits of `v` (n <= 64).
    pub fn put(&mut self, v: u64, n: u32) {
        if n == 0 {
            return;
        }
        if n > 32 {
            self.put(v >> 32, n - 32);
            self.put(v & 0xFFFF_FFFF, 32);
            return;
        }
        let v = v & ((1u64 << n) - 1);
        self.acc = (self.acc << n) | v;
        self.nacc += n;
        while self.nacc >= 8 {
            self.nacc -= 8;
            self.buf.push((self.acc >> self.nacc) as u8);
        }
        self.acc &= (1u64 << self.nacc) - 1;
    }

    /// Two's complement, n bits (n <= 64).
    pub fn put_signed(&mut self, v: i64, n: u32) {
        self.put(v as u64, n);
    }

    /// `q` zero bits followed by a one bit.
    pub fn unary(&mut self, mut q: u64) {
        debug_assert!(q < (1 << 24), "unreasonably long unary code");
        while q >= 32 {
            self.put(0, 32);
            q -= 32;
        }
        self.put(1, q as u32 + 1);
    }

    pub fn finish(mut self) -> Vec<u8> {
        if self.nacc > 0 {
            let pad = 8 - self.nacc;
            self.put(0, pad);
        }
        self.buf
    }
}

pub struct BitReader<'a> {
    data: &'a [u8],
    pos: usize, // in bits
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitReader { data, pos: 0 }
    }

    pub fn get(&mut self, n: u32) -> Result<u64, String> {
        if n == 0 {
            return Ok(0);
        }
        if n > 64 || self.pos + n as usize > self.data.len() * 8 {
            return Err("audio block is truncated".into());
        }
        let mut v = 0u64;
        let mut need = n;
        while need > 0 {
            let byte = self.data[self.pos >> 3];
            let avail = 8 - (self.pos & 7) as u32;
            let take = need.min(avail);
            let bits = ((byte >> (avail - take)) as u64) & ((1u64 << take) - 1);
            v = (v << take) | bits;
            self.pos += take as usize;
            need -= take;
        }
        Ok(v)
    }

    pub fn get_signed(&mut self, n: u32) -> Result<i64, String> {
        let v = self.get(n)?;
        if n == 0 || n >= 64 {
            return Ok(v as i64);
        }
        let sign = 1u64 << (n - 1);
        Ok(if v & sign != 0 { (v | !((1u64 << n) - 1)) as i64 } else { v as i64 })
    }

    /// Count zero bits up to the next one bit.
    pub fn unary(&mut self) -> Result<u64, String> {
        let mut q = 0u64;
        loop {
            if self.pos >= self.data.len() * 8 {
                return Err("audio block is truncated".into());
            }
            let bit = (self.data[self.pos >> 3] >> (7 - (self.pos & 7))) & 1;
            self.pos += 1;
            if bit == 1 {
                return Ok(q);
            }
            q += 1;
            if q > (1 << 40) {
                return Err("corrupt audio block".into());
            }
        }
    }
}
