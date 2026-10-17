//! Media-aware filters: WAV / AIFF / MOD (audio) and BMP (image).
//!
//! A *detector* looks at the file CONTENT (not the extension) and describes
//! which byte range holds raw samples / pixels. A *method* then transforms that
//! range into something the solid zstd stream compresses far better (or, for
//! the NAC audio codec, into an already tightly packed bit-stream). Everything
//! outside the range (headers, tags, patterns, palettes) is passed through.
//!
//! At creation time every candidate method is trial-compressed on a sample of
//! the file and the smallest one wins; if nothing beats plain compression the
//! file is stored normally. All transforms are lossless and the NAC codec is
//! verified block by block while writing.

use crate::nac;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

pub const FILTER_AUDIO: u8 = 1;
pub const FILTER_IMAGE: u8 = 2;

pub const M_NAC: u8 = 1;
pub const M_SHUFFLE: u8 = 2;
pub const M_SHUFFLE_DELTA: u8 = 3;
pub const M_MED: u8 = 1;

pub const MIN_MEDIA_SIZE: u64 = 8 * 1024;
const MIN_REGION: u64 = 4 * 1024;
const MAX_IMAGE_BYTES: u64 = 256 << 20;
const SH_BLOCK: usize = 32768;
const PAD_CHUNK: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Wav,
    Aiff,
    Mod,
    Bmp,
}

impl Kind {
    pub fn name(&self) -> &'static str {
        match self {
            Kind::Wav => "WAV",
            Kind::Aiff => "AIFF",
            Kind::Mod => "MOD",
            Kind::Bmp => "BMP",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AudioParams {
    pub offset: u64,
    pub frames: u64,
    pub channels: u8,
    pub bits: u8,
    pub big_endian: bool,
    pub signed: bool,
}

impl AudioParams {
    pub fn frame_bytes(&self) -> usize {
        self.channels as usize * (self.bits as usize / 8)
    }
    pub fn region_bytes(&self) -> u64 {
        self.frames * self.frame_bytes() as u64
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(19);
        v.extend_from_slice(&self.offset.to_le_bytes());
        v.extend_from_slice(&self.frames.to_le_bytes());
        v.push(self.channels);
        v.push(self.bits);
        v.push(self.big_endian as u8 | (self.signed as u8) << 1);
        v
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 19 {
            return None;
        }
        let p = AudioParams {
            offset: u64::from_le_bytes(b[0..8].try_into().ok()?),
            frames: u64::from_le_bytes(b[8..16].try_into().ok()?),
            channels: b[16],
            bits: b[17],
            big_endian: b[18] & 1 != 0,
            signed: b[18] & 2 != 0,
        };
        if p.channels == 0 || p.channels > 8 || !matches!(p.bits, 8 | 16 | 24 | 32) {
            return None;
        }
        Some(p)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ImageParams {
    pub offset: u64,
    pub width: u32,
    pub rows: u32,
    pub bpp: u8,
    pub stride: u32,
}

impl ImageParams {
    pub fn region_bytes(&self) -> u64 {
        self.stride as u64 * self.rows as u64
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(21);
        v.extend_from_slice(&self.offset.to_le_bytes());
        v.extend_from_slice(&self.width.to_le_bytes());
        v.extend_from_slice(&self.rows.to_le_bytes());
        v.push(self.bpp);
        v.extend_from_slice(&self.stride.to_le_bytes());
        v
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 21 {
            return None;
        }
        let p = ImageParams {
            offset: u64::from_le_bytes(b[0..8].try_into().ok()?),
            width: u32::from_le_bytes(b[8..12].try_into().ok()?),
            rows: u32::from_le_bytes(b[12..16].try_into().ok()?),
            bpp: b[16],
            stride: u32::from_le_bytes(b[17..21].try_into().ok()?),
        };
        let nch = (p.bpp / 8) as u64;
        if !matches!(p.bpp, 8 | 24 | 32) || (p.width as u64) * nch > p.stride as u64 || p.width == 0 || p.rows == 0 {
            return None;
        }
        if p.region_bytes() > MAX_IMAGE_BYTES {
            return None;
        }
        Some(p)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Plan {
    Audio(AudioParams),
    Image(ImageParams),
}

#[derive(Clone, Copy, Debug)]
pub struct Detected {
    pub kind: Kind,
    pub plan: Plan,
}

impl Detected {
    pub fn filter_id(&self) -> u8 {
        match self.plan {
            Plan::Audio(_) => FILTER_AUDIO,
            Plan::Image(_) => FILTER_IMAGE,
        }
    }
    pub fn params_bytes(&self) -> Vec<u8> {
        match self.plan {
            Plan::Audio(p) => p.to_bytes(),
            Plan::Image(p) => p.to_bytes(),
        }
    }
    pub fn default_method(&self) -> u8 {
        match self.plan {
            Plan::Audio(_) => M_NAC,
            Plan::Image(_) => M_MED,
        }
    }
    pub fn methods(&self) -> Vec<u8> {
        match self.plan {
            Plan::Audio(p) if p.bits == 8 => vec![M_NAC, M_SHUFFLE_DELTA],
            Plan::Audio(_) => vec![M_NAC, M_SHUFFLE, M_SHUFFLE_DELTA],
            Plan::Image(_) => vec![M_MED],
        }
    }
}

pub fn method_name(filter: u8, m: u8) -> &'static str {
    match (filter, m) {
        (FILTER_AUDIO, M_NAC) => "NAC",
        (FILTER_AUDIO, M_SHUFFLE) => "Shuffle",
        (FILTER_AUDIO, M_SHUFFLE_DELTA) => "Shuf+Delta",
        (FILTER_IMAGE, M_MED) => "MED",
        _ => "?",
    }
}

// ===========================================================================
// Detection
// ===========================================================================

fn read_at(f: &mut File, pos: u64, buf: &mut [u8]) -> io::Result<()> {
    f.seek(SeekFrom::Start(pos))?;
    f.read_exact(buf)
}

fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn u16be(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Inspect the content of a file; None if it is not a supported media file.
pub fn detect(f: &mut File, len: u64) -> Option<Detected> {
    if len < MIN_MEDIA_SIZE {
        return None;
    }
    let mut head = [0u8; 12];
    read_at(f, 0, &mut head).ok()?;
    let r = if &head[0..4] == b"RIFF" && &head[8..12] == b"WAVE" {
        detect_wav(f, len)
    } else if &head[0..4] == b"FORM" && (&head[8..12] == b"AIFF" || &head[8..12] == b"AIFC") {
        detect_aiff(f, len, &head[8..12] == b"AIFC")
    } else if &head[0..2] == b"BM" {
        detect_bmp(f, len)
    } else {
        detect_mod(f, len)
    };
    f.seek(SeekFrom::Start(0)).ok()?;
    r
}

fn make_audio(kind: Kind, offset: u64, region_len: u64, channels: u16, bits: u16, be: bool, signed: bool) -> Option<Detected> {
    if channels == 0 || channels > 8 || !matches!(bits, 8 | 16 | 24 | 32) {
        return None;
    }
    let fb = channels as u64 * (bits as u64 / 8);
    let frames = region_len / fb;
    if frames * fb < MIN_REGION {
        return None;
    }
    Some(Detected {
        kind,
        plan: Plan::Audio(AudioParams {
            offset,
            frames,
            channels: channels as u8,
            bits: bits as u8,
            big_endian: be,
            signed,
        }),
    })
}

fn detect_wav(f: &mut File, len: u64) -> Option<Detected> {
    let mut pos = 12u64;
    let mut fmt: Option<(u16, u16, u16, u16)> = None; // tag, channels, bits, align
    for _ in 0..256 {
        if pos + 8 > len {
            break;
        }
        let mut ch = [0u8; 8];
        read_at(f, pos, &mut ch).ok()?;
        let sz = u32le(&ch[4..8]) as u64;
        if &ch[0..4] == b"fmt " {
            if sz < 16 {
                return None;
            }
            let take = sz.min(40) as usize;
            let mut b = vec![0u8; take];
            read_at(f, pos + 8, &mut b).ok()?;
            let mut tag = u16le(&b[0..2]);
            if tag == 0xFFFE {
                if take < 26 {
                    return None;
                }
                tag = u16le(&b[24..26]);
            }
            fmt = Some((tag, u16le(&b[2..4]), u16le(&b[14..16]), u16le(&b[12..14])));
        } else if &ch[0..4] == b"data" {
            let (tag, channels, bits, align) = fmt?;
            if tag != 1 || align as u32 != channels as u32 * bits as u32 / 8 || bits % 8 != 0 {
                return None;
            }
            let off = pos + 8;
            let avail = len.saturating_sub(off);
            let region = if sz == 0 || sz > avail { avail } else { sz };
            return make_audio(Kind::Wav, off, region, channels, bits, false, bits != 8);
        }
        pos += 8 + sz + (sz & 1);
    }
    None
}

fn detect_aiff(f: &mut File, len: u64, aifc: bool) -> Option<Detected> {
    let mut pos = 12u64;
    let mut comm: Option<(u16, u32, u16)> = None; // channels, frames, bits
    for _ in 0..256 {
        if pos + 8 > len {
            break;
        }
        let mut ch = [0u8; 8];
        read_at(f, pos, &mut ch).ok()?;
        let sz = u32be(&ch[4..8]) as u64;
        if &ch[0..4] == b"COMM" {
            if sz < 18 {
                return None;
            }
            let take = sz.min(26) as usize;
            let mut b = vec![0u8; take];
            read_at(f, pos + 8, &mut b).ok()?;
            if aifc {
                if take < 22 || !(&b[18..22] == b"NONE" || &b[18..22] == b"twos") {
                    return None;
                }
            }
            comm = Some((u16be(&b[0..2]), u32be(&b[2..6]), u16be(&b[6..8])));
        } else if &ch[0..4] == b"SSND" {
            let (channels, frames, bits) = comm?;
            if sz < 8 {
                return None;
            }
            let mut b = [0u8; 8];
            read_at(f, pos + 8, &mut b).ok()?;
            let data_off = pos + 16 + u32be(&b[0..4]) as u64;
            if data_off > len || bits % 8 != 0 {
                return None;
            }
            let fb = channels as u64 * (bits as u64 / 8);
            if fb == 0 {
                return None;
            }
            let region = (len - data_off).min(frames as u64 * fb);
            return make_audio(Kind::Aiff, data_off, region, channels, bits, true, true);
        }
        pos += 8 + sz + (sz & 1);
    }
    None
}

fn detect_mod(f: &mut File, len: u64) -> Option<Detected> {
    if len < 1084 + 1024 {
        return None;
    }
    let mut h = vec![0u8; 1084];
    read_at(f, 0, &mut h).ok()?;
    let chans: u64 = match &h[1080..1084] {
        b"M.K." | b"M!K!" | b"FLT4" | b"4CHN" => 4,
        b"6CHN" => 6,
        b"8CHN" | b"FLT8" | b"OCTA" | b"CD81" => 8,
        _ => return None,
    };
    let patterns = h[952..1080].iter().copied().max().unwrap_or(0) as u64 + 1;
    let start = 1084 + patterns * 256 * chans;
    if start >= len {
        return None;
    }
    let mut total = 0u64;
    for i in 0..31 {
        let o = 20 + i * 30;
        total += u16be(&h[o + 22..o + 24]) as u64 * 2;
    }
    let region = total.min(len - start);
    make_audio(Kind::Mod, start, region, 1, 8, false, true)
}

fn detect_bmp(f: &mut File, len: u64) -> Option<Detected> {
    let mut h = [0u8; 54];
    read_at(f, 0, &mut h).ok()?;
    let off = u32le(&h[10..14]) as u64;
    let dib = u32le(&h[14..18]);
    if dib < 40 {
        return None;
    }
    let w = i32::from_le_bytes([h[18], h[19], h[20], h[21]]);
    let hh = i32::from_le_bytes([h[22], h[23], h[24], h[25]]);
    let bpp = u16le(&h[28..30]);
    let comp = u32le(&h[30..34]);
    if comp != 0 || w <= 0 || hh == 0 || !matches!(bpp, 8 | 24 | 32) {
        return None;
    }
    let rows = hh.unsigned_abs();
    let stride = (((w as u64 * bpp as u64) + 31) / 32) * 4;
    let region = stride * rows as u64;
    if region < MIN_REGION || region > MAX_IMAGE_BYTES || stride > u32::MAX as u64 || off + region > len {
        return None;
    }
    Some(Detected {
        kind: Kind::Bmp,
        plan: Plan::Image(ImageParams { offset: off, width: w as u32, rows, bpp: bpp as u8, stride: stride as u32 }),
    })
}

// ===========================================================================
// Small I/O helpers
// ===========================================================================

/// Copy exactly `n` bytes.
fn pipe<R: Read, W: Write>(src: &mut R, dst: &mut W, mut n: u64) -> io::Result<()> {
    let mut buf = vec![0u8; PAD_CHUNK];
    while n > 0 {
        let want = n.min(buf.len() as u64) as usize;
        src.read_exact(&mut buf[..want])?;
        dst.write_all(&buf[..want])?;
        n -= want as u64;
    }
    Ok(())
}

pub struct CrcRead<R: Read> {
    inner: R,
    crc: crc32fast::Hasher,
    left: u64,
}

impl<R: Read> CrcRead<R> {
    pub fn new(inner: R, size: u64) -> Self {
        CrcRead { inner, crc: crc32fast::Hasher::new(), left: size }
    }
    /// (crc, bytes not yet read)
    pub fn finish(self) -> (u32, u64) {
        (self.crc.finalize(), self.left)
    }
}

impl<R: Read> Read for CrcRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.left) as usize;
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "file became shorter while it was being archived"));
        }
        self.crc.update(&buf[..n]);
        self.left -= n as u64;
        Ok(n)
    }
}

pub struct CrcWrite<W: Write> {
    inner: W,
    crc: crc32fast::Hasher,
    count: u64,
}

impl<W: Write> CrcWrite<W> {
    pub fn new(inner: W) -> Self {
        CrcWrite { inner, crc: crc32fast::Hasher::new(), count: 0 }
    }
    pub fn finish(self) -> (u32, u64) {
        (self.crc.finalize(), self.count)
    }
}

impl<W: Write> Write for CrcWrite<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.inner.write_all(b)?;
        self.crc.update(b);
        self.count += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Frames a byte stream into [u32 len][bytes]... terminated by a zero length,
/// so a reader can always skip the stream without understanding it.
pub struct ChunkWriter<'a, W: Write> {
    inner: &'a mut W,
    buf: Vec<u8>,
}

impl<'a, W: Write> ChunkWriter<'a, W> {
    pub fn new(inner: &'a mut W) -> Self {
        ChunkWriter { inner, buf: Vec::with_capacity(PAD_CHUNK * 2) }
    }
    fn flush_chunk(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            self.inner.write_all(&(self.buf.len() as u32).to_le_bytes())?;
            self.inner.write_all(&self.buf)?;
            self.buf.clear();
        }
        Ok(())
    }
    pub fn finish(mut self) -> io::Result<()> {
        self.flush_chunk()?;
        self.inner.write_all(&0u32.to_le_bytes())
    }
}

impl<'a, W: Write> Write for ChunkWriter<'a, W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(b);
        if self.buf.len() >= PAD_CHUNK {
            self.flush_chunk()?;
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct ChunkReader<'a, R: Read> {
    inner: &'a mut R,
    left: u32,
    done: bool,
}

impl<'a, R: Read> ChunkReader<'a, R> {
    pub fn new(inner: &'a mut R) -> Self {
        ChunkReader { inner, left: 0, done: false }
    }
    /// Consume the rest of the stream; Ok(number of bytes that were still there).
    pub fn drain(&mut self) -> io::Result<u64> {
        io::copy(self, &mut io::sink())
    }
}

impl<'a, R: Read> Read for ChunkReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            if self.done {
                return Ok(0);
            }
            let mut b = [0u8; 4];
            self.inner.read_exact(&mut b)?;
            let len = u32::from_le_bytes(b);
            if len == 0 {
                self.done = true;
                return Ok(0);
            }
            self.left = len;
        }
        let want = (buf.len() as u64).min(self.left as u64) as usize;
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "media stream is truncated"));
        }
        self.left -= n as u32;
        Ok(n)
    }
}

// ===========================================================================
// Audio
// ===========================================================================

fn sample_from(b: &[u8], p: &AudioParams) -> i64 {
    match p.bits {
        8 => {
            if p.signed {
                b[0] as i8 as i64
            } else {
                b[0] as i64 - 128
            }
        }
        16 => {
            let v = if p.big_endian { i16::from_be_bytes([b[0], b[1]]) } else { i16::from_le_bytes([b[0], b[1]]) };
            v as i64
        }
        24 => {
            let u = if p.big_endian {
                (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32
            } else {
                (b[2] as u32) << 16 | (b[1] as u32) << 8 | b[0] as u32
            };
            (((u << 8) as i32) >> 8) as i64
        }
        _ => {
            let v = if p.big_endian {
                i32::from_be_bytes([b[0], b[1], b[2], b[3]])
            } else {
                i32::from_le_bytes([b[0], b[1], b[2], b[3]])
            };
            v as i64
        }
    }
}

fn put_sample(v: i64, p: &AudioParams, out: &mut Vec<u8>) {
    match p.bits {
        8 => out.push(if p.signed { v as i8 as u8 } else { (v + 128) as u8 }),
        16 => {
            let x = v as i16;
            out.extend_from_slice(&if p.big_endian { x.to_be_bytes() } else { x.to_le_bytes() });
        }
        24 => {
            let u = (v as i32 as u32) & 0xFF_FFFF;
            let b = [(u >> 16) as u8, (u >> 8) as u8, u as u8];
            if p.big_endian {
                out.extend_from_slice(&b);
            } else {
                out.extend_from_slice(&[b[2], b[1], b[0]]);
            }
        }
        _ => {
            let x = v as i32;
            out.extend_from_slice(&if p.big_endian { x.to_be_bytes() } else { x.to_le_bytes() });
        }
    }
}

fn unpack(raw: &[u8], p: &AudioParams, n: usize, chans: &mut [Vec<i64>]) {
    let bw = p.bits as usize / 8;
    let c = p.channels as usize;
    for ch in chans.iter_mut() {
        ch.clear();
    }
    for i in 0..n {
        for (k, ch) in chans.iter_mut().enumerate() {
            let o = (i * c + k) * bw;
            ch.push(sample_from(&raw[o..o + bw], p));
        }
    }
}

fn pack(chans: &[Vec<i64>], p: &AudioParams, n: usize, out: &mut Vec<u8>) {
    out.clear();
    for i in 0..n {
        for ch in chans {
            put_sample(ch[i], p, out);
        }
    }
}

fn read_uint(b: &[u8], be: bool) -> u32 {
    let mut v = 0u32;
    if be {
        for &x in b {
            v = (v << 8) | x as u32;
        }
    } else {
        for &x in b.iter().rev() {
            v = (v << 8) | x as u32;
        }
    }
    v
}

fn write_uint(v: u32, bw: usize, be: bool, out: &mut Vec<u8>) {
    if be {
        for k in (0..bw).rev() {
            out.push((v >> (8 * k)) as u8);
        }
    } else {
        for k in 0..bw {
            out.push((v >> (8 * k)) as u8);
        }
    }
}

fn sample_mask(bw: usize) -> u32 {
    if bw >= 4 {
        u32::MAX
    } else {
        (1u32 << (8 * bw)) - 1
    }
}

fn shuffle_block<W: Write>(raw: &[u8], p: &AudioParams, n: usize, delta: bool, prev: &mut [u32], out: &mut W) -> io::Result<()> {
    let bw = p.bits as usize / 8;
    let c = p.channels as usize;
    let mask = sample_mask(bw);
    let mut planes = vec![0u8; n * c * bw];
    for i in 0..n {
        for ch in 0..c {
            let o = (i * c + ch) * bw;
            let mut v = read_uint(&raw[o..o + bw], p.big_endian);
            if delta {
                let d = v.wrapping_sub(prev[ch]) & mask;
                prev[ch] = v;
                v = d;
            }
            for k in 0..bw {
                planes[(ch * bw + k) * n + i] = (v >> (8 * k)) as u8;
            }
        }
    }
    out.write_all(&planes)
}

fn unshuffle_block(planes: &[u8], p: &AudioParams, n: usize, delta: bool, prev: &mut [u32], out: &mut Vec<u8>) {
    let bw = p.bits as usize / 8;
    let c = p.channels as usize;
    let mask = sample_mask(bw);
    out.clear();
    for i in 0..n {
        for ch in 0..c {
            let mut v = 0u32;
            for k in 0..bw {
                v |= (planes[(ch * bw + k) * n + i] as u32) << (8 * k);
            }
            if delta {
                v = v.wrapping_add(prev[ch]) & mask;
                prev[ch] = v;
            }
            write_uint(v, bw, p.big_endian, out);
        }
    }
}

/// Encode only the sample region.
pub fn encode_audio_region<R: Read, W: Write>(src: &mut R, p: &AudioParams, method: u8, level: u32, out: &mut W) -> io::Result<()> {
    let fb = p.frame_bytes();
    let c = p.channels as usize;
    let bits = p.bits as u32;
    let blk = if method == M_NAC { nac::BLOCK } else { SH_BLOCK };
    let mut remaining = p.frames;
    let mut raw = vec![0u8; blk * fb];
    let mut chans: Vec<Vec<i64>> = vec![Vec::with_capacity(blk); c];
    let mut prev = vec![0u32; c];
    while remaining > 0 {
        let n = (remaining as usize).min(blk);
        src.read_exact(&mut raw[..n * fb])?;
        if method == M_NAC {
            unpack(&raw[..n * fb], p, n, &mut chans);
            let mut data = nac::encode_block(&chans, bits, level, false);
            let ok = matches!(nac::decode_block(&data, c, bits, n), Ok(d) if d == chans);
            if !ok {
                data = nac::encode_block(&chans, bits, level, true);
                if !matches!(nac::decode_block(&data, c, bits, n), Ok(d) if d == chans) {
                    return Err(io::Error::new(io::ErrorKind::Other, "internal error: audio codec self-check failed (use -mc- to disable media filters)"));
                }
            }
            out.write_all(&(data.len() as u32).to_le_bytes())?;
            out.write_all(&data)?;
        } else {
            shuffle_block(&raw[..n * fb], p, n, method == M_SHUFFLE_DELTA, &mut prev, out)?;
        }
        remaining -= n as u64;
    }
    Ok(())
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

pub fn decode_audio_region<R: Read, W: Write>(src: &mut R, p: &AudioParams, method: u8, out: &mut W) -> io::Result<()> {
    let fb = p.frame_bytes();
    let c = p.channels as usize;
    let bits = p.bits as u32;
    let blk = if method == M_NAC { nac::BLOCK } else { SH_BLOCK };
    let mut remaining = p.frames;
    let mut prev = vec![0u32; c];
    let mut outbuf: Vec<u8> = Vec::with_capacity(blk * fb);
    let mut inbuf: Vec<u8> = Vec::new();
    while remaining > 0 {
        let n = (remaining as usize).min(blk);
        if method == M_NAC {
            let mut lb = [0u8; 4];
            src.read_exact(&mut lb)?;
            let len = u32::from_le_bytes(lb) as usize;
            if len == 0 || len > n * c * 5 + 4096 {
                return Err(bad("corrupt audio block length"));
            }
            inbuf.resize(len, 0);
            src.read_exact(&mut inbuf)?;
            let chans = nac::decode_block(&inbuf, c, bits, n).map_err(|e| bad(&e))?;
            pack(&chans, p, n, &mut outbuf);
        } else if method == M_SHUFFLE || method == M_SHUFFLE_DELTA {
            inbuf.resize(n * fb, 0);
            src.read_exact(&mut inbuf)?;
            unshuffle_block(&inbuf, p, n, method == M_SHUFFLE_DELTA, &mut prev, &mut outbuf);
        } else {
            return Err(bad("unknown audio method"));
        }
        out.write_all(&outbuf)?;
        remaining -= n as u64;
    }
    Ok(())
}

// ===========================================================================
// Image (uncompressed BMP): colour decorrelation + MED predictor
// ===========================================================================

fn med_pred(pl: &[u8], w: usize, x: usize, y: usize) -> u8 {
    let i = y * w + x;
    if y == 0 {
        if x == 0 { 0 } else { pl[i - 1] }
    } else if x == 0 {
        pl[i - w]
    } else {
        let a = pl[i - 1] as i32;
        let b = pl[i - w] as i32;
        let c = pl[i - w - 1] as i32;
        let (mx, mn) = (a.max(b), a.min(b));
        (if c >= mx { mn } else if c <= mn { mx } else { a + b - c }) as u8
    }
}

fn image_forward(data: &[u8], p: &ImageParams) -> Vec<u8> {
    let (w, h, stride) = (p.width as usize, p.rows as usize, p.stride as usize);
    let nch = p.bpp as usize / 8;
    let padn = stride - w * nch;
    let mut pl: Vec<Vec<u8>> = vec![vec![0u8; w * h]; nch];
    let mut pad = Vec::with_capacity(h * padn);
    for y in 0..h {
        let row = &data[y * stride..(y + 1) * stride];
        for x in 0..w {
            for (c, plane) in pl.iter_mut().enumerate() {
                plane[y * w + x] = row[x * nch + c];
            }
        }
        pad.extend_from_slice(&row[w * nch..]);
    }
    if nch >= 3 {
        for i in 0..w * h {
            let g = pl[1][i];
            pl[0][i] = pl[0][i].wrapping_sub(g);
            pl[2][i] = pl[2][i].wrapping_sub(g);
        }
    }
    let mut out = Vec::with_capacity(h * stride);
    for plane in &pl {
        for y in 0..h {
            for x in 0..w {
                out.push(plane[y * w + x].wrapping_sub(med_pred(plane, w, x, y)));
            }
        }
    }
    out.extend_from_slice(&pad);
    out
}

fn image_inverse(enc: &[u8], p: &ImageParams) -> Vec<u8> {
    let (w, h, stride) = (p.width as usize, p.rows as usize, p.stride as usize);
    let nch = p.bpp as usize / 8;
    let padn = stride - w * nch;
    let mut pl: Vec<Vec<u8>> = vec![vec![0u8; w * h]; nch];
    for (c, plane) in pl.iter_mut().enumerate() {
        let res = &enc[c * w * h..(c + 1) * w * h];
        for y in 0..h {
            for x in 0..w {
                let v = res[y * w + x].wrapping_add(med_pred(plane, w, x, y));
                plane[y * w + x] = v;
            }
        }
    }
    if nch >= 3 {
        for i in 0..w * h {
            let g = pl[1][i];
            pl[0][i] = pl[0][i].wrapping_add(g);
            pl[2][i] = pl[2][i].wrapping_add(g);
        }
    }
    let pad = &enc[nch * w * h..];
    let mut out = vec![0u8; h * stride];
    for y in 0..h {
        let row = &mut out[y * stride..(y + 1) * stride];
        for x in 0..w {
            for (c, plane) in pl.iter().enumerate() {
                row[x * nch + c] = plane[y * w + x];
            }
        }
        row[w * nch..].copy_from_slice(&pad[y * padn..(y + 1) * padn]);
    }
    out
}

// ===========================================================================
// Whole-file encode / decode
// ===========================================================================

pub fn encode<R: Read, W: Write>(src: &mut R, size: u64, d: &Detected, method: u8, level: u32, out: &mut W) -> io::Result<()> {
    match d.plan {
        Plan::Audio(p) => {
            pipe(src, out, p.offset)?;
            encode_audio_region(src, &p, method, level, out)?;
            pipe(src, out, size - p.offset - p.region_bytes())
        }
        Plan::Image(p) => {
            pipe(src, out, p.offset)?;
            let mut data = vec![0u8; p.region_bytes() as usize];
            src.read_exact(&mut data)?;
            out.write_all(&image_forward(&data, &p))?;
            pipe(src, out, size - p.offset - p.region_bytes())
        }
    }
}

pub fn decode<R: Read, W: Write>(src: &mut R, size: u64, filter: u8, method: u8, params: &[u8], out: &mut W) -> io::Result<()> {
    match filter {
        FILTER_AUDIO => {
            let p = AudioParams::from_bytes(params).ok_or_else(|| bad("invalid audio parameters"))?;
            if p.offset.checked_add(p.region_bytes()).map_or(true, |e| e > size) {
                return Err(bad("invalid audio parameters"));
            }
            pipe(src, out, p.offset)?;
            decode_audio_region(src, &p, method, out)?;
            pipe(src, out, size - p.offset - p.region_bytes())
        }
        FILTER_IMAGE => {
            let p = ImageParams::from_bytes(params).ok_or_else(|| bad("invalid image parameters"))?;
            if method != M_MED || p.offset.checked_add(p.region_bytes()).map_or(true, |e| e > size) {
                return Err(bad("invalid image parameters"));
            }
            pipe(src, out, p.offset)?;
            let region = p.region_bytes() as usize;
            let mut enc = vec![0u8; region];
            src.read_exact(&mut enc)?;
            out.write_all(&image_inverse(&enc, &p))?;
            pipe(src, out, size - p.offset - region as u64)
        }
        _ => Err(bad("unknown media filter (archive made by a newer nikpak?)")),
    }
}

// ===========================================================================
// Trial: which method is best for this file?
// ===========================================================================

struct Counter(u64);
impl Write for Counter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0 += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ZCount(zstd::stream::write::Encoder<'static, Counter>);

impl ZCount {
    fn new() -> io::Result<Self> {
        Ok(ZCount(zstd::stream::write::Encoder::new(Counter(0), 3)?))
    }
    fn finish(self) -> io::Result<u64> {
        Ok(self.0.finish()?.0)
    }
}

impl Write for ZCount {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

pub struct Eval {
    /// bytes of the measured sample (before compression)
    pub sample: u64,
    /// plain zstd-3 size of the same sample
    pub raw: u64,
    /// (method, estimated size)
    pub cands: Vec<(u8, u64)>,
}

pub fn evaluate(f: &mut File, d: &Detected, level: u32, full: bool) -> io::Result<Eval> {
    let mut eval = Eval { sample: 0, raw: 0, cands: d.methods().into_iter().map(|m| (m, 0)).collect() };
    match d.plan {
        Plan::Audio(p) => {
            let fb = p.frame_bytes() as u64;
            let region = p.region_bytes();
            let mut windows: Vec<(u64, u64)> = Vec::new(); // (start frame, frames)
            if full || region <= 3 << 20 {
                windows.push((0, p.frames));
            } else {
                let wf = ((768u64 * 1024) / fb).max(1);
                for pct in [5u64, 45, 85] {
                    windows.push(((p.frames * pct / 100).min(p.frames - wf), wf));
                }
            }
            for (start, frames) in windows {
                let wp = AudioParams { frames, ..p };
                eval.sample += frames * fb;
                // plain
                f.seek(SeekFrom::Start(p.offset + start * fb))?;
                let mut z = ZCount::new()?;
                pipe(&mut Read::by_ref(f).take(frames * fb), &mut z, frames * fb)?;
                eval.raw += z.finish()?;
                for (m, size) in eval.cands.iter_mut() {
                    f.seek(SeekFrom::Start(p.offset + start * fb))?;
                    let mut src = Read::by_ref(f).take(frames * fb);
                    if *m == M_NAC {
                        let mut c = Counter(0);
                        encode_audio_region(&mut src, &wp, *m, level, &mut c)?;
                        *size += c.0;
                    } else {
                        let mut z = ZCount::new()?;
                        encode_audio_region(&mut src, &wp, *m, level, &mut z)?;
                        *size += z.finish()?;
                    }
                }
            }
        }
        Plan::Image(p) => {
            // estimate on at most ~4 MiB worth of rows
            let rows = ((4u64 << 20) / p.stride as u64).clamp(1, p.rows as u64) as u32;
            let sp = ImageParams { rows: if full { p.rows } else { rows }, ..p };
            let n = sp.region_bytes() as usize;
            f.seek(SeekFrom::Start(p.offset))?;
            let mut data = vec![0u8; n];
            f.read_exact(&mut data)?;
            eval.sample = n as u64;
            let mut z = ZCount::new()?;
            z.write_all(&data)?;
            eval.raw = z.finish()?;
            let mut z = ZCount::new()?;
            z.write_all(&image_forward(&data, &sp))?;
            eval.cands[0].1 = z.finish()?;
        }
    }
    f.seek(SeekFrom::Start(0))?;
    Ok(eval)
}

/// Pick the best method, or None when plain compression is (nearly) as good.
pub fn choose(f: &mut File, d: &Detected, level: u32) -> io::Result<Option<u8>> {
    let e = evaluate(f, d, level, false)?;
    let best = e.cands.iter().min_by_key(|c| c.1).copied();
    Ok(match best {
        Some((m, s)) if (s as f64) < e.raw as f64 * 0.98 => Some(m),
        _ => None,
    })
}

/// Map a compression level to the NAC effort level (0..=2).
pub fn nac_level(zstd_level: i32) -> u32 {
    if zstd_level <= 1 {
        0
    } else if zstd_level <= 9 {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn range(&mut self, lo: i64, hi: i64) -> i64 {
            lo + (self.next() % ((hi - lo + 1) as u64)) as i64
        }
    }

    fn limits(bits: u32) -> (i64, i64) {
        (-(1i64 << (bits - 1)), (1i64 << (bits - 1)) - 1)
    }

    fn signal(kind: u32, n: usize, bits: u32, rng: &mut Rng) -> Vec<i64> {
        let (lo, hi) = limits(bits);
        (0..n)
            .map(|i| match kind {
                0 => 0,
                1 => ((i as f64 * 0.05).sin() * (hi as f64 * 0.6)) as i64 + rng.range(-3, 3),
                2 => rng.range(lo, hi),
                3 => if (i / 7) % 2 == 0 { hi } else { lo },
                4 => (lo + (i as i64 * 977)).clamp(lo, hi),
                5 => if i == n / 2 { hi } else { 0 },
                6 => hi,
                7 => (rng.range(-40, 40) << 4).clamp(lo, hi), // wasted bits
                _ => lo,
            })
            .collect()
    }

    #[test]
    fn nac_roundtrip_matrix() {
        let mut rng = Rng(0x1234_5678_9abc_def1);
        for bits in [8u32, 16, 24, 32] {
            for channels in [1usize, 2, 3, 6] {
                for kind in 0..9u32 {
                    for n in [1usize, 2, 3, 17, 100, 1000, 4096, 5000] {
                        let chans: Vec<Vec<i64>> = (0..channels).map(|c| signal((kind + c as u32) % 9, n, bits, &mut rng)).collect();
                        for level in 0..=2u32 {
                            let data = nac::encode_block(&chans, bits, level, false);
                            let back = nac::decode_block(&data, channels, bits, n).expect("decode");
                            assert_eq!(back, chans, "bits={bits} ch={channels} kind={kind} n={n} level={level}");
                        }
                        let v = nac::encode_block(&chans, bits, 0, true);
                        assert_eq!(nac::decode_block(&v, channels, bits, n).unwrap(), chans, "verbatim");
                    }
                }
            }
        }
    }

    #[test]
    fn nac_decoder_survives_garbage() {
        let mut rng = Rng(42);
        for _ in 0..4000 {
            let len = rng.range(0, 300) as usize;
            let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let ch = rng.range(1, 3) as usize;
            let bits = [8u32, 16, 24, 32][rng.range(0, 3) as usize];
            let n = rng.range(1, 600) as usize;
            let _ = nac::decode_block(&data, ch, bits, n); // must not panic
        }
        // flipping bits of a valid block must not panic either
        let chans = vec![signal(1, 4096, 16, &mut rng), signal(1, 4096, 16, &mut rng)];
        let good = nac::encode_block(&chans, 16, 1, false);
        for i in 0..good.len().min(400) {
            let mut b = good.clone();
            b[i] ^= 1 << (i % 8);
            let _ = nac::decode_block(&b, 2, 16, 4096);
        }
    }

    fn make_params(bits: u8, channels: u8, be: bool, signed: bool, frames: u64) -> AudioParams {
        AudioParams { offset: 0, frames, channels, bits, big_endian: be, signed }
    }

    #[test]
    fn audio_methods_roundtrip_all_layouts() {
        let mut rng = Rng(99);
        for bits in [8u8, 16, 24, 32] {
            for channels in [1u8, 2, 5] {
                for (be, signed) in [(false, true), (true, true), (false, false)] {
                    if bits != 8 && !signed {
                        continue;
                    }
                    for frames in [1u64, 7, 4096, 4097, 40_000, 70_000] {
                        let p = make_params(bits, channels, be, signed, frames);
                        let mut raw = vec![0u8; p.region_bytes() as usize];
                        let smooth = rng.range(0, 1) == 1;
                        for (i, b) in raw.iter_mut().enumerate() {
                            *b = if smooth { ((i / (channels as usize * (bits as usize / 8))) as f64 * 0.01).sin().mul_add(60.0, 128.0) as u8 } else { rng.next() as u8 };
                        }
                        for m in [M_NAC, M_SHUFFLE, M_SHUFFLE_DELTA] {
                            let mut enc = Vec::new();
                            encode_audio_region(&mut Cursor::new(&raw), &p, m, 1, &mut enc).unwrap();
                            let mut dec = Vec::new();
                            decode_audio_region(&mut Cursor::new(&enc), &p, m, &mut dec).unwrap();
                            assert_eq!(dec, raw, "bits={bits} ch={channels} be={be} signed={signed} frames={frames} method={m}");
                        }
                    }
                }
            }
        }
    }

    fn tmp(name: &str, data: &[u8]) -> (File, std::path::PathBuf) {
        let p = std::env::temp_dir().join(format!("nikpak_test_{}_{}", std::process::id(), name));
        std::fs::write(&p, data).unwrap();
        (File::open(&p).unwrap(), p)
    }

    fn wav(channels: u16, bits: u16, frames: usize, extensible: bool, trailer: &[u8], data_len_field: Option<u32>) -> Vec<u8> {
        let mut rng = Rng(7);
        let fb = channels as usize * bits as usize / 8;
        let mut data = vec![0u8; frames * fb];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (((i / fb) as f64 * 0.02).sin() * 50.0 + 128.0) as u8 ^ (rng.next() as u8 & 3);
        }
        let mut fmt = Vec::new();
        fmt.extend_from_slice(&(if extensible { 0xFFFEu16 } else { 1 }).to_le_bytes());
        fmt.extend_from_slice(&channels.to_le_bytes());
        fmt.extend_from_slice(&44100u32.to_le_bytes());
        fmt.extend_from_slice(&(44100 * fb as u32).to_le_bytes());
        fmt.extend_from_slice(&(fb as u16).to_le_bytes());
        fmt.extend_from_slice(&bits.to_le_bytes());
        if extensible {
            fmt.extend_from_slice(&22u16.to_le_bytes());
            fmt.extend_from_slice(&bits.to_le_bytes());
            fmt.extend_from_slice(&3u32.to_le_bytes());
            fmt.extend_from_slice(&1u16.to_le_bytes()); // PCM sub-format
            fmt.extend_from_slice(&[0, 0, 0, 0, 0x10, 0, 0x80, 0, 0, 0xAA, 0, 0x38, 0x9B, 0x71]);
        }
        let mut out = b"RIFF\0\0\0\0WAVE".to_vec();
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&(fmt.len() as u32).to_le_bytes());
        out.extend_from_slice(&fmt);
        out.extend_from_slice(b"LIST\x04\0\0\0abcd");
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data_len_field.unwrap_or(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&data);
        out.extend_from_slice(trailer);
        out
    }

    fn roundtrip_file(name: &str, bytes: &[u8], expect: Option<Kind>) {
        let (mut f, path) = tmp(name, bytes);
        let det = detect(&mut f, bytes.len() as u64);
        assert_eq!(det.map(|d| d.kind), expect, "{name}: detection");
        if let Some(d) = det {
            for m in d.methods() {
                let mut enc = Vec::new();
                f.seek(SeekFrom::Start(0)).unwrap();
                encode(&mut f, bytes.len() as u64, &d, m, 1, &mut enc).unwrap();
                let mut dec = Vec::new();
                decode(&mut Cursor::new(&enc), bytes.len() as u64, d.filter_id(), m, &d.params_bytes(), &mut dec).unwrap();
                assert!(dec == bytes, "{name}: method {m} did not round-trip");
            }
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn wav_variants() {
        roundtrip_file("w16s", &wav(2, 16, 20_000, false, b"", None), Some(Kind::Wav));
        roundtrip_file("w16m", &wav(1, 16, 30_000, false, b"", None), Some(Kind::Wav));
        roundtrip_file("w8", &wav(1, 8, 30_000, false, b"", None), Some(Kind::Wav));
        roundtrip_file("w24", &wav(2, 24, 9_000, false, b"", None), Some(Kind::Wav));
        roundtrip_file("w32", &wav(2, 32, 6_000, false, b"", None), Some(Kind::Wav));
        roundtrip_file("wext", &wav(2, 16, 20_000, true, b"", None), Some(Kind::Wav));
        roundtrip_file("w6ch", &wav(6, 16, 5_000, true, b"", None), Some(Kind::Wav));
        // trailing chunk after the audio, odd leftover bytes, bogus/zero/oversized data length
        roundtrip_file("wtrail", &wav(2, 16, 20_000, false, b"LIST\x08\0\0\0abcdefgh", None), Some(Kind::Wav));
        roundtrip_file("wodd", &wav(2, 16, 20_000, false, b"xyz", Some(20_000 * 4 + 3)), Some(Kind::Wav));
        roundtrip_file("wzero", &wav(2, 16, 20_000, false, b"", Some(0)), Some(Kind::Wav));
        roundtrip_file("wbig", &wav(2, 16, 20_000, false, b"", Some(0xFFFF_FFF0)), Some(Kind::Wav));
        // not PCM / too small / not media
        let mut flt = wav(2, 16, 20_000, false, b"", None);
        flt[20] = 3; // float format tag
        roundtrip_file("wfloat", &flt, None);
        roundtrip_file("wtiny", &wav(1, 16, 100, false, b"", None), None);
        roundtrip_file("text", &vec![b'a'; 50_000], None);
    }

    #[test]
    fn aiff_mod_bmp() {
        // AIFF 16-bit stereo, big endian
        let frames = 10_000usize;
        let mut aiff = b"FORM\0\0\0\0AIFF".to_vec();
        aiff.extend_from_slice(b"COMM\0\0\0\x12");
        aiff.extend_from_slice(&2u16.to_be_bytes());
        aiff.extend_from_slice(&(frames as u32).to_be_bytes());
        aiff.extend_from_slice(&16u16.to_be_bytes());
        aiff.extend_from_slice(&[0x40, 0x0E, 0xAC, 0x44, 0, 0, 0, 0, 0, 0]);
        aiff.extend_from_slice(b"SSND");
        aiff.extend_from_slice(&((frames * 4 + 8) as u32).to_be_bytes());
        aiff.extend_from_slice(&[0u8; 8]);
        for i in 0..frames {
            let v = ((i as f64 * 0.03).sin() * 9000.0) as i16;
            aiff.extend_from_slice(&v.to_be_bytes());
            aiff.extend_from_slice(&(v / 2).to_be_bytes());
        }
        roundtrip_file("aiff", &aiff, Some(Kind::Aiff));

        // MOD: 2 patterns, one 20000-byte sample
        let mut m = vec![0u8; 1084];
        m[20 + 22..20 + 24].copy_from_slice(&10_000u16.to_be_bytes());
        m[950] = 2;
        m[953] = 1; // pattern table: 0,1
        m[1080..1084].copy_from_slice(b"M.K.");
        m.extend_from_slice(&vec![0x11u8; 2 * 1024]);
        for i in 0..20_000usize {
            m.push(((i as f64 * 0.05).sin() * 90.0) as i8 as u8);
        }
        roundtrip_file("mod", &m, Some(Kind::Mod));
        // truncated MOD (sample data cut short) must still be handled
        roundtrip_file("modtrunc", &m[..m.len() - 7000], Some(Kind::Mod));

        // BMP 24-bit with row padding (width 5 -> stride 16), 8-bit and 32-bit
        for (w, h, bpp) in [(5u32, 700u32, 24u16), (128, 100, 8), (33, 90, 32), (1, 5000, 24)] {
            let stride = (((w * bpp as u32) + 31) / 32 * 4) as usize;
            let mut b = vec![0u8; 54];
            b[0..2].copy_from_slice(b"BM");
            b[10..14].copy_from_slice(&54u32.to_le_bytes());
            b[14..18].copy_from_slice(&40u32.to_le_bytes());
            b[18..22].copy_from_slice(&(w as i32).to_le_bytes());
            b[22..26].copy_from_slice(&(h as i32).to_le_bytes());
            b[26..28].copy_from_slice(&1u16.to_le_bytes());
            b[28..30].copy_from_slice(&bpp.to_le_bytes());
            let mut rng = Rng(5);
            for y in 0..h as usize {
                for x in 0..stride {
                    b.push(((x * 3 + y * 2) as u8).wrapping_add(rng.next() as u8 & 7));
                }
            }
            b.extend_from_slice(b"trailing");
            roundtrip_file(&format!("bmp{bpp}_{w}"), &b, Some(Kind::Bmp));
        }
    }

    #[test]
    fn media_decoder_survives_garbage() {
        let mut rng = Rng(1234);
        for _ in 0..1500 {
            let len = rng.range(0, 400) as usize;
            let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let p = make_params([8u8, 16, 24, 32][rng.range(0, 3) as usize], rng.range(1, 4) as u8, rng.range(0, 1) == 1, true, rng.range(1, 3000) as u64);
            for m in [M_NAC, M_SHUFFLE, M_SHUFFLE_DELTA] {
                let _ = decode_audio_region(&mut Cursor::new(&data), &p, m, &mut io::sink());
            }
            let params: Vec<u8> = (0..rng.range(0, 30) as usize).map(|_| rng.next() as u8).collect();
            let _ = decode(&mut Cursor::new(&data), 100_000, rng.range(0, 3) as u8, rng.range(0, 4) as u8, &params, &mut io::sink());
        }
    }

    #[test]
    fn chunk_framing() {
        let mut out = Vec::new();
        {
            let mut cw = ChunkWriter::new(&mut out);
            cw.write_all(&vec![7u8; 200_000]).unwrap();
            cw.write_all(b"tail").unwrap();
            cw.finish().unwrap();
        }
        out.extend_from_slice(b"NEXT");
        let mut cur = Cursor::new(&out);
        let mut cr = ChunkReader::new(&mut cur);
        let mut got = Vec::new();
        cr.read_to_end(&mut got).unwrap();
        assert_eq!(got.len(), 200_004);
        let mut rest = Vec::new();
        cur.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"NEXT");
    }
}
