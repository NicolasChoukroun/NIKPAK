//! Encryption layer: Argon2id key derivation + XChaCha20-Poly1305 STREAM.
//!
//! * A fresh random salt and nonce prefix are generated for every archive.
//! * The STREAM construction (BE32) authenticates chunk order and marks the
//!   last chunk, so reordering, dropping or truncating chunks is detected.
//! * The whole header is passed as associated data, so changing KDF
//!   parameters, salt or method flags makes decryption fail.

use crate::error::AuthFailed;
use crate::format::*;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::Payload;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    mem: u32,
    time: u32,
    lanes: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let params = Params::new(mem, time, lanes, Some(KEY_LEN))
        .map_err(|e| format!("invalid key-derivation parameters: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key[..])
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Validate KDF parameters read from an (untrusted) archive header.
pub fn check_kdf_params(mem: u32, time: u32, lanes: u32) -> Result<(), String> {
    if lanes == 0 || lanes > KDF_MAX_LANES {
        return Err("archive header has invalid key-derivation parameters".into());
    }
    if mem < 8 * lanes || mem > KDF_MAX_MEM_KIB {
        return Err("archive header has invalid key-derivation parameters".into());
    }
    if time == 0 || time > KDF_MAX_TIME {
        return Err("archive header has invalid key-derivation parameters".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Buffers plaintext, seals it in CHUNK-sized frames: [u32 BE len][ciphertext].
///
/// A chunk is only sealed once at least one more byte has arrived, so the final
/// chunk is never empty and `finish()` can mark it as the last one.
pub struct EncryptWriter<W: Write> {
    inner: W,
    enc: Option<EncryptorBE32<XChaCha20Poly1305>>,
    aad: Vec<u8>,
    buf: Vec<u8>,
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(
        inner: W,
        key: &[u8; KEY_LEN],
        nonce_prefix: &[u8; NONCE_PREFIX_LEN],
        header_bytes: Vec<u8>,
    ) -> Self {
        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key));
        let enc = EncryptorBE32::from_aead(cipher, GenericArray::from_slice(nonce_prefix));
        EncryptWriter {
            inner,
            enc: Some(enc),
            aad: header_bytes,
            buf: Vec::with_capacity(CHUNK + 1),
        }
    }

    fn seal_full_chunk(&mut self) -> io::Result<()> {
        // buf holds > CHUNK bytes; seal the first CHUNK of them.
        let rest = self.buf.split_off(CHUNK);
        let ct = self
            .enc
            .as_mut()
            .expect("encryptor present")
            .encrypt_next(Payload { msg: &self.buf, aad: &self.aad })
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "encryption failed"))?;
        self.inner.write_all(&(ct.len() as u32).to_be_bytes())?;
        self.inner.write_all(&ct)?;
        self.buf = rest;
        Ok(())
    }

    /// Seal the remaining data as the last chunk and return the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        let enc = self.enc.take().expect("encryptor present");
        let ct = enc
            .encrypt_last(Payload { msg: &self.buf, aad: &self.aad })
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "encryption failed"))?;
        self.inner.write_all(&(ct.len() as u32).to_be_bytes())?;
        self.inner.write_all(&ct)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        while self.buf.len() > CHUNK {
            self.seal_full_chunk()?;
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

pub struct DecryptReader<R: Read> {
    inner: R,
    dec: Option<DecryptorBE32<XChaCha20Poly1305>>,
    aad: Vec<u8>,
    plain: Vec<u8>,
    pos: usize,
    next_len: Option<u32>,
    done: bool,
}

/// Read exactly 4 bytes. Ok(None) on clean EOF (0 bytes), error on partial.
fn read_len<R: Read>(r: &mut R) -> io::Result<Option<u32>> {
    let mut b = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = r.read(&mut b[got..])?;
        if n == 0 {
            if got == 0 {
                return Ok(None);
            }
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated chunk header"));
        }
        got += n;
    }
    Ok(Some(u32::from_be_bytes(b)))
}

impl<R: Read> DecryptReader<R> {
    pub fn new(
        inner: R,
        key: &[u8; KEY_LEN],
        nonce_prefix: &[u8; NONCE_PREFIX_LEN],
        header_bytes: Vec<u8>,
    ) -> Self {
        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key));
        let dec = DecryptorBE32::from_aead(cipher, GenericArray::from_slice(nonce_prefix));
        DecryptReader {
            inner,
            dec: Some(dec),
            aad: header_bytes,
            plain: Vec::new(),
            pos: 0,
            next_len: None,
            done: false,
        }
    }

    fn load_chunk(&mut self) -> io::Result<()> {
        let len = match self.next_len.take() {
            Some(l) => l,
            None => match read_len(&mut self.inner)? {
                Some(l) => l,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "encrypted stream is empty or truncated",
                    ))
                }
            },
        } as usize;
        if len < TAG_LEN || len > CHUNK + TAG_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid encrypted chunk size"));
        }
        let mut ct = vec![0u8; len];
        self.inner.read_exact(&mut ct)?;

        // Look ahead to learn whether this is the last chunk.
        self.next_len = read_len(&mut self.inner)?;
        let is_last = self.next_len.is_none();

        let payload = Payload { msg: &ct, aad: &self.aad };
        let pt = if is_last {
            let d = self.dec.take().expect("decryptor present");
            d.decrypt_last(payload)
        } else {
            self.dec.as_mut().expect("decryptor present").decrypt_next(payload)
        }
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, AuthFailed))?;

        self.plain = pt;
        self.pos = 0;
        if is_last {
            self.done = true;
        }
        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.plain.len() {
            if self.done {
                return Ok(0);
            }
            self.load_chunk()?;
        }
        let n = out.len().min(self.plain.len() - self.pos);
        out[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(len: usize) {
        let key = [7u8; KEY_LEN];
        let nonce = [9u8; NONCE_PREFIX_LEN];
        let hdr = b"header".to_vec();
        let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();

        let mut w = EncryptWriter::new(Vec::new(), &key, &nonce, hdr.clone());
        w.write_all(&data).unwrap();
        let ct = w.finish().unwrap();

        let mut r = DecryptReader::new(&ct[..], &key, &nonce, hdr.clone());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, data, "round trip of {len} bytes");

        // wrong header (AAD) must fail
        let mut r = DecryptReader::new(&ct[..], &key, &nonce, b"other".to_vec());
        assert!(r.read_to_end(&mut Vec::new()).is_err());
        // wrong key must fail
        let mut r = DecryptReader::new(&ct[..], &[8u8; KEY_LEN], &nonce, hdr.clone());
        assert!(r.read_to_end(&mut Vec::new()).is_err());
        // truncation must fail
        if ct.len() > 30 {
            let mut r = DecryptReader::new(&ct[..ct.len() - 5], &key, &nonce, hdr);
            assert!(r.read_to_end(&mut Vec::new()).is_err());
        }
    }

    #[test]
    fn stream_roundtrip_sizes() {
        for n in [0, 1, 100, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 5, 5 * CHUNK + 123] {
            roundtrip(n);
        }
    }

    #[test]
    fn kdf_params_are_bounded() {
        assert!(check_kdf_params(KDF_MEM_KIB, KDF_TIME, KDF_LANES).is_ok());
        assert!(check_kdf_params(u32::MAX, 3, 4).is_err());
        assert!(check_kdf_params(65536, 0, 4).is_err());
        assert!(check_kdf_params(65536, 3, 0).is_err());
        assert!(check_kdf_params(65536, 1000, 4).is_err());
    }
}
