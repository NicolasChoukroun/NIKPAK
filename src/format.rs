//! On-disk layout of a .nik archive.
//!
//! ```text
//! offset  size  field
//! 0       8     magic   89 4E 49 4B 0D 0A 1A 0A  ("\x89NIK\r\n\x1a\n")
//! 8       1     version (2; 1 is still readable)
//! 9       1     flags   bit0 = encrypted
//! 10      1     method  0 = store, 1 = zstd
//! 11      1     reserved (0)
//! -- only when encrypted --
//! 12      4     argon2 memory cost (KiB, LE)
//! 16      4     argon2 time cost   (LE)
//! 20      4     argon2 lanes       (LE)
//! 24      16    argon2 salt (random)
//! 40      19    stream nonce prefix (random)
//! -- body --
//! The "inner stream" (see archive.rs) optionally zstd-compressed, optionally
//! cut into 64 KiB chunks, each sealed with XChaCha20-Poly1305 (STREAM/BE32).
//! The complete header is bound to every chunk as associated data.
//! ```

pub const MAGIC: [u8; 8] = [0x89, b'N', b'I', b'K', 0x0D, 0x0A, 0x1A, 0x0A];
pub const VERSION: u8 = 2; // 2 = adds media records (REC_MEDIA); version-1 archives are still readable
pub const FLAG_ENCRYPTED: u8 = 1;
pub const METHOD_STORE: u8 = 0;
pub const METHOD_ZSTD: u8 = 1;

pub const SALT_LEN: usize = 16;
pub const NONCE_PREFIX_LEN: usize = 19;
pub const KEY_LEN: usize = 32;

/// Plaintext bytes per encrypted chunk.
pub const CHUNK: usize = 64 * 1024;
pub const TAG_LEN: usize = 16;

// Argon2id parameters written by this version (RFC 9106 "low memory" profile).
pub const KDF_MEM_KIB: u32 = 64 * 1024; // 64 MiB
pub const KDF_TIME: u32 = 3;
pub const KDF_LANES: u32 = 4;

// Upper bounds accepted when reading (protects against malicious archives
// that try to exhaust memory / CPU before authentication).
pub const KDF_MAX_MEM_KIB: u32 = 1024 * 1024; // 1 GiB
pub const KDF_MAX_TIME: u32 = 64;
pub const KDF_MAX_LANES: u32 = 64;

pub const MIN_PASSWORD_LEN: usize = 8;

pub const EXT: &str = "nik";

#[derive(Clone, Debug)]
pub struct Header {
    pub encrypted: bool,
    pub method: u8,
    pub kdf_mem: u32,
    pub kdf_time: u32,
    pub kdf_lanes: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl Header {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(&MAGIC);
        v.push(VERSION);
        v.push(if self.encrypted { FLAG_ENCRYPTED } else { 0 });
        v.push(self.method);
        v.push(0);
        if self.encrypted {
            v.extend_from_slice(&self.kdf_mem.to_le_bytes());
            v.extend_from_slice(&self.kdf_time.to_le_bytes());
            v.extend_from_slice(&self.kdf_lanes.to_le_bytes());
            v.extend_from_slice(&self.salt);
            v.extend_from_slice(&self.nonce_prefix);
        }
        v
    }
}

/// Entry record types in the inner stream.
pub const REC_END: u8 = 0;
pub const REC_FILE: u8 = 1;
pub const REC_DIR: u8 = 2;
pub const REC_MEDIA: u8 = 3;

pub const MAX_NAME_LEN: usize = 4096;
