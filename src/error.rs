//! Error type and exit codes (modelled on RAR's exit codes).

use std::fmt;

#[derive(Debug)]
pub enum NikError {
    /// Bad command line (exit 7)
    Usage(String),
    /// Fatal error (exit 2)
    Fatal(String),
    /// Checksum / corruption error (exit 3)
    Corrupt(String),
    /// Wrong or missing password (exit 11)
    Password(String),
    /// Nothing matched (exit 10)
    NoFiles(String),
}

impl NikError {
    pub fn exit_code(&self) -> u8 {
        match self {
            NikError::Usage(_) => 7,
            NikError::Fatal(_) => 2,
            NikError::Corrupt(_) => 3,
            NikError::Password(_) => 11,
            NikError::NoFiles(_) => 10,
        }
    }
}

impl fmt::Display for NikError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NikError::Usage(m)
            | NikError::Fatal(m)
            | NikError::Corrupt(m)
            | NikError::Password(m)
            | NikError::NoFiles(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for NikError {}

/// Marker error used inside io::Error when AEAD authentication fails.
#[derive(Debug)]
pub struct AuthFailed;

impl fmt::Display for AuthFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "authentication failed")
    }
}
impl std::error::Error for AuthFailed {}

pub type Result<T> = std::result::Result<T, NikError>;

/// Convert an io::Error into a NikError, recognising authentication failures.
pub fn from_io(e: std::io::Error, ctx: &str) -> NikError {
    if let Some(inner) = e.get_ref() {
        if inner.downcast_ref::<AuthFailed>().is_some() {
            return NikError::Password(
                "Wrong password, or the archive is damaged / has been tampered with.".into(),
            );
        }
    }
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        return NikError::Corrupt(format!("{ctx}: unexpected end of archive (file truncated?)"));
    }
    // Errors raised by the decompressor (checksum / frame errors) while reading an
    // archive are reported as corruption, not as generic failures.
    if e.kind() == std::io::ErrorKind::Other && (ctx.starts_with("Reading") || ctx.starts_with("Verifying")) {
        return NikError::Corrupt(format!("Archive is damaged: {e}"));
    }
    if e.kind() == std::io::ErrorKind::InvalidData {
        return NikError::Corrupt(format!("{ctx}: {e}"));
    }
    NikError::Fatal(format!("{ctx}: {e}"))
}
