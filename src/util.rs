//! Helpers: password handling, path sanitising, formatting.

use crate::error::{NikError, Result};
use crate::format::MIN_PASSWORD_LEN;
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum PwdSpec {
    /// No encryption requested.
    None,
    /// Encryption requested, password to be prompted (or generated).
    Prompt,
    /// Password given on the command line.
    Given(String),
}

pub const ENV_PASSWORD: &str = "NIKPAK_PASSWORD";

/// 24 characters from a 56-symbol alphabet without look-alikes: ~139 bits.
pub fn generate_password() -> Zeroizing<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    let n = ALPHABET.len() as u32; // 56
    let limit = (u32::MAX / n) * n; // rejection sampling: no modulo bias
    let mut out = Zeroizing::new(String::with_capacity(24));
    while out.len() < 24 {
        let r = OsRng.next_u32();
        if r < limit {
            out.push(ALPHABET[(r % n) as usize] as char);
        }
    }
    out
}

fn check_len(pw: &str) -> Result<()> {
    if pw.chars().count() < MIN_PASSWORD_LEN {
        return Err(NikError::Password(format!(
            "Password too short: at least {MIN_PASSWORD_LEN} characters are required."
        )));
    }
    Ok(())
}

fn read_line_stdin() -> Option<Zeroizing<String>> {
    let mut s = String::new();
    match io::stdin().lock().read_line(&mut s) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(Zeroizing::new(s.trim_end_matches(['\r', '\n']).to_string())),
    }
}

/// Password for CREATING an archive. Never fails because of a missing
/// password: if none is supplied a random one is generated and shown.
pub fn password_for_create(spec: &PwdSpec) -> Result<Option<Zeroizing<String>>> {
    match spec {
        PwdSpec::None => Ok(None),
        PwdSpec::Given(p) if !p.is_empty() => {
            check_len(p)?;
            Ok(Some(Zeroizing::new(p.clone())))
        }
        _ => {
            // Environment variable (useful for GUIs / scripts)
            if let Ok(p) = std::env::var(ENV_PASSWORD) {
                if !p.is_empty() {
                    check_len(&p)?;
                    return Ok(Some(Zeroizing::new(p)));
                }
            }
            if io::stdin().is_terminal() {
                eprintln!("Encrypted archive: choose a password (min. {MIN_PASSWORD_LEN} characters).");
                eprintln!("Press ENTER on an empty line to generate a random password.");
                let p1 = rpassword::prompt_password("Enter password: ")
                    .map_err(|e| NikError::Fatal(format!("Cannot read password: {e}")))?;
                let p1 = Zeroizing::new(p1);
                if !p1.is_empty() {
                    let p2 = Zeroizing::new(
                        rpassword::prompt_password("Repeat password: ")
                            .map_err(|e| NikError::Fatal(format!("Cannot read password: {e}")))?,
                    );
                    if *p1 != *p2 {
                        return Err(NikError::Password("Passwords do not match.".into()));
                    }
                    check_len(&p1)?;
                    return Ok(Some(p1));
                }
            } else if let Some(line) = read_line_stdin() {
                // Non-interactive: accept a password piped on stdin
                if !line.is_empty() {
                    check_len(&line)?;
                    return Ok(Some(line));
                }
            }
            let p = generate_password();
            println!();
            println!("==============================================================");
            println!(" No password supplied - a random password was generated:");
            println!();
            println!("     {}", &*p);
            println!();
            println!(" Copy it NOW and keep it safe. Without it the archive can");
            println!(" NEVER be opened - there is no recovery.");
            println!("==============================================================");
            println!();
            Ok(Some(p))
        }
    }
}

/// Password for OPENING an encrypted archive.
pub fn password_for_open(spec: &PwdSpec) -> Result<Zeroizing<String>> {
    if let PwdSpec::Given(p) = spec {
        if !p.is_empty() {
            return Ok(Zeroizing::new(p.clone()));
        }
    }
    if let Ok(p) = std::env::var(ENV_PASSWORD) {
        if !p.is_empty() {
            return Ok(Zeroizing::new(p));
        }
    }
    if io::stdin().is_terminal() {
        let p = rpassword::prompt_password("Enter password: ")
            .map_err(|e| NikError::Fatal(format!("Cannot read password: {e}")))?;
        if p.is_empty() {
            return Err(NikError::Password("No password entered.".into()));
        }
        return Ok(Zeroizing::new(p));
    }
    if let Some(line) = read_line_stdin() {
        if !line.is_empty() {
            return Ok(line);
        }
    }
    Err(NikError::Password(
        "This archive is encrypted and a password is required.\n\
         Use -p<password> on the command line, or set the NIKPAK_PASSWORD environment variable."
            .into(),
    ))
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Turn a user-supplied path into a clean, relative, '/'-separated name.
/// Drops root, drive prefix, `.` and `..` components.
pub fn clean_name_components(p: &Path) -> Vec<String> {
    let mut v = Vec::new();
    for c in p.components() {
        if let Component::Normal(s) = c {
            if let Some(s) = s.to_str() {
                v.push(s.to_string());
            }
        }
    }
    v
}

#[cfg(windows)]
fn component_is_bad(c: &str) -> bool {
    if c.chars().any(|ch| ch.is_control() || "<>:\"|?*".contains(ch)) {
        return true;
    }
    if c.ends_with(' ') || c.ends_with('.') {
        return true;
    }
    let stem = c.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL"
            | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9"
            | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
    )
}

#[cfg(not(windows))]
fn component_is_bad(c: &str) -> bool {
    c.contains('\0')
}

/// Validate an entry name read from an archive (UNTRUSTED input).
/// Returns the safe relative components, or Err(reason).
pub fn sanitize_entry_name(name: &str) -> std::result::Result<Vec<String>, String> {
    let n = name.replace('\\', "/");
    let mut out = Vec::new();
    for part in n.split('/') {
        match part {
            "" | "." => continue,
            ".." => return Err("path traversal ('..')".into()),
            p => {
                if component_is_bad(p) {
                    return Err(format!("invalid file name '{p}'"));
                }
                out.push(p.to_string());
            }
        }
    }
    if out.is_empty() {
        return Err("empty name".into());
    }
    Ok(out)
}

/// Refuse to write through symbolic links that already exist below `root`.
pub fn check_no_symlinks(root: &Path, comps: &[String]) -> std::result::Result<(), String> {
    let mut p = root.to_path_buf();
    for c in comps {
        p.push(c);
        if let Ok(md) = std::fs::symlink_metadata(&p) {
            if md.file_type().is_symlink() {
                return Err(format!("'{}' is a symbolic link", p.display()));
            }
        }
    }
    Ok(())
}

pub fn join_components(root: &Path, comps: &[String]) -> PathBuf {
    let mut p = root.to_path_buf();
    for c in comps {
        p.push(c);
    }
    p
}

// ---------------------------------------------------------------------------
// Wildcards
// ---------------------------------------------------------------------------

pub fn has_wildcard(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

pub fn wildcard_match(pattern: &str, name: &str) -> bool {
    let opts = glob::MatchOptions {
        case_sensitive: !cfg!(windows),
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };
    match glob::Pattern::new(pattern) {
        Ok(p) => p.matches_with(name, opts),
        Err(_) => pattern == name,
    }
}

/// Does `name` (stored path, '/' separated) match a user filter?
/// A filter matches the full path, the base name, or a parent directory.
pub fn filter_matches(filter: &str, name: &str) -> bool {
    let f = filter.replace('\\', "/");
    let f = f.trim_end_matches('/');
    if f.is_empty() {
        return true;
    }
    if wildcard_match(f, name) {
        return true;
    }
    if let Some(base) = name.rsplit('/').next() {
        if !f.contains('/') && wildcard_match(f, base) {
            return true;
        }
    }
    // directory prefix
    let prefix = format!("{f}/");
    if name.len() > prefix.len() && name[..prefix.len()].eq_ignore_ascii_case(&prefix) {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

pub fn human_size(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Unix seconds -> "YYYY-MM-DD HH:MM" (UTC).
pub fn format_time(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m) = (rem / 3600, (rem % 3600) / 60);
    // Howard Hinnant's civil-from-days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}")
}

pub fn ask_yes_no(prompt: &str) -> Option<char> {
    // returns 'y', 'n', 'a' (all), 's' (skip all) or None when not interactive
    if !io::stdin().is_terminal() {
        return None;
    }
    loop {
        eprint!("{prompt} [Y]es, [N]o, [A]ll, [S]kip all: ");
        let _ = io::stderr().flush();
        let mut s = String::new();
        if io::stdin().read_line(&mut s).unwrap_or(0) == 0 {
            return None;
        }
        match s.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Some('y'),
            "n" | "no" | "" => return Some('n'),
            "a" | "all" => return Some('a'),
            "s" | "skip" => return Some('s'),
            _ => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_blocks_traversal() {
        assert!(sanitize_entry_name("../x").is_err());
        assert!(sanitize_entry_name("a/../../x").is_err());
        assert!(sanitize_entry_name("..\\x").is_err());
        assert!(sanitize_entry_name("").is_err());
        assert_eq!(sanitize_entry_name("/etc/passwd").unwrap(), vec!["etc", "passwd"]);
        assert_eq!(sanitize_entry_name("./a//b/c.txt").unwrap(), vec!["a", "b", "c.txt"]);
    }

    #[test]
    fn generated_passwords_are_long_and_distinct() {
        let a = generate_password();
        let b = generate_password();
        assert_eq!(a.len(), 24);
        assert_ne!(*a, *b);
    }

    #[test]
    fn date_formatting() {
        assert_eq!(format_time(0), "1970-01-01 00:00");
        assert_eq!(format_time(1_700_000_000), "2023-11-14 22:13");
    }

    #[test]
    fn filters() {
        assert!(filter_matches("*.txt", "a/b/c.txt"));
        assert!(filter_matches("a", "a/b/c.txt"));
        assert!(filter_matches("a/b", "a/b/c.txt"));
        assert!(!filter_matches("*.bin", "a/b/c.txt"));
    }
}
