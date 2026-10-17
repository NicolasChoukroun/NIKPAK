//! Creating, listing, testing and extracting .nik archives.
//!
//! Inner stream (before compression/encryption), all integers little-endian:
//!
//!   record := type:u8
//!     REC_FILE : name_len:u16 name mtime:i64 mode:u32 size:u64 data[size] crc32:u32
//!     REC_DIR  : name_len:u16 name mtime:i64 mode:u32
//!     REC_END  : count:u64
//!
//! The REC_END marker lets us detect truncated archives even without
//! encryption.

use crate::cli::{Command, EpMode, Level, MediaMode, Options, Overwrite};
use crate::crypto::{self, DecryptReader, EncryptWriter};
use crate::error::{from_io, NikError, Result};
use crate::format::*;
use crate::media;
use crate::util::*;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};


/// println! that exits quietly when stdout is closed (e.g. `nikpak lb x | head`).
macro_rules! outln {
    () => { outln!("") };
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        if writeln!(std::io::stdout(), $($arg)*).is_err() {
            std::process::exit(0);
        }
    }};
}

const IO_BUF: usize = 256 * 1024;

// ===========================================================================
// Writer-side plumbing
// ===========================================================================

enum Sink {
    Plain(BufWriter<File>),
    Enc(EncryptWriter<BufWriter<File>>),
}

impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Sink::Plain(w) => w.write(b),
            Sink::Enc(w) => w.write(b),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Sink::Plain(w) => w.flush(),
            Sink::Enc(w) => w.flush(),
        }
    }
}

impl Sink {
    fn finish(self) -> io::Result<()> {
        match self {
            Sink::Plain(mut w) => w.flush(),
            Sink::Enc(w) => {
                let mut inner = w.finish()?;
                inner.flush()?;
                inner.get_ref().sync_all()
            }
        }
    }
}

enum Compressor {
    Store(Sink),
    Zstd(zstd::stream::write::Encoder<'static, Sink>),
}

impl Write for Compressor {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Compressor::Store(w) => w.write(b),
            Compressor::Zstd(w) => w.write(b),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Compressor::Store(w) => w.flush(),
            Compressor::Zstd(w) => w.flush(),
        }
    }
}

impl Compressor {
    fn finish(self) -> io::Result<()> {
        match self {
            Compressor::Store(s) => s.finish(),
            Compressor::Zstd(e) => e.finish()?.finish(),
        }
    }
}

/// Removes the temporary file unless `keep` is called.
struct TempGuard {
    path: PathBuf,
    armed: bool,
}
impl TempGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

// ===========================================================================
// Collecting files to add
// ===========================================================================

struct Item {
    src: PathBuf,
    name: String,
    is_dir: bool,
    mtime: i64,
    mode: u32,
}

fn mtime_of(md: &fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn mode_of(md: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(md: &fs::Metadata) -> u32 {
    if md.is_dir() {
        0o755
    } else if md.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

struct Collector<'a> {
    items: Vec<Item>,
    warnings: u32,
    exclude: &'a [String],
    quiet: bool,
    archive_canon: Option<PathBuf>,
}

impl<'a> Collector<'a> {
    fn warn(&mut self, msg: String) {
        self.warnings += 1;
        eprintln!("WARNING: {msg}");
    }

    fn excluded(&self, name: &str) -> bool {
        self.exclude.iter().any(|x| filter_matches(x, name))
    }

    fn add_path(&mut self, src: &Path, name: String, top: bool) {
        let md = match fs::symlink_metadata(src) {
            Ok(m) => m,
            Err(e) => {
                self.warn(format!("Cannot access '{}': {e}", src.display()));
                return;
            }
        };
        if md.file_type().is_symlink() {
            self.warn(format!("Skipping symbolic link '{}'", src.display()));
            return;
        }
        if let Some(a) = &self.archive_canon {
            if let Ok(c) = fs::canonicalize(src) {
                if &c == a {
                    return; // never add the archive to itself
                }
            }
        }
        if !name.is_empty() {
            if name.len() > MAX_NAME_LEN {
                self.warn(format!("Name too long, skipped: '{}'", src.display()));
                return;
            }
            if self.excluded(&name) {
                return;
            }
        }
        if md.is_dir() {
            if !name.is_empty() {
                self.items.push(Item {
                    src: src.to_path_buf(),
                    name: name.clone(),
                    is_dir: true,
                    mtime: mtime_of(&md),
                    mode: mode_of(&md),
                });
            }
            let rd = match fs::read_dir(src) {
                Ok(r) => r,
                Err(e) => {
                    self.warn(format!("Cannot read folder '{}': {e}", src.display()));
                    return;
                }
            };
            let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
            entries.sort_by_key(|e| e.file_name());
            for e in entries {
                let fname = match e.file_name().into_string() {
                    Ok(s) => s,
                    Err(_) => {
                        self.warn(format!("Skipping non-Unicode file name in '{}'", src.display()));
                        continue;
                    }
                };
                let child_name = if name.is_empty() { fname } else { format!("{name}/{fname}") };
                self.add_path(&e.path(), child_name, false);
            }
        } else if md.is_file() {
            let _ = top;
            self.items.push(Item {
                src: src.to_path_buf(),
                name,
                is_dir: false,
                mtime: mtime_of(&md),
                mode: mode_of(&md),
            });
        } else {
            self.warn(format!("Skipping special file '{}'", src.display()));
        }
    }
}

fn base_name_for(arg: &Path, is_dir: bool, ep: EpMode) -> String {
    let comps = clean_name_components(arg);
    match ep {
        EpMode::Keep => comps.join("/"),
        EpMode::Names => comps.last().cloned().unwrap_or_default(),
        EpMode::BaseDir => {
            if is_dir {
                String::new()
            } else {
                comps.last().cloned().unwrap_or_default()
            }
        }
    }
}

fn expand_args(args: &[String]) -> (Vec<PathBuf>, Vec<String>) {
    let mut out = Vec::new();
    let mut warns = Vec::new();
    for a in args {
        let p = Path::new(a);
        if p.exists() || fs::symlink_metadata(p).is_ok() || !has_wildcard(a) {
            out.push(p.to_path_buf());
            continue;
        }
        match glob::glob(a) {
            Ok(paths) => {
                let mut n = 0;
                for g in paths.flatten() {
                    out.push(g);
                    n += 1;
                }
                if n == 0 {
                    warns.push(format!("No files match '{a}'"));
                }
            }
            Err(_) => warns.push(format!("Invalid wildcard pattern '{a}'")),
        }
    }
    (out, warns)
}

// ===========================================================================
// CREATE
// ===========================================================================

pub fn create(o: &Options) -> Result<u8> {
    let started = Instant::now();
    let archive = PathBuf::from(&o.archive);

    if let Some(parent) = archive.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(NikError::Fatal(format!(
                "Cannot create '{}': the folder '{}' does not exist.",
                o.archive,
                parent.display()
            )));
        }
    }
    if archive.is_dir() {
        return Err(NikError::Fatal(format!("'{}' is a folder, not an archive file.", o.archive)));
    }
    if archive.exists() {
        let allow = match o.overwrite {
            Overwrite::All => true,
            Overwrite::Skip => false,
            Overwrite::Rename => false,
            Overwrite::Ask => matches!(
                ask_yes_no(&format!("Archive '{}' already exists. Overwrite it?", o.archive)),
                Some('y') | Some('a')
            ),
        };
        if !allow {
            return Err(NikError::Fatal(format!(
                "Archive '{}' already exists. Adding to an existing archive is not supported;\n\
                 use -o+ to overwrite it, or choose another name.",
                o.archive
            )));
        }
    }

    // ---- collect --------------------------------------------------------
    let archive_canon = archive
        .parent()
        .map(|p| if p.as_os_str().is_empty() { Path::new(".") } else { p })
        .and_then(|p| fs::canonicalize(p).ok())
        .and_then(|p| archive.file_name().map(|f| p.join(f)));
    let mut col = Collector {
        items: Vec::new(),
        warnings: 0,
        exclude: &o.excludes,
        quiet: o.quiet,
        archive_canon,
    };
    let (paths, warns) = expand_args(&o.files);
    for w in warns {
        col.warn(w);
    }
    for p in &paths {
        let md = match fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(_) => {
                col.warn(format!("Cannot find '{}'", p.display()));
                continue;
            }
        };
        let name = base_name_for(p, md.is_dir(), o.ep);
        if name.is_empty() && !md.is_dir() {
            col.warn(format!("Cannot determine a name for '{}'", p.display()));
            continue;
        }
        col.add_path(p, name, true);
    }
    let _ = col.quiet;
    let warnings_collect = col.warnings;
    let items = col.items;
    if items.is_empty() {
        return Err(NikError::NoFiles("No files to add: nothing matched the given names.".into()));
    }

    // ---- password -------------------------------------------------------
    let password = password_for_create(&o.password)?;

    // ---- header ---------------------------------------------------------
    let method = match o.level {
        Level::Store => METHOD_STORE,
        Level::Zstd(_) => METHOD_ZSTD,
    };
    let header = Header {
        encrypted: password.is_some(),
        method,
        kdf_mem: KDF_MEM_KIB,
        kdf_time: KDF_TIME,
        kdf_lanes: KDF_LANES,
        salt: crypto::random_bytes::<SALT_LEN>(),
        nonce_prefix: crypto::random_bytes::<NONCE_PREFIX_LEN>(),
    };
    let header_bytes = header.to_bytes();

    // ---- open temp output ------------------------------------------------
    let mut tmp_name = archive.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp_path = PathBuf::from(tmp_name);
    let file = File::create(&tmp_path)
        .map_err(|e| NikError::Fatal(format!("Cannot create '{}': {e}", tmp_path.display())))?;
    let mut guard = TempGuard { path: tmp_path.clone(), armed: true };
    let mut bw = BufWriter::with_capacity(IO_BUF, file);
    bw.write_all(&header_bytes).map_err(|e| from_io(e, "Write error"))?;

    let sink = if let Some(pw) = &password {
        if !o.quiet {
            outln!("Deriving encryption key (Argon2id, 64 MiB)...");
        }
        let key = crypto::derive_key(pw, &header.salt, header.kdf_mem, header.kdf_time, header.kdf_lanes)
            .map_err(NikError::Fatal)?;
        Sink::Enc(EncryptWriter::new(bw, &key, &header.nonce_prefix, header_bytes.clone()))
    } else {
        Sink::Plain(bw)
    };

    let mut comp = match o.level {
        Level::Store => Compressor::Store(sink),
        Level::Zstd(lvl) => {
            let mut enc = zstd::stream::write::Encoder::new(sink, lvl)
                .map_err(|e| from_io(e, "Cannot start compressor"))?;
            let threads = if o.threads > 0 {
                o.threads
            } else {
                std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
            };
            if threads > 1 {
                enc.multithread(threads as u32).map_err(|e| from_io(e, "Cannot enable multithreading"))?;
            }
            let _ = enc.include_checksum(true);
            // High levels: 128 MiB window + long-distance matching finds repeats
            // that are far apart (large source trees, many similar documents).
            // 2^27 is within the decoder's default window limit, so every
            // zstd-capable reader can still decode it.
            if lvl >= 15 {
                let _ = enc.window_log(27);
                let _ = enc.long_distance_matching(true);
            }
            Compressor::Zstd(enc)
        }
    };

    // ---- write entries ----------------------------------------------------
    let mut warnings = warnings_collect;
    let mut count: u64 = 0;
    let mut total_in: u64 = 0;
    let mut media_files: u64 = 0;
    let mut buf = vec![0u8; IO_BUF];

    for it in &items {
        let name_bytes = it.name.as_bytes();
        if it.is_dir {
            write_rec_header(&mut comp, REC_DIR, name_bytes, it.mtime, it.mode, None)
                .map_err(|e| from_io(e, "Write error"))?;
            count += 1;
            if !o.quiet {
                outln!("Adding    {}/", it.name);
            }
            continue;
        }
        let mut f = match File::open(&it.src) {
            Ok(f) => f,
            Err(e) => {
                warnings += 1;
                eprintln!("WARNING: Cannot open '{}': {e} - skipped", it.src.display());
                continue;
            }
        };
        let size = match f.metadata() {
            Ok(m) => m.len(),
            Err(e) => {
                warnings += 1;
                eprintln!("WARNING: Cannot read size of '{}': {e} - skipped", it.src.display());
                continue;
            }
        };
        // ---- media filters (WAV / AIFF / MOD / BMP) ----
        if let (Level::Zstd(zl), true) = (o.level, o.media != MediaMode::Off) {
            if let Some(det) = media::detect(&mut f, size) {
                let nl = media::nac_level(zl);
                let method = if o.media == MediaMode::Force {
                    Some(det.default_method())
                } else {
                    match media::choose(&mut f, &det, nl) {
                        Ok(m) => m,
                        Err(_) => None,
                    }
                };
                let _ = f.seek(io::SeekFrom::Start(0));
                if let Some(m) = method {
                    let params = det.params_bytes();
                    write_rec_header(&mut comp, REC_MEDIA, name_bytes, it.mtime, it.mode, Some(size))
                        .map_err(|e| from_io(e, "Write error"))?;
                    comp.write_all(&[det.filter_id(), m, params.len() as u8])
                        .and_then(|_| comp.write_all(&params))
                        .map_err(|e| from_io(e, "Write error"))?;
                    let mut cw = media::ChunkWriter::new(&mut comp);
                    let mut rd = media::CrcRead::new(&mut f, size);
                    media::encode(&mut rd, size, &det, m, nl, &mut cw)
                        .map_err(|e| from_io(e, &format!("'{}'", it.src.display())))?;
                    cw.finish().map_err(|e| from_io(e, "Write error"))?;
                    let (crc, left) = rd.finish();
                    if left != 0 {
                        return Err(NikError::Fatal(format!(
                            "'{}' changed while it was being archived; aborting (archive not created).",
                            it.src.display()
                        )));
                    }
                    comp.write_all(&crc.to_le_bytes()).map_err(|e| from_io(e, "Write error"))?;
                    count += 1;
                    total_in += size;
                    media_files += 1;
                    if !o.quiet {
                        outln!("Adding    {}   [{} {}]", it.name, det.kind.name(), media::method_name(det.filter_id(), m));
                    }
                    continue;
                }
            }
        }
        write_rec_header(&mut comp, REC_FILE, name_bytes, it.mtime, it.mode, Some(size))
            .map_err(|e| from_io(e, "Write error"))?;
        let mut crc = crc32fast::Hasher::new();
        let mut remaining = size;
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let n = f.read(&mut buf[..want]).map_err(|e| {
                NikError::Fatal(format!("Read error on '{}': {e}", it.src.display()))
            })?;
            if n == 0 {
                return Err(NikError::Fatal(format!(
                    "'{}' became shorter while it was being archived; aborting (archive not created).",
                    it.src.display()
                )));
            }
            crc.update(&buf[..n]);
            comp.write_all(&buf[..n]).map_err(|e| from_io(e, "Write error"))?;
            remaining -= n as u64;
        }
        comp.write_all(&crc.finalize().to_le_bytes()).map_err(|e| from_io(e, "Write error"))?;
        count += 1;
        total_in += size;
        if !o.quiet {
            outln!("Adding    {}", it.name);
        }
    }

    // ---- trailer ----------------------------------------------------------
    comp.write_all(&[REC_END]).map_err(|e| from_io(e, "Write error"))?;
    comp.write_all(&count.to_le_bytes()).map_err(|e| from_io(e, "Write error"))?;
    comp.finish().map_err(|e| from_io(e, "Cannot finish archive"))?;

    if archive.exists() {
        let _ = fs::remove_file(&archive);
    }
    fs::rename(&tmp_path, &archive)
        .map_err(|e| NikError::Fatal(format!("Cannot create '{}': {e}", archive.display())))?;
    guard.disarm();

    let out_size = fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
    if !o.quiet {
        let secs = started.elapsed().as_secs_f64();
        let ratio = if total_in > 0 { out_size as f64 * 100.0 / total_in as f64 } else { 100.0 };
        outln!();
        outln!(
            "Done. {} entries, {} -> {} ({:.1}%), {:.2}s{}",
            count,
            human_size(total_in),
            human_size(out_size),
            ratio,
            secs,
            if header.encrypted { ", encrypted" } else { "" }
        );
        if media_files > 0 {
            outln!("{} media file(s) were compressed with media filters.", media_files);
        }
    }
    Ok(if warnings > 0 { 1 } else { 0 })
}

fn write_rec_header<W: Write>(
    w: &mut W,
    kind: u8,
    name: &[u8],
    mtime: i64,
    mode: u32,
    size: Option<u64>,
) -> io::Result<()> {
    w.write_all(&[kind])?;
    w.write_all(&(name.len() as u16).to_le_bytes())?;
    w.write_all(name)?;
    w.write_all(&mtime.to_le_bytes())?;
    w.write_all(&mode.to_le_bytes())?;
    if let Some(s) = size {
        w.write_all(&s.to_le_bytes())?;
    }
    Ok(())
}

// ===========================================================================
// Reader-side plumbing
// ===========================================================================

enum Source {
    Plain(BufReader<File>),
    Dec(DecryptReader<BufReader<File>>),
}

impl Read for Source {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Source::Plain(r) => r.read(b),
            Source::Dec(r) => r.read(b),
        }
    }
}

enum Inner {
    Store(Source),
    Zstd(zstd::stream::read::Decoder<'static, BufReader<Source>>),
}

impl Read for Inner {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Inner::Store(r) => r.read(b),
            Inner::Zstd(r) => r.read(b),
        }
    }
}

struct Opened {
    inner: Inner,
    encrypted: bool,
}

fn open_archive(o: &Options) -> Result<Opened> {
    let path = Path::new(&o.archive);
    let file = File::open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            NikError::Fatal(format!("Cannot open '{}': file not found.", o.archive))
        } else {
            NikError::Fatal(format!("Cannot open '{}': {e}", o.archive))
        }
    })?;
    let mut br = BufReader::with_capacity(IO_BUF, file);

    let mut fixed = [0u8; 12];
    br.read_exact(&mut fixed).map_err(|_| {
        NikError::Corrupt(format!("'{}' is not a valid .nik archive (file too short).", o.archive))
    })?;
    if fixed[..8] != MAGIC {
        return Err(NikError::Corrupt(format!("'{}' is not a .nik archive (bad signature).", o.archive)));
    }
    if fixed[8] == 0 || fixed[8] > VERSION {
        return Err(NikError::Fatal(format!(
            "Unsupported archive version {}. This nikpak understands version {VERSION}; please update nikpak.",
            fixed[8]
        )));
    }
    let flags = fixed[9];
    let method = fixed[10];
    if flags & !FLAG_ENCRYPTED != 0 || fixed[11] != 0 {
        return Err(NikError::Fatal("Archive uses unknown features; please update nikpak.".into()));
    }
    if method != METHOD_STORE && method != METHOD_ZSTD {
        return Err(NikError::Fatal("Archive uses an unknown compression method; please update nikpak.".into()));
    }
    let encrypted = flags & FLAG_ENCRYPTED != 0;

    let source = if encrypted {
        let mut ext = [0u8; 12 + SALT_LEN + NONCE_PREFIX_LEN];
        br.read_exact(&mut ext)
            .map_err(|_| NikError::Corrupt("Archive header is truncated.".into()))?;
        let mem = u32::from_le_bytes(ext[0..4].try_into().unwrap());
        let time = u32::from_le_bytes(ext[4..8].try_into().unwrap());
        let lanes = u32::from_le_bytes(ext[8..12].try_into().unwrap());
        crypto::check_kdf_params(mem, time, lanes).map_err(NikError::Corrupt)?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&ext[12..12 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_PREFIX_LEN];
        nonce.copy_from_slice(&ext[12 + SALT_LEN..]);

        let mut header_bytes = fixed.to_vec();
        header_bytes.extend_from_slice(&ext);

        let pw = password_for_open(&o.password)?;
        if !o.quiet {
            outln!("Deriving decryption key (Argon2id)...");
        }
        let key = crypto::derive_key(&pw, &salt, mem, time, lanes).map_err(NikError::Fatal)?;
        Source::Dec(DecryptReader::new(br, &key, &nonce, header_bytes))
    } else {
        Source::Plain(br)
    };

    let inner = if method == METHOD_ZSTD {
        Inner::Zstd(
            zstd::stream::read::Decoder::new(source).map_err(|e| from_io(e, "Cannot start decompressor"))?,
        )
    } else {
        Inner::Store(source)
    };
    Ok(Opened { inner, encrypted })
}

// ---------------------------------------------------------------------------
// Record parsing
// ---------------------------------------------------------------------------

struct MediaHdr {
    filter: u8,
    method: u8,
    params: Vec<u8>,
}

struct Rec {
    is_dir: bool,
    name: String,
    mtime: i64,
    mode: u32,
    size: u64,
    media: Option<MediaHdr>,
}

enum Next {
    Rec(Rec),
    End(u64),
}

fn read_u8<R: Read>(r: &mut R) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}
fn read_u16<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}
fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn next_record<R: Read>(r: &mut R) -> Result<Next> {
    let ctx = "Reading archive";
    let kind = read_u8(r).map_err(|e| from_io(e, ctx))?;
    match kind {
        REC_END => {
            let n = read_u64(r).map_err(|e| from_io(e, ctx))?;
            Ok(Next::End(n))
        }
        REC_FILE | REC_DIR | REC_MEDIA => {
            let nlen = read_u16(r).map_err(|e| from_io(e, ctx))? as usize;
            if nlen > MAX_NAME_LEN {
                return Err(NikError::Corrupt("Archive is damaged (bad name length).".into()));
            }
            let mut nb = vec![0u8; nlen];
            r.read_exact(&mut nb).map_err(|e| from_io(e, ctx))?;
            let name = String::from_utf8(nb)
                .map_err(|_| NikError::Corrupt("Archive is damaged (invalid file name encoding).".into()))?;
            let mtime = read_u64(r).map_err(|e| from_io(e, ctx))? as i64;
            let mode = read_u32(r).map_err(|e| from_io(e, ctx))?;
            let size = if kind != REC_DIR { read_u64(r).map_err(|e| from_io(e, ctx))? } else { 0 };
            let media = if kind == REC_MEDIA {
                let filter = read_u8(r).map_err(|e| from_io(e, ctx))?;
                let method = read_u8(r).map_err(|e| from_io(e, ctx))?;
                let plen = read_u8(r).map_err(|e| from_io(e, ctx))? as usize;
                let mut params = vec![0u8; plen];
                r.read_exact(&mut params).map_err(|e| from_io(e, ctx))?;
                Some(MediaHdr { filter, method, params })
            } else {
                None
            };
            Ok(Next::Rec(Rec { is_dir: kind == REC_DIR, name, mtime, mode, size, media }))
        }
        _ => Err(NikError::Corrupt("Archive is damaged (unknown record type).".into())),
    }
}

/// Copy exactly `size` bytes from r to w (w may be io::sink()), return CRC32.
fn copy_exact<R: Read, W: Write>(r: &mut R, w: &mut W, size: u64, buf: &mut [u8]) -> Result<u32> {
    let mut crc = crc32fast::Hasher::new();
    let mut remaining = size;
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = r.read(&mut buf[..want]).map_err(|e| from_io(e, "Reading archive"))?;
        if n == 0 {
            return Err(NikError::Corrupt("Unexpected end of archive (file truncated?).".into()));
        }
        crc.update(&buf[..n]);
        w.write_all(&buf[..n])
            .map_err(|e| NikError::Fatal(format!("Write error: {e}")))?;
        remaining -= n as u64;
    }
    Ok(crc.finalize())
}

/// Read the data of one file entry (plain or media-filtered) into `w`; returns
/// the CRC32 of the reconstructed original bytes.
fn entry_data<W: Write>(inner: &mut Inner, rec: &Rec, w: &mut W, buf: &mut [u8]) -> Result<u32> {
    match &rec.media {
        None => copy_exact(inner, w, rec.size, buf),
        Some(m) => {
            let mut cr = media::ChunkReader::new(inner);
            let mut cw = media::CrcWrite::new(&mut *w);
            media::decode(&mut cr, rec.size, m.filter, m.method, &m.params, &mut cw)
                .map_err(|e| from_io(e, "Reading media data"))?;
            let extra = cr.drain().map_err(|e| from_io(e, "Reading media data"))?;
            if extra != 0 {
                return Err(NikError::Corrupt(format!("Archive is damaged (extra data after '{}').", rec.name)));
            }
            let (crc, count) = cw.finish();
            if count != rec.size {
                return Err(NikError::Corrupt(format!("Archive is damaged ('{}' has the wrong length).", rec.name)));
            }
            Ok(crc)
        }
    }
}

/// Skip a file entry. Plain entries are CRC-checked, media entries are only
/// skipped over (use the `t` command to fully verify them).
fn skip_entry(inner: &mut Inner, rec: &Rec, buf: &mut [u8]) -> Result<()> {
    if rec.media.is_some() {
        media::ChunkReader::new(inner).drain().map_err(|e| from_io(e, "Reading archive"))?;
        read_u32(inner).map_err(|e| from_io(e, "Reading archive"))?;
        return Ok(());
    }
    let c = copy_exact(inner, &mut io::sink(), rec.size, buf)?;
    let stored = read_u32(inner).map_err(|e| from_io(e, "Reading archive"))?;
    if stored != c {
        return Err(NikError::Corrupt(format!("CRC mismatch in '{}': archive is damaged.", rec.name)));
    }
    Ok(())
}

/// After REC_END: make sure the stream really ends here and (if encrypted)
/// that the final authenticated chunk has been verified.
fn verify_end(inner: &mut Inner) -> Result<()> {
    let mut sink = io::sink();
    io::copy(inner, &mut sink).map_err(|e| from_io(e, "Verifying end of archive"))?;
    Ok(())
}

// ===========================================================================
// LIST
// ===========================================================================

pub fn list(o: &Options) -> Result<u8> {
    let mut op = open_archive(o)?;
    let verbose = o.command == Command::ListVerbose;
    let bare = o.command == Command::ListBare;
    let mut buf = vec![0u8; IO_BUF];
    let (mut nfiles, mut ndirs, mut total) = (0u64, 0u64, 0u64);
    let mut matched = 0u64;

    if !bare {
        outln!("Archive: {}{}", o.archive, if op.encrypted { "   [encrypted]" } else { "" });
        outln!();
        if verbose {
            outln!("{:<10} {:>14}  {:<16} {:<8}  Name", "Attr", "Size", "Date (UTC)", "CRC32");
        } else {
            outln!("{:<10} {:>14}  {:<16}  Name", "Attr", "Size", "Date (UTC)");
        }
        outln!("{}", "-".repeat(70));
    }

    let count = loop {
        match next_record(&mut op.inner)? {
            Next::End(c) => break c,
            Next::Rec(r) => {
                let crc = if r.is_dir {
                    0
                } else if r.media.is_some() {
                    media::ChunkReader::new(&mut op.inner).drain().map_err(|e| from_io(e, "Reading archive"))?;
                    read_u32(&mut op.inner).map_err(|e| from_io(e, "Reading archive"))?
                } else {
                    let c = copy_exact(&mut op.inner, &mut io::sink(), r.size, &mut buf)?;
                    let stored = read_u32(&mut op.inner).map_err(|e| from_io(e, "Reading archive"))?;
                    if stored != c {
                        eprintln!("WARNING: CRC mismatch for '{}'", r.name);
                    }
                    stored
                };
                if !passes_filters(&r.name, o) {
                    continue;
                }
                matched += 1;
                if r.is_dir {
                    ndirs += 1;
                } else {
                    nfiles += 1;
                    total += r.size;
                }
                if bare {
                    outln!("{}{}", r.name, if r.is_dir { "/" } else { "" });
                } else {
                    let attr = attr_string(r.is_dir, r.mode);
                    if verbose {
                        outln!(
                            "{:<10} {:>14}  {:<16} {:08X}  {}{}",
                            attr, r.size, format_time(r.mtime), crc, r.name,
                            if r.is_dir { "/" } else { "" }
                        );
                    } else {
                        outln!(
                            "{:<10} {:>14}  {:<16}  {}{}",
                            attr, r.size, format_time(r.mtime), r.name,
                            if r.is_dir { "/" } else { "" }
                        );
                    }
                }
            }
        }
    };
    verify_end(&mut op.inner)?;

    if !bare {
        outln!("{}", "-".repeat(70));
        outln!("{} files, {} folders, {} bytes ({})", nfiles, ndirs, total, human_size(total));
    }
    let _ = count;
    if matched == 0 && !o.files.is_empty() {
        return Err(NikError::NoFiles("No files in the archive match the given names.".into()));
    }
    Ok(0)
}

fn attr_string(is_dir: bool, mode: u32) -> String {
    let mut s = String::with_capacity(10);
    s.push(if is_dir { 'd' } else { '-' });
    let bits = ['r', 'w', 'x'];
    for i in (0..9).rev() {
        let bit = (mode >> i) & 1;
        s.push(if bit == 1 { bits[(8 - i) % 3] } else { '-' });
    }
    s
}

fn passes_filters(name: &str, o: &Options) -> bool {
    if o.excludes.iter().any(|x| filter_matches(x, name)) {
        return false;
    }
    if o.files.is_empty() {
        return true;
    }
    o.files.iter().any(|f| filter_matches(f, name))
}

// ===========================================================================
// TEST
// ===========================================================================

pub fn test(o: &Options) -> Result<u8> {
    let mut op = open_archive(o)?;
    let mut buf = vec![0u8; IO_BUF];
    let mut bad = 0u64;
    let mut n = 0u64;
    let declared = loop {
        match next_record(&mut op.inner)? {
            Next::End(c) => break c,
            Next::Rec(r) => {
                n += 1;
                if r.is_dir {
                    continue;
                }
                let c = entry_data(&mut op.inner, &r, &mut io::sink(), &mut buf)?;
                let stored = read_u32(&mut op.inner).map_err(|e| from_io(e, "Reading archive"))?;
                if stored == c {
                    if !o.quiet {
                        outln!("Testing   {}   OK", r.name);
                    }
                } else {
                    bad += 1;
                    eprintln!("Testing   {}   FAILED (CRC mismatch)", r.name);
                }
            }
        }
    };
    verify_end(&mut op.inner)?;
    if declared != n {
        return Err(NikError::Corrupt("Entry count mismatch: the archive is damaged.".into()));
    }
    if bad > 0 {
        return Err(NikError::Corrupt(format!("{bad} file(s) failed the CRC check.")));
    }
    if !o.quiet {
        outln!();
        outln!(
            "All OK ({} entries){}",
            n,
            if op.encrypted { " - authentication verified" } else { "" }
        );
    }
    Ok(0)
}

// ===========================================================================
// EXTRACT
// ===========================================================================

fn unique_path(p: &Path) -> PathBuf {
    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = p.extension().map(|s| format!(".{}", s.to_string_lossy())).unwrap_or_default();
    let dir = p.parent().map(|d| d.to_path_buf()).unwrap_or_default();
    for i in 1..10_000 {
        let c = dir.join(format!("{stem} ({i}){ext}"));
        if !c.exists() && fs::symlink_metadata(&c).is_err() {
            return c;
        }
    }
    p.to_path_buf()
}

pub fn extract(o: &Options) -> Result<u8> {
    let started = Instant::now();
    let dest = o.dest.clone().unwrap_or_else(|| PathBuf::from("."));
    if dest.exists() && !dest.is_dir() {
        return Err(NikError::Fatal(format!("Destination '{}' is not a folder.", dest.display())));
    }
    let mut op = open_archive(o)?;
    fs::create_dir_all(&dest)
        .map_err(|e| NikError::Fatal(format!("Cannot create destination '{}': {e}", dest.display())))?;

    let flat = o.command == Command::ExtractFlat;
    let mut overwrite = o.overwrite;
    let mut buf = vec![0u8; IO_BUF];
    let mut warnings = 0u32;
    let mut extracted = 0u64;
    let mut total = 0u64;
    let mut matched = 0u64;
    let mut dir_times: Vec<(PathBuf, i64)> = Vec::new();

    let declared = loop {
        let rec = match next_record(&mut op.inner)? {
            Next::End(c) => break c,
            Next::Rec(r) => r,
        };

        let want = passes_filters(&rec.name, o);
        // Validate and map the name
        let comps = match sanitize_entry_name(&rec.name) {
            Ok(c) => Some(c),
            Err(why) => {
                warnings += 1;
                eprintln!("WARNING: Skipping unsafe entry '{}': {why}", rec.name);
                None
            }
        };
        let comps = if want { comps } else { None };

        if rec.is_dir {
            if let Some(c) = comps {
                matched += 1;
                if flat {
                    continue;
                }
                if let Err(why) = check_no_symlinks(&dest, &c) {
                    warnings += 1;
                    eprintln!("WARNING: Skipping '{}': {why}", rec.name);
                    continue;
                }
                let p = join_components(&dest, &c);
                if let Err(e) = fs::create_dir_all(&p) {
                    warnings += 1;
                    eprintln!("WARNING: Cannot create folder '{}': {e}", p.display());
                    continue;
                }
                dir_times.push((p, rec.mtime));
            }
            continue;
        }

        // ---- file entry ----
        let target_comps: Option<Vec<String>> = comps.map(|c| {
            if flat { vec![c.last().cloned().unwrap_or_default()] } else { c }
        });
        let Some(tc) = target_comps else {
            // skipped: consume the data
            skip_entry(&mut op.inner, &rec, &mut buf)?;
            continue;
        };
        matched += 1;

        let mut target = join_components(&dest, &tc);
        let mut skip_reason: Option<String> = None;

        if let Err(why) = check_no_symlinks(&dest, &tc) {
            skip_reason = Some(why);
        } else if let Some(parent) = target.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                skip_reason = Some(format!("cannot create folder '{}': {e}", parent.display()));
            }
        }

        if skip_reason.is_none() && fs::symlink_metadata(&target).is_ok() {
            let mut choice = overwrite;
            if choice == Overwrite::Ask {
                match ask_yes_no(&format!("'{}' already exists. Overwrite?", target.display())) {
                    Some('y') => choice = Overwrite::All,
                    Some('a') => {
                        overwrite = Overwrite::All;
                        choice = Overwrite::All;
                    }
                    Some('s') => {
                        overwrite = Overwrite::Skip;
                        choice = Overwrite::Skip;
                    }
                    _ => choice = Overwrite::Skip,
                }
            }
            match choice {
                Overwrite::All => {
                    // remove first so we never write THROUGH an existing link
                    let md = fs::symlink_metadata(&target);
                    let res = match md {
                        Ok(m) if m.is_dir() => Err(io::Error::new(io::ErrorKind::Other, "a folder with that name exists")),
                        _ => fs::remove_file(&target),
                    };
                    if let Err(e) = res {
                        skip_reason = Some(format!("cannot replace existing file: {e}"));
                    }
                }
                Overwrite::Rename => target = unique_path(&target),
                _ => skip_reason = Some("already exists (skipped)".into()),
            }
        }

        if let Some(why) = skip_reason {
            warnings += 1;
            eprintln!("WARNING: '{}': {why}", rec.name);
            skip_entry(&mut op.inner, &rec, &mut buf)?;
            continue;
        }

        // ---- write the file (create_new: never follows a pre-existing link)
        let mut f = match OpenOptions::new().write(true).create_new(true).open(&target) {
            Ok(f) => f,
            Err(e) => {
                warnings += 1;
                eprintln!("WARNING: Cannot create '{}': {e} - skipped", target.display());
                skip_entry(&mut op.inner, &rec, &mut buf)?;
                continue;
            }
        };
        let res = {
            let mut w = BufWriter::with_capacity(IO_BUF, &mut f);
            let r = entry_data(&mut op.inner, &rec, &mut w, &mut buf);
            match r {
                Ok(c) => w.flush().map(|_| c).map_err(|e| NikError::Fatal(format!("Write error on '{}': {e}", target.display()))),
                Err(e) => Err(e),
            }
        };
        let crc = match res {
            Ok(c) => c,
            Err(e) => {
                drop(f);
                let _ = fs::remove_file(&target);
                return Err(e);
            }
        };
        let stored = read_u32(&mut op.inner).map_err(|e| {
            let _ = fs::remove_file(&target);
            from_io(e, "Reading archive")
        })?;
        if stored != crc {
            drop(f);
            let _ = fs::remove_file(&target);
            return Err(NikError::Corrupt(format!(
                "CRC mismatch in '{}': the archive is damaged. The file was not kept.",
                rec.name
            )));
        }
        if rec.mtime >= 0 {
            let t = UNIX_EPOCH + std::time::Duration::from_secs(rec.mtime as u64);
            let _ = f.set_modified(t);
        }
        drop(f);
        set_file_mode(&target, rec.mode);

        extracted += 1;
        total += rec.size;
        if !o.quiet {
            outln!("Extracting  {}   OK", target.display());
        }
    };
    verify_end(&mut op.inner)?;

    // folder timestamps last (adding files changes them)
    #[cfg(unix)]
    for (p, t) in dir_times.iter().rev() {
        if *t >= 0 {
            if let Ok(d) = File::open(p) {
                let _ = d.set_modified(UNIX_EPOCH + std::time::Duration::from_secs(*t as u64));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = &dir_times;

    let _ = declared;
    if matched == 0 && !o.files.is_empty() {
        return Err(NikError::NoFiles("No files in the archive match the given names.".into()));
    }
    if !o.quiet {
        outln!();
        outln!(
            "Done. {} files extracted, {}, {:.2}s",
            extracted,
            human_size(total),
            started.elapsed().as_secs_f64()
        );
    }
    let _ = SystemTime::now;
    Ok(if warnings > 0 { 1 } else { 0 })
}

#[cfg(unix)]
fn set_file_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    // strip setuid / setgid / sticky: never restore privileged bits from an archive
    let m = (mode & 0o777) | 0o400;
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(m));
}

#[cfg(not(unix))]
fn set_file_mode(p: &Path, mode: u32) {
    if mode & 0o200 == 0 {
        if let Ok(md) = fs::metadata(p) {
            let mut perms = md.permissions();
            perms.set_readonly(true);
            let _ = fs::set_permissions(p, perms);
        }
    }
}


// ===========================================================================
// MEDIA TEST  (nikpak mt <files>)
// ===========================================================================

pub fn media_test(o: &Options) -> Result<u8> {
    let lvl = match o.level {
        Level::Zstd(l) => media::nac_level(l),
        Level::Store => 0,
    };
    let mut warnings = 0u32;
    let (mut tot_raw, mut tot_best, mut tot_files) = (0u64, 0u64, 0u32);
    outln!("{:<28} {:<5} {:>11} {:>11}  {:<28} {}", "File", "Type", "Samples", "zstd-3", "Filters (size)", "Best");
    outln!("{}", "-".repeat(110));
    for name in &o.files {
        let mut f = match File::open(name) {
            Ok(f) => f,
            Err(e) => {
                warnings += 1;
                eprintln!("WARNING: cannot open '{name}': {e}");
                continue;
            }
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let short: String = if name.chars().count() > 28 {
            format!("...{}", name.chars().rev().take(25).collect::<Vec<_>>().into_iter().rev().collect::<String>())
        } else {
            name.clone()
        };
        let Some(det) = media::detect(&mut f, len) else {
            outln!("{:<28} {:<5} {:>11}  not a supported uncompressed media file (WAV/AIFF/MOD/BMP)", short, "-", len);
            continue;
        };
        let ev = match media::evaluate(&mut f, &det, lvl, true) {
            Ok(e) => e,
            Err(e) => {
                warnings += 1;
                eprintln!("WARNING: '{name}': {e}");
                continue;
            }
        };
        let fid = det.filter_id();
        let list: Vec<String> = ev.cands.iter().map(|(m, s)| format!("{} {}", media::method_name(fid, *m), s)).collect();
        let best = ev.cands.iter().min_by_key(|c| c.1).copied();
        let verdict = match best {
            Some((m, s)) if (s as f64) < ev.raw as f64 * 0.98 => {
                tot_best += s;
                format!("{}  ({:.1}% of zstd-3)", media::method_name(fid, m), s as f64 * 100.0 / ev.raw.max(1) as f64)
            }
            _ => {
                tot_best += ev.raw;
                "none (plain compression)".to_string()
            }
        };
        tot_raw += ev.raw;
        tot_files += 1;
        outln!("{:<28} {:<5} {:>11} {:>11}  {:<28} {}", short, det.kind.name(), ev.sample, ev.raw, list.join(", "), verdict);
    }
    if tot_files > 0 {
        outln!("{}", "-".repeat(110));
        outln!(
            "{} media file(s): plain zstd-3 {} bytes -> best filters {} bytes ({:.1}%)",
            tot_files, tot_raw, tot_best, tot_best as f64 * 100.0 / tot_raw.max(1) as f64
        );
    }
    Ok(if warnings > 0 { 1 } else { 0 })
}
