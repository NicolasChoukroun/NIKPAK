//! Command-line parsing. RAR-style (`nikpak a -m3 -pSECRET archive.nik files`)
//! with the common zip switches accepted as well.

use crate::error::{NikError, Result};
use crate::format::EXT;
use crate::util::PwdSpec;
use std::path::PathBuf;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Add,
    ExtractFull,
    ExtractFlat,
    List,
    ListVerbose,
    ListBare,
    Test,
    MediaTest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overwrite {
    Ask,
    All,
    Skip,
    Rename,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpMode {
    /// store paths as given
    Keep,
    /// -ep : strip the path of each argument, keep only its last component
    Names,
    /// -ep1 : for directories, do not store the base directory name itself
    BaseDir,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaMode {
    /// detect media files and pick the best filter by trial (default)
    Auto,
    /// -mc- : never use media filters
    Off,
    /// -mc+ : always use the default filter for detected media files
    Force,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Store,
    Zstd(i32),
}

#[derive(Debug)]
pub struct Options {
    pub command: Command,
    pub archive: String,
    pub files: Vec<String>,
    pub password: PwdSpec,
    pub level: Level,
    pub ep: EpMode,
    pub overwrite: Overwrite,
    pub quiet: bool,
    pub dest: Option<PathBuf>,
    pub excludes: Vec<String>,
    pub threads: usize,
    pub media: MediaMode,
}

pub enum Parsed {
    Help,
    Version,
    Run(Box<Options>),
}

pub fn usage_err<T>(msg: impl Into<String>) -> Result<T> {
    Err(NikError::Usage(msg.into()))
}

fn parse_command(s: &str) -> Option<Command> {
    Some(match s.to_ascii_lowercase().as_str() {
        "a" | "add" => Command::Add,
        "x" | "extract" => Command::ExtractFull,
        "e" => Command::ExtractFlat,
        "l" | "list" => Command::List,
        "v" | "vl" => Command::ListVerbose,
        "lb" => Command::ListBare,
        "t" | "test" => Command::Test,
        "mt" | "media" => Command::MediaTest,
        _ => return None,
    })
}

/// zip-style numeric level (-0 .. -9) -> compression level
fn zip_level(n: u32) -> Level {
    match n {
        0 => Level::Store,
        1 => Level::Zstd(1),
        2 => Level::Zstd(2),
        3 => Level::Zstd(3),
        4 => Level::Zstd(4),
        5 => Level::Zstd(5),
        6 => Level::Zstd(6),
        7 => Level::Zstd(9),
        8 => Level::Zstd(12),
        _ => Level::Zstd(19),
    }
}

/// rar-style -m0..-m5
fn rar_level(n: u32) -> Level {
    match n {
        0 => Level::Store,
        1 => Level::Zstd(1),
        2 => Level::Zstd(3),
        3 => Level::Zstd(9),
        4 => Level::Zstd(15),
        _ => Level::Zstd(19),
    }
}

pub fn parse(args: &[String]) -> Result<Parsed> {
    let mut positional: Vec<String> = Vec::new();
    let mut password = PwdSpec::None;
    let mut level = Level::Zstd(3);
    let mut ep = EpMode::Keep;
    let mut overwrite = Overwrite::Ask;
    let mut quiet = false;
    let mut dest: Option<PathBuf> = None;
    let mut excludes: Vec<String> = Vec::new();
    let mut threads = 0usize;
    let mut media = MediaMode::Auto;
    let mut only_positional = false;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;

        if only_positional || !a.starts_with('-') || a == "-" {
            positional.push(a.clone());
            continue;
        }
        if a == "--" {
            only_positional = true;
            continue;
        }
        match a.as_str() {
            "-h" | "-?" | "-help" | "--help" | "-H" => return Ok(Parsed::Help),
            "-V" | "-version" | "--version" => return Ok(Parsed::Version),
            _ => {}
        }

        // ---- password -----------------------------------------------------
        if a == "-p" || a == "-hp" || a == "-e" {
            password = PwdSpec::Prompt;
            continue;
        }
        if a == "-P" {
            // zip style: password is the next argument
            match args.get(i) {
                Some(p) => {
                    password = PwdSpec::Given(p.clone());
                    i += 1;
                }
                None => return usage_err("Option -P needs a password argument."),
            }
            continue;
        }
        if let Some(p) = a.strip_prefix("-hp") {
            password = PwdSpec::Given(p.to_string());
            continue;
        }
        if let Some(p) = a.strip_prefix("-p") {
            password = PwdSpec::Given(p.to_string());
            continue;
        }

        // ---- overwrite ----------------------------------------------------
        match a.as_str() {
            "-o+" => { overwrite = Overwrite::All; continue; }
            "-o-" => { overwrite = Overwrite::Skip; continue; }
            "-or" => { overwrite = Overwrite::Rename; continue; }
            "-y" => { overwrite = Overwrite::All; continue; }
            "-o" => { overwrite = Overwrite::All; continue; } // unzip -o
            "-n" => { overwrite = Overwrite::Skip; continue; } // unzip -n
            _ => {}
        }

        // ---- paths --------------------------------------------------------
        match a.as_str() {
            "-ep" => { ep = EpMode::Names; continue; }
            "-ep1" => { ep = EpMode::BaseDir; continue; }
            "-j" => { ep = EpMode::Names; continue; } // zip -j (junk paths)
            _ => {}
        }

        // ---- quiet ---------------------------------------------------------
        match a.as_str() {
            "-q" | "-inul" | "-idq" | "-iq" => { quiet = true; continue; }
            _ => {}
        }

        // ---- destination dir (unzip -d) ------------------------------------
        if a == "-d" {
            match args.get(i) {
                Some(d) => {
                    dest = Some(PathBuf::from(d));
                    i += 1;
                }
                None => return usage_err("Option -d needs a directory argument."),
            }
            continue;
        }

        // ---- exclude -------------------------------------------------------
        if a == "-x" {
            match args.get(i) {
                Some(x) => {
                    excludes.push(x.clone());
                    i += 1;
                }
                None => return usage_err("Option -x needs a pattern argument."),
            }
            continue;
        }
        if let Some(x) = a.strip_prefix("-x") {
            if !x.is_empty() {
                excludes.push(x.to_string());
                continue;
            }
        }

        // ---- threads / level -------------------------------------------------
        if a == "-mc-" {
            media = MediaMode::Off;
            continue;
        }
        if a == "-mc+" || a == "-mc" {
            media = if a == "-mc" { MediaMode::Auto } else { MediaMode::Force };
            continue;
        }
        if let Some(n) = a.strip_prefix("-mt") {
            match n.parse::<usize>() {
                Ok(v) if (1..=256).contains(&v) => threads = v,
                _ => return usage_err(format!("Invalid thread count in option '{a}' (use -mt1 .. -mt256).")),
            }
            continue;
        }
        if let Some(n) = a.strip_prefix("-m") {
            if n.len() == 1 {
                if let Ok(v) = n.parse::<u32>() {
                    if v <= 5 {
                        level = rar_level(v);
                        continue;
                    }
                    return usage_err(format!("Invalid compression level '{a}' (use -m0 .. -m5)."));
                }
            }
            // other -m<...> options (-md, -ma, -ms ...) are accepted and ignored
            continue;
        }
        if a.len() == 2 {
            if let Ok(v) = a[1..].parse::<u32>() {
                level = zip_level(v);
                continue;
            }
        }

        // ---- accepted for RAR / zip compatibility, no effect -----------------
        const IGNORED: &[&str] = &[
            "-r", "-r0", "-s", "-ms", "-k", "-ibck", "-idp", "-idc", "-idd", "-ierr", "-ilog",
            "-ol", "-tk", "-tl", "-sc", "-ac", "-av", "-av-", "-cfg-", "-rr", "-ri", "-y-", "-sl",
            "-sm", "-t", "-v", "-ds", "-dh", "-dw", "-w", "-ver", "-vn", "-tn", "-to", "-ta", "-tb",
        ];
        if IGNORED.contains(&a.as_str())
            || a.starts_with("-ts")
            || a.starts_with("-rr")
            || a.starts_with("-ri")
            || a.starts_with("-ilog")
            || a.starts_with("-ierr")
            || a.starts_with("-w")
            || a.starts_with("-ag")
            || a.starts_with("-ap")
            || a.starts_with("-ioff")
            || a.starts_with("-sc")
        {
            continue;
        }

        return usage_err(format!("Unknown option '{a}'. Use 'nikpak -help' to see all options."));
    }

    // ---- positional: command, archive, files -----------------------------
    if positional.is_empty() {
        return usage_err(
            "Missing command.\nUsage: nikpak <command> [options] <archive.nik> [files...]\n\
             Use 'nikpak -help' for the full list of commands and options.",
        );
    }
    let cmd_s = positional.remove(0);
    let command = match parse_command(&cmd_s) {
        Some(c) => c,
        None => {
            return usage_err(format!(
                "Unknown command '{cmd_s}'. Valid commands: a, x, e, l, v, lb, t.\n\
                 Use 'nikpak -help' for details."
            ))
        }
    };
    if command == Command::MediaTest {
        if positional.is_empty() {
            return usage_err("Missing file names.\nUsage: nikpak mt [options] <file.wav|file.mod|file.bmp|...>...");
        }
        let mut files = Vec::new();
        for p in positional {
            if p.len() > 1 && p.starts_with('@') {
                files.extend(read_list_file(&p[1..])?);
            } else {
                files.push(p);
            }
        }
        return Ok(Parsed::Run(Box::new(Options {
            command,
            archive: String::new(),
            files,
            password: password,
            level,
            ep,
            overwrite,
            quiet,
            dest,
            excludes,
            threads,
            media,
        })));
    }
    if positional.is_empty() {
        return usage_err(format!(
            "Missing archive name for command '{cmd_s}'.\nUsage: nikpak {cmd_s} [options] <archive.{EXT}>{}",
            if command == Command::Add { " <files...>" } else { "" }
        ));
    }
    let mut archive = positional.remove(0);
    if command == Command::Add && std::path::Path::new(&archive).extension().is_none() {
        archive.push('.');
        archive.push_str(EXT);
    }

    // For x / e a trailing path separator marks the destination directory.
    let mut files: Vec<String> = Vec::new();
    for p in positional {
        // RAR-style list file: @names.txt (one file name per line)
        if p.len() > 1 && p.starts_with('@') {
            let list = read_list_file(&p[1..])?;
            files.extend(list);
            continue;
        }
        let is_dest = matches!(command, Command::ExtractFull | Command::ExtractFlat)
            && (p.ends_with('/') || p.ends_with('\\'));
        if is_dest {
            if dest.is_some() {
                return usage_err("More than one destination directory specified.");
            }
            dest = Some(PathBuf::from(p));
        } else {
            files.push(p);
        }
    }

    if command == Command::Add && files.is_empty() {
        return usage_err(
            "No files specified to add.\nUsage: nikpak a [options] <archive.nik> <file|dir|wildcard>...",
        );
    }
    if command == Command::Add && dest.is_some() {
        return usage_err("A destination directory only makes sense when extracting.");
    }

    Ok(Parsed::Run(Box::new(Options {
        command,
        archive,
        files,
        password,
        level,
        ep,
        overwrite,
        quiet,
        dest,
        excludes,
        threads,
        media,
    })))
}

/// Read a RAR-style list file: one name per line, UTF-8 (BOM allowed).
fn read_list_file(path: &str) -> Result<Vec<String>> {
    let bytes = std::fs::read(path)
        .map_err(|e| NikError::Usage(format!("Cannot read list file '{path}': {e}")))?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.trim_start_matches('\u{feff}');
    Ok(text
        .lines()
        .map(|l| l.trim().trim_matches('"').to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

pub const HELP: &str = r#"
nikpak - fast archiver for the .nik format

  Compression : Zstandard (multi-threaded, much faster than ZIP/RAR at similar ratio)
  Encryption  : Argon2id key derivation + XChaCha20-Poly1305 (file names are
                encrypted too; tampering and wrong passwords are detected)

USAGE
  nikpak <command> [options] <archive.nik> [files... | wildcards...] [destination\]

COMMANDS
  a    Add files/folders to a NEW archive (.nik is appended if no extension)
  x    Extract files with full paths
  e    Extract files to the current/destination folder, WITHOUT paths
  l    List archive contents
  v    List archive contents (verbose: adds CRC32)
  lb   Bare list: only file names, one per line (handy for scripts / GUIs)
  t    Test archive integrity (CRC32 and, for encrypted archives, authentication)
  mt   Media test: detect WAV/AIFF/MOD/BMP files and show how well each media
       filter compresses them (no archive is written)

OPTIONS (RAR style)                              (zip equivalent)
  -p             Encrypt / decrypt: ask for the password. If none is entered
                 when creating, a strong random one is generated and shown.
  -p<password>   Give the password on the command line      -P <password>, -e
  -hp[password]  Same as -p (file names are ALWAYS encrypted)
  -m0 .. -m5     Compression: 0=store 1=fastest 2=fast(default-like) 3=good
                 4=high 5=maximum                            -0 .. -9
  -mt<N>         Use N threads (default: all cores)
  -mc-           Do not use the media filters (WAV/AIFF/MOD/BMP are then compressed
                 like any other file)
  -mc+           Always use the media filter for detected media files (no trial)
  -r             Recurse into folders (always on: folders are always recursed)
  -ep            Store only the name of each argument, no path         -j
  -ep1           Do not store the base folder name of a folder argument
  -o+            Overwrite existing files without asking              -o
  -o-            Skip existing files without asking                   -n
  -or            Rename extracted files that already exist (name (1).ext)
  -y             Assume Yes on all queries (overwrite)
  -x<pattern>    Exclude files matching the pattern (can be repeated)  -x <pattern>
  -d <dir>       Extract into <dir> (or give a path ending in \ or / ).
                 For folders with spaces prefer -d "C:\My Folder" - a quoted path
                 ending in a backslash is mis-parsed by Windows.
  -inul, -idq, -q  Quiet: print only errors
  -h, -help, -?  Show this help
  -V, -version   Show the version
  @<listfile>    Read file names from a text file, one per line
  --             Stop option parsing (the rest are file names)

  Accepted and ignored for compatibility with RAR/zip front-ends (the format is
  always solid): -s -k -ms -md -ma -ibck -idp -rr -ts* -w<path> ...

EXAMPLES
  nikpak a backup.nik C:\Docs\*.txt Photos\          create archive
  nikpak a -m5 -mt8 big.nik Projects\                maximum compression, 8 threads
  nikpak a -p secret.nik Taxes2026\                  encrypted, asks for password
  nikpak a -pMyLongPassw0rd secret.nik file.pdf      encrypted, password on the command line
  nikpak x backup.nik C:\Restore\                    extract with paths
  nikpak e backup.nik *.jpg C:\Pics\                 extract only *.jpg, flat
  nikpak l backup.nik                                list
  nikpak t secret.nik                                test (asks for the password)
  nikpak mt song.wav tracker.mod photo.bmp           which media filter wins, and by how much

PASSWORDS
  * Minimum length when creating: 8 characters. Use a long passphrase.
  * -p<password> is visible to other users in the process list. Prefer -p (prompt)
    or the environment variable NIKPAK_PASSWORD.
  * Lost password = lost data. There is no backdoor and no recovery.

EXIT CODES
  0 success      1 warning (some files skipped)   2 fatal error
  3 corrupt archive / CRC error                   7 bad command line
  10 no files matched                             11 wrong or missing password

MEDIA FILES (WAV, AIFF, MOD, BMP)
  nikpak looks at the CONTENT of every file (not its extension). For uncompressed
  audio and images it trial-compresses a sample with each media filter and keeps the
  smallest result, falling back to normal compression when nothing wins:
    NAC         lossless audio codec (adaptive prediction + Rice coding), 8/16/24/32-bit
                PCM, mono to 8 channels; ProTracker MOD sample data (8-bit)
    Shuffle     byte-plane separation (helps odd material such as companded audio)
    Shuf+Delta  byte-plane separation after a per-channel delta
    MED         BMP images: colour decorrelation + edge-aware pixel predictor
  Everything is lossless and verified while writing. Already-compressed media (MP3,
  JPEG, FLAC, PNG, MP4 ...) is not touched. Archives that use media filters need
  nikpak 1.1 or newer to be read.

NOTES
  * Adding to an existing archive is not supported (solid format): create a new
    archive, or use -o+ to overwrite an existing one.
  * Symbolic links are skipped when creating and refused when extracting.
  * Dates are shown in UTC.
"#;
