<div align="center">

# NIKPAK

**Fast, media-aware, encrypted archiving for the `.nik` format.**
Smaller than RAR 7 on audio, images and tracker music. Quantum-resistant encryption. One small executable for Windows, macOS and Linux.

![Rust](https://img.shields.io/badge/written%20in-Rust-b7410e)
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-0b1f3a)
![Encryption](https://img.shields.io/badge/encryption-Argon2id%20%2B%20XChaCha20--Poly1305-0fa3b1)
![Dependencies](https://img.shields.io/badge/runtime%20dependencies-none-12355b)

</div>

---

## Why NIKPAK?

| | |
|---|---|
| **Smaller than RAR on media** | WAV, AIFF, ProTracker MOD and BMP files are detected by content and compressed with specialised lossless codecs. Measured against **RAR 7.00 at its best level**: **12-39 % smaller** on every media set tested. |
| **Smaller than RAR on general data too** | At `-m5` NIKPAK produced **24.4 MB** where RAR 7 (solid, 256 MB dictionary) needed **25.9 MB**. |
| **Very fast** | Zstandard with multithreading. The default level compresses 197 MB of source files in **0.9 s**; a 17 MB stereo WAV is archived in **1.45 s** (RAR -m3: 2.54 s). |
| **Modern, authenticated encryption** | Argon2id (64 MiB, memory-hard) + XChaCha20-Poly1305. File names are **always** encrypted. Tampering, truncation and reordering are detected. |
| **Quantum-resistant by design** | Only 256-bit symmetric cryptography. **No RSA, no elliptic curves, no Diffie-Hellman anywhere** - nothing for Shor's algorithm to attack. |
| **Never forget a password again... or choose a weak one** | No password given? NIKPAK generates a strong random one (about 139 bits) and shows it to you. |
| **Drop-in command line** | RAR-style commands and switches (`a x e l t -p -m5 -ep1 -o+ @list`) plus the common zip switches. Works with Total Commander and other front-ends that drive an external RAR. |
| **Safe by construction** | Written in Rust. Zip-slip, symlink and setuid attacks blocked, bounded decoders, atomic archive writes, every media filter self-verified. |
| **One file, no dependencies** | `NIKPAK.exe` is statically linked (about 1.7 MB). Build it yourself in two minutes. |

> **Honest scope.** NIKPAK is new. It has no recovery records, multi-volume archives or self-extractors yet, cannot append to an existing archive, and has not had an independent security audit. See [Limitations](#limitations-and-roadmap).

---

## Benchmarks: NIKPAK vs RAR 7

Everything below was measured on the same machine (Linux x86-64 VM, 1 CPU core) with **RAR 7.00** (Linux trial build) and NIKPAK 1.1.0. Sizes are in bytes. Each NIKPAK result was extracted again and compared byte for byte with the original.

### Media files (RAR at its best level, -m5)

| Test set | Original | RAR 7 -m5 | NIKPAK -m2 | NIKPAK -m5 | NIKPAK -m5 vs RAR |
|---|---:|---:|---:|---:|---:|
| 6 BMP photos | 9,183,956 | 2,862,744 | 2,035,223 | **1,750,706** | **38.8 % smaller** |
| 16 ProTracker MODs | 2,507,557 | 1,070,290 | 966,622 | **927,973** | **13.3 % smaller** |
| 35 gallery WAVs (mono 16-bit) | 2,991,820 | 1,605,879 | 1,529,219 | **1,418,532** | **11.7 % smaller** |
| Music 44.1 kHz stereo 16-bit | 17,371,848 | 11,024,411 | 9,415,519 | **9,411,898** | **14.6 % smaller** |
| Music 22 kHz mono 16-bit | 4,342,996 | 3,112,135 | 2,635,819 | **2,634,669** | **15.3 % smaller** |
| Music 22 kHz mono 8-bit | 2,171,520 | 844,160 | 742,462 | **740,751** | **12.2 % smaller** |
| Music 48 kHz stereo 24-bit | 28,362,206 | 21,467,283 (-m3) | 18,689,529 | **18,688,030** | **12.9 % smaller** |

For reference, FLAC -8 compresses the 44.1 kHz stereo track to 9,407,019 bytes: NIKPAK's audio codec is on par with FLAC, inside a general-purpose archiver.

### General data (197.6 MB, 10,949 source and document files)

| Tool and level | Size | Time (1 core) |
|---|---:|---:|
| **NIKPAK -m5** | **24,443,483** | 45.6 s |
| RAR 7 -m5 -s -md256m (solid, 256 MB dictionary) | 25,862,475 | 36.2 s |
| RAR 7 -m5 -s (solid) | 26,002,812 | 26.7 s |
| RAR 7 -m3 -s (solid) | 26,536,863 | 16.7 s |
| NIKPAK -m4 | 26,814,023 | 13.5 s |
| NIKPAK -m3 | 30,329,965 | 2.0 s |
| NIKPAK -m2 (default) | 36,266,743 | **0.9 s** |
| RAR 7 -m5 (default, not solid) | 50,851,230 | 14.8 s |
| RAR 7 -m3 (default, not solid) | 50,974,773 | 9.7 s |

How to read this honestly:

* NIKPAK archives are always solid, so the fair RAR comparison is RAR **with `-s`**. Plain RAR (not solid) is much larger on many small files.
* **At the top level NIKPAK is 5.5 % smaller than RAR's best, but RAR is faster there** (36 s vs 46 s).
* At the fast levels NIKPAK trades ratio for speed: `-m2` is about 18x faster than RAR solid `-m3` and 37 % larger; `-m4` has the same size as RAR `-m3` solid (+1 %) in 81 % of the time.
* Extraction: NIKPAK 0.8 s (fast archive) / 1.8 s (`-m5` archive); RAR 1.5 s (solid). On the 17 MB WAV, RAR extracted slightly faster (0.23 s vs 0.28 s).
* Encryption added about 0.3 s in total (key derivation included) and about 0.03 % extra size on a 222 MB data set.

Reproduce it yourself: `NIKPAK mt yourfile.wav` shows, per file, which media filter wins and by how much.

---

## Quick start

```powershell
# build (Windows PowerShell; see "Building" for prerequisites)
.\build.ps1

# create, list, test, extract
NIKPAK a backup.nik C:\Docs\ Photos\
NIKPAK l backup.nik
NIKPAK t backup.nik
NIKPAK x backup.nik C:\Restore\

# encrypted archive: asks for a password (press ENTER to get a random one)
NIKPAK a -p secret.nik Taxes2026\

# which media filter wins for these files?
NIKPAK mt song.wav tracker.mod photo.bmp
```

---

## Commands

| Command | Meaning |
|---|---|
| `a` | Create a new archive (`.nik` is appended when no extension is given) |
| `x` | Extract with full paths |
| `e` | Extract without paths (everything into one folder) |
| `l` / `v` / `lb` | List / list with CRC32 / bare names only (scripts and GUIs) |
| `t` | Test integrity (CRC32, and authentication for encrypted archives) |
| `mt` | Media test: detect WAV/AIFF/MOD/BMP files and compare the media filters (writes nothing) |

## Options

| RAR style | zip style | Meaning |
|---|---|---|
| `-p` | `-e` | Encrypt / decrypt. Prompts for the password; an empty entry **generates a random password** and shows it |
| `-p<password>` | `-P <password>` | Password on the command line (visible to other users; prefer the prompt or `NIKPAK_PASSWORD`) |
| `-hp[password]` | | Same as `-p` (file names are always encrypted) |
| `-m0` ... `-m5` | `-0` ... `-9` | Store / fastest / fast (default) / good / high / maximum |
| `-mt<N>` | | Number of threads (default: all cores) |
| `-mc-` / `-mc+` | | Media filters off / always on (default: automatic per-file trial) |
| `-r` | | Recurse (always on) |
| `-ep`, `-ep1` | `-j` | Do not store paths / do not store the base folder name |
| `-o+`, `-o-`, `-or` | `-o`, `-n` | Overwrite / skip / rename existing files |
| `-y` | | Assume Yes on all questions |
| `-x<pattern>` | `-x <pattern>` | Exclude files (repeatable) |
| `-d <dir>` or trailing `\` | `-d <dir>` | Destination folder for `x` / `e` |
| `-inul`, `-idq` | `-q` | Quiet |
| `@listfile` | | Read file names from a text file |
| `-h`, `-help`, `-?` | | Full help |

**Exit codes:** `0` success, `1` warning, `2` fatal, `3` corrupt archive / CRC error, `7` bad command line, `10` nothing matched, `11` wrong or missing password.

Switches used by RAR front-ends that have no effect here (`-s`, `-ma5`, `-md64m`, `-ibck`, ...) are accepted and ignored, so existing tool configurations keep working.

---

## How it works

```
 files --> media detector --> entry stream --> Zstandard --> (XChaCha20-Poly1305) --> .nik
            + per-file trial    names, dates,   multi-threaded    64 KiB chunks,
            NAC / Shuffle /     CRC32           solid stream      key from Argon2id
            Delta / MED
```

1. **Collect** files and folders (wildcards, `@listfile`, exclusions). Symbolic links are skipped.
2. **Detect media by content.** WAV (integer PCM 8/16/24/32-bit, 1-8 channels), AIFF, ProTracker MOD and uncompressed BMP are recognised from their headers, whatever their extension.
3. **Trial.** For each media file NIKPAK trial-compresses a sample (three 768 KiB windows across the audio, or the whole file when small) with every applicable filter and keeps the smallest, falling back to plain compression when nothing wins by at least 2 %.
4. **One solid stream.** All entries are written to a single Zstandard stream (multi-threaded; 128 MiB window with long-distance matching at `-m4`/`-m5`).
5. **Optional encryption.** The stream is cut into 64 KiB chunks sealed with XChaCha20-Poly1305. The key comes from the password via Argon2id.
6. **Atomic write.** The archive is written to `name.nik.tmp` and renamed only when complete.

### Media filters

| Filter | Used for | Technique |
|---|---|---|
| **NAC** | WAV/AIFF PCM audio, MOD sample data | Lossless audio codec: per-block stereo decorrelation (L/R, L/S, S/R, M/S), fixed and LPC predictors up to order 32, wasted-bits removal, partitioned Rice coding. The encoder decodes every block again and falls back to a verbatim block on any mismatch. |
| **Shuffle**, **Shuffle+Delta** | The same audio when NAC loses (e.g. companded or low-bit-depth sources) | Byte-plane separation, optionally after a per-channel delta, then Zstandard |
| **MED** | BMP 8/24/32-bit | Green-channel decorrelation plus the edge-aware MED pixel predictor, per-channel planes, then Zstandard |

Already compressed media (MP3, JPEG, FLAC, PNG, MP4, ...) is left alone.

### Archive format (version 2)

```
magic  89 4E 49 4B 0D 0A 1A 0A   version 2   flags   method   reserved
[encrypted only]  Argon2id memory/time/lanes | 16-byte salt | 19-byte nonce prefix
body   entries -> zstd -> (64 KiB chunks, XChaCha20-Poly1305, STREAM-BE32, header as AAD)

entry  FILE   name, mtime, mode, size, data, crc32
       DIR    name, mtime, mode
       MEDIA  name, mtime, mode, size, filter, method, params, framed stream, crc32 (of the ORIGINAL bytes)
       END    entry count
```

---

## Security

**Cryptography (no home-made primitives):**

* **Key derivation:** Argon2id, 64 MiB memory, 3 passes, 4 lanes (RFC 9106 low-memory profile), random 16-byte salt per archive. Every password guess costs an attacker 64 MiB of memory and three passes over it.
* **Encryption:** XChaCha20-Poly1305 (256-bit key, 192-bit nonce, 128-bit tag) in the STREAM construction, so chunk order, count and the *last-chunk* flag are authenticated.
* **Header binding:** the full header (KDF parameters, salt, method) is associated data of every chunk. Changing any bit makes decryption fail.
* **Metadata:** file names, sizes, timestamps, permissions and the file count are inside the encrypted stream.

**Quantum resistance.** A large quantum computer breaks RSA and elliptic-curve cryptography with Shor's algorithm. NIKPAK uses neither. Against symmetric cryptography the best known quantum attack, Grover's algorithm, only halves the effective key length: a 256-bit key keeps about 128 bits of security, which is the reference strength of NIST's strongest post-quantum category. The password-to-key step is memory-hard, which makes Grover-style password search far more expensive than for CPU-only key derivation. Data encrypted today is therefore not exposed to "harvest now, decrypt later" attacks based on public-key breakage. The remaining weak point is always the password, so use a long passphrase or the generated one.

**Hardening:**

* Path traversal (`../`), absolute paths, backslash tricks and Windows reserved names are neutralised on extraction; existing symlinks are never followed; setuid/setgid bits are never restored; files are created with `create_new`.
* Parameters read from an untrusted header are range-checked before any memory is allocated.
* The decoders were fuzzed with random and bit-flipped input and must never panic.
* Archives are written atomically; temporary files are removed on failure.

**Tested attacks (all detected):** flipped ciphertext and header bytes, truncation, dropping the last chunk, reordering chunks, wrong password, garbage files.

**What nobody can promise.** A weak password can always be guessed. `-p<password>` is visible in the process list. Compression happens before encryption, so the archive size reveals how compressible the data is. NIKPAK has **not been independently audited**; have it reviewed before protecting data whose exposure would be seriously harmful.

---

## NIKPAK vs RAR 7

| | NIKPAK 1.1 | RAR 7 |
|---|---|---|
| Compression of audio / images / MOD | Specialised lossless codecs, chosen per file by trial | General algorithm with built-in filters |
| General-data ratio at maximum level | Smaller in the benchmark above | Larger in the benchmark above |
| Speed at fast levels | 0.9 s for 197 MB (-m2) | 9.7-16.7 s (-m3) |
| Encryption | Argon2id + XChaCha20-Poly1305 (authenticated) | AES-256-CBC + PBKDF2-HMAC-SHA256 (RAR5) |
| File names encrypted | Always | Only with `-hp` |
| Memory-hard password hashing | Yes (64 MiB) | No |
| Random password generator | Built in | Not built in |
| Public-key cryptography in file encryption | None (nothing for Shor's algorithm to attack) | None |
| Source code | Full source, you choose the licence | Proprietary |
| Implementation language | Rust (memory safe) | C++ |
| **Recovery records** | Not yet | **Yes** |
| **Multi-volume archives, SFX** | Not yet | **Yes** |
| **Add to an existing archive** | Not yet | **Yes** |
| **GUI, shell integration** | Via Total Commander / scripts | **WinRAR** |
| Track record | New | Decades |

---

## Building

### Windows (PowerShell)

Prerequisites (administrator PowerShell, then reopen PowerShell):

```powershell
winget install Rustlang.Rustup
winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

Build:

```powershell
.\build.ps1            # produces dist\NIKPAK.exe
.\build.ps1 -Test      # run the unit tests first
# or with npm (a thin wrapper around cargo):
npm run dist
# or directly:
cargo build --release
```

`NIKPAK.exe` is statically linked (`.cargo\config.toml`), so it runs on any Windows PC without the Visual C++ Redistributable.

### macOS and Linux

```sh
./build.sh             # produces dist/NIKPAK
# macOS: xcode-select --install     Debian/Ubuntu: sudo apt install build-essential
```

### Total Commander

NIKPAK follows RAR's command syntax (`a`, `x`, `e`, `l`, `t`, `@listfile`, `-p<pwd>`, `-ep1`, `-o+`, `-y`, `-m<n>`), so a front-end that can drive an external `rar.exe` can drive `NIKPAK.exe`. Register the extension `nik` in *Configuration > Packer > Additional packer programs* and use `-o+` or `-y` for unattended extraction. Menu names differ between versions; check the built-in help.

---

## Testing

* **13 unit tests:** the encryption stream, parameter bounds, path sanitising, and the media layer: audio codec round trips for every bit depth (8/16/24/32), channel counts 1-8 and 9 signal types including 32-bit full-scale extremes; all three audio methods across layouts; WAV/AIFF/MOD/BMP detection and round trips including trailing chunks, WAVE_FORMAT_EXTENSIBLE and truncated files; decoders fed with random and corrupted data.
* **End-to-end:** archives of every test set are extracted and compared byte for byte (SHA-256 for the 10,949-file set); encrypted archives with media; archives from the previous format version still open.
* **Attack tests:** zip-slip, planted symlinks, tampering, truncation, chunk reordering, wrong password.

```sh
cargo test --release
```

---

## Limitations and roadmap

* No recovery records, multi-volume archives, self-extractors or in-place update (the format is one solid stream; create a new archive or overwrite with `-o+`).
* Media filters cover integer PCM WAV/AIFF, ProTracker MOD (M.K., M!K!, FLT4, 4CHN, 6CHN, 8CHN, FLT8, OCTA, CD81) and uncompressed BMP. Float WAV, ADPCM, XM/S3M/IT and compressed images are not filtered.
* A solid archive is read sequentially: extracting one file from a very large archive reads everything before it.
* Archives that use media filters need NIKPAK 1.1 or newer. Older archives stay readable.
* The `-m4`/`-m5` levels use a 128 MiB window, so decompression of those archives needs up to that much memory.
* Symbolic links are skipped when archiving; dates are listed in UTC.
* No independent security audit yet.

Ideas for later: recovery records, multi-volume and append support, public-key sharing with a hybrid post-quantum scheme (X25519 + ML-KEM), more filters (float audio, XM/S3M/IT, PNG recompression), a GUI, and an external security review.

---

## Project layout

```
src/main.rs      entry point, exit codes
src/cli.rs       RAR/zip-style argument parsing and help text
src/archive.rs   create / list / test / extract / media test
src/media.rs     content detection, trial selection, Shuffle/Delta/MED filters, stream framing
src/nac.rs       NAC lossless audio codec
src/bits.rs      bit reader / writer
src/crypto.rs    Argon2id key derivation, XChaCha20-Poly1305 chunk stream
src/format.rs    on-disk constants
src/util.rs      passwords, path safety, wildcards, formatting
src/error.rs     error type and exit codes
docs/            technical guide (Word)
```

## Licence

Choose a licence before publishing (MIT or Apache-2.0 are common for tools like this) and add a `LICENSE` file.
