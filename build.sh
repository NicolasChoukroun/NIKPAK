#!/usr/bin/env sh
# build.sh - build nikpak on macOS / Linux.   Usage: ./build.sh
set -e
cd "$(dirname "$0")"
if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust (cargo) not found. Install it with:"
  echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  echo "(macOS also needs the Xcode command line tools:  xcode-select --install)"
  echo "(Debian/Ubuntu also needs a C compiler:           sudo apt install build-essential)"
  exit 1
fi
cargo build --release
mkdir -p dist
cp target/release/nikpak dist/nikpak
echo "OK -> $(pwd)/dist/nikpak"
echo "Optional install:  sudo cp dist/nikpak /usr/local/bin/"
