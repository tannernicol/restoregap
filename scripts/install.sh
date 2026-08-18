#!/usr/bin/env sh
# install.sh — download the latest Restore Gap release binary for this machine,
# verify it against the release's checksums.txt, and put it on PATH.
#
#   curl -sSfLO https://raw.githubusercontent.com/tannernicol/restoregap/<tag>/scripts/install.sh
#   less install.sh && sh install.sh        # read it, then run it — never pipe it into a shell
#
# Environment:
#   RESTOREGAP_VERSION   tag to install (default: latest release)
#   RESTOREGAP_BIN_DIR   where to install (default: ~/.local/bin, or /usr/local/bin as root)
#
# It never runs anything it downloaded before the checksum matches, and it
# never asks for sudo: if the target dir is not writable, it says so and stops.
set -eu

REPO="tannernicol/restoregap"
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "install.sh: unsupported architecture: $arch (linux/darwin amd64/arm64 are built)" >&2; exit 1 ;;
esac
case "$os" in linux|darwin) ;; *) echo "install.sh: unsupported OS: $os" >&2; exit 1 ;; esac

if [ -n "${RESTOREGAP_VERSION:-}" ]; then
  tag="$RESTOREGAP_VERSION"
else
  tag=$(curl -sSfL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
  [ -n "$tag" ] || { echo "install.sh: could not determine the latest release" >&2; exit 1; }
fi
ver=${tag#v}
archive="restoregap_${ver}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"

if [ -n "${RESTOREGAP_BIN_DIR:-}" ]; then bindir="$RESTOREGAP_BIN_DIR"
elif [ "$(id -u)" = 0 ]; then bindir=/usr/local/bin
else bindir="$HOME/.local/bin"; fi
mkdir -p "$bindir"
[ -w "$bindir" ] || { echo "install.sh: $bindir is not writable — set RESTOREGAP_BIN_DIR" >&2; exit 1; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
curl -sSfLO "$base/$archive"
curl -sSfLO "$base/checksums.txt"
if command -v sha256sum >/dev/null; then sha256sum -c checksums.txt --ignore-missing --quiet
else shasum -a 256 -c checksums.txt --ignore-missing --quiet; fi
tar -xzf "$archive" restoregap
install -m 0755 restoregap "$bindir/restoregap"
echo "installed $("$bindir/restoregap" --version) to $bindir/restoregap"
case ":$PATH:" in *":$bindir:"*) ;; *) echo "note: $bindir is not on your PATH" ;; esac
