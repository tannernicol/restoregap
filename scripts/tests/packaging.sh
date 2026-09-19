#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Tanner Nicol
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/restoregap-packaging-test.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT
for dependency in go sqlite3 sha256sum; do
  command -v "$dependency" >/dev/null || { echo "packaging tests require $dependency" >&2; exit 1; }
done

empty="$tmp/empty"
mkdir "$empty"
bash "$repo/demo/setup.sh" "$empty" >/dev/null
if bash "$repo/demo/setup.sh" "$empty" >/dev/null 2>&1; then
  echo "setup accepted a non-empty directory" >&2
  exit 1
fi
ln -s "$empty" "$tmp/link"
if bash "$repo/demo/setup.sh" "$tmp/link" >/dev/null 2>&1; then
  echo "setup accepted a symlink" >&2
  exit 1
fi

bin="$tmp/restoregap"
(cd "$repo" && go build -o "$bin" ./cmd/restoregap)
(cd "$tmp" && RESTOREGAP_BIN=./restoregap bash "$repo/demo/run.sh" run >/dev/null)

# Exercise the installer against a synthetic release without contacting GitHub.
release="$tmp/release"
fakebin="$tmp/fakebin"
mkdir -p "$release" "$fakebin"
printf '#!/bin/sh\nprintf demo-binary\\n\n' > "$release/restoregap"
chmod +x "$release/restoregap"
tar -czf "$release/restoregap_9.8.7_linux_amd64.tar.gz" -C "$release" restoregap
archive="restoregap_9.8.7_linux_amd64.tar.gz"
digest="$(sha256sum "$release/$archive" | awk '{print $1}')"
printf '%s  %s\n%s  %s\n' "$digest" "$archive" "$digest" "other.tar.gz" > "$release/checksums.txt"
printf '{"tag_name":"v9.8.7"}\n' > "$release/latest.json"
printf '%s\n' '#!/bin/sh' 'set -eu' 'for arg do case "$arg" in http://*|https://*) url="$arg" ;; esac; done' 'name="${url##*/}"' 'case "$name" in' '  latest.json) cp "$TEST_RELEASE/latest.json" latest.json ;;' '  *) cp "$TEST_RELEASE/$name" "$name" ;;' 'esac' > "$fakebin/curl"
chmod +x "$fakebin/curl"
install_dir="$tmp/bin"
TEST_RELEASE="$release" PATH="$fakebin:$PATH" RESTOREGAP_BIN_DIR="$install_dir" RESTOREGAP_VERSION=v9.8.7 sh "$repo/scripts/install.sh" >/dev/null
test -x "$install_dir/restoregap"
cp "$release/$archive" "$release/restoregap_9.8.8_linux_amd64.tar.gz"
printf '%064d  %s\n' 0 restoregap_9.8.8_linux_amd64.tar.gz > "$release/checksums.txt"
if TEST_RELEASE="$release" PATH="$fakebin:$PATH" RESTOREGAP_BIN_DIR="$tmp/bad-bin" RESTOREGAP_VERSION=v9.8.8 sh "$repo/scripts/install.sh" >/dev/null 2>&1; then
  echo "installer accepted a bad archive checksum" >&2
  exit 1
fi
test ! -e "$tmp/bad-bin/restoregap"
if TEST_RELEASE="$release" PATH="$fakebin:$PATH" RESTOREGAP_BIN_DIR="$tmp/invalid-bin" RESTOREGAP_VERSION=latest sh "$repo/scripts/install.sh" >/dev/null 2>&1; then
  echo "installer accepted an invalid release tag" >&2
  exit 1
fi
echo "packaging tests: PASS"
