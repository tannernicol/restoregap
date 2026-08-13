#!/usr/bin/env bash
# publish-export.sh — build the public tree from this private repo.
#
# The public repo is an EXPORT, not this repo with a flipped visibility switch.
# Two reasons, both learned the hard way:
#
#   1. History. Scrubbing the working tree does nothing about what is still
#      sitting in an earlier commit. A squashed single-commit export has no
#      history to leak. This repo's history includes a Python-era scanner and
#      a cloud/AWS surface that were deliberately cut from the product.
#   2. Internal docs. Anything listed in .publishignore stays private.
#
# Usage: scripts/publish-export.sh [output-dir]
#        (default: ../restoregap-public)
#
# The export is refused if scrub-check.sh fails against it. That is the point.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$(dirname "$REPO_ROOT")/restoregap-public}"

cd "$REPO_ROOT"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "refusing to export from a dirty tree — commit or set the work aside first" >&2
  exit 1
fi

if [[ -e "$OUT" ]]; then
  echo "refusing to overwrite existing path: $OUT" >&2
  echo "remove it yourself if that is what you meant" >&2
  exit 1
fi

mkdir -p "$OUT"

# Copy tracked files only (never the working tree — untracked junk and
# gitignored real-machine files must not ride along), minus .publishignore.
excluded=()
if [[ -f .publishignore ]]; then
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    excluded+=("$line")
  done < .publishignore
fi

while IFS= read -r f; do
  skip=0
  for pat in "${excluded[@]}"; do
    # shellcheck disable=SC2053
    [[ "$f" == $pat ]] && { skip=1; break; }
  done
  [[ $skip -eq 1 ]] && continue
  mkdir -p "$OUT/$(dirname "$f")"
  cp -p "$f" "$OUT/$f"
done < <(git ls-files)

git -C "$OUT" init -q
git -C "$OUT" add -A
git -C "$OUT" -c commit.gpgsign=false commit -q -m "Initial public release"

echo "exported $(git -C "$OUT" ls-files | wc -l) files to $OUT (1 commit, no history)"
echo

if ! "$REPO_ROOT/scripts/scrub-check.sh" "$OUT"; then
  echo
  echo "export left in place at $OUT for inspection — DO NOT PUSH IT." >&2
  exit 1
fi

echo
echo "Export is clean. Remaining manual steps before it is public:"
echo "  1. The module path must resolve. Confirm 'go install <module>/cmd/restoregap@latest'"
echo "     actually works from a machine that has never seen this repo."
echo "  2. Cut a real tag — Version in internal/cli/root.go must not ship as 0.0.0-dev."
echo "  3. gh repo create --private first, push, review it on the web as a stranger"
echo "     would read it, THEN flip visibility. Never create it public."
echo "  4. Publishing is gated on the allowlist in ~/CLAUDE.md. 'restoregap' is NOT on it"
echo "     as of 2026-08-06 — Tanner must add it explicitly before anything is flipped."
