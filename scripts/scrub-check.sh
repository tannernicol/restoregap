#!/usr/bin/env bash
# scrub-check.sh — pre-publish gate. Run before any push to a public remote.
#
# Checks THREE independent classes of leak. An identity-only scan is not
# enough: an earlier pre-publish pass on a sibling repo caught the names and
# missed a real SSH private key sitting in test data.
#
#   1. IDENTITY       — real people, real domains, real overlay addresses.
#   2. MACHINE PATHS  — absolute paths from the machine this was built on.
#                       RestoreGap is a recovery tool, so its fixtures are made
#                       of real backup paths. This is its specific hazard.
#   3. KEY MATERIAL   — private keys, tokens, other credential shapes.
#
# The identity denylist lives in `.scrub-denylist` (GITIGNORED). It must never
# be committed: a file listing the names you are trying to keep out of the repo
# is itself the leak. Copy `.scrub-denylist.example` and fill it in locally.
#
# Exit 0 = clean. Exit 1 = something matched; DO NOT PUBLISH.
# Exit 3 = the gate itself is broken. That is NOT a pass — see scan() below.
#
# Usage: scrub-check.sh [target-dir]     (default: the repo this script is in)
# Point it at an export tree to gate a publish; see scripts/publish-export.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The denylist always comes from the working repo, even when scanning an export
# tree — the export must not contain it.
DENYLIST="${SCRUB_DENYLIST:-$REPO_ROOT/.scrub-denylist}"

cd "${1:-$REPO_ROOT}"
fail=0

# Everything tracked by git, minus this script (which necessarily contains the
# patterns it hunts for) and the denylist itself.
#
# -x (whole-line match) is load-bearing: an unanchored prefix pattern also
# excluded `.scrub-denylist.example`, and would silently drop a
# `.scrub-denylist.backup` full of real terms straight out of the scan set.
# Excluding a file from the scan is exactly how a leak walks past a gate that
# reports CLEAN, so the exclusion list is exact paths only.
mapfile -t files < <(git ls-files | grep -vxE 'scripts/scrub-check\.sh|\.scrub-denylist')
if [[ ${#files[@]} -eq 0 ]]; then
  echo "scrub: no tracked files to scan" >&2
  exit 1
fi

report() {   # report <class> <label> <matches...>
  local class="$1" label="$2"; shift 2
  printf '\n\033[31mFAIL\033[0m [%s] %s\n' "$class" "$label"
  printf '  %s\n' "$@"
  fail=1
}

# scan <grep-args...> — run a scan, put hits in MATCH_OUT, return 0 if any.
#
# This exists because of a real bug it now prevents: patterns that start with
# "-" (every PEM header: -----BEGIN ... KEY-----) are parsed by grep as options
# unless passed via -e. With stderr swallowed, that broken pattern looked
# exactly like "no matches found" — the private-key detector silently never
# fired. A gate that fails open is worse than no gate, so grep's error exit (2)
# is now a hard, loud stop rather than a quiet pass.
MATCH_OUT=""
scan() {
  local out rc
  set +e
  out="$("$@" 2>&1)"; rc=$?
  set -e
  if (( rc >= 2 )); then
    printf '\n\033[31mGATE BROKEN\033[0m — a scan command failed, so this run proves nothing:\n' >&2
    printf '  cmd: %s\n' "$*" >&2
    printf '  err: %s\n' "$out" >&2
    printf '\nRefusing to report a verdict. Fix the scanner, then re-run.\n' >&2
    exit 3
  fi
  MATCH_OUT="$out"
  return $rc
}

# ---- 1. Identity ---------------------------------------------------------
if [[ -f "$DENYLIST" ]]; then
  # One term per line; blank lines and #-comments ignored. Case-insensitive,
  # fixed-string (not regex) so surnames with punctuation behave.
  while IFS= read -r term; do
    [[ -z "$term" || "$term" =~ ^[[:space:]]*# ]] && continue
    if scan grep -rniF -e "$term" -- "${files[@]}"; then
      report identity "denylisted term: $term" "$MATCH_OUT"
    fi
  done < "$DENYLIST"
else
  printf '\n\033[33mWARN\033[0m no %s found — identity scan SKIPPED.\n' "$DENYLIST"
  printf '  Copy .scrub-denylist.example and fill it in before publishing.\n'
  fail=1
fi

# Tailscale/CGNAT overlay addresses (100.64.0.0/10) are always real hosts.
if scan grep -rnE -e '\b100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}\b' -- "${files[@]}"; then
  report identity "overlay (CGNAT 100.64/10) address" "$MATCH_OUT"
fi

# ---- 2. Machine paths ----------------------------------------------------
# Deliberately generic — this script ships in the export, so it must not name
# the machine it is protecting. A username in a doc comment is cosmetic; a
# backup path in a golden fixture tells a stranger where the backups live.
#
# PLACEHOLDER_USER is the set of home-directory names that are *supposed* to be
# in the fixtures. This repo's testdata was genericized to /home/user, so
# flagging that would fire on every golden case and train the reader to ignore
# the gate. A gate that cries wolf is worse than no gate: keep this list tight,
# and only add a name that is genuinely a placeholder.
PLACEHOLDER_USER='^/(home|Users)/(user|users|other|runner|ci|example|test|you)$'

# A home directory whose owner is not a known placeholder is a real account.
if scan grep -rnoE -e '/(home|Users)/[A-Za-z][A-Za-z0-9_.-]*' -- "${files[@]}"; then
  real_homes=""
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    path="${line##*:}"
    [[ "$path" =~ $PLACEHOLDER_USER ]] || real_homes+="$line"$'\n'
  done <<< "$MATCH_OUT"
  [[ -n "$real_homes" ]] && report machine-path "home directory of a real account" "${real_homes%$'\n'}"
fi

# The literal mount point on the machine this was built from. Generic-looking
# fixture paths (/mnt/backup, /media/recovery-usb) are deliberately NOT matched:
# the recovery-USB pattern is a shipped product default in
# internal/contextspec/default.go, and a rule that fires on the product's own
# defaults is a rule nobody will read. A *named* external volume is an identity
# problem — put the name in .scrub-denylist, which is where names belong.
if scan grep -rnE -e '/mnt/nas' -- "${files[@]}"; then
  report machine-path "NAS mount path" "$MATCH_OUT"
fi

# ---- 3. Key material -----------------------------------------------------
# Ordered roughly by how badly it ends if one gets through. Every pattern goes
# through scan()'s -e, including the PEM headers that start with a dash.
declare -A KEYPAT=(
  ["private key block"]='-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'
  ["SSH public key"]='ssh-(rsa|ed25519|dss) AAAA'
  ["PEM certificate block"]='-----BEGIN CERTIFICATE-----'
  ["age/minisign secret key"]='AGE-SECRET-KEY-1|RWRTY0Iy'
  ["GitHub token"]='(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{20,}'
  ["AWS access key id"]='\b(AKIA|ASIA)[0-9A-Z]{16}\b'
  ["Slack token"]='xox[baprs]-[0-9A-Za-z-]{10,}'
  ["JWT"]='\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
  ["assigned secret literal"]='(password|passwd|secret|token|api_?key)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9/+_-]{16,}'
  ["argon2/bcrypt hash"]='[$](argon2(id|i|d)|2[aby])[$]'
)
for label in "${!KEYPAT[@]}"; do
  if scan grep -rnE -e "${KEYPAT[$label]}" -- "${files[@]}"; then
    # .example files may legitimately show a placeholder shape; require the
    # match to be outside them before failing.
    real=$(printf '%s\n' "$MATCH_OUT" | grep -vE '\.example(\.[a-z]+)?:' || true)
    [[ -n "$real" ]] && report key-material "$label" "$real"
  fi
done

# ---- 4. Files that must never be tracked ---------------------------------
# Exact paths, not globs: testdata/golden/cases/*/restoregap.local.yml are
# legitimate fixtures, while a restoregap.local.yml at the root is the real
# machine's config and must never ship.
for forbidden in restoregap.local.yml .env .scrub-denylist .restoregap/context.yml; do
  if git ls-files --error-unmatch "$forbidden" >/dev/null 2>&1; then
    report tracked-file "must be gitignored, but git is tracking it" "$forbidden"
  fi
done

if [[ $fail -eq 0 ]]; then
  printf '\n\033[32mCLEAN\033[0m — %d tracked files scanned (identity + machine paths + key material).\n' "${#files[@]}"
else
  printf '\n\033[31mDO NOT PUBLISH.\033[0m Resolve every FAIL above, then re-run.\n'
  printf 'Remember: fixing the working tree is not enough if the leak is in history.\n'
fi
exit $fail
