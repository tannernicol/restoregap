#!/usr/bin/env bash
# snapshot-remote-config.sh - pull a tar snapshot of access/config files OFF
# a remote host on a cadence, so a Restore Gap attestation or recovery drill
# can check freshness or restore from it. Generic over the remote (NAS, VPS,
# router — anything reachable over ssh) and the destination (a local dir or
# an rclone remote).
#
# Freshness check (pair this with a Restore Gap proof / drill):
#   ls -1t <dest>/<label>-*.tar.gz* 2>/dev/null | head -1   # then compare mtime to your max-age
#
# Usage:
#   snapshot-remote-config.sh --host <ssh-host-or-alias> \
#     --dest <dir | rclone:<remote>:<path>> [--label <name>=remote-config] \
#     [--keep <N>=14] [--gpg-recipient <id>] [--ssh-opt <opt>]... \
#     -- <remote path>...
#
# Examples:
#   NAS:    snapshot-remote-config.sh --host nas --dest /srv/backups/nas \
#             --label nas-access -- /etc/config/ssh/authorized_keys /etc/passwd
#   VPS:    snapshot-remote-config.sh --host vps1 --dest /srv/backups/vps1 \
#             --label vps-access --gpg-recipient ops@example.com -- \
#             /etc/ssh/sshd_config /etc/passwd /root/.ssh/authorized_keys
#   rclone: snapshot-remote-config.sh --host router \
#             --dest rclone:gdrive:backups/router --label router-config \
#             -- /etc/config /etc/passwd
#
# Exit codes: 0 ok · 1 failure (including an empty archive) · 2 usage.
set -euo pipefail

label="remote-config"
keep=14
gpg_recipient=""
host=""
dest=""
ssh_opts=()
paths=()

usage() {
  echo "Usage: $0 --host H --dest D [--label L] [--keep N] [--gpg-recipient ID] [--ssh-opt OPT]... -- <remote path>..." >&2
}

while (($#)); do
  case "$1" in
    --host) host=$2; shift 2 ;;
    --dest) dest=$2; shift 2 ;;
    --label) label=$2; shift 2 ;;
    --keep) keep=$2; shift 2 ;;
    --gpg-recipient) gpg_recipient=$2; shift 2 ;;
    --ssh-opt) ssh_opts+=("$2"); shift 2 ;;
    --) shift; paths=("$@"); break ;;
    *) usage; exit 2 ;;
  esac
done

[[ -n "$host" && -n "$dest" && ${#paths[@]} -gt 0 ]] || { usage; exit 2; }

tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT

# POSIX single-quote each remote path so the tar command survives whatever
# shell the remote host runs (busybox ash on a NAS/router, bash on a VPS).
quote() { local s=$1; printf "'%s'" "${s//\'/\'\\\'\'}"; }
remote_cmd="tar czf -"
for p in "${paths[@]}"; do remote_cmd+=" $(quote "$p")"; done

plain="$tmpdir/payload.tar.gz"
# SC2029: intentional — remote_cmd is already single-quoted per-path above,
# so it must expand client-side into one command string handed to ssh.
# shellcheck disable=SC2029
(umask 077; ssh "${ssh_opts[@]}" "$host" "$remote_cmd" >"$plain")

entries=$(tar tzf "$plain" 2>/dev/null | wc -l)
if ((entries == 0)); then
  echo "snapshot-remote-config: empty archive from $host (0 entries) — refusing" >&2
  exit 1
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
final="$tmpdir/${label}-${stamp}.tar.gz"
mv "$plain" "$final"

if [[ -n "$gpg_recipient" ]]; then
  gpg --batch --yes --trust-model always -r "$gpg_recipient" -e -o "${final}.gpg" "$final"
  rm -f -- "$final"
  final="${final}.gpg"
fi
chmod 0600 "$final"

fname=$(basename "$final")
sha_full=$(sha256sum "$final" | awk '{print $1}')
printf '%s  %s\n' "$sha_full" "$fname" >"${final}.sha256"
chmod 0600 "${final}.sha256"
bytes=$(stat -c%s "$final")

if [[ "$dest" == rclone:* ]]; then
  target="${dest#rclone:}"
  rclone copyto "$final" "${target%/}/$fname"
  rclone copyto "${final}.sha256" "${target%/}/$fname.sha256"
  echo "note: rclone dest — retention (--keep) is not enforced remotely; prune ${target} manually" >&2
else
  mkdir -p "$dest"
  mv "$final" "${final}.sha256" "$dest/"
  mapfile -t archives < <(find "$dest" -maxdepth 1 -type f \
    \( -name "${label}-*.tar.gz" -o -name "${label}-*.tar.gz.gpg" \) \
    -printf '%T@ %p\n' | sort -rn | awk '{print $2}')
  if ((${#archives[@]} > keep)); then
    for ((i = keep; i < ${#archives[@]}; i++)); do
      rm -f -- "${archives[$i]}" "${archives[$i]}.sha256"
    done
  fi
fi

echo "label=$label dest=$dest bytes=$bytes sha256=${sha_full:0:12} files=$entries"
