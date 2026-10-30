#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Tanner Nicol

# demo/setup.sh — build the small fixture the README demo runs against.
#
# A live project with three files and a "backup" of it that quietly went
# stale: one file was never copied, one is out of date, and the SQLite
# database has a recovery copy sitting beside it. Nothing here is a real
# system — the point is that `restoregap check` finds all of it with no
# configuration, and the drill/preflight steps then work on app.db.
#
# Usage: demo/setup.sh [dir]     (default: /tmp/rg-demo; must be new or empty)
set -euo pipefail

DEMO="${1:-/tmp/rg-demo}"
command -v sqlite3 >/dev/null || {
  echo "demo/setup.sh: sqlite3 is required (install it with your OS package manager, then retry)" >&2
  exit 1
}
if [ -L "$DEMO" ]; then
  echo "demo/setup.sh: refusing symlink target: $DEMO" >&2
  exit 1
fi
if [ -e "$DEMO" ] && [ ! -d "$DEMO" ]; then
  echo "demo/setup.sh: target exists and is not a directory: $DEMO" >&2
  exit 1
fi
if [ -d "$DEMO" ] && find "$DEMO" -mindepth 1 -print -quit | grep -q .; then
  echo "demo/setup.sh: refusing non-empty directory: $DEMO (choose a fresh path)" >&2
  exit 1
fi
mkdir -p "$DEMO/proj" "$DEMO/backup/proj"
cd "$DEMO"
DEMO="$PWD"

# Live project.
printf 'DATABASE_URL=sqlite:///app.db\nSECRET_KEY=not-a-real-secret\n' > proj/.env
printf 'listen = :8080\nworkers = 4\n' > proj/app.conf
sqlite3 proj/app.db 'CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT);'
i=1
while [ "$i" -le 100 ]; do
  echo "INSERT INTO users(name) VALUES ('user$i');"
  i=$((i + 1))
done | sqlite3 proj/app.db

# The recovery copy: .env was never backed up, app.conf is stale, and the
# database copy is a little behind (95 of 100 rows) — realistic for a nightly job.
printf 'listen = :8080\nworkers = 2\n' > backup/proj/app.conf
cp proj/app.db backup/proj/app.db
cp proj/app.db backup/app.db
sqlite3 backup/app.db 'DELETE FROM users WHERE id > 95;'
sqlite3 backup/proj/app.db 'DELETE FROM users WHERE id > 95;'
touch -t 202001010000 backup/proj/app.conf backup/proj/app.db backup/app.db

# The intent: what a coding agent (or you) is about to do.
cat > rm-app-db.yml <<YAML
version: 2
action: delete_file
path: $DEMO/proj/app.db
actor: agent/claude
description: remove app.db during cleanup
YAML

# Keep the demo out of the machine's real ledger.
export RESTOREGAP_LEDGER="$DEMO/ledger.jsonl"
echo "demo fixture ready in $DEMO"
