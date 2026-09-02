#!/bin/sh
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Tanner Nicol

# ui_check.sh — the frontend lane for the restoregap.com landing page.
#
# CONTRACT (mk/ui.mk): exit 0 pass · exit 75 could-not-run-here · else fail.
# This repo's lane is invoked as `sh scripts/ui_check.sh`, so the script is
# POSIX sh — no bashisms.
#
# Two halves, same as money's ui_check:
#   1. STRUCTURAL — always runs, no browser needed: the page is one
#      self-contained file with NO JavaScript (that is a promise the site
#      makes on its face), so a stray <script> tag is a regression, and so
#      are a missing h1 and a demo.gif that stopped being referenced.
#   2. MOBILE — the fleet-shared gate (~/homelab/scripts/mobile-ui-check.py)
#      at three phone widths: 320x568 (smallest iPhone SE), 390x844 and
#      430x932. The browser runs in a container, so the page is served on
#      the Docker bridge address the container CAN reach, from a temp COPY
#      of site/ (money's trick: the server never touches the working tree).
#
#      --allow-scroll-x 'pre': the site's own rule is that long code lines
#      scroll INSIDE their <pre> rather than wrapping mid-token; the flag is
#      the checker's mechanism for declaring exactly that scroller.
#
#      --views '.site-nav a[href^="#"]': the sweep selector matches IN-PAGE
#      nav anchors only. Sweeping the whole <nav> clicked the external
#      Walkthrough/GitHub links, navigated off-site, and graded GitHub's 404
#      page (the repo is private) — tap-target findings about Primer buttons
#      that have nothing to do with this site.
set -eu

cd "$(dirname "$0")/.."

EX_CANNOT_RUN=75

# --- 1. structural checks (always) ------------------------------------------
fails=0
if grep -q '<script' site/index.html; then
    echo "FAIL structural: site/index.html contains a <script> tag — the page is promised JS-free"
    fails=$((fails + 1))
else
    echo "ok   structural: no <script> in site/index.html"
fi
if grep -q 'Prove your recovery works' site/index.html && grep -q '<h1' site/index.html; then
    echo "ok   structural: h1 present with hero copy"
else
    echo "FAIL structural: h1 hero copy missing from site/index.html"
    fails=$((fails + 1))
fi
if grep -q 'demo.gif' site/index.html; then
    echo "ok   structural: demo.gif referenced"
else
    echo "FAIL structural: demo.gif not referenced in site/index.html"
    fails=$((fails + 1))
fi
[ "$fails" -eq 0 ] || exit 1

# --- 2. mobile gate ----------------------------------------------------------
SDK="${PLATFORM_SDK:-$HOME/homelab}"
CHECKER="$SDK/scripts/mobile-ui-check.py"
[ -f "$CHECKER" ] || { echo "SKIP mobile: shared checker not found at $CHECKER"; exit "$EX_CANNOT_RUN"; }

bridge=$(ip -4 -o addr show docker0 2>/dev/null | awk '{print $4}' | cut -d/ -f 1 || true)
if [ -z "$bridge" ]; then
    echo "SKIP mobile: no docker0 bridge address — browser container would not reach a served page"
    exit "$EX_CANNOT_RUN"
fi
command -v python3 >/dev/null 2>&1 || { echo "SKIP mobile: python3 not on PATH"; exit "$EX_CANNOT_RUN"; }

# A FIXED port is a trap: a leftover instance from an earlier run answers the
# readiness curl and the check silently grades the stale page (money learned
# this the hard way). Pick a free port and refuse to reuse an occupied one.
port=${RG_UI_CHECK_PORT:-0}
if [ "$port" -eq 0 ]; then
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        candidate=$((20000 + $$ % 20000))
        if ! ss -ltn "sport = :$candidate" 2>/dev/null | grep -q LISTEN; then
            port=$candidate
            break
        fi
    done
fi
if ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN; then
    echo "ui_check: port $port already in use — refusing to grade another process"
    exit "$EX_CANNOT_RUN"
fi

TMP_DIR=$(mktemp -d -t rg-uicheck-XXXXXX)
cp -r site/. "$TMP_DIR/"
SERVE_ADDR="$bridge:$port"
python3 -m http.server --bind "$bridge" "$port" --directory "$TMP_DIR" >"$TMP_DIR/serve.log" 2>&1 &
SERVE_PID=$!

cleanup() {
    # Kill the server by its own argv (bind address + port), which is unique
    # to this run, then the PID — a `python3 -m http.server` child survives
    # a bare parent kill and keeps holding the port.
    pkill -f -- "--bind $bridge $port" 2>/dev/null || true
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

up=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if curl -sf -o /dev/null "http://$SERVE_ADDR/"; then up=1; break; fi
    sleep 0.5
done
if [ "$up" -ne 1 ]; then
    echo "SKIP mobile: temp server did not come up on $SERVE_ADDR"
    sed -n '1,5p' "$TMP_DIR/serve.log" || true
    exit "$EX_CANNOT_RUN"
fi

# One width per run; screenshots land in per-width subdirs so the three runs
# do not overwrite each other's mobile-*.png (they share a view name).
rc_overall=0
saw_run=0
for viewport in 320x568 390x844 430x932; do
    echo "--- mobile gate: $viewport ---"
    python3 "$CHECKER" \
        --url "http://$SERVE_ADDR/" \
        --views '.site-nav a[href^="#"]' \
        --screenshot-dir "/tmp/rg-site-shots/$viewport" \
        --viewport "$viewport" \
        --allow-scroll-x 'pre'
    rc=$?
    if [ "$rc" -eq "$EX_CANNOT_RUN" ]; then
        echo "SKIP mobile ($viewport): checker could not run here (no browser endpoint?)"
    elif [ "$rc" -ne 0 ]; then
        rc_overall=1
    else
        saw_run=1
    fi
done

if [ "$rc_overall" -ne 0 ]; then
    exit 1
fi
if [ "$saw_run" -ne 1 ]; then
    exit "$EX_CANNOT_RUN"
fi
echo "ui_check: all mobile widths green"
exit 0
