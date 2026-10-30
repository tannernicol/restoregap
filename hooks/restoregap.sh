#!/bin/sh
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Tanner Nicol

if ! command -v restoregap >/dev/null 2>&1; then
    if [ "$1" = hook ]; then
        printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"restoregap not installed: install restoregap on PATH, then retry"}}'
        exit 0
    fi
    echo 'restoregap not installed: install restoregap on PATH, then retry' >&2
    exit 1
fi
case "$1" in
    hook)
        restoregap agent hook claude
        result=$?
        if [ "$result" -ne 0 ]; then
            echo 'restoregap recovery gate unavailable' >&2
            exit 2
        fi
        ;;
    mcp) exec restoregap mcp serve ;;
    *) echo 'expected hook or mcp' >&2; exit 2 ;;
esac
