// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/discovery"
)

// contextDiscoveryHelp documents the fallback order applied whenever
// --context is omitted, for reuse in every affected command's --help text so
// the order never drifts out of sync with discoverContext below.
const contextDiscoveryHelp = "discovery order when omitted: $RESTOREGAP_CONTEXT, then ./restoregap.local.yml, then ./restoregap.yml, " +
	"then every *.yml in $XDG_CONFIG_HOME/restoregap (or ~/.config/restoregap)"

// contextDiscoveryHelpRepeatable is contextDiscoveryHelp's variant for the
// repeatable-context commands (preflight, status): $RESTOREGAP_CONTEXT may
// itself hold a colon-separated list, the config directory may hold several
// files, and every loaded file's guards/proofs are merged rather than the
// single-file replace-only semantics of the write commands.
const contextDiscoveryHelpRepeatable = "repeatable; also $RESTOREGAP_CONTEXT may hold a colon-separated list " +
	"and every *.yml in the config directory is discovered — " +
	"proofs and guards from every file are merged, duplicate ids are an error"

// ledgerDiscoveryHelp documents the fallback order applied whenever --ledger
// is omitted, for reuse in --help text.
const ledgerDiscoveryHelp = "discovery order when omitted: $RESTOREGAP_LEDGER, then $XDG_STATE_HOME/restoregap/ledger.jsonl, then ~/.local/state/restoregap/ledger.jsonl"

// discoverContext resolves a single --context flag value. If explicit is
// non-empty it is returned unchanged (and silently — an explicitly passed
// context is never announced). Otherwise it tries, in order:
// $RESTOREGAP_CONTEXT (taking the first entry if it holds a colon-separated
// list), then ./restoregap.local.yml, then ./restoregap.yml relative to the
// current working directory, then the first *.yml in the user config
// directory ($XDG_CONFIG_HOME/restoregap, or ~/.config/restoregap) —
// preferring restoregap.local.yml wherever present, per the tier order. It
// returns "" when none of those resolves to anything, leaving the caller to
// decide what "no context" means for it (the built-in zero-config default
// policy for status/preflight, or a hard refusal for commands with no such
// fallback).
//
// Whenever a context is found by discovery — never when the caller passed
// --context explicitly — exactly one line is printed to stderr naming it,
// so a run's provenance is never silent.
func discoverContext(cmd *cobra.Command, explicit string) string {
	if explicit != "" {
		return explicit
	}
	paths := discovery.ContextPaths()
	if len(paths) == 0 {
		return ""
	}
	announceDiscovery(cmd, "context", paths[0])
	return paths[0]
}

// discoverContextPaths is discoverContext for the repeatable-context
// commands (preflight, status): explicit, when non-empty, is returned
// unchanged and silently; otherwise every path discovery.ContextPaths()
// finds is returned (which may be more than one, from a colon-separated
// $RESTOREGAP_CONTEXT or from a config directory holding several context
// files). Up to 3 files are announced as a single joined line, same as
// always. More than 3 — the routine shape once one context file per drill
// is the real deployment — collapses to a one-line summary instead of
// dumping every path; --verbose (a root persistent flag) opts back into the
// full list.
func discoverContextPaths(cmd *cobra.Command, explicit []string) []string {
	if len(explicit) > 0 {
		return explicit
	}
	paths := discovery.ContextPaths()
	if len(paths) == 0 {
		return nil
	}
	if len(paths) > maxAnnouncedContextPaths && !verboseRequested(cmd) {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "context: %d files (%s, discovered) — --verbose lists them\n",
			len(paths), summarizeContextPaths(paths))
		return paths
	}
	announceDiscovery(cmd, "context", strings.Join(paths, ", "))
	return paths
}

// maxAnnouncedContextPaths is the discovered-file count above which the
// context announcement collapses to a summary instead of listing every
// path.
const maxAnnouncedContextPaths = 3

// verboseRequested reports whether --verbose was passed. It is a root
// persistent flag (registered in root.go), inherited by every subcommand's
// FlagSet, so any leaf command's cmd.Flags() sees it once cobra has parsed
// the command line.
func verboseRequested(cmd *cobra.Command) bool {
	v, _ := cmd.Flags().GetBool("verbose")
	return v
}

// summarizeContextPaths builds the "<named file> + N drill files" label
// used when more than maxAnnouncedContextPaths context files are
// discovered. "Drill file" is the established deployment convention — one
// context file per drill, named *-drill.yml in the config directory (see
// internal/discovery) — so a base name matching that suffix is folded into
// the drill count instead of being named individually; anything else
// discovered (restoregap.local.yml/restoregap.yml, or an arbitrarily named
// file from a colon-separated $RESTOREGAP_CONTEXT) is named explicitly by
// its base name.
func summarizeContextPaths(paths []string) string {
	var named []string
	drillCount := 0
	for _, p := range paths {
		base := filepath.Base(p)
		if strings.HasSuffix(base, "-drill.yml") {
			drillCount++
			continue
		}
		named = append(named, base)
	}
	label := strings.Join(named, " + ")
	if drillCount > 0 {
		unit := "drill files"
		if drillCount == 1 {
			unit = "drill file"
		}
		drillPart := fmt.Sprintf("%d %s", drillCount, unit)
		if label == "" {
			label = drillPart
		} else {
			label = label + " + " + drillPart
		}
	}
	return label
}

// requireContext is discoverContext for commands that have no zero-config
// fallback: when nothing is discoverable it refuses with the standard
// "run `restoregap context init` first, or pass --context" message rather
// than silently defaulting to anything. cmdName names the failing command
// in the error, e.g. "drill" or "evidence ingest".
func requireContext(cmd *cobra.Command, explicit, cmdName string) (string, error) {
	path := discoverContext(cmd, explicit)
	if path == "" {
		return "", fmt.Errorf("%s: --context is required — run `restoregap context init` first, or pass --context", cmdName)
	}
	return path, nil
}

func announceDiscovery(cmd *cobra.Command, kind, path string) {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s (discovered)\n", kind, path)
}

// defaultLedgerPath resolves the default ledger location applied whenever
// --ledger is omitted: $RESTOREGAP_LEDGER, then
// $XDG_STATE_HOME/restoregap/ledger.jsonl, then
// ~/.local/state/restoregap/ledger.jsonl. It creates the parent directory
// so callers can append to the returned path immediately.
func defaultLedgerPath() (string, error) {
	path := os.Getenv("RESTOREGAP_LEDGER")
	if path == "" {
		stateDir := os.Getenv("XDG_STATE_HOME")
		if stateDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("resolve default ledger path: %w", err)
			}
			stateDir = filepath.Join(home, ".local", "state")
		}
		path = filepath.Join(stateDir, "restoregap", "ledger.jsonl")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("default ledger: %w", err)
	}
	return path, nil
}

// resolveLedger returns explicit unchanged when set. Otherwise it resolves
// and returns the default ledger path, plus defaulted=true so callers that
// need to report provenance (preflight's report footer) can tell the two
// cases apart.
func resolveLedger(explicit string) (path string, defaulted bool, err error) {
	if explicit != "" {
		return explicit, false, nil
	}
	p, err := defaultLedgerPath()
	if err != nil {
		return "", false, err
	}
	return p, true, nil
}
