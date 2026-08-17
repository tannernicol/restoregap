package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// contextDiscoveryHelp documents the fallback order applied whenever
// --context is omitted, for reuse in every affected command's --help text so
// the order never drifts out of sync with discoverContext below.
const contextDiscoveryHelp = "discovery order when omitted: $RESTOREGAP_CONTEXT, then ./restoregap.local.yml, then ./restoregap.yml"

// ledgerDiscoveryHelp documents the fallback order applied whenever --ledger
// is omitted, for reuse in --help text.
const ledgerDiscoveryHelp = "discovery order when omitted: $RESTOREGAP_LEDGER, then $XDG_STATE_HOME/restoregap/ledger.jsonl, then ~/.local/state/restoregap/ledger.jsonl"

// discoverContext resolves a --context flag value. If explicit is non-empty
// it is returned unchanged (and silently — an explicitly passed context is
// never announced). Otherwise it tries, in order: $RESTOREGAP_CONTEXT, then
// ./restoregap.local.yml, then ./restoregap.yml relative to the current
// working directory. It returns "" when none of those resolves to anything,
// leaving the caller to decide what "no context" means for it (the built-in
// zero-config default policy for status/preflight, or a hard refusal for
// commands with no such fallback).
//
// Whenever a context is found by discovery — never when the caller passed
// --context explicitly — exactly one line is printed to stderr naming it,
// so a run's provenance is never silent.
func discoverContext(cmd *cobra.Command, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v := os.Getenv("RESTOREGAP_CONTEXT"); v != "" {
		announceDiscovery(cmd, "context", v)
		return v
	}
	for _, candidate := range []string{"restoregap.local.yml", "restoregap.yml"} {
		if isRegularFile(candidate) {
			announceDiscovery(cmd, "context", candidate)
			return candidate
		}
	}
	return ""
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

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
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
