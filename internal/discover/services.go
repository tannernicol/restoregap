// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"os/exec"
	"sort"
	"strings"
)

// serviceStateHints are substrings that mark a path referenced by a unit as
// "state" worth backing up, beyond the .db/.sqlite* extensions
// looksLikeStatePath also checks.
var serviceStateHints = []string{"/data", "/state", "/db"}

// runSystemctlListUnits, runSystemctlListUnitFiles and runSystemctlCat are
// function variables so tests can inject fixed output or simulate
// systemctl being absent; production shells out to the real systemctl.
var runSystemctlListUnits = func() ([]byte, error) {
	return exec.Command("systemctl", "--user", "list-units", //nolint:gosec // fixed invocation
		"--type=service", "--all", "--no-legend", "--plain", "--no-pager").Output()
}

var runSystemctlListUnitFiles = func() ([]byte, error) {
	return exec.Command("systemctl", "--user", "list-unit-files", //nolint:gosec // fixed invocation
		"--type=service", "--no-legend", "--no-pager").Output()
}

var runSystemctlCat = func(unit string) ([]byte, error) {
	return exec.Command("systemctl", "--user", "cat", unit).Output() //nolint:gosec // unit comes from our own systemctl calls
}

// collectServices reports one candidate per enabled-or-active systemd user
// unit whose declared content (ExecStart or anything else in the unit
// file) references a path under home that looks like state. It degrades to
// an empty result — never an error — when systemctl is not on PATH or the
// user systemd instance is not reachable.
func collectServices(home string) []Candidate {
	units, err := enabledOrActiveUnits()
	if err != nil {
		return nil
	}
	var out []Candidate
	for _, unit := range units {
		content, err := runSystemctlCat(unit)
		if err != nil {
			continue
		}
		if statePath, ok := findStatePath(string(content), home); ok {
			out = append(out, Candidate{
				Kind: KindServiceState, Name: unit, Path: statePath,
				SizeBytes: dirEntrySize(statePath), Weight: weightFor(KindServiceState),
			})
		}
	}
	return out
}

// enabledOrActiveUnits returns the sorted, de-duplicated union of unit
// names that are either enabled or currently active. Either underlying
// systemctl call failing is treated as "no user systemd instance
// reachable" and reported to the caller so it degrades to empty rather
// than reporting a partial, misleading list.
func enabledOrActiveUnits() ([]string, error) {
	activeOut, err := runSystemctlListUnits()
	if err != nil {
		return nil, err
	}
	enabledOut, err := runSystemctlListUnitFiles()
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for unit := range parseActiveUnits(activeOut) {
		set[unit] = true
	}
	for unit := range parseEnabledUnits(enabledOut) {
		set[unit] = true
	}
	units := make([]string, 0, len(set))
	for unit := range set {
		units = append(units, unit)
	}
	sort.Strings(units)
	return units, nil
}

// parseActiveUnits parses `systemctl --user list-units` output (columns
// UNIT LOAD ACTIVE SUB DESCRIPTION) into the set of units whose ACTIVE
// column reads "active".
func parseActiveUnits(out []byte) map[string]bool {
	units := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[2] == "active" {
			units[fields[0]] = true
		}
	}
	return units
}

// parseEnabledUnits parses `systemctl --user list-unit-files` output
// (columns UNIT_FILE STATE) into the set of units whose STATE column reads
// "enabled".
func parseEnabledUnits(out []byte) map[string]bool {
	units := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "enabled" {
			units[fields[0]] = true
		}
	}
	return units
}

// findStatePath scans content for a whitespace/"="-separated token that
// starts with home and looks like state (per looksLikeStatePath), returning
// the first one found.
func findStatePath(content, home string) (string, bool) {
	if home == "" {
		return "", false
	}
	fields := strings.FieldsFunc(content, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '='
	})
	for _, tok := range fields {
		if strings.HasPrefix(tok, home) && looksLikeStatePath(tok) {
			return tok, true
		}
	}
	return "", false
}

// looksLikeStatePath reports whether path contains one of
// serviceStateHints, or ends in .db/.sqlite/.sqlite3.
func looksLikeStatePath(path string) bool {
	for _, hint := range serviceStateHints {
		if strings.Contains(path, hint) {
			return true
		}
	}
	return strings.HasSuffix(path, ".db") || strings.HasSuffix(path, ".sqlite") || strings.HasSuffix(path, ".sqlite3")
}
