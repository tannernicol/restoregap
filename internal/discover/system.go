// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import "os"

// SystemPaths names the fixed, always-emitted machine-floor candidates:
// things a rebuild needs even though nobody would normally "back them up".
// Overridable so tests never touch the real /etc.
type SystemPaths struct {
	// MachineID is /etc/machine-id by default.
	MachineID string
	// PackageManifests are candidate package-database locations, checked in
	// order; the first that exists is reported. Defaults cover dpkg, rpm,
	// and pacman.
	PackageManifests []string
	// Etc is the hand-edited /etc directory, reported as one candidate
	// standing in for every local customization under it — enumerating the
	// actual diff against each package's pristine files is out of scope for
	// a deterministic, offline enumerator.
	Etc string
}

// isZero reports whether sp is the unset zero value, so Collect knows to
// substitute defaultSystemPaths() — SystemPaths holds a slice field, so it
// is not `==`-comparable, hence this explicit check instead.
func (sp SystemPaths) isZero() bool {
	return sp.MachineID == "" && sp.Etc == "" && len(sp.PackageManifests) == 0
}

// defaultSystemPaths returns SystemPaths for the real machine.
func defaultSystemPaths() SystemPaths {
	return SystemPaths{
		MachineID:        "/etc/machine-id",
		PackageManifests: []string{"/var/lib/dpkg/status", "/var/lib/rpm", "/var/lib/pacman/local"},
		Etc:              "/etc",
	}
}

// collectSystem returns the three fixed system candidates: machine-id,
// package-manifest, and etc-config. These are candidates even though they
// are not files anyone would normally "back up" — a rebuild needs them.
func collectSystem(sp SystemPaths) []Candidate {
	return []Candidate{
		systemCandidate(KindMachineID, "machine-id", sp.MachineID),
		systemCandidate(KindPackageManifest, "package-manifest", firstExisting(sp.PackageManifests)),
		systemCandidate(KindEtcConfig, "etc-customizations", sp.Etc),
	}
}

// systemCandidate builds one fixed-kind candidate. Size is best-effort: 0
// for an empty path, a directory, or anything unreadable — see
// dirEntrySize (repos.go).
func systemCandidate(kind Kind, name, path string) Candidate {
	return Candidate{Kind: kind, Name: name, Path: path, SizeBytes: dirEntrySize(path), Weight: weightFor(kind)}
}

// firstExisting returns the first path in candidates that exists, or "" if
// none do (the report still names the candidate; an empty path just means
// this host's package manager was not one of the ones checked).
func firstExisting(candidates []string) string {
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
