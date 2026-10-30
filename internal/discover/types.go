// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package discover enumerates recovery CANDIDATES on this host — things a
// rebuild would need that nothing has necessarily declared — and diffs them
// against a context's declared drills and guards, answering the question
// `restoregap status` never asks: not "are my declared things proven?" but
// "what did I forget to declare?"
//
// This package is purely deterministic enumeration plus a diff. It never
// calls an LLM, never phones home, and needs no network or API key: the
// judgment about which gaps matter belongs to the agent reading the report,
// not to this binary.
//
// Artifact coverage is derived from a declared context's drills and guards
// (coverage.go) — nothing in this package, and no caller, can mark an
// artifact candidate covered any other way. Agent coverage instead reports
// installed hook and MCP wiring, never recovery evidence. A previous scan's
// snapshot (state.go) is
// read back only to carry forward FirstSeen and compute the new-since-last-
// scan list; its Covered/CoveredBy values are never trusted or reused. See
// docs/DISCOVER.md.
package discover

import "time"

// Kind identifies a candidate's source collector.
type Kind string

// The Kind values, one per collector in this package.
const (
	KindContainerVolume Kind = "container-volume"
	KindDatabase        Kind = "database"
	KindRepo            Kind = "repo"
	KindServiceState    Kind = "service-state"
	KindPackageManifest Kind = "package-manifest"
	KindEtcConfig       Kind = "etc-config"
	KindMachineID       Kind = "machine-id"
	KindAgent           Kind = "agent"
)

// Candidate is one recovery candidate discovered on this host, diffed
// against the declared context.
type Candidate struct {
	Agent     *AgentWiring `json:"agent,omitempty"`
	Kind      Kind         `json:"kind"`
	Name      string       `json:"name"`
	Path      string       `json:"path"`
	SizeBytes int64        `json:"size_bytes"`
	Covered   bool         `json:"covered"`
	// CoveredBy names what covered this candidate — "drill:<proof-id>" or
	// "guard:<guard-id>" — empty when Covered is false.
	CoveredBy string `json:"covered_by,omitempty"`
	// Weight is a small integer blast-radius hint derived from Kind alone
	// (see weight.go); it is never adjusted per-candidate — the agent
	// reading the report does the judging, not this tool.
	Weight int `json:"weight"`
	// FirstSeen is when this exact candidate (by Kind+Path, see
	// candidateKey) was first observed. Carried forward from the previous
	// scan when it named the same key, else set to this scan's
	// GeneratedAt — so a candidate's FirstSeen only ever moves on the run
	// where it was genuinely new.
	FirstSeen time.Time `json:"first_seen"`
	// Suppressed marks a candidate as noise under discover.go's default
	// exclude list or an owner's .restoregapignore/discoverignore (see
	// exclude.go) — regenerable caches, retired copies, browser-profile
	// churn. It is a RENDERING decision only: a suppressed candidate is
	// still fully counted (Counts.Suppressed) and still appears, with
	// SuppressedBy set, whenever --all is passed. Nothing here ever drops
	// a candidate from the data.
	Suppressed bool `json:"suppressed"`
	// SuppressedBy names the exact rule that suppressed this candidate —
	// "default:<glob>", "ignore:.restoregapignore:<glob>", or
	// "ignore:discoverignore:<glob>" — so an owner knows exactly which
	// file to edit to un-suppress it. Empty when Suppressed is false.
	SuppressedBy string `json:"suppressed_by,omitempty"`
	// AlternatePaths lists every OTHER apparent path that resolved (via
	// EvalSymlinks) to this same candidate — a symlink alias or a second
	// docker bind mount of the same host directory — so a real duplicate
	// (the same auth.db reachable as both ~/ntfy/data/auth.db and
	// ~/infra-config/compose/ntfy/data/auth.db) is one candidate, not two,
	// without silently dropping either path. Empty when there is only one.
	AlternatePaths []string `json:"alternate_paths,omitempty"`
}

// Counts summarizes a Report's candidates.
type Counts struct {
	Candidates int `json:"candidates"`
	Covered    int `json:"covered"`
	Uncovered  int `json:"uncovered"`
	// New is len(Report.New) — candidates whose key (kind+path) was not
	// present in the previous scan. 0 on a report with no previous scan to
	// compare against (never "everything is new" on the very first run).
	New int `json:"new"`
	// Suppressed is how many UNCOVERED candidates are also Suppressed —
	// noise the default text view hides (see the summary line in
	// render.go). Always a subset of Uncovered: a covered candidate's
	// suppression state is irrelevant since it never appears in the
	// uncovered listing regardless.
	Suppressed int `json:"suppressed"`
}

// Report is the full result of a discover run.
type Report struct {
	GeneratedAt time.Time   `json:"generated_at"`
	Host        string      `json:"host"`
	Counts      Counts      `json:"counts"`
	Candidates  []Candidate `json:"candidates"`
	// New lists the candidateKey (kind:path) of every candidate new since
	// the previous scan, sorted. Empty (and omitted) when there is no
	// previous scan, or nothing new.
	New []string `json:"new,omitempty"`
	// PreviousGeneratedAt is the previous scan's GeneratedAt, when one was
	// found to diff against — the date the New list's "since" refers to.
	// Zero (and omitted) on a report with no previous scan.
	PreviousGeneratedAt time.Time `json:"previous_generated_at,omitempty"`
}
