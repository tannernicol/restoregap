// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package bundle builds, verifies, and inspects the portable signed bundle
// (docs/SCHEMA.md §Portable signed bundle) — a single tar.gz one host can
// hand to another host, a share, or a fleet aggregator: the context files
// in force, a --since-bounded ledger slice, proof-evidence METADATA (never
// evidence file contents, and never a path under a secret store), and a
// manifest naming all of it, detached-signed with the same Ed25519 key
// material `restoregap drill --signing-key` already uses.
package bundle

import (
	"time"
)

// FormatVersion is the bundle format's own version, independent of the
// context schema version (contextspec.CurrentVersion) any embedded context
// file declares — the two evolve on separate clocks.
const FormatVersion = 1

// Manifest is bundle.json's decoded shape: everything bundle verify checks
// digests against, and everything bundle inspect prints.
type Manifest struct {
	FormatVersion  int         `json:"format_version"`
	Host           HostInfo    `json:"host"`
	Epoch          string      `json:"epoch"`
	PolicyRevision string      `json:"policy_revision,omitempty"`
	GeneratedAt    time.Time   `json:"generated_at"`
	Scope          ScopeFilter `json:"scope"`
	Counts         Counts      `json:"counts"`
	ContextFiles   []FileRef   `json:"context_files"`
	LedgerSlice    LedgerSlice `json:"ledger_slice"`
	// Evidence is proof-evidence METADATA only (path/size/hash) — never the
	// evidence file's own bytes, and never an entry at all for a path under
	// contextspec.SecretPathGlobs (see ExcludedSecretEvidence).
	Evidence []EvidenceRef `json:"evidence"`
	// ExcludedSecretEvidence counts evidence references skipped because
	// they resolved to a path under a secret store (docs/SCHEMA.md
	// §Portable signed bundle: "assert no file under a secret store path is
	// ever included") — a count, never the path itself, so the manifest
	// cannot leak what it is protecting by omission.
	ExcludedSecretEvidence int `json:"excluded_secret_evidence"`
}

// HostInfo is the exporting host's identity, mirroring internal/hostid.
type HostInfo struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// ScopeFilter records the --since/--env/--system/--host filters export ran
// with, so a bundle names what it does (and does not) vouch for. Empty
// fields mean "unfiltered on that axis".
type ScopeFilter struct {
	Since       string `json:"since,omitempty"`
	Environment string `json:"environment,omitempty"`
	System      string `json:"system,omitempty"`
	Host        string `json:"host,omitempty"`
}

// Counts summarizes what the bundle carries, for a human glancing at
// `bundle inspect` without decoding every embedded file.
type Counts struct {
	Guards        int `json:"guards"`
	Proofs        int `json:"proofs"`
	LedgerEntries int `json:"ledger_entries"`
}

// FileRef is one embedded file's tar member name and content digest.
type FileRef struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// LedgerSlice is the embedded ledger slice's own digest plus enough to
// re-verify its internal hash chain without needing the ledger it was cut
// from (see ledger.VerifyEntriesFrom in decodeAndVerifyLedgerSlice).
type LedgerSlice struct {
	Name       string `json:"name"`
	SHA256     string `json:"sha256"`
	EntryCount int    `json:"entry_count"`
	// FirstPrev is the first included entry's own Prev hash — the link back
	// into ledger history before the slice, trusted (not independently
	// re-derivable from the slice alone) and recorded purely for
	// provenance: `restoregap history` can use it to say "this slice
	// continues from ...".
	FirstPrev string `json:"first_prev,omitempty"`
}

// EvidenceRef is one proof's evidence, described but never embedded.
type EvidenceRef struct {
	ProofID   string `json:"proof_id"`
	Path      string `json:"path"`
	Exists    bool   `json:"exists"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

// Signature is bundle.sig's decoded shape — the same {public_key,
// signature} hex-string wire shape a signed proof's `signature:` block
// uses (docs/ARCHITECTURE.md §5), so the two never need separate tooling to
// read.
type Signature struct {
	PublicKeyHex string `json:"public_key"`
	SignatureHex string `json:"signature"`
}

// Tar member names inside the bundle.
const (
	manifestName   = "manifest.json"
	signatureName  = "manifest.sig"
	ledgerSliceRel = "ledger/slice.jsonl"
	contextDirRel  = "context/"
)
