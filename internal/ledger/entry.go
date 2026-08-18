// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package ledger implements the v2 append-only decision ledger: hash-chained
// JSONL, ULID entry ids, typed payloads (no map[string]any in the domain
// model — only at the JSON serialization boundary). docs/ARCHITECTURE.md §5.
package ledger

import (
	"fmt"
	"time"
)

// EntryType is the kind of event one ledger entry records.
type EntryType string

// The EntryType values.
const (
	EntryDecision        EntryType = "decision"
	EntryOverride        EntryType = "override"
	EntryAcknowledgement EntryType = "acknowledgement"
	EntryCheckpoint      EntryType = "checkpoint"
	EntryDrill           EntryType = "drill"
	EntryChainAnchor     EntryType = "chain_anchor"
)

// FindingRecord is the ledger's durable summary of one evaluated finding —
// intentionally smaller than engine.Finding (no prose fields) since the
// ledger is a permanent audit record, not a rendering source.
type FindingRecord struct {
	FindingID   string `json:"finding_id"`
	GuardID     string `json:"guard_id"`
	Resource    string `json:"resource"`
	Verdict     string `json:"verdict"`
	RiskClass   string `json:"risk_class"`
	ProofStatus string `json:"proof_status"`
}

// DecisionPayload records the outcome of one preflight evaluation.
type DecisionPayload struct {
	Verdict       string          `json:"verdict"`
	Findings      []FindingRecord `json:"findings"`
	Actor         string          `json:"actor"`
	ContextWindow string          `json:"context_window,omitempty"`
}

// OverridePayload records an owner override of a specific finding.
type OverridePayload struct {
	FindingID  string     `json:"finding_id"`
	ApprovedBy string     `json:"approved_by"`
	Reason     string     `json:"reason"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	// Acknowledgement is the owner's statement of what risk they accept
	// (required by the acknowledge_risk MCP tool; optional elsewhere).
	Acknowledgement string `json:"acknowledgement,omitempty"`
}

// AcknowledgementPayload records that an actor reviewed a finding without
// changing its verdict (a lighter-weight audit trail than an override).
type AcknowledgementPayload struct {
	FindingID string `json:"finding_id"`
	Note      string `json:"note"`
}

// CheckpointPayload records a point-in-time summary of chain integrity,
// written by `restoregap ledger checkpoint`.
type CheckpointPayload struct {
	EntryCount int    `json:"entry_count"`
	LastHash   string `json:"last_hash"`
}

// DrillCheckRecord is the ledger's durable summary of one check outcome
// within a drill result — type and pass/fail only, matching FindingRecord's
// "smaller than the domain type" pattern (Detail is prose, not a stable key).
type DrillCheckRecord struct {
	Type string `json:"type"`
	Pass bool   `json:"pass"`
}

// DrillPayload records one drill or pin_check run — the history/trend
// substrate for recovery telemetry (docs/ARCHITECTURE.md §5). RTO/RPO are
// recorded as whole milliseconds rather than floating-point seconds:
// canonical.go documents ledger entries as float-free by construction (every
// numeric Go field is an int), and ValidateNoFloats enforces that invariant
// on anything read back off disk.
type DrillPayload struct {
	ProofID  string `json:"proof_id"`
	Mode     string `json:"mode"` // "drill" | "pin_check"
	Verified bool   `json:"verified"`
	// Level is the recovery level earned (contextspec.RecoveryLevel.String():
	// "declared" | "restores" | "data-valid" | "serves"), so telemetry
	// trends capture rung changes over time, not just pass/fail.
	Level string `json:"level,omitempty"`
	RTOMs int64  `json:"rto_ms,omitempty"`
	RPOMs *int64 `json:"rpo_ms,omitempty"`
	// BudgetRTOMet/BudgetRPOMet are nil when that budget was not declared,
	// so "no budget" and "budget declared and met" stay distinguishable.
	BudgetRTOMet *bool              `json:"budget_rto_met,omitempty"`
	BudgetRPOMet *bool              `json:"budget_rpo_met,omitempty"`
	Checks       []DrillCheckRecord `json:"checks,omitempty"`
}

// ChainAnchorPayload records an owner-approved attestation for one earlier
// entry whose stored hash no longer matches its content and cannot be
// repaired in place: Prev is part of every entry's hashed content, so
// rewriting the entry's payload would cascade and break every hash after
// it. An anchor is appended, never edited in — see docs/ARCHITECTURE.md.
// Verify honors it only when StoredHash matches the target entry's claimed
// Hash, so an anchor vouches for exactly one historical mismatch, not any
// future one.
type ChainAnchorPayload struct {
	// EntryID is the id of the entry being vouched for.
	EntryID string `json:"entry_id"`
	// StoredHash is that entry's claimed (on-disk) hash — the value locked
	// in by the next entry's prev, which is why it cannot simply be
	// recomputed and rewritten.
	StoredHash string `json:"stored_hash"`
	// RecomputedHash is the hash Verify computes from the entry's current
	// (mutated) content, recorded so the anchor documents exactly what
	// changed, not just that something did.
	RecomputedHash string `json:"recomputed_hash"`
	// Reason explains why the mismatch is accepted rather than treated as
	// tampering (e.g. a pre-union payload edited after writing).
	Reason string `json:"reason"`
	// ApprovedBy is the owner who approved anchoring this entry.
	ApprovedBy string `json:"approved_by"`
}

// Payload is a closed union over the typed per-entry-type payloads. Exactly
// one field is set, matching EntryType — see Entry.Validate.
type Payload struct {
	Decision        *DecisionPayload        `json:"decision,omitempty"`
	Override        *OverridePayload        `json:"override,omitempty"`
	Acknowledgement *AcknowledgementPayload `json:"acknowledgement,omitempty"`
	Checkpoint      *CheckpointPayload      `json:"checkpoint,omitempty"`
	Drill           *DrillPayload           `json:"drill,omitempty"`
	ChainAnchor     *ChainAnchorPayload     `json:"chain_anchor,omitempty"`
}

// Entry is one hash-chained ledger record.
type Entry struct {
	Schema    int       `json:"schema"`
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	EntryType EntryType `json:"entry_type"`
	Actor     string    `json:"actor"`
	Payload   Payload   `json:"payload"`
	Prev      string    `json:"prev"`
	Hash      string    `json:"hash"`
}

// SchemaVersion is the current ledger entry schema.
const SchemaVersion = 2

// payloadTypes lists, in a fixed order, each Payload field paired with the
// EntryType it must accompany. Validate walks this instead of a type switch
// so adding a new entry type only ever means adding one line here.
func (p Payload) payloadTypes() map[EntryType]bool {
	set := make(map[EntryType]bool, 6)
	if p.Decision != nil {
		set[EntryDecision] = true
	}
	if p.Override != nil {
		set[EntryOverride] = true
	}
	if p.Acknowledgement != nil {
		set[EntryAcknowledgement] = true
	}
	if p.Checkpoint != nil {
		set[EntryCheckpoint] = true
	}
	if p.Drill != nil {
		set[EntryDrill] = true
	}
	if p.ChainAnchor != nil {
		set[EntryChainAnchor] = true
	}
	return set
}

// Validate checks that Entry's Payload carries exactly one field, and that
// it matches EntryType. Entries round-trip through JSON as read off disk, so
// a hand-edited or corrupted line can set zero, several, or a mismatched
// payload field — Validate is the single place that catches it.
func (e Entry) Validate() error {
	set := e.Payload.payloadTypes()
	if len(set) != 1 {
		return fmt.Errorf("ledger: entry %s: payload must set exactly one field, got %d", e.ID, len(set))
	}
	if !set[e.EntryType] {
		return fmt.Errorf("ledger: entry %s: entry_type %q does not match its payload", e.ID, e.EntryType)
	}
	return nil
}
