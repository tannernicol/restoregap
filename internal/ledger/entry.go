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
	EntryAccept          EntryType = "accept"
	EntryAcceptClear     EntryType = "accept_clear"
	EntryEpoch           EntryType = "epoch"
)

// FindingRecord is the ledger's durable summary of one evaluated finding.
// The optional decision detail makes the record useful on its own while
// preserving the canonical bytes of older schema-v2 entries.
type FindingRecord struct {
	FindingID        string                 `json:"finding_id"`
	GuardID          string                 `json:"guard_id"`
	Resource         string                 `json:"resource"`
	Verdict          string                 `json:"verdict"`
	RiskClass        string                 `json:"risk_class"`
	ProofStatus      string                 `json:"proof_status"`
	Actions          []string               `json:"actions,omitempty"`
	Why              string                 `json:"why,omitempty"`
	Proof            string                 `json:"proof,omitempty"`
	RequiredNextStep string                 `json:"required_next_step,omitempty"`
	Override         *FindingOverrideRecord `json:"override,omitempty"`
}

// FindingOverrideRecord keeps an applied owner exception typed in the
// decision entry. Older records only carry the resulting verdict and remain
// valid because this is optional.
type FindingOverrideRecord struct {
	ApprovedBy string `json:"approved_by"`
	Reason     string `json:"reason"`
}

// IntentRecord preserves the proposed operation that produced a decision.
// It is deliberately a snapshot: later edits to an intent file cannot change
// what the gate actually inspected.
type IntentRecord struct {
	Action        string   `json:"action,omitempty"`
	Command       string   `json:"command,omitempty"`
	Packages      []string `json:"packages,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	TargetPaths   []string `json:"target_paths,omitempty"`
	Actor         string   `json:"actor,omitempty"`
	ContextWindow string   `json:"context_window,omitempty"`
	Description   string   `json:"description,omitempty"`
	Source        string   `json:"source,omitempty"`
}

// DecisionCheckRecord records one ordered stage of a preflight evaluation.
// Outcome is deliberately a small, presentation-safe vocabulary: pass, fail,
// skip, or broken. DurationMS is an integer so the ledger remains float-free.
//
// These are gate-execution checks, not recovery drill validation checks. The
// latter live in DrillCheckRecord because a drill's check vocabulary and
// lifetime are independent from an individual preflight decision.
type DecisionCheckRecord struct {
	ID         string `json:"id"`
	Outcome    string `json:"outcome"`
	DurationMS int64  `json:"duration_ms"`
}

// DecisionPayload records the outcome of one preflight evaluation.
type DecisionPayload struct {
	Verdict  string          `json:"verdict"`
	Findings []FindingRecord `json:"findings"`
	Actor    string          `json:"actor"`
	// Operation and Executed are optional additive agent-facing metadata. A
	// preflight decision describes a proposed operation; it never executes it.
	Operation     string         `json:"operation,omitempty"`
	Executed      *bool          `json:"executed,omitempty"`
	Intents       []IntentRecord `json:"intents,omitempty"`
	ContextWindow string         `json:"context_window,omitempty"`
	// GateState distinguishes a policy decision that ran ("ran") from a
	// gate that could not be trusted to run ("broken"). It is optional so
	// schema-v2 entries written before this field existed retain their exact
	// canonical form and continue to verify.
	GateState    string                `json:"gate_state,omitempty"`
	BrokenReason string                `json:"broken_reason,omitempty"`
	Checks       []DecisionCheckRecord `json:"checks,omitempty"`
	DurationMS   int64                 `json:"duration_ms,omitempty"`
	ToolVersion  string                `json:"tool_version,omitempty"`
	// EvaluatedAt is the policy clock used for proof freshness. It can differ
	// from Entry.CreatedAt when a caller pins --as-of for a reproducible run.
	EvaluatedAt *time.Time `json:"evaluated_at,omitempty"`
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

// AcceptPayload records an owner accepting, with a reason and a review
// date, that a proof will not be drilled within that window — the durable
// counterpart of the accepted: block `restoregap accept` writes onto the
// proof in its context file. The ledger entry survives later context edits
// even when the proof (or its acceptance) is removed.
type AcceptPayload struct {
	ProofID string `json:"proof_id"`
	By      string `json:"by"`
	Reason  string `json:"reason"`
	// ReviewAt is when the acceptance lapses (accepted.review_by), nil never
	// in practice — `restoregap accept` refuses to record one without it.
	ReviewAt *time.Time `json:"review_at,omitempty"`
}

// AcceptClearPayload records an owner removing a proof's acceptance — the
// durable counterpart of `restoregap accept --clear`. It carries no reason
// field: clearing returns the proof to the ordinary unreviewed bucket, it
// does not assert anything that needs justifying.
type AcceptClearPayload struct {
	ProofID string `json:"proof_id"`
	By      string `json:"by"`
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
	Accept          *AcceptPayload          `json:"accept,omitempty"`
	AcceptClear     *AcceptClearPayload     `json:"accept_clear,omitempty"`
	Epoch           *EpochPayload           `json:"epoch,omitempty"`
}

// HostRecord is the durable host stamp on an entry: the machine's name plus
// its stable id (sha256 of /etc/machine-id, truncated — internal/hostid).
// Optional so entries written before host stamping existed keep their exact
// canonical form and continue to verify.
type HostRecord struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// PolicyFileRecord is one context file hashed into a policy revision.
type PolicyFileRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// PolicyRecord is the policy an entry was decided under: the revision digest
// over every context file in force plus the files themselves, so a verdict
// can be reproduced (or shown stale) years later. Optional on Entry for the
// same backward-compatibility reason as HostRecord.
type PolicyRecord struct {
	Revision string             `json:"revision"`
	Files    []PolicyFileRecord `json:"files"`
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
	// Host/Epoch/Policy are the portability stamps (docs/SCHEMA.md): where
	// the entry was written, under which install of that machine, and which
	// policy text was in force. All three are omitempty so pre-stamping
	// entries re-encode byte-identically and their hashes still verify.
	Host   *HostRecord   `json:"host,omitempty"`
	Epoch  string        `json:"epoch,omitempty"`
	Policy *PolicyRecord `json:"policy,omitempty"`
}

// EpochPayload records a labelled epoch marker — `restoregap epoch new
// "<label>"`. It has no gating effect: it exists so the ledger narrates when
// a new epoch began (reinstall, machine-id reset) from a human's point of
// view, next to the machine-derived epoch ids every other entry carries.
type EpochPayload struct {
	Label string `json:"label"`
}

// SchemaVersion remains 2: all newer decision fields are optional and use
// omitempty, so an older v2 entry has byte-identical canonical JSON when it is
// decoded and re-encoded by this version. Bumping it would not make old hashes
// safer; the compatibility test in canonical_test.go pins this guarantee.
const SchemaVersion = 2

// payloadTypes lists, in a fixed order, each Payload field paired with the
// EntryType it must accompany. Validate walks this instead of a type switch
// so adding a new entry type only ever means adding one line here.
func (p Payload) payloadTypes() map[EntryType]bool {
	set := make(map[EntryType]bool, 8)
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
	if p.Accept != nil {
		set[EntryAccept] = true
	}
	if p.AcceptClear != nil {
		set[EntryAcceptClear] = true
	}
	if p.Epoch != nil {
		set[EntryEpoch] = true
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
