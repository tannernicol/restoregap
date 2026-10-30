// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package ledger

import "time"

// DecisionView is the compact, human-facing projection shared by ledger show
// and the status dashboard. It contains only data already present in an
// entry; it never rebuilds a legacy record from current policy.
type DecisionView struct {
	EntryID      string          `json:"entry_id"`
	CreatedAt    time.Time       `json:"created_at"`
	EvaluatedAt  *time.Time      `json:"evaluated_at,omitempty"`
	Actor        string          `json:"actor"`
	Verdict      string          `json:"verdict"`
	GateState    string          `json:"gate_state,omitempty"`
	BrokenReason string          `json:"broken_reason,omitempty"`
	Operation    string          `json:"operation,omitempty"`
	Executed     *bool           `json:"executed,omitempty"`
	Intents      []IntentRecord  `json:"intents,omitempty"`
	Findings     []FindingRecord `json:"findings,omitempty"`
	Legacy       bool            `json:"legacy"`
}

// DrillView is the useful portion of one recovery proof event for a recent
// ledger view.
type DrillView struct {
	EntryID   string    `json:"entry_id"`
	CreatedAt time.Time `json:"created_at"`
	Actor     string    `json:"actor"`
	ProofID   string    `json:"proof_id"`
	Mode      string    `json:"mode"`
	Verified  bool      `json:"verified"`
	Level     string    `json:"level,omitempty"`
	RTOMs     int64     `json:"rto_ms,omitempty"`
}

// OverrideView is one owner exception, including its expiry and rationale.
type OverrideView struct {
	EntryID    string     `json:"entry_id"`
	CreatedAt  time.Time  `json:"created_at"`
	Actor      string     `json:"actor"`
	FindingID  string     `json:"finding_id"`
	ApprovedBy string     `json:"approved_by"`
	Reason     string     `json:"reason"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// RecentSummary contains the newest entries up to limit, reduced into the
// categories readers need to decide what happened. Slices are newest first.
type RecentSummary struct {
	Decisions []DecisionView
	Drills    []DrillView
	Overrides []OverrideView
}

// Recent returns a bounded newest-first view of entries. Empty optional
// fields stay empty for legacy records, so this function cannot invent intent,
// proof, or next-step data that was not recorded at decision time.
func Recent(entries []Entry, limit int) RecentSummary {
	if limit <= 0 {
		limit = 10
	}
	start := len(entries) - limit
	if start < 0 {
		start = 0
	}
	out := RecentSummary{}
	for i := len(entries) - 1; i >= start; i-- {
		e := entries[i]
		switch e.EntryType {
		case EntryDecision:
			if e.Payload.Decision == nil {
				continue
			}
			d := e.Payload.Decision
			out.Decisions = append(out.Decisions, DecisionView{
				EntryID: e.ID, CreatedAt: e.CreatedAt, EvaluatedAt: d.EvaluatedAt, Actor: e.Actor,
				Verdict: d.Verdict, GateState: d.GateState, BrokenReason: d.BrokenReason,
				Operation: d.Operation, Executed: d.Executed,
				Intents:  append([]IntentRecord(nil), d.Intents...),
				Findings: append([]FindingRecord(nil), d.Findings...),
				Legacy:   d.Operation == "" && d.Executed == nil && d.Intents == nil,
			})
		case EntryDrill:
			if e.Payload.Drill == nil {
				continue
			}
			d := e.Payload.Drill
			out.Drills = append(out.Drills, DrillView{
				EntryID: e.ID, CreatedAt: e.CreatedAt, Actor: e.Actor,
				ProofID: d.ProofID, Mode: d.Mode, Verified: d.Verified,
				Level: d.Level, RTOMs: d.RTOMs,
			})
		case EntryOverride:
			if e.Payload.Override == nil {
				continue
			}
			o := e.Payload.Override
			out.Overrides = append(out.Overrides, OverrideView{
				EntryID: e.ID, CreatedAt: e.CreatedAt, Actor: e.Actor,
				FindingID: o.FindingID, ApprovedBy: o.ApprovedBy,
				Reason: o.Reason, ExpiresAt: o.ExpiresAt,
			})
		}
	}
	return out
}

// Decisions returns all decision views in append order. Status uses this
// longer projection for history; ledger show uses Recent for the bounded view.
func Decisions(entries []Entry) []DecisionView {
	views := Recent(entries, len(entries))
	for i, j := 0, len(views.Decisions)-1; i < j; i, j = i+1, j-1 {
		views.Decisions[i], views.Decisions[j] = views.Decisions[j], views.Decisions[i]
	}
	return views.Decisions
}
