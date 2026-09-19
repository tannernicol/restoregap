// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package report renders a preflight evaluation as JSON or Markdown. It is
// a pure formatting layer: it takes already-decided engine.Findings and
// produces bytes, performing no evaluation and no I/O of its own (callers
// decide where the bytes go).
package report

import (
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/engine"
)

// Schema is the stable JSON/Markdown report schema version.
const Schema = 2

// Finding is the rendered, JSON/Markdown-facing view of an engine.Finding.
type Finding struct {
	ID               string   `json:"id"`
	Verdict          string   `json:"verdict"`
	RiskClass        string   `json:"risk_class"`
	ProofStatus      string   `json:"proof_status"`
	Title            string   `json:"title"`
	Proof            string   `json:"proof"`
	RequiredNextStep string   `json:"required_next_step"`
	GuardID          string   `json:"guard_id"`
	Resource         string   `json:"resource"`
	Actions          []string `json:"actions"`
}

// findingHeadline keeps the readable subject ahead of the technical id in
// human renderings. The id remains available in the detail tail for support
// and machine correlation.
func findingHeadline(f Finding) string {
	parts := make([]string, 0, 2)
	if f.Resource != "" {
		parts = append(parts, f.Resource)
	}
	if len(f.Actions) > 0 {
		parts = append(parts, strings.Join(f.Actions, ", "))
	}
	if len(parts) == 0 {
		parts = append(parts, "recovery finding")
	}
	return strings.Join(parts, " · ") + " — " + strings.ToUpper(f.Verdict)
}

// ProposedChange is the operation a preflight inspected. It is descriptive
// evidence for the decision; rendering it never runs the operation.
type ProposedChange struct {
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

// Report is the full rendered preflight outcome.
type Report struct {
	Schema    int              `json:"schema"`
	Verdict   string           `json:"verdict"`
	Operation string           `json:"operation,omitempty"`
	Executed  *bool            `json:"executed,omitempty"`
	Proposed  []ProposedChange `json:"proposed,omitempty"`
	// GateState is "ran" for a completed evaluation and "broken" when a
	// required gate check could not run. It is omitted for reports emitted by
	// older callers, preserving their JSON shape.
	GateState     string    `json:"gate_state,omitempty"`
	BrokenReason  string    `json:"broken_reason,omitempty"`
	Checks        []Check   `json:"checks,omitempty"`
	DurationMS    int64     `json:"duration_ms,omitempty"`
	Findings      []Finding `json:"findings"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
	Actor         string    `json:"actor"`
	ContextWindow string    `json:"context_window,omitempty"`
}

// Check is one preflight execution stage rendered for a human or a machine.
// It mirrors ledger.DecisionCheckRecord without importing ledger into the
// presentation package.
type Check struct {
	ID         string `json:"id"`
	Outcome    string `json:"outcome"`
	DurationMS int64  `json:"duration_ms"`
}

// FromFindings builds a Report from decided findings plus run metadata.
func FromFindings(findings []engine.Finding, overall engine.Verdict, evaluatedAt time.Time, actor, contextWindow string) Report {
	rendered := make([]Finding, 0, len(findings))
	for _, f := range findings {
		rendered = append(rendered, Finding{
			ID:               f.ID,
			Verdict:          string(f.Verdict),
			RiskClass:        string(f.RiskClass),
			ProofStatus:      string(f.ProofStatus),
			Title:            f.Title,
			Proof:            f.Proof,
			RequiredNextStep: f.RequiredNextStep,
			GuardID:          f.GuardID,
			Resource:         f.Resource,
			Actions:          f.Actions,
		})
	}
	return Report{
		Schema:        Schema,
		Verdict:       string(overall),
		Findings:      rendered,
		EvaluatedAt:   evaluatedAt,
		Actor:         actor,
		ContextWindow: contextWindow,
	}
}
