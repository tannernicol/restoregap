// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package report renders a preflight evaluation as JSON or Markdown. It is
// a pure formatting layer: it takes already-decided engine.Findings and
// produces bytes, performing no evaluation and no I/O of its own (callers
// decide where the bytes go).
package report

import (
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

// Report is the full rendered preflight outcome.
type Report struct {
	Schema        int       `json:"schema"`
	Verdict       string    `json:"verdict"`
	Findings      []Finding `json:"findings"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
	Actor         string    `json:"actor"`
	ContextWindow string    `json:"context_window,omitempty"`
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
