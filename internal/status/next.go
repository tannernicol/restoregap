// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// NextStep is one proof that is not green: why it is not green, and the
// exact command that moves it — drill what can be drilled, accept (with a
// reason) what cannot. Command comes from the same sources the dashboard
// already shows: the drilled row's re-drill command (nextStepCommand) or,
// for an attestation-only proof, the accept invocation. JSON field names
// match the taxonomy spec's agent-facing shape (section D): id, layer,
// category, state, why, command, context_file, artifact.
type NextStep struct {
	Proof       string            `json:"id"`
	Layer       string            `json:"layer"`
	Category    string            `json:"category"`
	State       string            `json:"state"`
	Why         string            `json:"why"`
	Command     string            `json:"command"`
	ContextFile string            `json:"context_file"`
	Artifact    string            `json:"artifact"`
	Scope       contextspec.Scope `json:"scope"`
	// rank is the sort key — see classifyProofState; attention states (0),
	// lapsed acceptances (1), unreviewed attestations (2), drilled-but-
	// unproven (3). The renderer never reads it.
	rank int
	// proposeArtifact is InventoryRow.ProposeArtifact — a real, concrete
	// path inferred from a guard requiring this proof — carried through
	// only for `next --prompt`'s drill-first suggestion on an unreviewed
	// attestation (RenderPrompt). Never serialized (JSON keeps Artifact,
	// the row-subtitle field, unchanged) and never used by plain `next`,
	// which already prints the accept command via Command.
	proposeArtifact string
}

// NextSteps lists every declared proof that is not green, ordered by the
// taxonomy spec's fixed effective ordering (section F, "effective ordering
// everywhere"): environment criticality first (contextspec.EnvironmentRank
// — prod > staging > dev > lab > unset > unknown names alphabetically),
// then layer (contextspec.LayerRank, vocabulary/blast-radius order), then
// problems-first within that (a proof that failed — disputed/unreachable/
// expired/stale — outranks a lapsed acceptance, which outranks an
// unreviewed attestation, which outranks a drill that simply has not
// produced a verified proof yet), then proof id for a fully deterministic
// tie-break. A proof is green exactly when contextspec.LevelOf puts it above
// LevelDeclared — the one derivation, same as everywhere else. Layer/
// Category/State/ContextFile/Artifact come from the same Classify function
// the taxonomy tree uses, so `next`, `status`, and the MCP next_steps tool
// never disagree about where a proof belongs or in what order.
func (s *Summary) NextSteps() []NextStep {
	stateByProof := make(map[string]ProofState, len(s.Proofs))
	for _, p := range s.Proofs {
		stateByProof[p.ID] = p
	}
	var steps []NextStep
	for _, r := range s.Inventory {
		if r.Level != contextspec.LevelDeclared.String() {
			continue // green: restores or better
		}
		if r.AcceptedReason != "" {
			continue // an active (not lapsed) acceptance is a decision, not a gap
		}
		ps, hasState := stateByProof[r.Proof]
		c := Classify(s.Context, r.Proof, r, ps, hasState)
		if c.State == StateObserved {
			continue // fresh, actively re-observed evidence is not a gap
		}
		why := r.ProofAge
		switch {
		case isAttentionState(c.State):
			why = nextStepWhyProblem(ps)
		case c.State == StateUnreviewed && !r.IsDrilled:
			why = "attested, no drill"
		}
		steps = append(steps, NextStep{
			Proof: r.Proof, Layer: c.Layer, Category: c.Category, State: c.State,
			Why: why, Command: nextStepCommandFor(r), ContextFile: c.ContextFile, Artifact: c.Artifact,
			Scope: c.Scope, rank: c.Rank, proposeArtifact: r.ProposeArtifact,
		})
	}
	sort.SliceStable(steps, func(i, j int) bool { return nextStepLess(steps[i], steps[j]) })
	return steps
}

// nextStepLess implements the taxonomy spec's fixed "effective ordering
// everywhere": environment criticality, then layer, then problems-first
// rank, then proof id — see NextSteps' doc comment.
func nextStepLess(a, b NextStep) bool {
	envA, envB := a.Scope.Environment, b.Scope.Environment
	if envA != envB {
		if contextspec.EnvironmentLess(envA, envB) {
			return true
		}
		if contextspec.EnvironmentLess(envB, envA) {
			return false
		}
	}
	if la, lb := contextspec.LayerRank(a.Layer), contextspec.LayerRank(b.Layer); la != lb {
		return la < lb
	}
	if a.rank != b.rank {
		return a.rank < b.rank
	}
	return a.Proof < b.Proof
}

// FilterNextSteps keeps only the steps matching f — the same TreeFilter the
// taxonomy tree and `status --layer/--state/--env/--system/--owner/--tag`
// use, so `next`'s filters agree with `status`'s.
func FilterNextSteps(steps []NextStep, f TreeFilter) []NextStep {
	if f.IsEmpty() {
		return steps
	}
	var out []NextStep
	for _, s := range steps {
		c := ProofClassification{Layer: s.Layer, State: s.State, Scope: s.Scope}
		if f.matches(c) {
			out = append(out, s)
		}
	}
	return out
}

// nextStepWhyProblem renders the why for a proof whose own record says it
// is bad (disputed/unreachable/expired/stale) — the state word first, then
// the same remediation language status.Gather already assigned it.
func nextStepWhyProblem(ps ProofState) string {
	return ps.Status + " · " + ps.Detail
}

// nextStepCommandFor is the exact command for one not-green row: the
// drilled row's literal re-drill command (nextStepCommand's logic), or —
// for a proof with no drill behind it at all — the accept invocation that
// converges an attestation the owner has decided not to drill.
func nextStepCommandFor(r InventoryRow) string {
	if r.IsDrilled {
		if c := nextStepCommand(r); c != "" {
			return c
		}
		// A drilled row with no known source file cannot name a --context
		// value; the honest fallback is drafting the drill again.
		artifact := "<artifact>"
		if r.ProposeArtifact != "" {
			artifact = r.ProposeArtifact
		}
		return fmt.Sprintf("restoregap drill propose %s", artifact)
	}
	return fmt.Sprintf("restoregap accept %s --reason \"…\"", r.Proof)
}

// ToGreenLines renders each step as the single line `restoregap next` and
// the dashboard's to-green panel both print: proof, why, command.
func ToGreenLines(steps []NextStep) []string {
	lines := make([]string, len(steps))
	for i, s := range steps {
		lines[i] = fmt.Sprintf("%s  %s  →  %s", s.Proof, s.Why, s.Command)
	}
	return lines
}

// PromptRules is the rules block `restoregap next --prompt` prints verbatim
// (taxonomy spec section D) — an agent handed this brief follows exactly
// these five clauses, word for word, every time.
const PromptRules = "Run the listed commands; never edit context YAML by hand; never `restoregap accept` " +
	"without an owner-stated reason — ask the owner; re-run `restoregap next` after each step; " +
	"stop when it prints nothing to do."

// PromptHeader carries the header fields RenderPrompt needs beyond the
// steps themselves.
type PromptHeader struct {
	Host        string
	GeneratedAt time.Time
	// Scope is a human-readable description of the filters this brief was
	// cut for ("all" when --prompt was run with no --layer/--state/--env/
	// --system/--owner/--tag) — section F: "the header states the scope it
	// was cut for."
	Scope string
}

// RenderPrompt renders the ready-to-hand agent brief: header (host,
// generated-at, the scope it was cut for, counts by layer), one bullet per
// gap with its exact command, and the PromptRules block verbatim.
func RenderPrompt(steps []NextStep, h PromptHeader) string {
	var b strings.Builder
	fmt.Fprintf(&b, "restoregap next — scope: %s\n", h.Scope)
	fmt.Fprintf(&b, "host: %s\n", h.Host)
	fmt.Fprintf(&b, "generated: %s\n", h.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "by layer: %s\n\n", layerCountsLine(steps))
	if len(steps) == 0 {
		b.WriteString("nothing to do — all matching proofs are green\n\n")
	}
	for _, s := range steps {
		command := s.Command
		extra := ""
		if s.Why == "attested, no drill" && s.proposeArtifact != "" {
			// An unreviewed attestation whose drill artifact is a real
			// (concrete, non-glob) path: offer the drill first — that's a
			// stronger claim than an acceptance — and the accept fallback
			// only as the "if it cannot be drilled" alternative.
			command = fmt.Sprintf("restoregap drill propose %s --source <recovery_source if known>", s.proposeArtifact)
			extra = fmt.Sprintf("\n  or, if it cannot be drilled: restoregap accept %s --reason \"…\"", s.Proof)
		}
		fmt.Fprintf(&b, "- %s (%s/%s): %s → %s%s  [context_file: %s]\n",
			s.Proof, s.Layer, orNone(s.Category), s.Why, command, extra, orNone(s.ContextFile))
	}
	b.WriteString("\n" + PromptRules + "\n")
	return b.String()
}

// layerCountsLine renders "identity-secrets 2 · recovery-kit 1", in
// vocabulary order, one entry per layer actually present among steps.
func layerCountsLine(steps []NextStep) string {
	counts := map[string]int{}
	for _, s := range steps {
		counts[s.Layer]++
	}
	var parts []string
	for _, layer := range contextspec.LayerOrder {
		if n := counts[layer]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", layer, n))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " · ")
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
