package contextspec

import (
	"fmt"
	"sort"
	"strings"
)

// LintSeverity ranks a lint finding. Error means the policy cannot work as
// written; warn means it works but carries dead weight or ambiguity.
type LintSeverity string

// The LintSeverity values.
const (
	LintError LintSeverity = "error"
	LintWarn  LintSeverity = "warn"
)

// LintFinding is one problem discovered in a context document.
type LintFinding struct {
	Severity LintSeverity `json:"severity"`
	Rule     string       `json:"rule"`
	Subject  string       `json:"subject"` // guard or proof id
	Message  string       `json:"message"`
	Fix      string       `json:"fix"`
}

// Lint reports problems that make a context document unworkable or misleading.
//
// It exists because these problems are otherwise undiscoverable until a
// preflight blocks — which is the worst possible moment, since the operator is
// mid-change and the only remaining exit is an owner override. A policy whose
// guards can never be satisfied does not make a system safer; it trains whoever
// runs it to override reflexively, and an override habit is worse than no guard
// at all.
func (c Context) Lint() []LintFinding {
	var out []LintFinding
	out = append(out, c.lintUnsatisfiableGuards()...)
	out = append(out, c.lintUndeclaredProofs()...)
	out = append(out, c.lintOrphanProofs()...)
	out = append(out, c.lintDuplicateGuards()...)

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity == LintError
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// lintUnsatisfiableGuards finds blocking lifeline guards with nothing declared
// that could ever satisfy them. checkRequirements treats an empty Requires on a
// lifeline as fail-closed by design, so such a guard blocks EVERY matching
// change forever and no proof can clear it.
func (c Context) lintUnsatisfiableGuards() []LintFinding {
	var out []LintFinding
	for _, g := range c.Guards {
		if g.Kind != GuardKindLifeline || !g.Requires.Empty() {
			continue
		}
		if g.Enforcement == EnforcementWarn {
			out = append(out, LintFinding{
				Severity: LintWarn,
				Rule:     "guard-never-satisfiable",
				Subject:  g.ID,
				Message: fmt.Sprintf("lifeline guard %q declares no requires, so it can never pass; "+
					"enforcement is warn, so it only ever emits a warning", g.ID),
				Fix: fixForGuard(g),
			})
			continue
		}
		out = append(out, LintFinding{
			Severity: LintError,
			Rule:     "guard-never-satisfiable",
			Subject:  g.ID,
			Message: fmt.Sprintf("lifeline guard %q declares no requires, so nothing can satisfy it: "+
				"every matching change BLOCKS and an owner override is the only exit", g.ID),
			Fix: fixForGuard(g),
		})
	}
	return out
}

// fixForGuard renders the concrete edit that makes a guard satisfiable, plus
// the command that records the proof it will then ask for. A remedy the reader
// can paste beats a remedy they have to design.
func fixForGuard(g Guard) string {
	proofID := g.ID + "-recovery"
	return fmt.Sprintf(
		"add to guard %q:  requires: {proofs: [%s]}   then record it:  "+
			"restoregap evidence ingest --proof %s --context <ctx> --command '<verifier that exits 0 when recovery is provable>' --expires-in 720h",
		g.ID, proofID, proofID)
}

// lintUndeclaredProofs finds guards requiring proof/fact ids that the document
// never declares. CheckProof treats an unknown id as missing, so these block
// exactly like an unsatisfiable guard but look configured at a glance.
func (c Context) lintUndeclaredProofs() []LintFinding {
	declaredProofs := make(map[string]bool, len(c.Proofs))
	for _, p := range c.Proofs {
		declaredProofs[p.ID] = true
	}
	declaredFacts := make(map[string]bool, len(c.Facts))
	for _, f := range c.Facts {
		declaredFacts[f.ID] = true
	}

	var out []LintFinding
	for _, g := range c.Guards {
		for _, id := range g.Requires.Proofs {
			if declaredProofs[id] {
				continue
			}
			out = append(out, LintFinding{
				Severity: LintError,
				Rule:     "proof-not-declared",
				Subject:  g.ID,
				Message: fmt.Sprintf("guard %q requires proof %q, which this context never declares — "+
					"it is treated as missing, so the guard always blocks", g.ID, id),
				Fix: fmt.Sprintf("restoregap evidence ingest --proof %s --context <ctx> --command '<verifier>' --expires-in 720h", id),
			})
		}
		for _, id := range g.Requires.Facts {
			if declaredFacts[id] {
				continue
			}
			out = append(out, LintFinding{
				Severity: LintError,
				Rule:     "fact-not-declared",
				Subject:  g.ID,
				Message:  fmt.Sprintf("guard %q requires fact %q, which this context never declares", g.ID, id),
				Fix:      fmt.Sprintf("declare a facts: entry with id %s, a statement, and its provenance", id),
			})
		}
	}
	return out
}

// lintOrphanProofs finds declared proofs no guard ever requires. They are
// refreshed on a timer and rendered in status, so they read as protection while
// gating nothing.
func (c Context) lintOrphanProofs() []LintFinding {
	required := map[string]bool{}
	for _, g := range c.Guards {
		for _, id := range g.Requires.Proofs {
			required[id] = true
		}
	}
	var out []LintFinding
	for _, p := range c.Proofs {
		if required[p.ID] {
			continue
		}
		out = append(out, LintFinding{
			Severity: LintWarn,
			Rule:     "proof-gates-nothing",
			Subject:  p.ID,
			Message: fmt.Sprintf("proof %q is declared but no guard requires it — it is maintained "+
				"and displayed, but gates no change", p.ID),
			Fix: fmt.Sprintf("reference it from a guard's requires.proofs, or drop it: %s", p.ID),
		})
	}
	return out
}

// lintDuplicateGuards finds guards that are redundant in SUBSTANCE, not merely
// guards that match the same thing.
//
// Matching the same resource twice is a legitimate and useful pattern: one
// guard can demand an off-machine snapshot while another demands a
// boot-rollback proof observed within the hour. Flagging that as a duplicate
// would push someone to merge them and silently drop a requirement or a
// freshness constraint — the lint would be causing the exact class of hole it
// exists to find. So a duplicate is only a duplicate when nothing distinguishes
// the two: same match, same kind, same enforcement, same freshness bound, and
// the same required evidence.
func (c Context) lintDuplicateGuards() []LintFinding {
	seen := map[string]string{}
	var out []LintFinding
	for _, g := range c.Guards {
		key := guardSubstanceKey(g)
		if first, ok := seen[key]; ok {
			out = append(out, LintFinding{
				Severity: LintWarn,
				Rule:     "guard-duplicates",
				Subject:  g.ID,
				Message: fmt.Sprintf("guard %q is indistinguishable from %q — same match, enforcement, "+
					"freshness bound and required proofs — so one blocked change is reported twice",
					g.ID, first),
				Fix: fmt.Sprintf("delete %q; %q already provides identical cover", g.ID, first),
			})
			continue
		}
		seen[key] = g.ID
	}
	return out
}

// guardSubstanceKey renders everything that makes a guard behave differently.
// Two guards sharing this key are interchangeable; deleting one loses nothing.
func guardSubstanceKey(g Guard) string {
	reqProofs := append([]string(nil), g.Requires.Proofs...)
	reqFacts := append([]string(nil), g.Requires.Facts...)
	sort.Strings(reqProofs)
	sort.Strings(reqFacts)
	return strings.Join([]string{
		string(g.Kind),
		matcherKey(g.Match),
		string(g.Enforcement),
		fmt.Sprintf("%d", g.MaxProofAgeHours),
		fmt.Sprintf("%t", g.RequireVerified),
		strings.Join(reqProofs, ","),
		strings.Join(reqFacts, ","),
	}, "|")
}

// matcherKey renders a matcher into a stable comparable string. Every field
// must be included: two guards differing only in Packages or Actors match
// different intents, and calling them duplicates would be wrong.
func matcherKey(m Matcher) string {
	groups := [][]string{m.Paths, m.Commands, m.Packages, m.Actions, m.Actors, m.ContextWindows}
	parts := make([]string, 0, len(groups))
	for _, group := range groups {
		cp := append([]string(nil), group...)
		sort.Strings(cp)
		parts = append(parts, strings.Join(cp, ","))
	}
	return strings.Join(parts, "|")
}

// HasErrors reports whether any finding is fatal to the policy working.
func HasErrors(findings []LintFinding) bool {
	for _, f := range findings {
		if f.Severity == LintError {
			return true
		}
	}
	return false
}
