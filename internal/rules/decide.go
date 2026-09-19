// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/engine"
)

// decide turns one guard match into a fully decided Finding: it checks every
// required proof/fact via contextspec, derives a RiskClass from the guard's
// kind, and calls engine.Decide for the final verdict.
func decide(m MatchResult, ctx contextspec.Context, now time.Time, dependencyConflicts map[string][]string) engine.Finding {
	proofStatus, risk, detail, unreachable := checkRequirements(m, ctx, now, dependencyConflicts)
	enforcement := mapEnforcement(m.Enforcement)
	verdict := engine.Decide(risk, proofStatus, enforcement)

	return engine.Finding{
		ID:               findingID(m),
		GuardID:          m.GuardID,
		Kind:             string(m.Kind),
		Resource:         m.Resource,
		Actions:          m.Actions,
		RiskClass:        risk,
		ProofStatus:      proofStatus,
		Verdict:          verdict,
		Title:            title(m, verdict),
		Proof:            detail,
		RequiredNextStep: requiredNextStep(m, verdict, ctx, unreachable, dependencyConflicts),
	}
}

// checkRequirements resolves a guard's Requires against the context's
// declared proofs/facts and derives the risk class implied by its kind. A
// lifeline guard with nothing to prove it safe (no requires declared, as in
// contextspec.Default()) is fail-closed by design: docs/ARCHITECTURE.md
// §Compatibility stance, point 2. The final return value lists the required
// proof ids that came back unreachable, so requiredNextStep can say "re-run
// the drill once the source is reachable" instead of the generic refresh
// text — a source that was merely asleep needs different advice than a copy
// that failed verification.
func checkRequirements(m MatchResult, ctx contextspec.Context, now time.Time, dependencyConflicts map[string][]string) (engine.ProofStatus, engine.RiskClass, string, []string) {
	if m.Requires.Empty() {
		if m.Kind == contextspec.GuardKindLifeline {
			return engine.ProofMissing, engine.RiskCannotProveSafe,
				fmt.Sprintf("guard %q matched a declared lifeline resource with no proof vocabulary configured for it", m.GuardID), nil
		}
		return engine.ProofNotRequired, engine.RiskNone, fmt.Sprintf("guard %q is informational; no proof required", m.GuardID), nil
	}

	worst := contextspec.StatePresent
	var details []string
	var unreachable []string
	for _, id := range m.Requires.Proofs {
		res := ctx.CheckProofWithBinding(id, m.MaxProofAgeHours, m.RequireVerified, m.RequireBound, now)
		if reasons := dependencyConflicts[id]; len(reasons) > 0 {
			res = dependencyConflictResult(id, reasons)
		}
		details = append(details, res.Detail)
		worst = worstState(worst, res.State)
		if res.State == contextspec.StateUnreachable {
			unreachable = append(unreachable, id)
		}
	}
	for _, id := range m.Requires.Facts {
		res := ctx.CheckFact(id, now)
		details = append(details, res.Detail)
		worst = worstState(worst, res.State)
	}

	proofStatus := mapProofState(worst)
	if worst == contextspec.StatePresent {
		return proofStatus, engine.RiskNone, strings.Join(details, "; "), unreachable
	}
	if m.Kind == contextspec.GuardKindLifeline {
		return proofStatus, engine.RiskDataLossUnrecoverable, strings.Join(details, "; "), unreachable
	}
	return proofStatus, engine.RiskRecoveryProofGap, strings.Join(details, "; "), unreachable
}

func dependencyConflictResult(id string, reasons []string) contextspec.CheckResult {
	return contextspec.CheckResult{
		State:  contextspec.StateContradicted,
		Detail: fmt.Sprintf("proof %q recovery dependency changed: %s", id, strings.Join(reasons, ", ")),
	}
}

// worstState returns the more severe of two proof states, in the priority
// order contradicted/unreachable (same tier — both prove nothing and both
// block) > missing > stale > present.
func worstState(a, b contextspec.ProofState) contextspec.ProofState {
	rank := map[contextspec.ProofState]int{
		contextspec.StateContradicted: 3,
		contextspec.StateUnreachable:  3,
		contextspec.StateMissing:      2,
		contextspec.StateStale:        1,
		contextspec.StatePresent:      0,
	}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func mapProofState(s contextspec.ProofState) engine.ProofStatus {
	switch s {
	case contextspec.StatePresent:
		return engine.ProofPresent
	case contextspec.StateStale:
		return engine.ProofStale
	case contextspec.StateContradicted:
		return engine.ProofContradicted
	case contextspec.StateUnreachable:
		return engine.ProofUnreachable
	default:
		return engine.ProofMissing
	}
}

func mapEnforcement(e contextspec.Enforcement) engine.Enforcement {
	if e == contextspec.EnforcementWarn {
		return engine.EnforceWarn
	}
	return engine.EnforceBlock
}

func title(m MatchResult, verdict engine.Verdict) string {
	switch verdict {
	case engine.VerdictBlock:
		return "Restore Gap preflight could not prove the declared recovery path survives this change."
	case engine.VerdictWarn:
		return "Restore Gap preflight found a declared guard whose proof needs review."
	default:
		return "Restore Gap preflight matched a declared guard with satisfied proof."
	}
}

func requiredNextStep(m MatchResult, verdict engine.Verdict, ctx contextspec.Context, unreachable []string, dependencyConflicts map[string][]string) string {
	if verdict == engine.VerdictPass {
		return "No action required; proof is current."
	}
	var dependencyIDs []string
	for _, id := range m.Requires.Proofs {
		if len(dependencyConflicts[id]) > 0 {
			dependencyIDs = append(dependencyIDs, id)
		}
	}
	if len(dependencyIDs) > 0 {
		return fmt.Sprintf("Changing a recovery dependency invalidated proof %s; provide independent recovery evidence or revise the change proposal. Re-drilling the same dependency does not make this dangerous plan pass.", strings.Join(dependencyIDs, ", "))
	}
	// A guard already matched — that is why there is a finding at all — so
	// telling the operator to "declare a guard" sends them to do something they
	// have done. What is missing is a requires: block ON THAT GUARD, and until
	// the remedy says so the only exit anyone finds is an owner override.
	if m.Requires.Empty() {
		// The built-in zero-config policy (contextspec.Default) is not a file
		// the caller owns or can edit — telling them to add requires: to it
		// points at nothing. Origin is data set by the loader (parse.go sets
		// it to the file path; Default() sets it to DefaultOrigin), never
		// derived by string-matching the guard id, so this stays correct even
		// as more built-in guard ids are added.
		if ctx.Origin == contextspec.DefaultOrigin {
			return fmt.Sprintf(
				"Guard %q is part of restoregap's built-in zero-config lifeline policy, which has no proof "+
					"vocabulary of its own — it always blocks until you declare a real context. Run "+
					"`restoregap context init` to write a starter restoregap.local.yml (it already declares "+
					"an ssh-keys guard with `requires: {proofs: [ssh-key-recovery-copy]}`), then record that "+
					"proof with `restoregap evidence ingest --proof ssh-key-recovery-copy "+
					"--context restoregap.local.yml --command '<a command that proves the recovery copy exists>' "+
					"--expires-in 720h` (or draft a real recovery drill first with "+
					"`restoregap drill propose <path>`), and re-run preflight with "+
					"`--context restoregap.local.yml`. Or record an owner override before proceeding.",
				m.GuardID,
			)
		}
		proofID := m.GuardID + "-recovery"
		return fmt.Sprintf(
			"Guard %q matches this resource but declares no requires:, so no proof can ever satisfy it. "+
				"Add `requires: {proofs: [%s]}` to that guard and record the proof with "+
				"`restoregap evidence ingest --proof %s --context <ctx> --command '<verifier>'`, "+
				"or record an owner override before proceeding. "+
				"`restoregap context lint` lists every guard in this state.",
			m.GuardID, proofID, proofID,
		)
	}
	var need []string
	for _, id := range m.Requires.Proofs {
		need = append(need, fmt.Sprintf("proof %q", id))
	}
	// An unreachable proof is not missing evidence — the drill could not even
	// try, because its recovery source (NAS, remote, object store) was not
	// reachable when it ran. The generic "refresh or supply" advice would send
	// someone hunting for corruption that was never observed; the honest remedy
	// is to re-run the drill once the source answers. No data loss implied.
	for _, id := range unreachable {
		need = append(need, fmt.Sprintf(
			"proof %q (unreachable — the recovery source was not reachable when the drill last ran, so nothing was proven; "+
				"this is not evidence of data loss; re-run the drill once the source is reachable)", id))
	}
	for _, id := range m.Requires.Facts {
		need = append(need, fmt.Sprintf("fact %q", id))
	}
	return fmt.Sprintf("Refresh or supply %s, or record an owner override before proceeding.", strings.Join(need, ", "))
}

// findingID is a stable, deterministic identifier for a finding so ledger
// overrides can reference it across runs of the same guard match.
func findingID(m MatchResult) string {
	sum := sha256.Sum256([]byte(string(m.Kind) + "|" + m.GuardID + "|" + m.Resource))
	return "finding_" + hex.EncodeToString(sum[:])[:24]
}
