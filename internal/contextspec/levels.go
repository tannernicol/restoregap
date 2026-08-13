package contextspec

import (
	"fmt"
	"time"
)

// RecoveryLevel is how far a proof's last verified drill actually got:
// the inventory's unit of meaning. Declared once here and used by status,
// drill CLI output, and ledger telemetry — never re-derived elsewhere.
type RecoveryLevel int

// The RecoveryLevel rungs, lowest (weakest claim) first — RecoveryLevel is
// deliberately an ordered int so "the max rung among passing checks" is a
// plain integer comparison.
const (
	LevelDeclared  RecoveryLevel = iota // drill declared, no live verified proof
	LevelRestores                       // verified: recover produced validated content (byte_identical / file_tree / command)
	LevelDataValid                      // verified incl. a sqlite or git check (opens, invariants hold)
	LevelServes                         // verified incl. a serve check (boots and answers probes)
)

// String renders the level the way it's shown to a human: the inventory
// table, the drill CLI's verified line, and ledger telemetry all use this.
func (l RecoveryLevel) String() string {
	switch l {
	case LevelRestores:
		return "restores"
	case LevelDataValid:
		return "data-valid"
	case LevelServes:
		return "serves"
	default:
		return "declared"
	}
}

// Rung is the 1-indexed "L1".."L4" number the drill CLI's verified line
// shows next to the level word (e.g. "serves (L4)").
func (l RecoveryLevel) Rung() int { return int(l) + 1 }

// checkTypeLevel maps one PASSING check's type to the rung it earns.
// Unlisted types — an unrecognized future check type, or the synthetic
// budget_rto/budget_rpo outcomes drill.applyBudgets records — never raise
// the level: a budget can only have blocked verification, it never promotes
// a rung on its own.
var checkTypeLevel = map[string]RecoveryLevel{
	"byte_identical": LevelRestores,
	"file_tree":      LevelRestores,
	"command":        LevelRestores,
	"sqlite":         LevelDataValid,
	"git":            LevelDataValid,
	// key_fingerprint is a data-validity class check, same rung as
	// sqlite/git: like sqlite's integrity check, it proves the recovered
	// bytes are a semantically valid, usable artifact (the right key
	// material, by fingerprint) — not merely present.
	"key_fingerprint": LevelDataValid,
	"serve":           LevelServes,
}

// LevelOf derives the recovery level a proof's last verified drill actually
// earned. "A drill is declared" is not the same claim as "a drill currently
// proves this": an expired proof, one marked stale or disputed, or one that
// was never verified all collapse to LevelDeclared, with reason explaining
// why. A verified proof's level is the MAX rung among its passing checks
// (proof.Measurements.Checks) — a drill with both a serve check and a
// sqlite check that both passed is LevelServes, not merely LevelDataValid.
func LevelOf(p Proof, now time.Time) (RecoveryLevel, string) {
	if p.Status == ProofRecordDisputed {
		return LevelDeclared, "disputed"
	}
	if p.Status == ProofRecordStale {
		return LevelDeclared, "stale"
	}
	if p.ExpiresAt != nil && now.After(*p.ExpiresAt) {
		return LevelDeclared, fmt.Sprintf("proof expired %s ago", FormatAge(now.Sub(*p.ExpiresAt)))
	}
	if !p.Verified {
		return LevelDeclared, "not verified"
	}
	if p.Measurements == nil {
		// A verified proof with no per-check breakdown: either a pre-drill-v2
		// proof (verified meant byte-identical, full stop, before typed
		// checks existed) or a hand-authored one. Credit it at the level
		// "verified" always meant before this rung system existed, rather
		// than guessing higher.
		return LevelRestores, ""
	}
	return LevelFromChecks(p.Measurements.Checks), ""
}

// LevelFromChecks derives the recovery level a set of checks earns — the
// max rung among the PASSING ones, ignoring proof-record concerns (expiry,
// disputed status, the verified bit) that only apply once a drill result
// has become a recorded Proof. Exported so a live drill.Result (which
// carries checks before any proof is recorded) and LevelOf share exactly
// one type -> rung mapping rather than two that could drift apart.
func LevelFromChecks(checks []CheckOutcome) RecoveryLevel {
	level := LevelDeclared
	for _, c := range checks {
		if !c.Pass {
			continue
		}
		if lv, ok := checkTypeLevel[c.Type]; ok && lv > level {
			level = lv
		}
	}
	return level
}

// FormatAge renders a duration at the grain the recovery inventory uses:
// whole days. Shared by LevelOf's expiry reason and the inventory's own
// PROOF AGE column so "how old" is spelled one way everywhere it appears.
func FormatAge(d time.Duration) string {
	days := int(d.Hours() / 24)
	return fmt.Sprintf("%dd", days)
}
