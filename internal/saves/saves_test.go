// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package saves

import (
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/ledger"
)

func at(min int) time.Time {
	return time.Date(2026, 8, 1, 0, min, 0, 0, time.UTC)
}

func decision(min int, verdict, guard, resource, findingID string) ledger.Entry {
	return ledger.Entry{
		EntryType: ledger.EntryDecision,
		CreatedAt: at(min),
		Payload: ledger.Payload{Decision: &ledger.DecisionPayload{
			Verdict: verdict,
			Findings: []ledger.FindingRecord{{
				FindingID: findingID, GuardID: guard, Resource: resource,
				Verdict: verdict, RiskClass: "recovery_proof_gap", ProofStatus: "missing",
			}},
		}},
	}
}

func override(min int, findingID, by string) ledger.Entry {
	return ledger.Entry{
		EntryType: ledger.EntryOverride,
		CreatedAt: at(min),
		Payload: ledger.Payload{Override: &ledger.OverridePayload{
			FindingID: findingID, ApprovedBy: by, Reason: "shipping anyway",
		}},
	}
}

// TestBlockThenPassIsASave: the whole point. A gap that was blocked and later
// cleared is the only shape that demonstrates the gate changed an outcome.
func TestBlockThenPassIsASave(t *testing.T) {
	rep := Build([]ledger.Entry{
		decision(1, "block", "secret-store", "~/.password-store", "f1"),
		decision(2, "pass", "secret-store", "~/.password-store", "f1"),
	})
	if rep.Saves != 1 || rep.OpenBlocks != 0 || rep.AcceptedRisks != 0 {
		t.Fatalf("want exactly one save, got %+v", rep)
	}
	if rep.Episodes[0].Outcome != OutcomeSave || rep.Episodes[0].ResolvedAt.IsZero() {
		t.Errorf("episode should be a resolved save, got %+v", rep.Episodes[0])
	}
}

// TestRepeatedBlocksAreOneEpisode: a timer re-detecting the same gap must not
// inflate the count. Fifty checks of one unfixed gap is one story.
func TestRepeatedBlocksAreOneEpisode(t *testing.T) {
	var entries []ledger.Entry
	for i := 1; i <= 50; i++ {
		entries = append(entries, decision(i, "block", "g", "r", "f1"))
	}
	rep := Build(entries)
	if len(rep.Episodes) != 1 || rep.OpenBlocks != 1 {
		t.Fatalf("50 repeats must coalesce to one open block, got %+v", rep)
	}
	if rep.Episodes[0].Evaluations != 50 {
		t.Errorf("the raw count should still be visible, got %d", rep.Episodes[0].Evaluations)
	}
	if rep.Saves != 0 {
		t.Error("an unresolved gap is not a save")
	}
}

// TestOverrideIsAcceptedRiskNotASave: counting an override as a save would be
// marking our own homework — the risk was accepted, not removed.
func TestOverrideIsAcceptedRiskNotASave(t *testing.T) {
	rep := Build([]ledger.Entry{
		decision(1, "block", "g", "r", "f1"),
		override(2, "f1", "owner/tanner"),
	})
	if rep.AcceptedRisks != 1 || rep.Saves != 0 {
		t.Fatalf("override must count as accepted risk, not a save: %+v", rep)
	}
	if rep.Episodes[0].ApprovedBy != "owner/tanner" {
		t.Errorf("who accepted it must be recorded, got %q", rep.Episodes[0].ApprovedBy)
	}
}

// TestPassWithoutPriorBlockIsNotASave: a guard that never blocked prevented
// nothing, no matter how many times it passed.
func TestPassWithoutPriorBlockIsNotASave(t *testing.T) {
	rep := Build([]ledger.Entry{
		decision(1, "pass", "g", "r", "f1"),
		decision(2, "pass", "g", "r", "f1"),
	})
	if rep.Saves != 0 || len(rep.Episodes) != 0 {
		t.Errorf("passes alone are not an episode, got %+v", rep)
	}
}

// TestRegressionReopensAnEpisode: a gap that was fixed and came back is open
// again, not permanently credited as a save.
func TestRegressionReopensAnEpisode(t *testing.T) {
	rep := Build([]ledger.Entry{
		decision(1, "block", "g", "r", "f1"),
		decision(2, "pass", "g", "r", "f1"),
		decision(3, "block", "g", "r", "f1"),
	})
	if rep.Saves != 0 || rep.OpenBlocks != 1 {
		t.Fatalf("a regression must reopen the episode, got %+v", rep)
	}
	if !rep.Episodes[0].ResolvedAt.IsZero() {
		t.Error("a reopened episode has no resolution time")
	}
}

// TestOutOfOrderEntriesStillAnalyse: the file may be concatenated or restored
// out of order; ordering must come from timestamps, not file position.
func TestOutOfOrderEntriesStillAnalyse(t *testing.T) {
	rep := Build([]ledger.Entry{
		decision(2, "pass", "g", "r", "f1"),
		decision(1, "block", "g", "r", "f1"),
	})
	if rep.Saves != 1 {
		t.Errorf("want the save recognised despite input order, got %+v", rep)
	}
}
