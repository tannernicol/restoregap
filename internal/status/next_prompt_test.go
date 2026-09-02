// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

func TestRenderPromptIncludesHeaderRulesAndBullets(t *testing.T) {
	steps := []NextStep{
		{Proof: "ssh-key-recovery", Layer: "identity-secrets", Category: "ssh-keys", Why: "attested, no drill", Command: "restoregap accept ssh-key-recovery --reason \"…\""},
	}
	h := PromptHeader{Host: "host-b", GeneratedAt: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC), Scope: "layer=identity-secrets"}
	out := RenderPrompt(steps, h)

	for _, want := range []string{
		"scope: layer=identity-secrets",
		"host: host-b",
		"generated: 2026-08-24T12:00:00Z",
		"identity-secrets 1",
		"ssh-key-recovery (identity-secrets/ssh-keys): attested, no drill → restoregap accept ssh-key-recovery",
		PromptRules,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderPrompt output missing %q, got:\n%s", want, out)
		}
	}
}

func TestRenderPromptRulesAreVerbatim(t *testing.T) {
	want := "Run the listed commands; never edit context YAML by hand; never `restoregap accept` " +
		"without an owner-stated reason — ask the owner; re-run `restoregap next` after each step; " +
		"stop when it prints nothing to do."
	if PromptRules != want {
		t.Errorf("PromptRules = %q, want %q", PromptRules, want)
	}
}

func TestRenderPromptEmptyStepsSaysNothingToDo(t *testing.T) {
	out := RenderPrompt(nil, PromptHeader{Host: "h", GeneratedAt: time.Now(), Scope: "all"})
	if !strings.Contains(out, "nothing to do") {
		t.Errorf("expected a nothing-to-do line for zero steps, got:\n%s", out)
	}
}

// TestRenderPromptOffersDrillFirstForUnreviewedAttestationWithArtifact: an
// unreviewed attestation whose drill artifact is a real (concrete) path
// gets offered the drill FIRST — a stronger claim than an acceptance —
// with the accept command only as the "if it cannot be drilled" fallback.
// The context_file must also appear in the bullet's text line.
func TestRenderPromptOffersDrillFirstForUnreviewedAttestationWithArtifact(t *testing.T) {
	steps := buildNextStepsWithArtifact(t, "/home/example/.ssh/id_ed25519", "restoregap.local.yml")
	out := RenderPrompt(steps, PromptHeader{Host: "h", GeneratedAt: time.Now(), Scope: "all"})
	for _, want := range []string{
		"restoregap drill propose /home/example/.ssh/id_ed25519 --source <recovery_source if known>",
		`or, if it cannot be drilled: restoregap accept ssh-key-recovery --reason "…"`,
		"[context_file: restoregap.local.yml]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderPrompt missing %q, got:\n%s", want, out)
		}
	}
	if !strings.Contains(out, PromptRules) {
		t.Error("RenderPrompt must still keep the fixed rules block verbatim")
	}
}

// buildNextStepsWithArtifact builds one real NextStep for an unreviewed,
// undrilled attestation whose requiring guard names a concrete artifact
// path — via Gather/NextSteps end-to-end, so this exercises the exact
// production wiring (InventoryRow.ProposeArtifact -> NextStep.
// proposeArtifact) rather than hand-constructing the unexported field.
func buildNextStepsWithArtifact(t *testing.T, artifact, contextFile string) []NextStep {
	t.Helper()
	ctx := contextspec.Context{
		Guards: []contextspec.Guard{{
			ID: "ssh-guard", Kind: contextspec.GuardKindLifeline,
			Match:    contextspec.Matcher{Paths: []string{artifact}},
			Requires: contextspec.Requirement{Proofs: []string{"ssh-key-recovery"}},
		}},
		Proofs: []contextspec.Proof{{ID: "ssh-key-recovery", Status: contextspec.ProofRecordObserved}},
	}
	now := time.Now().UTC()
	s := &Summary{Verdict: "warn", Context: ctx}
	s.Inventory = buildInventory(ctx, &sourceFiles{proofs: map[string]string{"ssh-key-recovery": contextFile}}, now, "")
	s.Proofs = getProofs(ctx, now, "", &s.Verdict, &s.ExpiringSoon)
	return s.NextSteps()
}
