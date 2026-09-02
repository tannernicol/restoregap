// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tannernicol/restoregap/internal/preflight"
)

// TestParityDrillSeamsAgree runs the real thing end to end against a fixture
// context: the same change, built both ways, must reach the same verdict.
func TestParityDrillSeamsAgree(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secrets", "key")
	ctxPath := filepath.Join(dir, "context.yml")
	spec := "version: 2\nguards:\n  - id: secrets\n    kind: lifeline\n    match:\n      paths:\n        - " +
		filepath.Join(dir, "secrets") + "/**\n    enforcement: block\n    requires:\n      facts:\n        - never-satisfied\n"
	if err := os.WriteFile(ctxPath, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}

	intent := filepath.Join(dir, "intent.yml")
	if err := os.WriteFile(intent, []byte(parityIntent(target)), 0o600); err != nil {
		t.Fatal(err)
	}
	diff := filepath.Join(dir, "change.diff")
	if err := os.WriteFile(diff, []byte(parityDiff(target)), 0o600); err != nil {
		t.Fatal(err)
	}

	intentVerdict, err := planVerdict(context.Background(), preflight.Request{
		IntentPath: intent, ContextPaths: []string{ctxPath}, Format: "json", Plan: true, Actor: "test",
	})
	if err != nil {
		t.Fatalf("intent seam: %v", err)
	}
	diffVerdict, err := planVerdict(context.Background(), preflight.Request{
		DiffPath: diff, DiffRoot: "/", ContextPaths: []string{ctxPath}, Format: "json", Plan: true, Actor: "test",
	})
	if err != nil {
		t.Fatalf("diff seam: %v", err)
	}
	if intentVerdict != diffVerdict {
		t.Fatalf("seams disagree: intent=%q diff=%q", intentVerdict, diffVerdict)
	}
	if intentVerdict != "block" {
		t.Fatalf("a lifeline with an unsatisfiable requirement must block, got %q", intentVerdict)
	}
}

// TestParityFormsNameTheSamePath is the property the drill rests on: if the
// two constructed forms ever stop describing the same change, the drill is
// comparing apples to oranges and would pass while proving nothing.
func TestParityFormsNameTheSamePath(t *testing.T) {
	const target = "/var/lib/thing/db.sqlite"
	if !strings.Contains(parityIntent(target), target) {
		t.Error("intent form does not name the target")
	}
	d := parityDiff(target)
	if !strings.Contains(d, "a/"+target) || !strings.Contains(d, "deleted file mode") {
		t.Errorf("diff form does not delete the target: %q", d)
	}
	if !strings.Contains(parityIntent(target), "version: 2") {
		t.Error("intent form must declare its schema version or preflight refuses it")
	}
}

// TestPlanVerdictNeverWrites pins the "a rehearsal is not a decision" rule.
func TestPlanVerdictNeverWrites(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	intent := filepath.Join(dir, "intent.yml")
	if err := os.WriteFile(intent, []byte(parityIntent(filepath.Join(dir, "x"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := planVerdict(context.Background(), preflight.Request{
		IntentPath: intent, Format: "json", Plan: true, LedgerPath: ledgerPath, Actor: "test",
	}); err != nil {
		t.Fatalf("plan: %v", err)
	}
	if _, err := os.Stat(ledgerPath); !os.IsNotExist(err) {
		t.Fatal("parity-drill must not write to the ledger")
	}
}
