// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"strings"
	"testing"
)

// explainFixture is one drilled, currently-good proof plus the guard that
// requires it — the minimum `explain` needs to show every line it promises:
// level, status, evidence, last drill with a check, and the satisfies line.
const explainFixture = `version: 2
guards:
  - id: app-db-guard
    kind: guard
    match: {paths: ["/x/app.db"]}
    requires: {proofs: [app-db-recovery]}
    enforcement: block
drills:
  - proof: app-db-recovery
    artifact: /x/app.db
    recover: cp /backup/app.db "$RG_TARGET"
    recovery_source: /backup/app.db
proofs:
  - id: app-db-recovery
    status: validated
    observed_at: "2026-08-20T00:00:00Z"
    verified: true
    measurements:
      rto_seconds: 2.1
      checks: [{type: sqlite, pass: true, detail: "integrity ok"}]
`

func runExplain(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newExplainCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// TestExplainDrilledProofRendersEveryLine: the happy path — a data-valid
// proof with one passing check, satisfying one blocking guard.
func TestExplainDrilledProofRendersEveryLine(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", explainFixture)

	out, err := runExplain(t, "--context", ctxPath, "app-db-recovery")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	for _, want := range []string{
		"app-db-recovery — data-valid (restored and the data passed typed checks)",
		"  status      present · observed 2026-08-20T00:00:00Z",
		"  earned by   drill: cp /backup/app.db \"$RG_TARGET\"   source: /backup/app.db   artifact: /x/app.db",
		"  last drill  2026-08-20T00:00:00Z · RTO 2.1s · RPO —",
		"    ✓ integrity ok",
		"  satisfies   app-db-guard (block)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output missing %q, got:\n%s", want, out)
		}
	}
}

// TestExplainUnknownIDSuggestsClosest: an unknown id exits 2 and names the
// nearest declared id, not a bare "not found".
func TestExplainUnknownIDSuggestsClosest(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", explainFixture)

	_, err := runExplain(t, "--context", ctxPath, "app-db-recover")
	if err == nil {
		t.Fatal("expected an error for an unknown proof id")
	}
	exit, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if exit.Code != 2 {
		t.Errorf("exit code = %d, want 2", exit.Code)
	}
	if !strings.Contains(exit.Message, "no proof app-db-recover") ||
		!strings.Contains(exit.Message, "did you mean: app-db-recovery") {
		t.Errorf("message should name the id and the nearest candidate, got %q", exit.Message)
	}
}

// TestExplainShowsAcceptedLine: a proof carrying an active acceptance gets
// its own "accepted" line naming who, why, and the review date.
func TestExplainShowsAcceptedLine(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", `version: 2
proofs:
  - id: phone-reprovision-path
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
    accepted:
      by: owner/tanner
      at: "2026-08-20T00:00:00Z"
      reason: cannot be drilled unattended
      review_by: "2026-11-20T00:00:00Z"
`)

	out, err := runExplain(t, "--context", ctxPath, "phone-reprovision-path")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	want := "  accepted    owner/tanner — cannot be drilled unattended (review by 2026-11-20)"
	if !strings.Contains(out, want) {
		t.Errorf("explain output missing %q, got:\n%s", want, out)
	}
}

// TestExplainRegisteredOnRoot: explain self-registers through the same
// extraCommands mechanism every other leaf command uses, so it shows up in
// `restoregap --help` without root.go knowing about it.
func TestExplainRegisteredOnRoot(t *testing.T) {
	for _, build := range extraCommands {
		if cmd := build(); cmd.Name() == "explain" {
			return
		}
	}
	t.Error("explain is not registered in extraCommands — it will not appear in --help")
}
