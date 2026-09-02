// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func runNext(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newNextCmd()
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// TestNextPrintsOneLinePerGapAndExits1: a never-drilled attestation is not
// green, so `next` names it and exits 1.
func TestNextPrintsOneLinePerGapAndExits1(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", acceptFixture)

	out, err := runNext(t, "--context", ctxPath)
	if err == nil {
		t.Fatal("expected exit 1 when a proof is not green")
	}
	exit, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if exit.Code != 1 {
		t.Errorf("exit code = %d, want 1", exit.Code)
	}
	if !strings.Contains(out, "phone-reprovision-path") || !strings.Contains(out, "restoregap accept phone-reprovision-path") {
		t.Errorf("expected a line naming the proof and the accept command, got %q", out)
	}
}

// TestNextNothingToDoWhenGreen: a proof that already serves needs no
// action; `next` says so and exits 0.
func TestNextNothingToDoWhenGreen(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", `version: 2
drills:
  - proof: money-db-recovery
    artifact: /fake/money.db
    recover: "true"
proofs:
  - id: money-db-recovery
    status: validated
    observed_at: "2026-08-20T00:00:00Z"
    verified: true
    measurements:
      rto_seconds: 2.1
      checks: [{type: serve, pass: true, detail: "ready"}]
`)

	out, err := runNext(t, "--context", ctxPath)
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	if !strings.Contains(out, "nothing to do — all proofs green") {
		t.Errorf("expected the nothing-to-do message, got %q", out)
	}
}

// TestNextJSONFormatMatchesExitCode: --format json still exits 1 when work
// is left, and the JSON decodes to one object per step.
func TestNextJSONFormatMatchesExitCode(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", acceptFixture)

	out, err := runNext(t, "--context", ctxPath, "--format", "json")
	exit, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if exit.Code != 1 {
		t.Errorf("exit code = %d, want 1", exit.Code)
	}
	// Updated 2026-08 for the taxonomy spec's agent-facing JSON shape
	// (section D): the proof id field is now "id", not "Proof".
	var steps []struct {
		ID, Why, Command string
	}
	if err := json.Unmarshal([]byte(out), &steps); err != nil {
		t.Fatalf("json.Unmarshal: %v (%s)", err, out)
	}
	if len(steps) != 1 || steps[0].ID != "phone-reprovision-path" {
		t.Errorf("steps = %+v, want one step for phone-reprovision-path", steps)
	}
}

// TestNextJSONFormatEmptyExits0: --format json with nothing to do prints an
// empty array and exits 0.
func TestNextJSONFormatEmptyExits0(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", `version: 2
drills:
  - proof: money-db-recovery
    artifact: /fake/money.db
    recover: "true"
proofs:
  - id: money-db-recovery
    status: validated
    observed_at: "2026-08-20T00:00:00Z"
    verified: true
    measurements:
      rto_seconds: 2.1
      checks: [{type: serve, pass: true, detail: "ready"}]
`)

	out, err := runNext(t, "--context", ctxPath, "--format", "json")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	var steps []any
	if err := json.Unmarshal([]byte(out), &steps); err != nil {
		t.Fatalf("json.Unmarshal: %v (%s)", err, out)
	}
	if len(steps) != 0 {
		t.Errorf("steps = %+v, want empty", steps)
	}
}

// TestNextExcludesActiveAcceptance: a proof with an active (non-lapsed)
// acceptance is a decision, not a gap — it must not appear in `next`.
func TestNextExcludesActiveAcceptance(t *testing.T) {
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

	out, err := runNext(t, "--context", ctxPath)
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	if !strings.Contains(out, "nothing to do") {
		t.Errorf("expected nothing to do (active acceptance is not a gap), got %q", out)
	}
}

// TestNextRegisteredOnRoot: next self-registers through extraCommands, same
// as every other leaf command.
func TestNextRegisteredOnRoot(t *testing.T) {
	for _, build := range extraCommands {
		if cmd := build(); cmd.Name() == "next" {
			return
		}
	}
	t.Error("next is not registered in extraCommands — it will not appear in --help")
}

// TestNextPromptEmitsBrief: --prompt prints the ready-to-hand agent brief —
// header (scope, host, generated-at, counts by layer), one bullet per gap
// with its exact command, and the fixed rules block verbatim.
func TestNextPromptEmitsBrief(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", `version: 2
guards:
  - id: lifeline-key-guard
    kind: lifeline
    match: {paths: ["~/keys/id_ed25519"]}
    layer: identity-secrets
    category: ssh-keys
    requires: {proofs: [key-recovery]}
proofs:
  - id: key-recovery
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
`)

	out, err := runNext(t, "--context", ctxPath, "--prompt")
	if err == nil {
		t.Fatal("expected exit 1 while a matching proof is not green")
	}
	for _, want := range []string{
		"restoregap next — scope: all",
		"host: ",
		"generated: ",
		"by layer: identity-secrets 1",
		"key-recovery (identity-secrets/ssh-keys): attested, no drill",
		"Run the listed commands; never edit context YAML by hand",
		"stop when it prints nothing to do.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("next --prompt missing %q, got:\n%s", want, out)
		}
	}
}

// TestNextPromptScopeHeaderNamesFilters: a brief cut with --layer says so
// in its header (section F: "the header states the scope it was cut for").
func TestNextPromptScopeHeaderNamesFilters(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", acceptFixture)
	out, err := runNext(t, "--context", ctxPath, "--layer", "identity-secrets", "--prompt")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	if !strings.Contains(out, "scope: layer=identity-secrets") {
		t.Errorf("expected the header to name the layer filter, got:\n%s", out)
	}
	if strings.Contains(out, "phone-reprovision-path") {
		t.Errorf("a layer=identity-secrets brief must exclude other layers' gaps, got:\n%s", out)
	}
}
