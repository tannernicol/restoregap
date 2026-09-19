// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/engine"
	"github.com/tannernicol/restoregap/internal/intent"
)

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }

var fixedNow = time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)

func TestEvaluateZeroConfigBlocksSSHKeyDelete(t *testing.T) {
	ci := intent.ChangeIntent{Action: intent.ActionDeleteFile, Paths: []string{"~/.ssh/id_ed25519"}}
	findings := Evaluate([]intent.ChangeIntent{ci}, contextspec.Default(), fixedNow)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Verdict != engine.VerdictBlock {
		t.Errorf("verdict = %s, want block", findings[0].Verdict)
	}
	if findings[0].RiskClass != engine.RiskCannotProveSafe {
		t.Errorf("risk = %s, want cannot_prove_safe", findings[0].RiskClass)
	}
	// The built-in policy has no requires: block for the caller to edit —
	// the next step must be user-actionable (context init / evidence
	// ingest), never "add requires: to that guard" (there is no file).
	step := findings[0].RequiredNextStep
	if !strings.Contains(step, "restoregap context init") {
		t.Errorf("required_next_step = %q, want it to mention `restoregap context init`", step)
	}
	if !strings.Contains(step, "restoregap evidence ingest") {
		t.Errorf("required_next_step = %q, want it to mention `restoregap evidence ingest`", step)
	}
	if strings.Contains(step, "declares no requires") {
		t.Errorf("required_next_step = %q, should not tell the operator to edit the built-in guard", step)
	}
}

func TestEvaluateZeroConfigPassesUnrelatedChange(t *testing.T) {
	ci := intent.ChangeIntent{Action: intent.ActionModifyFile, Paths: []string{"notes/todo.md"}}
	findings := Evaluate([]intent.ChangeIntent{ci}, contextspec.Default(), fixedNow)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
	if engine.Overall(findings) != engine.VerdictPass {
		t.Errorf("overall = %s, want pass", engine.Overall(findings))
	}
}

func explicitContext(t *testing.T) contextspec.Context {
	t.Helper()
	yaml := `version: 2
guards:
  - id: agent-runtime-control-plane
    kind: lifeline
    match:
      commands: ["openclaw*"]
    requires:
      proofs: [agent-runtime-state-backup, portable-recovery-kit]
    max_proof_age_hours: 168
proofs:
  - id: agent-runtime-state-backup
    status: observed
    observed_at: "2026-05-14T00:00:00Z"
  - id: portable-recovery-kit
    status: validated
    observed_at: "2026-05-14T00:00:00Z"
`
	ctx, err := contextspec.Parse(stringsReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return ctx
}

func TestEvaluatePassesWithFreshProofs(t *testing.T) {
	ctx := explicitContext(t)
	ci := intent.ChangeIntent{Action: intent.ActionRunCommand, Command: "openclaw update"}
	findings := Evaluate([]intent.ChangeIntent{ci}, ctx, fixedNow)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Verdict != engine.VerdictPass {
		t.Errorf("verdict = %s, want pass: %+v", findings[0].Verdict, findings[0])
	}
}

func TestEvaluateBlocksWithMissingProofs(t *testing.T) {
	yaml := `version: 2
guards:
  - id: agent-runtime-control-plane
    kind: lifeline
    match:
      commands: ["openclaw*"]
    requires:
      proofs: [agent-runtime-state-backup]
`
	ctx, err := contextspec.Parse(stringsReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ci := intent.ChangeIntent{Action: intent.ActionRunCommand, Command: "openclaw update"}
	findings := Evaluate([]intent.ChangeIntent{ci}, ctx, fixedNow)
	if len(findings) != 1 || findings[0].Verdict != engine.VerdictBlock {
		t.Fatalf("got %+v, want one blocking finding", findings)
	}
	if findings[0].ProofStatus != engine.ProofMissing {
		t.Errorf("proof status = %s, want missing", findings[0].ProofStatus)
	}
}

func TestEvaluateWarnEnforcementDowngrades(t *testing.T) {
	yaml := `version: 2
guards:
  - id: gpu-packages
    kind: guard
    match:
      packages: ["nvidia*"]
    requires:
      proofs: [gpu-rollback-plan]
    enforcement: warn
`
	ctx, err := contextspec.Parse(stringsReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ci := intent.ChangeIntent{Action: intent.ActionPackageUpdate, Packages: []string{"nvidia-driver"}}
	findings := Evaluate([]intent.ChangeIntent{ci}, ctx, fixedNow)
	if len(findings) != 1 || findings[0].Verdict != engine.VerdictWarn {
		t.Fatalf("got %+v, want one warning finding", findings)
	}
}

func TestEvaluateDeclaredGuardWithNoRequiresNextStep(t *testing.T) {
	// A user-declared guard (not the built-in default) that forgot a
	// requires: block IS something the operator can fix directly by editing
	// their own context file, so the old "add requires: to that guard"
	// guidance stays correct here.
	yaml := `version: 2
guards:
  - id: my-custom-guard
    kind: lifeline
    match:
      paths: ["**/my-secret"]
`
	ctx, err := contextspec.Parse(stringsReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ci := intent.ChangeIntent{Action: intent.ActionDeleteFile, Paths: []string{"my-secret"}}
	findings := Evaluate([]intent.ChangeIntent{ci}, ctx, fixedNow)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	step := findings[0].RequiredNextStep
	if !strings.Contains(step, `Guard "my-custom-guard" matches this resource but declares no requires:`) {
		t.Errorf("required_next_step = %q, want the declared-guard-no-requires guidance", step)
	}
	if !strings.Contains(step, "requires: {proofs: [my-custom-guard-recovery]}") {
		t.Errorf("required_next_step = %q, want it to name the requires: block to add", step)
	}
	if !strings.Contains(step, "restoregap context lint") {
		t.Errorf("required_next_step = %q, want it to mention `restoregap context lint`", step)
	}
}

func TestEvaluateExplicitEmptyContextReplacesDefault(t *testing.T) {
	// An explicitly supplied but otherwise-empty v2 context REPLACES the
	// zero-config default rather than merging with it (ARCHITECTURE.md §5).
	ctx, err := contextspec.Parse(stringsReader("version: 2\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ci := intent.ChangeIntent{Action: intent.ActionDeleteFile, Paths: []string{"~/.ssh/id_ed25519"}}
	findings := Evaluate([]intent.ChangeIntent{ci}, ctx, fixedNow)
	if len(findings) != 0 {
		t.Fatalf("got %d findings against an empty explicit context, want 0 (no guards declared): %+v", len(findings), findings)
	}
}

func TestGuardMatchingANDsAcrossCategories(t *testing.T) {
	yaml := `version: 2
guards:
  - id: codex-only-openclaw
    kind: guard
    match:
      commands: ["openclaw*"]
      actors: ["codex"]
`
	ctx, err := contextspec.Parse(stringsReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	matchingActor := intent.ChangeIntent{Action: intent.ActionRunCommand, Command: "openclaw update", Actor: "codex"}
	otherActor := intent.ChangeIntent{Action: intent.ActionRunCommand, Command: "openclaw update", Actor: "claude"}

	if got := len(Evaluate([]intent.ChangeIntent{matchingActor}, ctx, fixedNow)); got != 1 {
		t.Errorf("matching actor: got %d findings, want 1", got)
	}
	if got := len(Evaluate([]intent.ChangeIntent{otherActor}, ctx, fixedNow)); got != 0 {
		t.Errorf("non-matching actor: got %d findings, want 0 (AND semantics require both command and actor to match)", got)
	}
}

func TestEvaluateWithOptionsRequiresEveryAddressedPath(t *testing.T) {
	ctx, err := contextspec.Parse(stringsReader(`version: 2
guards:
  - id: covered
    kind: guard
    match:
      paths: ["/covered"]
      actions: [delete_file]
`))
	if err != nil {
		t.Fatal(err)
	}
	ci := intent.ChangeIntent{Action: intent.ActionDeleteFile, Paths: []string{"/covered", "/uncovered"}}
	legacy := Evaluate([]intent.ChangeIntent{ci}, ctx, fixedNow)
	if len(legacy) != 1 || legacy[0].Verdict != engine.VerdictPass {
		t.Fatalf("legacy evaluation changed: %+v", legacy)
	}
	strict := EvaluateWithOptions([]intent.ChangeIntent{ci}, ctx, fixedNow, EvaluateOptions{RequireCoverage: true})
	if len(strict) != 2 {
		t.Fatalf("strict findings = %+v, want guard result plus one coverage finding", strict)
	}
	var gap *engine.Finding
	for i := range strict {
		if strict[i].Kind == "coverage" {
			gap = &strict[i]
		}
	}
	if gap == nil || gap.Verdict != engine.VerdictBlock || gap.Resource != "/uncovered" {
		t.Fatalf("strict uncovered finding = %+v, want block for /uncovered", gap)
	}
}

func TestEvaluateWithOptionsCoversPackagesAndCommandsIndependently(t *testing.T) {
	ctx, err := contextspec.Parse(stringsReader(`version: 2
guards:
  - id: gpu
    kind: guard
    match: {packages: ["nvidia*"]}
  - id: service
    kind: guard
    match: {commands: ["systemctl restart*"]}
`))
	if err != nil {
		t.Fatal(err)
	}
	ci := intent.ChangeIntent{Action: intent.ActionRunCommand, Command: "systemctl restart gpu", Packages: []string{"nvidia-driver"}}
	findings := EvaluateWithOptions([]intent.ChangeIntent{ci}, ctx, fixedNow, EvaluateOptions{RequireCoverage: true})
	for _, f := range findings {
		if f.Kind == "coverage" {
			t.Fatalf("covered package/command unexpectedly produced gap: %+v", findings)
		}
	}
}

func TestEvaluateWithOptionsUsesExplicitResourceDimensionWithOtherANDDimensions(t *testing.T) {
	ctx, err := contextspec.Parse(stringsReader(`version: 2
guards:
  - id: combined
    kind: guard
    match:
      paths: ["/covered"]
      packages: ["nvidia*"]
      commands: ["systemctl restart*"]
`))
	if err != nil {
		t.Fatal(err)
	}
	ci := intent.ChangeIntent{
		Action:   intent.ActionRunCommand,
		Paths:    []string{"/covered"},
		Packages: []string{"nvidia-driver"},
		Command:  "systemctl restart gpu",
	}
	findings := EvaluateWithOptions([]intent.ChangeIntent{ci}, ctx, fixedNow, EvaluateOptions{RequireCoverage: true})
	for _, f := range findings {
		if f.Kind == "coverage" {
			t.Fatalf("combined guard unexpectedly left a resource uncovered: %+v", findings)
		}
	}
}

func TestEvaluateWithOptionsRequiresExplicitParentCoverage(t *testing.T) {
	ctx, err := contextspec.Parse(stringsReader(`version: 2
guards:
  - id: child
    kind: guard
    match:
      paths: ["/parent/one"]
`))
	if err != nil {
		t.Fatal(err)
	}
	ci := intent.ChangeIntent{Action: intent.ActionDeleteFile, Paths: []string{"/parent"}}
	findings := EvaluateWithOptions([]intent.ChangeIntent{ci}, ctx, fixedNow, EvaluateOptions{RequireCoverage: true})
	var gap *engine.Finding
	for i := range findings {
		if findings[i].Kind == "coverage" {
			gap = &findings[i]
		}
	}
	if gap == nil || gap.Resource != "/parent" || gap.Verdict != engine.VerdictBlock {
		t.Fatalf("descendant-only guard must leave parent uncovered, got %+v", findings)
	}
}

func TestEvaluateWithOptionsIgnoresWhitespaceResources(t *testing.T) {
	ctx, err := contextspec.Parse(stringsReader(`version: 2
guards:
  - id: package
    kind: guard
    match:
      packages: ["nvidia*"]
`))
	if err != nil {
		t.Fatal(err)
	}
	ci := intent.ChangeIntent{Action: intent.ActionPackageUpdate, Packages: []string{" \t", "nvidia-driver"}}
	findings := EvaluateWithOptions([]intent.ChangeIntent{ci}, ctx, fixedNow, EvaluateOptions{RequireCoverage: true})
	for _, f := range findings {
		if f.Kind == "coverage" {
			t.Fatalf("whitespace package unexpectedly counted as a resource: %+v", findings)
		}
	}
	unknown := EvaluateWithOptions([]intent.ChangeIntent{{Action: intent.ActionRunCommand, Command: " \t"}}, contextspec.Context{}, fixedNow, EvaluateOptions{RequireCoverage: true})
	if len(unknown) != 1 || unknown[0].Resource != "intent" || unknown[0].Verdict != engine.VerdictBlock {
		t.Fatalf("whitespace command should produce one explicit intent block, got %+v", unknown)
	}
}

func TestEvaluateWithOptionsBlocksUnknownIntent(t *testing.T) {
	findings := EvaluateWithOptions([]intent.ChangeIntent{{}}, contextspec.Context{}, fixedNow, EvaluateOptions{RequireCoverage: true})
	if len(findings) != 1 || findings[0].Kind != "coverage" || findings[0].Verdict != engine.VerdictBlock {
		t.Fatalf("unknown strict intent findings = %+v, want one explicit block", findings)
	}
	if !strings.Contains(findings[0].Proof, "cannot classify") {
		t.Errorf("unknown strict intent proof = %q, want classification explanation", findings[0].Proof)
	}
	if strings.Contains(findings[0].RequiredNextStep, "disable strict coverage") {
		t.Errorf("strict coverage remediation must not recommend disabling strict coverage: %q", findings[0].RequiredNextStep)
	}
	if !strings.Contains(findings[0].RequiredNextStep, "Declare or review") {
		t.Errorf("strict coverage remediation should require declaration/review: %q", findings[0].RequiredNextStep)
	}
}

// TestGuardMatchesAncestorSubtreeDelete covers the dogfood bug where a guard
// on a file was not fired by an intent to delete or move the DIRECTORY above
// it — the directory delete destroys the guarded file without naming it.
func TestGuardMatchesAncestorSubtreeDelete(t *testing.T) {
	yaml := `version: 2
guards:
  - id: nas-key
    kind: lifeline
    match:
      paths: ["/home/user/.ssh/id_ed25519_nas"]
    requires:
      proofs: ["nas-key-recovery"]
`
	ctx, err := contextspec.Parse(stringsReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	blocks := func(ci intent.ChangeIntent) bool {
		return len(Evaluate([]intent.ChangeIntent{ci}, ctx, fixedNow)) == 1
	}
	cases := []struct {
		name string
		ci   intent.ChangeIntent
		want bool
	}{
		{"delete the guarded file itself", intent.ChangeIntent{Action: intent.ActionDeleteFile, Paths: []string{"/home/user/.ssh/id_ed25519_nas"}}, true},
		{"delete the parent directory", intent.ChangeIntent{Action: intent.ActionDeleteFile, Paths: []string{"/home/user/.ssh"}}, true},
		{"delete a grandparent directory", intent.ChangeIntent{Action: intent.ActionDeleteFile, Paths: []string{"/home/user"}}, true},
		{"move the parent directory", intent.ChangeIntent{Action: intent.ActionMoveFile, Paths: []string{"/home/user/.ssh"}}, true},
		{"modify the parent directory is NOT a subtree destroyer", intent.ChangeIntent{Action: intent.ActionModifyFile, Paths: []string{"/home/user/.ssh"}}, false},
		{"a sibling directory does not match", intent.ChangeIntent{Action: intent.ActionDeleteFile, Paths: []string{"/home/user/.config"}}, false},
		{"a prefix that is not a path boundary does not match", intent.ChangeIntent{Action: intent.ActionDeleteFile, Paths: []string{"/home/user/.ss"}}, false},
	}
	for _, c := range cases {
		if got := blocks(c.ci); got != c.want {
			t.Errorf("%s: blocked=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestAncestorMatchResourceExplainsItself: the finding text names both the
// directory the operator asked to delete and the guarded path underneath, so
// a refused directory delete is legible.
func TestAncestorMatchResourceExplainsItself(t *testing.T) {
	yaml := `version: 2
guards:
  - id: nas-key
    kind: lifeline
    match:
      paths: ["/home/user/.ssh/id_ed25519_nas"]
    requires:
      proofs: ["nas-key-recovery"]
`
	ctx, err := contextspec.Parse(stringsReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ci := intent.ChangeIntent{Action: intent.ActionDeleteFile, Paths: []string{"/home/user/.ssh"}}
	findings := Evaluate([]intent.ChangeIntent{ci}, ctx, fixedNow)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	res := findings[0].Resource
	if !strings.Contains(res, "/home/user/.ssh") || !strings.Contains(res, "/home/user/.ssh/id_ed25519_nas") {
		t.Errorf("resource = %q, want it to name both the deleted dir and the guarded path", res)
	}
}

// TestEvaluateUnreachableProofBlocksDistinctFromDisputed: an unreachable
// proof ("the recovery source was not reachable, nothing was proven") must
// block a guard exactly like a disputed one — but as its own ProofStatus,
// with remediation that says re-run the drill once the source is reachable
// instead of treating the copy as bad. require_verified must not be
// satisfied by it either: the gate never weakens, only the story changes.
func TestEvaluateUnreachableProofBlocksDistinctFromDisputed(t *testing.T) {
	newCtx := func(status contextspec.ProofRecordStatus, verified bool) contextspec.Context {
		t.Helper()
		yaml := `version: 2
guards:
  - id: nas-backed-lifeline
    kind: lifeline
    match:
      paths: ["creds/**"]
    requires:
      proofs: [nas-copy]
proofs:
  - id: nas-copy
    status: ` + string(status) + `
    observed_at: "2026-05-14T00:00:00Z"
    verified: ` + fmt.Sprintf("%v", verified) + `
`
		ctx, err := contextspec.Parse(stringsReader(yaml))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		return ctx
	}
	ci := intent.ChangeIntent{Action: intent.ActionDeleteFile, Paths: []string{"creds/store.tar.gz.gpg"}}

	findings := Evaluate([]intent.ChangeIntent{ci}, newCtx(contextspec.ProofRecordUnreachable, false), fixedNow)
	if len(findings) != 1 || findings[0].Verdict != engine.VerdictBlock {
		t.Fatalf("unreachable proof must block, got %+v", findings)
	}
	if findings[0].ProofStatus != engine.ProofUnreachable {
		t.Errorf("proof status = %s, want unreachable", findings[0].ProofStatus)
	}
	step := findings[0].RequiredNextStep
	if !strings.Contains(step, "re-run the drill once the source is reachable") {
		t.Errorf("required_next_step should carry the reachability remedy, got %q", step)
	}
	if !strings.Contains(step, "not evidence of data loss") {
		t.Errorf("required_next_step must not imply data loss, got %q", step)
	}
	if !strings.Contains(findings[0].Proof, "not reachable") {
		t.Errorf("finding detail should say why: %q", findings[0].Proof)
	}

	// A lifeline marked require_verified gets the same block from an
	// unreachable proof — it is not a verified drill product.
	rv := newCtx(contextspec.ProofRecordUnreachable, false)
	rv.Guards[0].RequireVerified = true
	findings = Evaluate([]intent.ChangeIntent{ci}, rv, fixedNow)
	if len(findings) != 1 || findings[0].Verdict != engine.VerdictBlock {
		t.Fatalf("unreachable must not satisfy require_verified, got %+v", findings)
	}

	// The disputed twin blocks too, as its own status with its own remedy —
	// the two must remain distinguishable to the operator.
	findings = Evaluate([]intent.ChangeIntent{ci}, newCtx(contextspec.ProofRecordDisputed, false), fixedNow)
	if len(findings) != 1 || findings[0].Verdict != engine.VerdictBlock {
		t.Fatalf("disputed proof must keep blocking, got %+v", findings)
	}
	if findings[0].ProofStatus != engine.ProofContradicted {
		t.Errorf("disputed proof status = %s, want contradicted (unchanged)", findings[0].ProofStatus)
	}
	if strings.Contains(findings[0].RequiredNextStep, "re-run the drill once the source is reachable") {
		t.Errorf("disputed remedy must stay the investigate-the-copy path, got %q", findings[0].RequiredNextStep)
	}
}
