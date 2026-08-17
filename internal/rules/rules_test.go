package rules

import (
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
