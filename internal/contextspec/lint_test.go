// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package contextspec

import (
	"strings"
	"testing"
)

func guard(id string, kind GuardKind, enf Enforcement, req Requirement, paths ...string) Guard {
	return Guard{
		ID:          id,
		Kind:        kind,
		Enforcement: enf,
		Requires:    req,
		Match:       Matcher{Paths: paths},
	}
}

func rules(findings []LintFinding) map[string][]LintFinding {
	m := map[string][]LintFinding{}
	for _, f := range findings {
		m[f.Rule] = append(m[f.Rule], f)
	}
	return m
}

// TestLintFlagsUnsatisfiableLifelineGuard is the case that motivated this file:
// a blocking lifeline guard with no requires: blocks every matching change and
// no proof can ever clear it, so an owner override is the only exit. Discovering
// that by being blocked mid-change is what trains people to override reflexively.
func TestLintFlagsUnsatisfiableLifelineGuard(t *testing.T) {
	c := Context{Guards: []Guard{
		guard("recovery-kit", GuardKindLifeline, EnforcementBlock, Requirement{}, "**/recovery-usb/**"),
	}}

	got := rules(c.Lint())["guard-never-satisfiable"]
	if len(got) != 1 {
		t.Fatalf("want 1 unsatisfiable finding, got %d", len(got))
	}
	if got[0].Severity != LintError {
		t.Errorf("a blocking lifeline that can never pass is an error, got %s", got[0].Severity)
	}
	// The remedy has to be actionable: name the guard and how to satisfy it.
	if !strings.Contains(got[0].Fix, "recovery-kit") || !strings.Contains(got[0].Fix, "requires:") {
		t.Errorf("fix must name the guard and the requires: block, got %q", got[0].Fix)
	}
	if !strings.Contains(got[0].Fix, "evidence ingest") {
		t.Errorf("fix must show how to record the proof it asks for, got %q", got[0].Fix)
	}
}

// TestLintDowngradesWarnEnforcement: the same shape under warn enforcement only
// ever warns, so it must not be reported as fatal.
func TestLintDowngradesWarnEnforcement(t *testing.T) {
	c := Context{Guards: []Guard{
		guard("advisory", GuardKindLifeline, EnforcementWarn, Requirement{}, "**/x/**"),
	}}
	got := rules(c.Lint())["guard-never-satisfiable"]
	if len(got) != 1 || got[0].Severity != LintWarn {
		t.Fatalf("warn-enforced guard must lint as warn, got %+v", got)
	}
	if HasErrors(c.Lint()) {
		t.Error("a warn-only guard must not make the whole context an error")
	}
}

// TestLintIgnoresSatisfiableAndNonLifelineGuards: a guard with requires is fine,
// and a non-lifeline guard with no requires is informational by design.
func TestLintIgnoresSatisfiableAndNonLifelineGuards(t *testing.T) {
	c := Context{
		Guards: []Guard{
			guard("ok", GuardKindLifeline, EnforcementBlock, Requirement{Proofs: []string{"p1"}}, "**/a/**"),
			guard("informational", GuardKind("guard"), EnforcementBlock, Requirement{}, "**/b/**"),
		},
		Proofs: []Proof{{ID: "p1"}},
	}
	if got := rules(c.Lint())["guard-never-satisfiable"]; len(got) != 0 {
		t.Errorf("no guard should be flagged unsatisfiable, got %+v", got)
	}
}

// TestLintFlagsProofRequiredButNeverDeclared: an undeclared proof id is treated
// as missing at decide time, so the guard always blocks while looking configured.
func TestLintFlagsProofRequiredButNeverDeclared(t *testing.T) {
	c := Context{Guards: []Guard{
		guard("ssh-keys", GuardKindLifeline, EnforcementBlock, Requirement{Proofs: []string{"ghost-proof"}}, "**/.ssh/**"),
	}}
	got := rules(c.Lint())["proof-not-declared"]
	if len(got) != 1 || got[0].Severity != LintError {
		t.Fatalf("want one error for the undeclared proof, got %+v", got)
	}
	if !strings.Contains(got[0].Message, "ghost-proof") {
		t.Errorf("message must name the missing proof, got %q", got[0].Message)
	}
}

// TestLintFlagsProofThatGatesNothing: a proof kept fresh on a timer and shown in
// status, but required by no guard, reads as protection while gating nothing.
func TestLintFlagsProofThatGatesNothing(t *testing.T) {
	c := Context{
		Guards: []Guard{guard("g", GuardKindLifeline, EnforcementBlock, Requirement{Proofs: []string{"used"}}, "**/a/**")},
		Proofs: []Proof{{ID: "used"}, {ID: "orphan"}},
	}
	got := rules(c.Lint())["proof-gates-nothing"]
	if len(got) != 1 || got[0].Subject != "orphan" {
		t.Fatalf("want exactly the orphan proof flagged, got %+v", got)
	}
	if got[0].Severity != LintWarn {
		t.Errorf("an unused proof is waste, not a broken policy; want warn, got %s", got[0].Severity)
	}
}

// TestLintFlagsDuplicateGuards: guards indistinguishable in every respect turn
// one blocked change into several findings.
func TestLintFlagsDuplicateGuards(t *testing.T) {
	req := Requirement{Proofs: []string{"p"}}
	c := Context{
		Guards: []Guard{
			guard("kit", GuardKindLifeline, EnforcementBlock, req, "**/recovery-usb/**"),
			guard("kit-2", GuardKindLifeline, EnforcementBlock, req, "**/recovery-usb/**"),
		},
		Proofs: []Proof{{ID: "p"}},
	}
	got := rules(c.Lint())["guard-duplicates"]
	if len(got) != 1 || got[0].Subject != "kit-2" {
		t.Fatalf("want the second guard flagged as the duplicate, got %+v", got)
	}
}

// TestLintDoesNotCallDistinctMatchersDuplicates: guards differing in any matcher
// field target different intents. Packages and Actors were omitted from the
// comparison key at first, which would have called these two a duplicate pair.
func TestLintDoesNotCallDistinctMatchersDuplicates(t *testing.T) {
	req := Requirement{Proofs: []string{"p"}}
	a := Guard{ID: "a", Kind: GuardKindLifeline, Enforcement: EnforcementBlock, Requires: req,
		Match: Matcher{Packages: []string{"kernel*"}}}
	b := Guard{ID: "b", Kind: GuardKindLifeline, Enforcement: EnforcementBlock, Requires: req,
		Match: Matcher{Packages: []string{"nvidia*"}}}
	c := Context{Guards: []Guard{a, b}, Proofs: []Proof{{ID: "p"}}}

	if got := rules(c.Lint())["guard-duplicates"]; len(got) != 0 {
		t.Errorf("guards matching different packages are not duplicates, got %+v", got)
	}
}

// TestLintCleanContextIsSilent: no findings on a well-formed context, so the
// command is usable as a gate.
func TestLintCleanContextIsSilent(t *testing.T) {
	c := Context{
		Guards: []Guard{guard("g", GuardKindLifeline, EnforcementBlock, Requirement{Proofs: []string{"p"}}, "**/a/**")},
		Proofs: []Proof{{ID: "p"}},
	}
	if findings := c.Lint(); len(findings) != 0 {
		t.Errorf("clean context must produce no findings, got %+v", findings)
	}
}

// TestLintAllowsLayeredGuardsOnTheSameResource is the correction to a rule that
// was too eager. Two guards deliberately covering the same packages with
// DIFFERENT evidence — an off-machine snapshot versus a boot-rollback proof
// observed within the hour — are layered defence, not duplication. Calling them
// duplicates would invite a merge that silently drops a requirement or a
// freshness bound, so the lint would create the very hole it exists to find.
func TestLintAllowsLayeredGuardsOnTheSameResource(t *testing.T) {
	match := Matcher{Packages: []string{"akmod-nvidia", "kernel*"}}
	broad := Guard{
		ID: "graphics-boot-stack", Kind: GuardKindGuard, Enforcement: EnforcementBlock,
		Match: match, Requires: Requirement{Proofs: []string{"off-machine-os-snapshot"}},
	}
	strict := Guard{
		ID: "contract-graphics-boot-assurance", Kind: GuardKindGuard, Enforcement: EnforcementBlock,
		Match: match, MaxProofAgeHours: 1,
		Requires: Requirement{Proofs: []string{"os-boot-rollback-observed"}},
	}
	c := Context{
		Guards: []Guard{broad, strict},
		Proofs: []Proof{{ID: "off-machine-os-snapshot"}, {ID: "os-boot-rollback-observed"}},
	}
	if got := rules(c.Lint())["guard-duplicates"]; len(got) != 0 {
		t.Errorf("layered guards requiring different evidence are not duplicates, got %+v", got)
	}
}

// TestLintFlagsGuardsDifferingOnlyInName: the real duplicate shape — everything
// identical except the id.
func TestLintFlagsGuardsDifferingOnlyInName(t *testing.T) {
	mk := func(id string) Guard {
		return Guard{
			ID: id, Kind: GuardKindLifeline, Enforcement: EnforcementBlock,
			Match:    Matcher{Paths: []string{"~/.codex/state_5.sqlite"}},
			Requires: Requirement{Proofs: []string{"codex-state-offline-backup-observed"}},
		}
	}
	c := Context{
		Guards: []Guard{mk("codex-state"), mk("codex-runtime-state")},
		Proofs: []Proof{{ID: "codex-state-offline-backup-observed"}},
	}
	got := rules(c.Lint())["guard-duplicates"]
	if len(got) != 1 || got[0].Subject != "codex-runtime-state" {
		t.Fatalf("want the second flagged as a true duplicate, got %+v", got)
	}
	if !strings.Contains(got[0].Fix, "delete") {
		t.Errorf("fix should say to delete it, got %q", got[0].Fix)
	}
}
