// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDrillFlagOnlyInvocationsStillWorkWithProposeSubcommand is the
// regression test the propose feature demands: `drill` had no subcommands
// before propose was added, only flags. Adding `drill propose` as a
// subcommand must not change how `drill --context ...`, `--lint`, or
// `--pins-only` parse and run — cobra must still dispatch a flag-only
// invocation (no positional args at all) to the parent command's own RunE,
// not get confused by the new child command.
func TestDrillFlagOnlyInvocationsStillWorkWithProposeSubcommand(t *testing.T) {
	if _, _, err := newDrillCmd().Find([]string{"propose"}); err != nil {
		t.Fatalf("expected drill to have a propose subcommand registered: %v", err)
	}

	dir := t.TempDir()
	lintArtifact := writeFile(t, dir, "lint-artifact", "x")
	lintPath := writeContext(t, fmt.Sprintf(lintCleanYAML, lintArtifact))

	// --lint, flag-only, no positional args.
	var lintOut bytes.Buffer
	lintCmd := newDrillCmd()
	lintCmd.SetOut(&lintOut)
	lintCmd.SetErr(&lintOut)
	lintCmd.SetArgs([]string{"--context", lintPath, "--lint"})
	if err := lintCmd.Execute(); err != nil {
		t.Fatalf("drill --context --lint (flag-only) must still work: %v (%s)", err, lintOut.String())
	}

	// A real, passing drill, flag-only, no positional args.
	drillArtifact := writeFile(t, dir, "drill-artifact", "same\n")
	recover := fmt.Sprintf("cat %s > \"$RG_TARGET\"", drillArtifact)
	drillPath := writeContext(t, fmt.Sprintf(oneDrillYAML, drillArtifact, recover))

	var drillOut bytes.Buffer
	drillCmd := newDrillCmd()
	drillCmd.SetOut(&drillOut)
	drillCmd.SetErr(&drillOut)
	drillCmd.SetArgs([]string{"--context", drillPath})
	if err := drillCmd.Execute(); err != nil {
		t.Fatalf("plain drill --context (flag-only) must still work: %v (%s)", err, drillOut.String())
	}
	if !strings.Contains(drillOut.String(), "widget-recovery") {
		t.Errorf("expected the drill's pass line, got %q", drillOut.String())
	}
}

func TestDrillProposeRequiresArtifactArg(t *testing.T) {
	cmd := newDrillProposeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("propose with no artifact arg must error")
	}
}

func TestDrillProposeMissingArtifactExitsTwo(t *testing.T) {
	cmd := newDrillProposeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{filepath.Join(t.TempDir(), "does-not-exist")})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("propose against a nonexistent artifact must error")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an *ExitError, got %T: %v", err, err)
	}
	if exitErr.Code != 2 {
		t.Errorf("Code = %d, want 2", exitErr.Code)
	}
}

func TestDrillProposePrintsToStdout(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "plain.bin", "hello")

	cmd := newDrillProposeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{artifact})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.HasPrefix(out.String(), "version: 2\ndrills:\n") || !strings.Contains(out.String(), "type: byte_identical") {
		t.Errorf("expected a drills: fragment on stdout, got %q", out.String())
	}
}

func TestDrillProposeOutWritesFile(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "plain.bin", "hello")
	outPath := filepath.Join(dir, "draft.yml")

	cmd := newDrillProposeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{artifact, "--out", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.String() != "" {
		t.Errorf("with --out, nothing should go to stdout, got %q", out.String())
	}
	written, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read --out file: %v", err)
	}
	if !strings.Contains(string(written), "drills:") {
		t.Errorf("expected a drills: fragment in the --out file, got %q", written)
	}
}

func TestDrillProposeViaParentSubcommand(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "plain.bin", "hello")

	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"propose", artifact})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("drill propose <artifact> via the parent command: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "drills:") {
		t.Errorf("expected a drills: fragment, got %q", out.String())
	}
}
