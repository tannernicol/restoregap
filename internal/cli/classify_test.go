// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// classifyFixture spans the whole suggest→apply cycle: one already-filed
// guard (must never be overridden), one unfiled guard whose id carries a
// clear keyword, and one unattached unfiled proof.
const classifyFixture = `version: 2
guards:
  - id: hand-filed-guard
    kind: lifeline
    match: {paths: ["~/important"]}
    layer: data-apps
    requires: {proofs: [classified-proof]}
  - id: ssh-key-guard
    kind: lifeline
    match: {paths: ["~/.ssh/id_ed25519"]}
    requires: {proofs: [classified-proof]}
proofs:
  - id: orphan-backup-proof
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
  - id: classified-proof
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
`

func runClassify(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newClassifyCmd()
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// TestClassifySuggestPrintsTableAndExits1WhenUnfiled: --suggest (the
// default) prints the id/current/suggested/reason table and exits 1 while
// anything is still unfiled.
func TestClassifySuggestPrintsTableAndExits1WhenUnfiled(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", classifyFixture)

	out, err := runClassify(t, "--context", ctxPath)
	if err == nil {
		t.Fatal("expected exit 1 while any entry is unfiled")
	}
	exit, ok := err.(*ExitError)
	if !ok || exit.Code != 1 {
		t.Fatalf("expected *ExitError code 1, got %T: %v", err, err)
	}
	for _, want := range []string{"ID", "CURRENT", "SUGGESTED", "REASON", "unfiled",
		"ssh-key-guard", "identity-secrets", "orphan-backup-proof", "data-apps"} {
		if !strings.Contains(out, want) {
			t.Errorf("classify --suggest missing %q, got:\n%s", want, out)
		}
	}
	// classified-proof is attached (a guard requires it) — classify does not
	// suggest a layer for it; the guard's layer is its effective layer.
	if strings.Contains(out, "classified-proof") {
		t.Errorf("an attached proof must not get its own suggestion row, got:\n%s", out)
	}
}

// TestClassifyApplyWritesOnlyUnfiledAndBacksUp: --apply writes layer: onto
// exactly the unfiled entries, never touches an explicit one, and leaves a
// .bak.<UTC> sibling behind.
func TestClassifyApplyWritesOnlyUnfiledAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	ctxPath := writeFile(t, dir, "restoregap.yml", classifyFixture)

	out, err := runClassify(t, "--context", ctxPath, "--apply")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	if !strings.Contains(out, "wrote ssh-key-guard: layer: identity-secrets") {
		t.Errorf("expected the ssh-key-guard write to be reported, got:\n%s", out)
	}
	if !strings.Contains(out, "wrote orphan-backup-proof") {
		t.Errorf("expected the unattached proof write to be reported, got:\n%s", out)
	}

	ctx := loadContext(t, ctxPath)
	for _, g := range ctx.Guards {
		switch g.ID {
		case "hand-filed-guard":
			if g.Layer != "data-apps" {
				t.Errorf("an explicit layer must never be overridden, got %q", g.Layer)
			}
		case "ssh-key-guard":
			if g.Layer != "identity-secrets" {
				t.Errorf("ssh-key-guard layer = %q, want identity-secrets", g.Layer)
			}
		}
	}
	if len(ctx.Proofs) != 2 {
		t.Fatalf("proofs were lost or duplicated: %+v", ctx.Proofs)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var sawBackup bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "restoregap.yml.bak.") {
			sawBackup = true
		}
	}
	if !sawBackup {
		t.Error("expected a .bak.<UTC> backup beside the rewritten context file")
	}

	// A second --apply is a no-op now that everything declares a layer —
	// and --suggest exits 0.
	out, err = runClassify(t, "--context", ctxPath, "--apply")
	if err != nil {
		t.Fatalf("second --apply: %v (%s)", err, out)
	}
	if !strings.Contains(out, "nothing to apply") {
		t.Errorf("second --apply should report nothing to apply, got:\n%s", out)
	}
	if _, err := runClassify(t, "--context", ctxPath); err != nil {
		t.Errorf("post-apply --suggest must exit 0 (nothing unfiled), got: %v", err)
	}
}

// TestClassifyApplyPreservesFieldsItDoesNotOwn: applying writes layer: and
// nothing else — every other field on the touched entries (scope, category,
// guard match blocks) must round-trip unchanged (taxonomy spec section A).
// Context parsing is strict (KnownFields), so there are no truly unknown
// fields to preserve; the meaningful check is the fields classify never
// reads or writes.
func TestClassifyApplyPreservesFieldsItDoesNotOwn(t *testing.T) {
	dir := t.TempDir()
	ctxPath := filepath.Join(dir, "restoregap.yml")
	fixture := strings.Replace(classifyFixture, "    requires: {proofs: [classified-proof]}",
		"    requires: {proofs: [classified-proof]}\n    scope:\n      environment: prod\n      tags: [cold-metal]", 1)
	if err := os.WriteFile(ctxPath, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}

	if out, err := runClassify(t, "--context", ctxPath, "--apply"); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	raw, err := os.ReadFile(ctxPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"environment: prod", "cold-metal", "~/important", "~/.ssh/id_ed25519"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("classify --apply dropped a field it does not own (%q), got:\n%s", want, raw)
		}
	}
}
