// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package migrate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

func writeFixture(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

const v1Fixture = `lifeline_artifacts:
  - id: recovery-kit
    paths: ["recovery-usb/**", "runbooks/**"]
    enforcement: block
    requires_proofs: [kit-restore-drill]
    max_proof_age_hours: 24
change_guards:
  - id: app-db
    paths: ["/var/app/data.db"]
    enforcement: warn
    requires_proofs: [db-backup-drill]
facts:
  - id: kit-location
    statement: "kit lives in the safe"
    provenance: "manual check 2026-01-01"
proofs:
  - id: kit-restore-drill
    status: validated
    observed_at: "2026-08-01T00:00:00Z"
`

func TestFileUpgradesV1ToV2AndWritesBackup(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "restoregap.yml", v1Fixture)

	res, err := File(path, false)
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if !res.Changed || res.FromVersion != 1 || res.ToVersion != contextspec.CurrentVersion {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.BackupPath == "" {
		t.Fatal("expected a backup path")
	}
	if !strings.Contains(filepath.Base(res.BackupPath), ".bak.") {
		t.Errorf("backup path %q does not look like <path>.bak.<UTC>", res.BackupPath)
	}
	backupBytes, err := os.ReadFile(res.BackupPath)
	if err != nil {
		t.Fatalf("reading backup: %v", err)
	}
	if string(backupBytes) != v1Fixture {
		t.Error("backup must hold the exact original bytes")
	}

	// The upgraded file must now Load as a valid v2 context, with both
	// legacy guard lists folded into one `guards:` and matcher/requirement
	// fields nested.
	ctx, err := contextspec.Load(path)
	if err != nil {
		t.Fatalf("upgraded document does not Load as v2: %v", err)
	}
	if len(ctx.Guards) != 2 {
		t.Fatalf("expected 2 guards, got %d: %+v", len(ctx.Guards), ctx.Guards)
	}
	kit, ok := ctx.GuardByID("recovery-kit")
	if !ok {
		t.Fatal("recovery-kit guard missing")
	}
	if kit.Kind != contextspec.GuardKindLifeline {
		t.Errorf("expected lifeline kind, got %q", kit.Kind)
	}
	if len(kit.Match.Paths) != 2 {
		t.Errorf("expected matcher paths nested, got %+v", kit.Match)
	}
	if len(kit.Requires.Proofs) != 1 || kit.Requires.Proofs[0] != "kit-restore-drill" {
		t.Errorf("expected required proof nested, got %+v", kit.Requires)
	}
	appDB, ok := ctx.GuardByID("app-db")
	if !ok {
		t.Fatal("app-db guard missing")
	}
	if appDB.Kind != contextspec.GuardKindGuard {
		t.Errorf("expected guard kind, got %q", appDB.Kind)
	}
	if len(ctx.Facts) != 1 || len(ctx.Proofs) != 1 {
		t.Errorf("facts/proofs must pass through unchanged, got facts=%+v proofs=%+v", ctx.Facts, ctx.Proofs)
	}
}

func TestFileDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "restoregap.yml", v1Fixture)

	res, err := File(path, true)
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if !res.Changed || res.DryRun != true {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.BackupPath != "" {
		t.Errorf("dry-run must not write a backup, got %q", res.BackupPath)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != v1Fixture {
		t.Error("dry-run must not modify the original file")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("dry-run must not create any extra file, got %v", entries)
	}
}

func TestFileAlreadyCurrentIsANoOp(t *testing.T) {
	dir := t.TempDir()
	const v2 = "version: 2\nguards:\n  - id: g\n    kind: guard\n    match: {paths: [x]}\n"
	path := writeFixture(t, dir, "restoregap.yml", v2)

	res, err := File(path, false)
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if res.Changed {
		t.Fatalf("expected no-op for an already-current document, got %+v", res)
	}
	if res.FromVersion != contextspec.CurrentVersion || res.ToVersion != contextspec.CurrentVersion {
		t.Errorf("unexpected versions: %+v", res)
	}
	if res.BackupPath != "" {
		t.Errorf("a no-op must not write a backup, got %q", res.BackupPath)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != v2 {
		t.Error("an already-current document must be left byte-identical")
	}
}

func TestFileRefusesNewerVersion(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "restoregap.yml", "version: 99\nsome_future_thing: true\n")

	_, err := File(path, false)
	if err == nil {
		t.Fatal("expected an error for a version newer than this binary understands")
	}
	var uv *contextspec.UnsupportedVersionError
	if !errors.As(err, &uv) {
		t.Fatalf("expected *contextspec.UnsupportedVersionError, got %T: %v", err, err)
	}
	if uv.Got != 99 {
		t.Errorf("Got = %d, want 99", uv.Got)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "version: 99\nsome_future_thing: true\n" {
		t.Error("a refused file must be left completely untouched")
	}
}

func TestFileUndeclaredVersionTreatedAsV1(t *testing.T) {
	dir := t.TempDir()
	// No `version:` field at all — the oldest, pre-versioning shape.
	path := writeFixture(t, dir, "restoregap.yml", strings.TrimPrefix(v1Fixture, ""))

	res, err := File(path, true)
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if res.FromVersion != 1 {
		t.Errorf("expected an undeclared version to be treated as 1, got %d", res.FromVersion)
	}
}
