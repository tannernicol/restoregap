// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package proofstore

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

var contextFixture = strings.Join([]string{
	"version: 2",
	"# Keep this comment through generated proof updates.",
	"guards:",
	"  - id: backup",
	"    kind: guard",
	"    enforcement: warn",
	"    match: {paths: [\"data/**\"]}",
	"    requires: {proofs: [base]}",
	"proofs:",
	"  - id: base",
	"    status: observed",
	"    observed_at: \"2026-09-19T00:00:00Z\"",
	"    scope:",
	"      environment: prod",
	"      system: vault",
	"      host: original-host",
	"    host: {name: old-host, id: old-id}",
	"    measurements: {rto_seconds: 9, rpo_seconds: 99, checks: [{type: old, pass: true, detail: old}]}",
	"    signature: {public_key: old-pub, signature: old-sig}",
	"    command: \"test -f /backup\"",
	"    category: backups",
	"facts: []",
	"drills: []",
	"",
}, "\n")

func writeFixture(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "restoregap.yml")
	if err := os.WriteFile(path, []byte(contextFixture), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func proof(id string) map[string]any {
	return map[string]any{
		"id":          id,
		"status":      "validated",
		"observed_at": "2026-09-19T01:00:00Z",
	}
}

func TestUpsertPreservesCommentsFieldsAndMode(t *testing.T) {
	path := writeFixture(t, 0o400)
	entry := proof("base")
	entry["verified"] = true
	entry["sha256"] = "sha256:generated"
	entry["host"] = map[string]any{"name": "new-host", "id": "new-id"}
	entry["scope"] = map[string]any{"host": "new-scope-host"}
	entry["signature"] = map[string]any{"public_key": "pub", "signature": "sig"}
	entry["measurements"] = map[string]any{
		"rto_seconds": 1.25,
		"checks":      []any{map[string]any{"type": "sqlite", "pass": true, "detail": "ok"}},
	}
	if err := Upsert(path, []map[string]any{entry}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Keep this comment") {
		t.Fatalf("top-level comment was not preserved:\n%s", raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o400 {
		t.Fatalf("mode = %04o, want 0400", got)
	}
	ctx, err := contextspec.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx.Proofs) != 1 || !ctx.Proofs[0].Verified || ctx.Proofs[0].Signature == nil || ctx.Proofs[0].Measurements == nil {
		t.Fatalf("generated fields did not survive roundtrip: %+v", ctx.Proofs)
	}
	if got := ctx.Proofs[0].Signature; got.PublicKeyHex != "pub" || got.SignatureHex != "sig" {
		t.Fatalf("generated signature retained stale fields: %+v", got)
	}
	if got := ctx.Proofs[0].Host; got == nil || got.Name != "new-host" || got.ID != "new-id" {
		t.Fatalf("generated host identity was not replaced: %+v", got)
	}
	if got := ctx.Proofs[0].Measurements; got.RPOSeconds != nil || len(got.Checks) != 1 || got.Checks[0].Type != "sqlite" {
		t.Fatalf("generated measurements retained stale nested fields: %+v", got)
	}
	if got := ctx.Proofs[0].Scope; got.Environment != "prod" || got.System != "vault" || got.Host != "original-host" {
		t.Fatalf("unowned scope fields were lost: %+v", got)
	}
	if ctx.Proofs[0].Command != "test -f /backup" || ctx.Proofs[0].Category != "backups" {
		t.Fatalf("unrelated proof fields were lost: %+v", ctx.Proofs[0])
	}
}

func TestUpsertRejectsInvalidUpdateWithoutChangingBytes(t *testing.T) {
	path := writeFixture(t, 0o644)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bad := proof("base")
	bad["status"] = "not-a-status"
	if err := Upsert(path, []map[string]any{bad}); err == nil {
		t.Fatal("invalid proof update unexpectedly succeeded")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("invalid update changed bytes")
	}
	if err := Upsert(path, []map[string]any{proof("same"), proof("same")}); err == nil {
		t.Fatal("duplicate IDs unexpectedly succeeded")
	}
	afterDuplicate, _ := os.ReadFile(path)
	if !bytes.Equal(before, afterDuplicate) {
		t.Fatal("duplicate update changed bytes")
	}
}

func TestUpsertPreRenameFailureLeavesDestinationUntouched(t *testing.T) {
	path := writeFixture(t, 0o644)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	originalSync := syncTemp
	syncTemp = func(*os.File) error { return fmt.Errorf("injected sync failure") }
	t.Cleanup(func() { syncTemp = originalSync })
	if err := Upsert(path, []map[string]any{proof("new-proof")}); err == nil || !strings.Contains(err.Error(), "injected sync failure") {
		t.Fatalf("Upsert error = %v, want injected sync failure", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("pre-rename failure changed destination bytes")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".restoregap.yml.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", matches)
	}
}

func TestUpsertRejectsSymlinkAndNonregularDestination(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		target := writeFixture(t, 0o644)
		link := filepath.Join(t.TempDir(), "restoregap.yml")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := Upsert(link, []map[string]any{proof("new-proof")}); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("Upsert error = %v, want symlink rejection", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "restoregap.yml")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := Upsert(dir, []map[string]any{proof("new-proof")}); err == nil || !strings.Contains(err.Error(), "regular") {
			t.Fatalf("Upsert error = %v, want nonregular rejection", err)
		}
	})
}

func TestUpsertConcurrentProcessesPreserveDistinctProofs(t *testing.T) {
	path := writeFixture(t, 0o644)
	const count = 12
	cmds := make([]*exec.Cmd, 0, count)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("process-%02d", i)
		cmd := exec.Command(os.Args[0], "-test.run=TestProofStoreHelperProcess", "--")
		cmd.Env = append(os.Environ(), "PROOFSTORE_HELPER=1", "PROOFSTORE_PATH="+path, "PROOFSTORE_ID="+id)
		cmds = append(cmds, cmd)
	}
	for _, cmd := range cmds {
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for _, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("concurrent writer failed: %v", err)
		}
	}
	ctx, err := contextspec.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(ctx.Proofs))
	for _, p := range ctx.Proofs {
		got = append(got, p.ID)
	}
	sort.Strings(got)
	want := []string{"base"}
	for i := 0; i < count; i++ {
		want = append(want, fmt.Sprintf("process-%02d", i))
	}
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("proof IDs = %v, want %v", got, want)
	}
}

func TestUpsertConcurrentShuffle(t *testing.T) {
	path := writeFixture(t, 0o644)
	const count = 20
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("goroutine-%02d", i)
			if err := Upsert(path, []map[string]any{proof(id)}); err != nil {
				t.Errorf("Upsert(%s): %v", id, err)
			}
		}(i)
	}
	wg.Wait()
	ctx, err := contextspec.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx.Proofs) != count+1 {
		t.Fatalf("got %d proofs, want %d", len(ctx.Proofs), count+1)
	}
}

func TestProofStoreHelperProcess(t *testing.T) {
	if os.Getenv("PROOFSTORE_HELPER") != "1" {
		return
	}
	if err := Upsert(os.Getenv("PROOFSTORE_PATH"), []map[string]any{proof(os.Getenv("PROOFSTORE_ID"))}); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}
