// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package intent

import (
	"strings"
	"testing"
)

const caddyDiff = `diff --git a/Caddyfile b/Caddyfile
index 1111111..2222222 100644
--- a/Caddyfile
+++ b/Caddyfile
@@ -1,3 +1,3 @@
-admin.home.example {
-  reverse_proxy 127.0.0.1:8080
+app.home.example {
+  reverse_proxy 127.0.0.1:8081
 }
`

const deleteDiff = `diff --git a/secrets.json b/secrets.json
deleted file mode 100644
index 1111111..0000000
--- a/secrets.json
+++ /dev/null
@@ -1,2 +0,0 @@
-{
-}
`

const addDiff = `diff --git a/notes/new.md b/notes/new.md
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/notes/new.md
@@ -0,0 +1,2 @@
+# New
+text
`

func TestParseDiffModified(t *testing.T) {
	files, err := ParseDiff(strings.NewReader(caddyDiff))
	if err != nil {
		t.Fatalf("ParseDiff: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	f := files[0]
	if f.Status != FileModified {
		t.Errorf("status = %s, want modified", f.Status)
	}
	if f.Path() != "Caddyfile" {
		t.Errorf("path = %s, want Caddyfile", f.Path())
	}
	if len(f.Hunks) != 1 {
		t.Fatalf("got %d hunks, want 1", len(f.Hunks))
	}
	h := f.Hunks[0]
	if h.Added != 2 || h.Removed != 2 {
		t.Errorf("added=%d removed=%d, want 2/2", h.Added, h.Removed)
	}
	if h.OldStart != 1 || h.OldLines != 3 || h.NewStart != 1 || h.NewLines != 3 {
		t.Errorf("unexpected hunk range: %+v", h)
	}
}

func TestParseDiffDeleted(t *testing.T) {
	files, err := ParseDiff(strings.NewReader(deleteDiff))
	if err != nil {
		t.Fatalf("ParseDiff: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	f := files[0]
	if f.Status != FileDeleted {
		t.Errorf("status = %s, want deleted", f.Status)
	}
	if f.Path() != "secrets.json" {
		t.Errorf("path = %s, want secrets.json", f.Path())
	}
}

func TestParseDiffAdded(t *testing.T) {
	files, err := ParseDiff(strings.NewReader(addDiff))
	if err != nil {
		t.Fatalf("ParseDiff: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if files[0].Status != FileAdded {
		t.Errorf("status = %s, want added", files[0].Status)
	}
}

func TestToChangeIntents(t *testing.T) {
	files, err := ParseDiff(strings.NewReader(deleteDiff))
	if err != nil {
		t.Fatalf("ParseDiff: %v", err)
	}
	intents := ToChangeIntents(files)
	if len(intents) != 1 || intents[0].Action != ActionDeleteFile {
		t.Fatalf("got %+v, want one delete_file intent", intents)
	}
	if intents[0].Paths[0] != "secrets.json" {
		t.Errorf("path = %v", intents[0].Paths)
	}
}

func TestParseDiffMalformedHunk(t *testing.T) {
	_, err := ParseDiff(strings.NewReader("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ garbage @@\n"))
	if err == nil {
		t.Fatal("expected error for malformed hunk header")
	}
}

func TestRebaseMakesDiffPathsAbsolute(t *testing.T) {
	files, err := ParseDiff(strings.NewReader(deleteDiff))
	if err != nil {
		t.Fatalf("ParseDiff: %v", err)
	}
	intents := ToChangeIntents(Rebase(files, "/home/user/app"))
	if got := intents[0].Paths[0]; got != "/home/user/app/secrets.json" {
		t.Errorf("path = %q, want it resolved against the repo root", got)
	}
}

func TestRebaseLeavesAbsoluteAndRootlessPathsAlone(t *testing.T) {
	files := []FileDiff{{OldPath: "/etc/passwd", NewPath: "/etc/passwd", Status: FileModified}}
	if got := Rebase(files, "/home/user")[0].Path(); got != "/etc/passwd" {
		t.Errorf("absolute path rewritten to %q", got)
	}
	rel := []FileDiff{{OldPath: "bin/ctx", NewPath: "bin/ctx", Status: FileModified}}
	if got := Rebase(rel, "")[0].Path(); got != "bin/ctx" {
		t.Errorf("empty root rewrote path to %q", got)
	}
}
