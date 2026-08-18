package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContextPathsEnvVarColonList(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.yml")
	pathB := filepath.Join(dir, "b.yml")
	t.Setenv("RESTOREGAP_CONTEXT", pathA+":"+pathB)
	t.Chdir(t.TempDir())

	got := ContextPaths()
	if len(got) != 2 || got[0] != pathA || got[1] != pathB {
		t.Errorf("got %v, want [%q %q]", got, pathA, pathB)
	}
}

func TestContextPathsEnvVarSingleValueNoColon(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "/some/path.yml")
	t.Chdir(t.TempDir())

	got := ContextPaths()
	if len(got) != 1 || got[0] != "/some/path.yml" {
		t.Errorf("got %v, want [/some/path.yml]", got)
	}
}

func TestContextPathsPrefersLocalOverPlain(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "")
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("restoregap.local.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("restoregap.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ContextPaths()
	if len(got) != 1 || got[0] != "restoregap.local.yml" {
		t.Errorf("got %v, want [restoregap.local.yml]", got)
	}
}

func TestContextPathsFallsBackToPlainYml(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "")
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("restoregap.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ContextPaths()
	if len(got) != 1 || got[0] != "restoregap.yml" {
		t.Errorf("got %v, want [restoregap.yml]", got)
	}
}

func TestContextPathsNothingDiscoverable(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "")
	t.Chdir(t.TempDir())

	if got := ContextPaths(); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
