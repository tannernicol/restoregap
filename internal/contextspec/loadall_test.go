package contextspec

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeLoadAllFixture(t *testing.T, dir, name, yaml string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

const loadAllContextA = `version: 2
guards:
  - id: guard-a
    kind: guard
    match: {paths: ["/x/app.db"]}
    requires: {proofs: [proof-a]}
proofs:
  - id: proof-a
    status: validated
    observed_at: "2026-08-01T00:00:00Z"
`

const loadAllContextB = `version: 2
guards:
  - id: guard-b
    kind: guard
    match: {paths: ["/y/other.db"]}
facts:
  - id: fact-b
    statement: "b is true"
drills:
  - proof: proof-b
    artifact: /y/other.db
    recover: "true"
proofs:
  - id: proof-b
    status: validated
    observed_at: "2026-08-01T00:00:00Z"
`

func TestLoadAllMergesTwoFiles(t *testing.T) {
	dir := t.TempDir()
	pathA := writeLoadAllFixture(t, dir, "a.yml", loadAllContextA)
	pathB := writeLoadAllFixture(t, dir, "b.yml", loadAllContextB)

	ctx, err := LoadAll([]string{pathA, pathB})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(ctx.Guards) != 2 {
		t.Fatalf("got %d guards, want 2: %+v", len(ctx.Guards), ctx.Guards)
	}
	if len(ctx.Proofs) != 2 {
		t.Fatalf("got %d proofs, want 2: %+v", len(ctx.Proofs), ctx.Proofs)
	}
	if len(ctx.Facts) != 1 || ctx.Facts[0].ID != "fact-b" {
		t.Errorf("unexpected facts: %+v", ctx.Facts)
	}
	if len(ctx.Drills) != 1 || ctx.Drills[0].Proof != "proof-b" {
		t.Errorf("unexpected drills: %+v", ctx.Drills)
	}
	if ctx.Origin != pathA+", "+pathB {
		t.Errorf("Origin = %q, want %q", ctx.Origin, pathA+", "+pathB)
	}
	if ctx.Version != 2 {
		t.Errorf("Version = %d, want 2", ctx.Version)
	}
}

func TestLoadAllDuplicateGuardIDErrorsNamingBothPaths(t *testing.T) {
	dir := t.TempDir()
	pathA := writeLoadAllFixture(t, dir, "a.yml", `version: 2
guards:
  - id: shared-guard
    kind: guard
    match: {paths: ["/x"]}
`)
	pathB := writeLoadAllFixture(t, dir, "b.yml", `version: 2
guards:
  - id: shared-guard
    kind: guard
    match: {paths: ["/y"]}
`)

	_, err := LoadAll([]string{pathA, pathB})
	if err == nil {
		t.Fatal("expected an error for a duplicate guard id across files")
	}
	for _, want := range []string{"shared-guard", pathA, pathB} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}

func TestLoadAllDuplicateProofFactDrillIDsError(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name  string
		a, b  string
		match string
	}{
		{"proof", "version: 2\nproofs:\n  - id: p\n    status: observed\n    observed_at: \"2026-08-01T00:00:00Z\"\n",
			"version: 2\nproofs:\n  - id: p\n    status: observed\n    observed_at: \"2026-08-01T00:00:00Z\"\n", "proof"},
		{"fact", "version: 2\nfacts:\n  - id: f\n    statement: x\n", "version: 2\nfacts:\n  - id: f\n    statement: y\n", "fact"},
		{"drill", "version: 2\ndrills:\n  - proof: d\n    artifact: /x\n    recover: \"true\"\n",
			"version: 2\ndrills:\n  - proof: d\n    artifact: /y\n    recover: \"true\"\n", "drill"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pathA := writeLoadAllFixture(t, dir, c.name+"-a.yml", c.a)
			pathB := writeLoadAllFixture(t, dir, c.name+"-b.yml", c.b)
			_, err := LoadAll([]string{pathA, pathB})
			if err == nil {
				t.Fatalf("expected a duplicate %s id error", c.name)
			}
			if !strings.Contains(err.Error(), c.match) {
				t.Errorf("error %q does not name the %s kind", err.Error(), c.match)
			}
		})
	}
}

func TestLoadAllSinglePathEqualsLoad(t *testing.T) {
	dir := t.TempDir()
	path := writeLoadAllFixture(t, dir, "solo.yml", loadAllContextA)

	viaLoadAll, err := LoadAll([]string{path})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	viaLoad, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(viaLoadAll, viaLoad) {
		t.Errorf("LoadAll([]string{path}) = %+v, want identical to Load(path) = %+v", viaLoadAll, viaLoad)
	}
}

func TestLoadAllPropagatesLoadError(t *testing.T) {
	if _, err := LoadAll([]string{"/nonexistent/a.yml", "/nonexistent/b.yml"}); err == nil {
		t.Fatal("expected an error for an unreadable path")
	}
}

func TestLoadAllEmptyPathsErrors(t *testing.T) {
	if _, err := LoadAll(nil); err == nil {
		t.Fatal("expected an error for zero paths")
	}
}
