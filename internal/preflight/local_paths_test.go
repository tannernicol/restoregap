// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package preflight

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/intent"
)

func TestResolveLocalPathResolvesSymlinkParentOfMissingChild(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveLocalPath(filepath.Join(alias, "new", "child.db"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(real, "new", "child.db")
	if got != want {
		t.Fatalf("ResolveLocalPath = %q, want %q", got, want)
	}
}

func TestLocalPathAliasesResolvesGlobPrefixHomeRelativeAndDeduplicates(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(filepath.Join(home, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Chdir(dir)
	raw := filepath.Join(dir, "alias", "data", "**")
	ctx := contextspec.Context{Guards: []contextspec.Guard{{Match: contextspec.Matcher{Paths: []string{raw, raw, "~/data/**", "relative/**"}}}}, Proofs: []contextspec.Proof{{Dependencies: &contextspec.Dependencies{Paths: []string{raw}}}}}
	aliases, err := localPathAliases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := aliases[raw]; got != filepath.Join(dir, "real", "data", "**") {
		t.Fatalf("glob alias = %q", got)
	}
	if got := aliases["~/data/**"]; got != filepath.Join(home, "data", "**") {
		t.Fatalf("home alias = %q", got)
	}
	if got := aliases["relative/**"]; got != filepath.Join(dir, "relative", "**") {
		t.Fatalf("relative alias = %q", got)
	}
	if len(aliases) != 3 {
		t.Fatalf("aliases = %#v, want three unique raw paths", aliases)
	}
}

func TestResolveLocalPathRejectsSymlinkLoop(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	_, err = ResolveLocalPath(a)
	// Go's filepath.EvalSymlinks on Linux currently flattens ELOOP to this
	// message; retain the errno assertion for platforms that preserve it.
	if err == nil || (!errors.Is(err, syscall.ELOOP) && err.Error() != "EvalSymlinks: too many links") {
		t.Fatalf("ResolveLocalPath loop error = %v, want ELOOP", err)
	}
}

func TestRunResolveLocalPathsRetainsInaccessiblePolicyPath(t *testing.T) {
	dir := t.TempDir()
	blockedDir := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blockedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	blockedPath := filepath.Join(blockedDir, "zones", "*.xml")
	if err := os.Chmod(blockedDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blockedDir, 0o700) })
	if _, err := ResolveLocalPath(blockedPath); err == nil {
		t.Skip("test user can resolve paths beneath chmod 000 directories")
	}

	guarded := filepath.Join(dir, "guarded")
	contextPath := writeTemp(t, "context.yml", "version: 2\nguards:\n  - id: inaccessible-policy\n    kind: lifeline\n    enforcement: block\n    match: {paths: [\""+blockedPath+"\"], actions: [modify_file]}\n  - id: guarded\n    kind: lifeline\n    enforcement: block\n    match: {paths: [\""+guarded+"\"], actions: [modify_file]}\n")

	for _, tc := range []struct {
		name string
		path string
		want int
	}{
		{name: "unrelated benign edit is decided", path: filepath.Join(dir, "benign"), want: 0},
		{name: "guarded edit is denied", path: guarded, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Run(context.Background(), Request{
				Format:            "json",
				Intents:           []intent.ChangeIntent{{Action: intent.ActionModifyFile, Paths: []string{tc.path}}},
				ContextPaths:      []string{contextPath},
				ResolveLocalPaths: true,
				Plan:              true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.ExitCode != tc.want {
				t.Fatalf("exit = %d, want %d: %s", result.ExitCode, tc.want, result.Rendered)
			}
		})
	}
}
