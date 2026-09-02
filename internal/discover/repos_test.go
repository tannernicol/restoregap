// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// runGitT runs a git command for test setup, failing the test on error.
func runGitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec // test helper, fixed dir
	cmd.Env = scrubbedGitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// initRepo creates a git repo at dir with local (not global) identity
// config, so the test never depends on the host's git config existing.
func initRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	runGitT(t, dir, "init", "-q", "-b", "main")
	runGitT(t, dir, "config", "user.email", "test@example.com")
	runGitT(t, dir, "config", "user.name", "Test")
}

func commitFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	runGitT(t, dir, "add", name)
	runGitT(t, dir, "commit", "-q", "-m", "commit "+name)
}

// TestCollectReposNoRemoteIsCandidate: a repo with no remote at all is
// always unbacked.
func TestCollectReposNoRemoteIsCandidate(t *testing.T) {
	home := t.TempDir()
	repo := filepath.Join(home, "proj")
	initRepo(t, repo)
	commitFile(t, repo, "a.txt", "a")

	got := collectRepos(home)
	if len(got) != 1 || got[0].Path != repo {
		t.Fatalf("collectRepos = %+v; want one candidate at %s", got, repo)
	}
	if got[0].Kind != KindRepo {
		t.Errorf("Kind = %q, want %q", got[0].Kind, KindRepo)
	}
}

// TestCollectReposRemoteNamedGiteaFullyPushedIsNotCandidate is the exact
// regression a real audit hit: a repo whose only remote is named "gitea"
// (not "origin") and is fully pushed must NOT be reported as unbacked.
func TestCollectReposRemoteNamedGiteaFullyPushedIsNotCandidate(t *testing.T) {
	home := t.TempDir()
	bareRemote := filepath.Join(home, "remote.git")
	runGitT(t, home, "init", "-q", "--bare", "-b", "main", bareRemote)

	repo := filepath.Join(home, "proj")
	initRepo(t, repo)
	commitFile(t, repo, "a.txt", "a")
	runGitT(t, repo, "remote", "add", "gitea", bareRemote)
	runGitT(t, repo, "push", "-q", "gitea", "main")

	got := collectRepos(home)
	for _, c := range got {
		if c.Path == repo {
			t.Fatalf("repo fully pushed to a non-origin remote %q was still reported as a candidate: %+v", "gitea", c)
		}
	}
}

// TestCollectReposRemoteNamedGiteaWithUnpushedCommitIsCandidate: same setup
// as above, but with one commit made after the push — the repo IS unbacked
// again, and must be reported even though its remote is not "origin".
func TestCollectReposRemoteNamedGiteaWithUnpushedCommitIsCandidate(t *testing.T) {
	home := t.TempDir()
	bareRemote := filepath.Join(home, "remote.git")
	runGitT(t, home, "init", "-q", "--bare", "-b", "main", bareRemote)

	repo := filepath.Join(home, "proj")
	initRepo(t, repo)
	commitFile(t, repo, "a.txt", "a")
	runGitT(t, repo, "remote", "add", "gitea", bareRemote)
	runGitT(t, repo, "push", "-q", "gitea", "main")
	commitFile(t, repo, "b.txt", "b") // unpushed

	got := collectRepos(home)
	var found bool
	for _, c := range got {
		if c.Path == repo {
			found = true
		}
	}
	if !found {
		t.Fatalf("collectRepos = %+v; want a candidate for %s (unpushed commit on top of a gitea-only remote)", got, repo)
	}
}

// TestCollectReposSkipsGitInternals: the walk must not descend into a
// repo's own .git/objects tree looking for nested repos.
func TestCollectReposSkipsGitInternals(t *testing.T) {
	home := t.TempDir()
	repo := filepath.Join(home, "proj")
	initRepo(t, repo)
	commitFile(t, repo, "a.txt", "a")

	got := collectRepos(home)
	if len(got) != 1 {
		t.Fatalf("collectRepos = %+v; want exactly one candidate (no duplicates from walking .git internals)", got)
	}
}

// TestScrubbedGitEnvStripsGitVars ensures the pre-push-hook safety net
// actually removes the three variables, never merely blanking them (an
// empty value still counts as set for git).
func TestScrubbedGitEnvStripsGitVars(t *testing.T) {
	t.Setenv("GIT_DIR", "/somewhere/.git")
	t.Setenv("GIT_WORK_TREE", "/somewhere")
	t.Setenv("GIT_INDEX_FILE", "/somewhere/.git/index")
	env := scrubbedGitEnv()
	for _, kv := range env {
		for _, bad := range []string{"GIT_DIR=", "GIT_WORK_TREE=", "GIT_INDEX_FILE="} {
			if len(kv) >= len(bad) && kv[:len(bad)] == bad {
				t.Errorf("scrubbedGitEnv() leaked %q", kv)
			}
		}
	}
}
