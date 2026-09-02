// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// repoMaxDepth bounds the $HOME walk repos collect against. Depth is
// measured to the ".git" directory itself, so a repo at ~/a/b/.git is
// depth 3.
const repoMaxDepth = 3

// runGit and runGitRemote are function variables so tests can override
// them; production always shells out to the real git binary.
var runGit = func(dir string, args ...string) ([]byte, error) {
	//nolint:gosec // fixed git invocation, dir is a discovered filesystem path
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = scrubbedGitEnv()
	return cmd.Output()
}

// scrubbedGitEnv strips GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE from the
// inherited environment before a `git -C <dir>` call. Those variables beat
// -C, so a discover run invoked from inside a git hook (the pre-push gate
// runs `go test` there) would otherwise silently operate on the outer repo
// instead of dir. Setting them to "" would not unset them for git — an
// empty value is still a value — so the entries must be absent entirely.
func scrubbedGitEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		switch {
		case strings.HasPrefix(kv, "GIT_DIR="),
			strings.HasPrefix(kv, "GIT_WORK_TREE="),
			strings.HasPrefix(kv, "GIT_INDEX_FILE="):
			continue
		}
		env = append(env, kv)
	}
	return env
}

// collectRepos walks home (bounded depth repoMaxDepth, skipping
// skipDirNames) for ".git" directories and reports one candidate for each
// repo that has NO remote at all, or has commits not present on any
// remote-tracking branch (across every declared remote — a repo whose only
// remote happens to be named something other than "origin" is not
// unbacked just because it lacks that one name). A repo whose git commands
// fail (corrupt, mid-operation, permission denied) is skipped rather than
// reported or aborting the walk — this is a best-effort survey.
func collectRepos(home string) []Candidate {
	var out []Candidate
	walkBounded(home, repoMaxDepth, func(path string, d fs.DirEntry) {
		if !d.IsDir() || d.Name() != ".git" {
			return
		}
		repoRoot := filepath.Dir(path)
		if c, ok := repoCandidate(repoRoot); ok {
			out = append(out, c)
		}
	})
	return out
}

// repoCandidate reports repoRoot as a candidate, and true, when it has no
// remote or carries commits unreachable from every remote-tracking branch.
// It reports false (no candidate) both when the repo is fully backed by a
// remote and when its git commands could not be run at all.
func repoCandidate(repoRoot string) (Candidate, bool) {
	remoteOut, err := runGit(repoRoot, "remote")
	if err != nil {
		return Candidate{}, false
	}
	if strings.TrimSpace(string(remoteOut)) == "" {
		return newRepoCandidate(repoRoot), true
	}
	// `rev-list --branches --not --remotes` lists commits reachable from any
	// local branch that are NOT reachable from any remote-tracking branch,
	// across every remote in one shot — the fix for the real audit that
	// falsely flagged ~47 repos whose remote was named "gitea" rather than
	// "origin".
	unpushed, err := runGit(repoRoot, "rev-list", "--branches", "--not", "--remotes")
	if err != nil {
		return Candidate{}, false
	}
	if strings.TrimSpace(string(unpushed)) == "" {
		return Candidate{}, false
	}
	return newRepoCandidate(repoRoot), true
}

// newRepoCandidate builds the Candidate for an unbacked repo at repoRoot.
func newRepoCandidate(repoRoot string) Candidate {
	return Candidate{
		Kind: KindRepo, Name: filepath.Base(repoRoot), Path: repoRoot,
		SizeBytes: dirEntrySize(repoRoot), Weight: weightFor(KindRepo),
	}
}

// dirEntrySize is a best-effort top-level stat: repos can be arbitrarily
// large, so this reports 0 rather than paying for a recursive walk just to
// print a byte count.
func dirEntrySize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return 0
	}
	return info.Size()
}
