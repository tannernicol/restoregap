// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/globmatch"
)

// ownerEnv lets the human who declared the lifelines edit them. An agent must
// never set it: that is the whole point of the check.
const ownerEnv = "RESTOREGAP_OWNER"

// newProtectCheckCmd builds `restoregap protect-check`.
//
// The gap it closes: every other gate here asks "is this change safe given the
// declared lifelines?" — and answers using declarations the same change is
// free to rewrite. An agent that deletes a backup and, in the same commit,
// deletes the guard that declared it, passes every check by construction.
// protect-check reads the declarations at the BASE ref and enforces them
// against the diff, so the rules a change is graded by are the rules that
// existed before it.
func newProtectCheckCmd() *cobra.Command {
	var base, dir string
	var contexts []string

	cmd := &cobra.Command{
		Use:    "protect-check",
		Hidden: true,
		Short:  "Refuse a diff that edits or un-declares the lifelines it will be graded by",
		Long: "Reads the declared lifelines as they exist at --base, then fails if the diff\n" +
			"base..HEAD removes a lifeline declaration or edits a file one of them protects.\n\n" +
			"Exit 0 when the diff leaves the declarations intact, 1 when it does not, 2 on error.\n" +
			"Set " + ownerEnv + "=1 to override — that is the owner's decision to move the bar,\n" +
			"and it is deliberately not something a delegated worker can do for itself.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if base == "" {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "protect-check: --base <ref> is required"}
			}
			if dir == "" {
				dir = "."
			}
			out := cmd.OutOrStdout()
			if os.Getenv(ownerEnv) == "1" {
				_, _ = fmt.Fprintf(out, "protect-check: %s=1 — owner override, not checking\n", ownerEnv)
				return nil
			}

			paths := discoverContextPaths(cmd, contexts)
			if len(paths) == 0 {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "protect-check: no context file found — run `restoregap context init` or pass --context"}
			}
			baseCtx, err := contextAtRef(dir, base, paths)
			if err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "protect-check: " + err.Error()}
			}
			headCtx, err := contextspec.LoadAll(paths)
			if err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "protect-check: reading current context: " + err.Error()}
			}
			changed, err := changedFiles(dir, base)
			if err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "protect-check: " + err.Error()}
			}

			findings := protectFindings(baseCtx, headCtx, paths, changed, dir)
			if len(findings) == 0 {
				_, _ = fmt.Fprintf(out, "protect-check: OK — %d changed file(s), declarations intact\n", len(changed))
				return nil
			}
			cmd.SilenceUsage = true
			var b strings.Builder
			fmt.Fprintf(&b, "protect-check: BLOCKED — this diff changes what it would be graded by (set %s=1 to override as the owner):", ownerEnv)
			for _, f := range findings {
				b.WriteString("\n  " + f)
			}
			return &ExitError{Code: 1, Message: b.String()}
		},
	}
	cmd.Flags().StringVar(&base, "base", "", "git ref the diff starts from (the declarations at this ref are the ones enforced)")
	cmd.Flags().StringVar(&dir, "dir", "", "repository to inspect (default: current directory)")
	cmd.Flags().StringArrayVar(&contexts, "context", nil, "context file(s) declaring the lifelines (default: discovered)")
	return cmd
}

// protectFindings is the whole judgement, kept pure so the tests state the
// rule rather than drive a git fixture for every case.
func protectFindings(baseCtx, headCtx contextspec.Context, contextPaths, changed []string, dir string) []string {
	findings := droppedLifelines(baseCtx, headCtx)
	protectedFiles := declarationFiles(contextPaths, dir)
	patterns := lifelinePatterns(baseCtx)

	for _, rel := range changed {
		clean := filepath.Clean(rel)
		if protectedFiles[clean] {
			findings = append(findings, fmt.Sprintf("%s is a lifeline declaration — edit it as the owner, not as part of the work it governs", rel))
			continue
		}
		abs := filepath.Clean(filepath.Join(dir, rel))
		if globmatch.MatchPathAny(patterns, abs) || globmatch.MatchPathAny(patterns, clean) {
			findings = append(findings, fmt.Sprintf("%s is protected by a declared lifeline", rel))
		}
	}
	return findings
}

// droppedLifelines names lifelines that existed at the base ref and are gone
// at HEAD: un-declaring one is not a code change.
func droppedLifelines(baseCtx, headCtx contextspec.Context) []string {
	head := make(map[string]bool, len(headCtx.Guards))
	for _, g := range headCtx.Guards {
		head[g.ID] = true
	}
	var dropped []string
	for _, g := range baseCtx.Guards {
		if g.Kind == contextspec.GuardKindLifeline && !head[g.ID] {
			dropped = append(dropped, g.ID)
		}
	}
	sort.Strings(dropped)
	out := make([]string, 0, len(dropped))
	for _, id := range dropped {
		out = append(out, fmt.Sprintf("lifeline %q was declared at the base ref and is gone at HEAD — un-declaring a lifeline is not a code change", id))
	}
	return out
}

// declarationFiles is the set of context files, repo-relative and absolute,
// since a diff names paths relative to the repo root.
func declarationFiles(contextPaths []string, dir string) map[string]bool {
	out := make(map[string]bool, len(contextPaths)*2)
	for _, p := range contextPaths {
		if rel, err := filepath.Rel(dir, p); err == nil && !strings.HasPrefix(rel, "..") {
			out[filepath.Clean(rel)] = true
		}
		out[filepath.Clean(p)] = true
	}
	return out
}

// lifelinePatterns collects every path a declared lifeline covers: what it
// matches, its recovery copy, and its alternates.
func lifelinePatterns(baseCtx contextspec.Context) []string {
	var patterns []string
	for _, g := range baseCtx.Guards {
		if g.Kind != contextspec.GuardKindLifeline {
			continue
		}
		patterns = append(patterns, g.Match.Paths...)
		if g.RecoveryCopy != "" {
			patterns = append(patterns, g.RecoveryCopy)
		}
		patterns = append(patterns, g.AlternatePaths...)
	}
	return patterns
}

// contextAtRef materialises the context files as they exist at ref, so the
// declarations being enforced are the ones the change did not get to write.
func contextAtRef(dir, ref string, paths []string) (contextspec.Context, error) {
	tmp, err := os.MkdirTemp("", "restoregap-protect-")
	if err != nil {
		return contextspec.Context{}, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	var materialised []string
	for _, p := range paths {
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil || strings.HasPrefix(rel, "..") {
			// A context file outside the repo cannot have been rewritten by
			// this diff; read it as it is.
			materialised = append(materialised, p)
			continue
		}
		blob, gerr := gitShow(dir, ref, rel)
		if gerr != nil {
			// Absent at base = newly added by this diff; nothing to enforce.
			continue
		}
		dst := filepath.Join(tmp, filepath.Base(rel))
		if werr := os.WriteFile(dst, blob, 0o600); werr != nil {
			return contextspec.Context{}, werr
		}
		materialised = append(materialised, dst)
	}
	if len(materialised) == 0 {
		return contextspec.Context{}, nil
	}
	return contextspec.LoadAll(materialised)
}

// scrubbedGitEnv strips GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE from the
// inherited environment before a `git -C <dir>` call: those variables beat
// -C, so a protect-check run invoked from inside a git hook (the pre-push
// gate runs `go test` there) would otherwise silently operate on the outer
// repo instead of dir. Setting them to "" would not unset them for git — an
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

func gitShow(dir, ref, rel string) ([]byte, error) {
	cmd := exec.Command("git", "-C", dir, "show", ref+":"+rel) //nolint:gosec // fixed git invocation
	cmd.Env = scrubbedGitEnv()
	return cmd.Output()
}

func changedFiles(dir, base string) ([]string, error) {
	cmd := exec.Command("git", "-C", dir, "diff", "--name-only", base, "HEAD") //nolint:gosec // fixed git invocation
	cmd.Env = scrubbedGitEnv()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only %s HEAD: %w", base, err)
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}
