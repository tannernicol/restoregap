// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/preflight"
)

// isTTYStdout reports whether w is an interactive terminal. It is a seam
// over isatty so tests can force TTY behavior without a real terminal —
// cmd.OutOrStdout() in tests is a bytes.Buffer, which is correctly never a
// TTY, so most tests get the non-TTY path for free; forcing the TTY path
// means overriding this var directly.
var isTTYStdout = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && isatty.IsTerminal(f.Fd())
}

// newPreflightCmd defines the frozen preflight flag surface. Every flag here is
// load-bearing for external callers (git hooks, ~/bin guarded-update wrappers,
// MCP); see docs/ARCHITECTURE.md §compatibility before touching.
func newPreflightCmd() *cobra.Command {
	req := preflight.Request{}
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Gate a proposed change on declared recovery invariants and proofs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			req.ToolVersion = Version
			// discoverContextPaths leaves req.ContextPaths (nil from the
			// flag, unless --context was passed at least once) nil when
			// nothing is discoverable — preflight.Run already treats that as
			// "use the built-in zero-config default policy", so no extra
			// fallback logic is needed here.
			req.ContextPaths = discoverContextPaths(cmd, req.ContextPaths)

			// --format defaults to "auto": a human at an interactive
			// terminal did not ask for markdown source, so auto renders
			// plain text there; piped/redirected/CI output (agents, MCP,
			// scripts) keeps the existing markdown rendering so nothing
			// that parses this output today breaks. "markdown" is accepted
			// as an explicit alias for the internal "md" format value;
			// json/html/md pass through unchanged for callers already
			// pinning one of those.
			switch req.Format {
			case "auto":
				if isTTYStdout(cmd.OutOrStdout()) {
					req.Format = "text"
				} else {
					req.Format = "md"
				}
			case "markdown":
				req.Format = "md"
			}

			ledgerPath, defaulted, err := resolveLedger(req.LedgerPath)
			if err != nil {
				// A ledger path that cannot be prepared makes the gate unable
				// to produce the auditable decision callers rely on. It is a
				// gate-broken condition, not a malformed user intent.
				return &ExitError{Code: 3, Message: "GATE BROKEN: resolve ledger: " + err.Error()}
			}
			req.LedgerPath = ledgerPath

			result, err := preflight.Run(cmd.Context(), req)
			if err != nil {
				return err
			}
			if err := writeResult(cmd, req.OutPath, result); err != nil {
				return err
			}
			// Every preflight run now lands a decision in a ledger — the
			// README's "every decision lands in an append-only,
			// hash-chained ledger" claim, made true instead of aspirational.
			// Printed once to stderr (not into the rendered report body) so
			// the frozen json/md/html report schema stays untouched.
			label := "explicit"
			if defaulted {
				label = "default"
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ledger: %s (%s)\n", req.LedgerPath, label)
			if result.ExitCode != 0 {
				return &ExitError{Code: result.ExitCode}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&req.DiffPath, "diff", "", "path to a unified diff to preflight (- for stdin)")
	f.StringVar(&req.DiffRoot, "diff-root", "", "repo root to resolve repo-relative diff paths against (git emits relative paths; guards are absolute)")
	f.StringVar(&req.IntentPath, "intent", "", "path to an action-intent YAML file")
	f.StringArrayVar(&req.ContextPaths, "context", nil, "path to restoregap.yml / restoregap.local.yml (omit for built-in default policy; "+contextDiscoveryHelpRepeatable+")")
	f.StringVar(&req.LedgerPath, "ledger", "", "path to the append-only decision ledger (JSONL); "+ledgerDiscoveryHelp)
	f.StringVar(&req.Actor, "actor", "", "acting identity, e.g. agent/claude")
	f.StringVar(&req.IntentActor, "intent-actor", "", "actor recorded inside the intent, if different")
	f.StringVar(&req.ContextWindow, "context-window", "", "execution context, e.g. git-commit, coding-agent")
	f.StringVar(&req.CommitSHA, "commit-sha", "", "git commit associated with this change")
	f.StringVar(&req.Format, "format", "auto", "output format: auto (text on a TTY, markdown otherwise), text, markdown, json, or html")
	f.StringVar(&req.OutPath, "out", "", "write the report to this path (- for stdout)")
	f.BoolVar(&req.FailOnWarn, "fail-on-warn", false, "exit non-zero on warnings, not just blocks")
	f.BoolVar(&req.RequireCoverage, "require-coverage", false, "strict mode: every addressed path, target, package, and command must be covered by a matching guard")
	f.BoolVar(&req.Plan, "plan", false, "evaluate without recording — for readiness probes and dry runs; a plan is not a decision")
	f.StringVar(&req.AsOf, "as-of", "", "evaluate proof freshness as of this RFC3339 time instead of now")
	return cmd
}

// writeResult sends the rendered report to outPath, or to cmd's configured
// stdout when outPath is empty or "-".
func writeResult(cmd *cobra.Command, outPath string, result *preflight.Result) error {
	if outPath == "" || outPath == "-" {
		return result.Write(cmd.OutOrStdout())
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return result.Write(f)
}
