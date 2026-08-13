package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/preflight"
)

// newPreflightCmd defines the frozen preflight flag surface. Every flag here is
// load-bearing for external callers (git hooks, ~/bin guarded-update wrappers,
// MCP); see docs/ARCHITECTURE.md §compatibility before touching.
func newPreflightCmd() *cobra.Command {
	req := preflight.Request{}
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Gate a proposed change on declared recovery invariants and proofs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := preflight.Run(cmd.Context(), req)
			if err != nil {
				return err
			}
			if err := writeResult(cmd, req.OutPath, result); err != nil {
				return err
			}
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
	f.StringVar(&req.ContextPath, "context", "", "path to restoregap.yml / restoregap.local.yml")
	f.StringVar(&req.LedgerPath, "ledger", "", "path to the append-only decision ledger (JSONL)")
	f.StringVar(&req.Actor, "actor", "", "acting identity, e.g. agent/claude")
	f.StringVar(&req.IntentActor, "intent-actor", "", "actor recorded inside the intent, if different")
	f.StringVar(&req.ContextWindow, "context-window", "", "execution context, e.g. git-commit, coding-agent")
	f.StringVar(&req.CommitSHA, "commit-sha", "", "git commit associated with this change")
	f.StringVar(&req.Format, "format", "md", "output format: json, md, or html")
	f.StringVar(&req.OutPath, "out", "", "write the report to this path (- for stdout)")
	f.BoolVar(&req.FailOnWarn, "fail-on-warn", false, "exit non-zero on warnings, not just blocks")
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
