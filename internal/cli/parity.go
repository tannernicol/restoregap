// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/preflight"
)

// newParityDrillCmd builds `restoregap parity-drill`.
//
// RestoreGap is reachable through two seams: an agent DECLARES what it is
// about to do (intent), or a change is read from a git DIFF. They are meant to
// be the same gate. Nothing proved they agreed — and a gate that answers
// differently depending on how it was called is not one gate, it is two
// policies with one name. Money spent a day red for the same shape one level
// up: the pre-push hook and CI ran different checks.
//
// parity-drill constructs the same change both ways and asserts the verdicts
// match. It uses --plan, so it never writes to the ledger: a rehearsal must
// not look like a decision.
func newParityDrillCmd() *cobra.Command {
	var dir, target string
	var contexts []string

	cmd := &cobra.Command{
		Use:    "parity-drill",
		Hidden: true,
		Short:  "Prove the intent seam and the diff seam reach the same verdict",
		Long: "Builds one change two ways — as a declared intent and as a unified diff — and\n" +
			"fails if the two verdicts differ. Runs with --plan: nothing is recorded.\n\n" +
			"Exit 0 when the seams agree, 1 when they do not, 2 on error.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dir == "" {
				dir = "."
			}
			if target == "" {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "parity-drill: --target <path> is required (the file the rehearsed change would delete)"}
			}
			paths := discoverContextPaths(cmd, contexts)

			tmp, err := os.MkdirTemp("", "restoregap-parity-")
			if err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: err.Error()}
			}
			defer func() { _ = os.RemoveAll(tmp) }()

			intentPath := filepath.Join(tmp, "intent.yml")
			if err := os.WriteFile(intentPath, []byte(parityIntent(target)), 0o600); err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: err.Error()}
			}
			diffPath := filepath.Join(tmp, "change.diff")
			if err := os.WriteFile(diffPath, []byte(parityDiff(target)), 0o600); err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: err.Error()}
			}

			intentVerdict, err := planVerdict(cmd.Context(), preflight.Request{
				IntentPath: intentPath, ContextPaths: paths, Format: "json", Plan: true, Actor: "parity-drill",
			})
			if err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "parity-drill (intent seam): " + err.Error()}
			}
			diffVerdict, err := planVerdict(cmd.Context(), preflight.Request{
				DiffPath: diffPath, DiffRoot: dir, ContextPaths: paths, Format: "json", Plan: true, Actor: "parity-drill",
			})
			if err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "parity-drill (diff seam): " + err.Error()}
			}

			out := cmd.OutOrStdout()
			if intentVerdict == diffVerdict {
				_, _ = fmt.Fprintf(out, "parity-drill: OK — both seams say %q for %s\n", intentVerdict, target)
				return nil
			}
			cmd.SilenceUsage = true
			return &ExitError{Code: 1, Message: fmt.Sprintf(
				"parity-drill: SEAMS DISAGREE for %s — intent seam says %q, diff seam says %q.\n"+
					"One gate with two answers is two policies sharing a name; fix the seam, do not pick a winner.",
				target, intentVerdict, diffVerdict)}
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "repository root the diff is relative to (default: current directory)")
	cmd.Flags().StringVar(&target, "target", "", "path the rehearsed change would delete")
	cmd.Flags().StringArrayVar(&contexts, "context", nil, "context file(s) (default: discovered)")
	return cmd
}

// planVerdict runs one preflight in plan mode and extracts its verdict.
func planVerdict(ctx context.Context, req preflight.Request) (string, error) {
	res, err := preflight.Run(ctx, req)
	if err != nil {
		return "", err
	}
	var decoded struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(res.Rendered, &decoded); err != nil {
		return "", fmt.Errorf("decoding plan output: %w", err)
	}
	if decoded.Verdict == "" {
		return "", fmt.Errorf("plan output carried no verdict")
	}
	return decoded.Verdict, nil
}

// parityIntent is the declared form of "delete this path".
func parityIntent(target string) string {
	return strings.Join([]string{
		"version: 2",
		"action: delete_file",
		"actor: parity-drill",
		"context_window: parity-drill",
		"paths:",
		"  - " + target,
		"command: rm -f " + target,
		"description: parity rehearsal — declared intent form",
		"",
	}, "\n")
}

// parityDiff is the same change expressed as a unified diff that removes the
// file, so the diff seam sees the identical path.
func parityDiff(target string) string {
	return strings.Join([]string{
		"diff --git a/" + target + " b/" + target,
		"deleted file mode 100644",
		"--- a/" + target,
		"+++ /dev/null",
		"@@ -1 +0,0 @@",
		"-parity rehearsal",
		"",
	}, "\n")
}
