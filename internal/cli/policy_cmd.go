// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/policy"
)

// newPolicyCmd builds `restoregap policy`: print the current policy
// revision — sha256 over the sorted (path, sha256) list of every context
// file in force — plus the file list itself. The same revision is stamped
// onto every decision/drill/accept ledger entry, so `policy` answers "what
// revision would a verdict made right now carry" and lets an old entry's
// stamp be compared against the present.
func newPolicyCmd() *cobra.Command {
	var contextPaths []string
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Print the current policy revision and the context files it hashes",
		Long: "The policy revision is sha256 over the sorted (path, sha256) list of every context file in\n" +
			"force — order-independent (the same set in any order is the same revision), but any edit to\n" +
			"any file flips it. Every decision/drill/accept ledger entry records the revision it was\n" +
			"decided under (and `status --last` / `restoregap explain` print it), so a years-old verdict\n" +
			"can always be traced back to the exact policy text it was made under. Context discovery is\n" +
			"the same as `restoregap status`: " + contextDiscoveryHelp + ".",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths := discoverContextPaths(cmd, contextPaths)
			if len(paths) == 0 {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no context files discovered — the built-in default policy is in force (no revision)")
				return nil
			}
			rev, files, err := policy.Revision(paths)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "revision %s over %d file(s):\n", rev, len(files))
			for _, f := range files {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s  sha256:%s\n", f.Path, f.SHA256)
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&contextPaths, "context", nil,
		"path to restoregap.yml / restoregap.local.yml; "+contextDiscoveryHelpRepeatable+
			" (when omitted entirely: "+contextDiscoveryHelp+")")
	return cmd
}

func init() { extraCommands = append(extraCommands, newPolicyCmd) }
