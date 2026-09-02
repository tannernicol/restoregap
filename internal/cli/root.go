// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package cli builds the restoregap command tree. It maps flags to request
// structs and dispatches to internal packages — no business logic lives here.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ExitError carries an explicit process exit code through the command tree.
// Contract (frozen, shared with the Python implementation and its callers):
// 0 = pass, 1 = block / --fail-on-warn warning, 2 = usage or internal error.
type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string { return e.Message }

// Version is stamped at build time via -ldflags.
var Version = "0.0.0-dev"

// extraCommands lets command files self-register from init() so adding a
// command never edits this file (parallel-work friendly).
var extraCommands []func() *cobra.Command

// Execute runs the CLI with the given arguments.
func Execute(args []string) error {
	root := &cobra.Command{
		Use:           "restoregap",
		Short:         "Prove your recovery works — then refuse the risky change until it does",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().Bool("verbose", false, "print full discovered-context file lists instead of a summary (status, preflight)")
	root.SetArgs(args)
	root.AddCommand(newPreflightCmd(), newStatusCmd(), newLedgerCmd(), newMCPCmd(),
		newEvidenceCmd(), newContextCmd(), newProtectCheckCmd(),
		newDoraCmd(), newParityDrillCmd())
	for _, build := range extraCommands {
		root.AddCommand(build())
	}
	root.RunE = func(cmd *cobra.Command, _ []string) error {
		// No-args landing: the ladder, in the order a stranger should climb it.
		// check comes first deliberately — it needs no config and finds something
		// real on the first run, which is the whole on-ramp. preflight is the
		// destination, not the entry point.
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "restoregap — prove your recovery works, then refuse the change that would break it")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Start here:")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  restoregap check <live> <recovery-copy>  # what is in one and not the other (no config)")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  restoregap drill --context <file>        # prove a recovery for real, in a sandbox")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  restoregap preflight --help              # gate a risky change on that proof")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  restoregap status                        # unified recovery-chain view")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "preflight decides whether a guarded change is allowed — pair it with your agent's own deny rules or sandbox as the net")
		return nil
	}
	return root.Execute()
}
