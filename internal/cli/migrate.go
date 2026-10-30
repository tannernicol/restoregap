// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/discovery"
	"github.com/tannernicol/restoregap/internal/migrate"
)

// newMigrateCmd builds `restoregap migrate`: upgrade every discovered
// context file to the schema version this binary understands, chaining
// per-version transforms (docs/SCHEMA.md §Versioning policy) and writing a
// `.bak.<UTC>` of each file's original bytes before touching it. Discovery
// here is discovery.CandidatePaths, not the usual discoverContextPaths —
// migrate's whole reason to exist is to fix the files ordinary discovery
// silently skips (a v1 document, or one newer than this binary reads).
func newMigrateCmd() *cobra.Command {
	var dryRun bool
	var contextPaths []string
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Upgrade context file(s) to the current schema version (writes a .bak.<UTC> first)",
		Long: "Reads each discovered context file's `version:` field and, if it is older than this\n" +
			"binary's current schema, upgrades it hop by hop (v1 -> v2 -> ...) to the current one,\n" +
			"writing a timestamped backup of the original bytes before the file itself changes.\n" +
			"A file already at the current version is left untouched. A file declaring a version\n" +
			"NEWER than this binary understands is refused outright — same one-line, exit-2 refusal\n" +
			"every other command gives for that case; the fix is to upgrade the restoregap binary,\n" +
			"not to run migrate. --dry-run performs every read/transform step but writes nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths := contextPaths
			if len(paths) == 0 {
				paths = discovery.CandidatePaths()
			}
			if len(paths) == 0 {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "migrate: no context file found — pass --context or run `restoregap context init`"}
			}
			return runMigrate(cmd, paths, dryRun)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would change without writing anything")
	cmd.Flags().StringArrayVar(&contextPaths, "context", nil, "context file(s) to migrate (default: every discovered file, including ones ordinary discovery cannot load yet)")
	return cmd
}

// runMigrate migrates each path in turn, printing one summary line per
// file, and stops at the first hard failure (e.g. a newer-than-understood
// version) rather than migrating some files and silently skipping others.
func runMigrate(cmd *cobra.Command, paths []string, dryRun bool) error {
	out := cmd.OutOrStdout()
	for _, p := range paths {
		res, err := migrate.File(p, dryRun)
		if err != nil {
			cmd.SilenceUsage = true
			return err
		}
		printMigrateResult(out, res)
	}
	return nil
}

func printMigrateResult(out io.Writer, res migrate.Result) {
	if !res.Changed {
		_, _ = fmt.Fprintf(out, "%s: already version %d — nothing to do\n", res.Path, res.FromVersion)
		return
	}
	if res.DryRun {
		_, _ = fmt.Fprintf(out, "%s: would upgrade version %d -> %d\n", res.Path, res.FromVersion, res.ToVersion)
		return
	}
	_, _ = fmt.Fprintf(out, "%s: upgraded version %d -> %d (backup: %s)\n", res.Path, res.FromVersion, res.ToVersion, res.BackupPath)
}

func init() { extraCommands = append(extraCommands, newMigrateCmd) }
