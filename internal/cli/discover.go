// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/discover"
	"github.com/tannernicol/restoregap/internal/policy"
)

// newDiscoverCmd builds `restoregap discover`: enumerate recovery
// CANDIDATES on this host (running containers' bind mounts, local
// databases, unbacked git repos, systemd user units with state on disk,
// plus the fixed machine-id/package-manifest/etc-config floor) and diff
// them against the declared context — the denominator `restoregap status`
// never computes. This is purely deterministic enumeration and a diff:
// discover proposes nothing and proves nothing. Only a real `restoregap
// drill` produces a proof; a candidate reads "covered" here solely because
// a declared drill or guard already names its path. See docs/DISCOVER.md.
func newDiscoverCmd() *cobra.Command {
	var contextPaths []string
	var format string
	var all, noSave, trend, prompt bool
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Enumerate recovery candidates on this host and diff them against declared proofs",
		Long: "Deterministic enumeration only — no AI, no network, nothing phoned home. Reports what a\n" +
			"rebuild would need that nothing has necessarily declared: running containers' writable\n" +
			"bind mounts, local databases over 64KiB, git repos with no remote or with commits not on\n" +
			"any remote-tracking branch, systemd user units whose declared state lives under $HOME, and\n" +
			"the fixed machine-id/package-manifest/etc-config floor. A candidate is \"covered\" only when\n" +
			"a declared drill's artifact/recovery_source or a guard's matched path already names it —\n" +
			"discover never marks anything covered itself. Every run is compared against the previous\n" +
			"one (state under --no-save's default location) so new candidates surface on their own;\n" +
			"--no-save skips writing that snapshot. --trend prints the last " +
			fmt.Sprintf("%d", discover.TrendDisplayLimit) + " scans as a compact table instead of scanning again.\n" +
			"--prompt emits a ready-to-hand agent brief instead: header (host, coverage, generated-at,\n" +
			"scope), one bullet per uncovered candidate ranked by consequence, and the fixed rules block\n" +
			"for proposing a drill. Context discovery is the same as `restoregap status`: " + contextDiscoveryHelpRepeatable + ".",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if trend {
				return runDiscoverTrend(cmd)
			}
			paths := discoverContextPaths(cmd, contextPaths)
			ctx, err := loadDiscoverContext(paths)
			if err != nil {
				return err
			}
			report, err := discover.Collect(discover.Options{Context: ctx, NoSave: noSave})
			if err != nil {
				return err
			}
			if prompt {
				_, err := fmt.Fprint(cmd.OutOrStdout(), discover.RenderPrompt(report, all, "all"))
				return err
			}
			return renderDiscoverReport(cmd, report, format, all)
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&contextPaths, "context", nil,
		"path to restoregap.yml / restoregap.local.yml; "+contextDiscoveryHelpRepeatable+
			" (when omitted entirely: "+contextDiscoveryHelp+"; falls back further to the built-in zero-config policy)")
	f.StringVar(&format, "format", "text", "output format: text or json")
	f.BoolVar(&all, "all", false, "also list covered candidates, each with what covered it")
	f.BoolVar(&noSave, "no-save", false, "read-only run: do not write/rotate the snapshot or append to trend history")
	f.BoolVar(&trend, "trend", false, "print the last scans as a compact coverage-trend table instead of scanning")
	f.BoolVar(&prompt, "prompt", false, "emit a ready-to-hand agent brief instead of the plain enumerate/diff output")
	return cmd
}

func init() { extraCommands = append(extraCommands, newDiscoverCmd) }

// loadDiscoverContext loads and merges every declared context path via
// policy.Merge, same as status.Gather's own loadMerged — falling back to
// the built-in zero-config default when no context is discoverable, so
// discover's coverage diff means the same thing status's guard/proof view
// already means.
func loadDiscoverContext(paths []string) (contextspec.Context, error) {
	if len(paths) == 0 {
		return contextspec.Default(), nil
	}
	ctx, _, err := policy.Merge(paths)
	if err != nil {
		return contextspec.Context{}, fmt.Errorf("discover: %w", err)
	}
	return ctx, nil
}

// renderDiscoverReport writes report to cmd's stdout in the requested
// format.
func renderDiscoverReport(cmd *cobra.Command, report *discover.Report, format string, all bool) error {
	out := cmd.OutOrStdout()
	if format == "json" {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(encoded))
		return err
	}
	_, err := out.Write(discover.RenderText(report, all))
	return err
}

// runDiscoverTrend implements `discover --trend`: read scan history from
// the default state dir and print the last discover.TrendDisplayLimit rows
// as a compact table. It never scans.
func runDiscoverTrend(cmd *cobra.Command) error {
	stateDir, err := discover.DefaultStateDir()
	if err != nil {
		return err
	}
	rows, err := discover.ReadHistory(stateDir)
	if err != nil {
		return err
	}
	_, err = cmd.OutOrStdout().Write(discover.RenderTrend(rows, discover.TrendDisplayLimit))
	return err
}
