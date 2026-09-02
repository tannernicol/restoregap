// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/bundle"
	"github.com/tannernicol/restoregap/internal/status"
)

// newBundleCmd builds `restoregap bundle`: export/verify/inspect the
// portable signed bundle (docs/SCHEMA.md §Portable signed bundle) — one
// host's context files, a bounded ledger slice, and proof-evidence
// metadata, detached-signed, that another host, a share, or `bundle merge`
// (fleet aggregation) can consume without ever running restoregap against
// the original host's live state.
func newBundleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "bundle", Short: "Export, verify, inspect, and merge portable signed bundles"}
	cmd.AddCommand(newBundleExportCmd(), newBundleVerifyCmd(), newBundleInspectCmd(), newBundleMergeCmd())
	return cmd
}

// newBundleMergeCmd builds `restoregap bundle merge`: offline fleet
// aggregation (docs/SCHEMA.md §Offline fleet merge) — verify every given
// bundle, merge their proofs keyed by (guard id, environment, system,
// host), and write the result as fleet.json (machine-readable) and
// fleet.html (a self-contained dashboard) into --out. `restoregap status
// --fleet <dir>` renders the same merged tree in a terminal.
func newBundleMergeCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "merge <bundle.tgz> [bundle.tgz...]",
		Short: "Merge several verified bundles into one fleet view (fleet.json + fleet.html)",
		Long: "Verifies every given bundle first (the same check `bundle verify` runs — an unverifiable\n" +
			"bundle aborts the whole merge rather than silently ingesting untrusted data), then merges\n" +
			"their proofs keyed by (guard id, environment, system, host): a later bundle's generated_at\n" +
			"wins a key collision, and every collision is reported, never silently dropped. Writes\n" +
			"fleet.json (every merged proof: full scope, host, epoch, layer, category, state) and a\n" +
			"self-contained, dark fleet.html dashboard into --out.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fleet, err := status.MergeBundles(args)
			if err != nil {
				cmd.SilenceUsage = true
				return err
			}
			outDir := out
			if outDir == "" {
				outDir = "restoregap-fleet-" + time.Now().UTC().Format("20060102T150405Z")
			}
			jsonPath, htmlPath, err := status.WriteFleet(fleet, outDir)
			if err != nil {
				cmd.SilenceUsage = true
				return err
			}
			printBundleMergeSummary(cmd, fleet, jsonPath, htmlPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "output directory for fleet.json/fleet.html (default: restoregap-fleet-<UTC timestamp>)")
	return cmd
}

// printBundleMergeSummary prints `bundle merge`'s result: counts, the two
// written paths, and every reported merge-key conflict.
func printBundleMergeSummary(cmd *cobra.Command, fleet status.Fleet, jsonPath, htmlPath string) {
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "merged %d bundle(s), %d proof(s)", len(fleet.Bundles), len(fleet.Proofs))
	if len(fleet.Conflicts) > 0 {
		_, _ = fmt.Fprintf(out, ", %d conflict(s)", len(fleet.Conflicts))
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "wrote %s\n", jsonPath)
	_, _ = fmt.Fprintf(out, "wrote %s\n", htmlPath)
	for _, c := range fleet.Conflicts {
		_, _ = fmt.Fprintf(out, "conflict: %s — kept %s over %s (%s)\n", c.Key, c.KeptBundle, c.DroppedBundle, c.Reason)
	}
}

func newBundleExportCmd() *cobra.Command {
	var out, since, env, system, host, signingKey, ledgerPath string
	var contextPaths []string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export a signed bundle: context files, a bounded ledger slice, and proof-evidence metadata",
		Long: "Writes a single tar.gz containing manifest.json (host/epoch/policy revision/counts),\n" +
			"the context files in force, a ledger slice (--since bounds it, e.g. 30d), proof-evidence\n" +
			"METADATA only (never a file's contents, and never a path under a secret store), and a\n" +
			"detached Ed25519 signature over the manifest — the same key material `restoregap drill\n" +
			"--signing-key` uses. Context discovery is the same as `restoregap status`: " + contextDiscoveryHelpRepeatable + ".",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths := discoverContextPaths(cmd, contextPaths)
			if len(paths) == 0 {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "bundle export: no context file found — pass --context or run `restoregap context init`"}
			}
			sinceDur, err := parseSince(since)
			if err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "bundle export: " + err.Error()}
			}
			ledgerP, _, err := resolveLedger(ledgerPath)
			if err != nil {
				return err
			}
			path, err := bundle.Export(bundle.ExportRequest{
				ContextPaths: paths, LedgerPath: ledgerP, Since: sinceDur,
				Environment: env, System: system, Host: host,
				SigningKey: signingKey, Out: out,
			})
			if err != nil {
				cmd.SilenceUsage = true
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "output tar.gz path (default: restoregap-bundle-<host>-<UTC timestamp>.tgz)")
	cmd.Flags().StringVar(&since, "since", "", "bound the ledger slice to entries within this window (e.g. 30d, 720h); empty = every entry")
	cmd.Flags().StringVar(&env, "env", "", "narrow proof counts/evidence to this scope.environment")
	cmd.Flags().StringVar(&system, "system", "", "narrow proof counts/evidence to this scope.system")
	cmd.Flags().StringVar(&host, "host", "", "narrow proof counts/evidence to this scope.host")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "hex ed25519 seed to sign the bundle (required)")
	cmd.Flags().StringVar(&ledgerPath, "ledger", "", "ledger to slice; "+ledgerDiscoveryHelp)
	cmd.Flags().StringArrayVar(&contextPaths, "context", nil, "path to restoregap.yml / restoregap.local.yml; "+contextDiscoveryHelpRepeatable)
	return cmd
}

func newBundleVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <bundle.tgz>",
		Short: "Verify a bundle's signature, content digests, and ledger-slice hash chain",
		Long: "Checks the detached Ed25519 signature over manifest.json, recomputes and compares every\n" +
			"context-file and ledger-slice digest the manifest claims, and re-verifies the embedded\n" +
			"ledger slice's own internal hash chain. Exits 0 and prints the host/epoch/policy revision\n" +
			"it vouches for when everything checks out; exits 1 and names the first failed check\n" +
			"otherwise.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := bundle.Verify(args[0])
			if err != nil {
				cmd.SilenceUsage = true
				return err
			}
			if !res.OK {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "FAIL: %s\n", res.Reason)
				cmd.SilenceUsage = true
				return &ExitError{Code: 1}
			}
			m := res.Manifest
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "OK — host %s (%s) · epoch %s\n", m.Host.Name, m.Host.ID, m.Epoch)
			if m.PolicyRevision != "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "policy revision %s\n", m.PolicyRevision)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "generated %s · %d guard(s) · %d proof(s) · %d ledger entr(y/ies)\n",
				m.GeneratedAt.Format(time.RFC3339), m.Counts.Guards, m.Counts.Proofs, m.Counts.LedgerEntries)
			return nil
		},
	}
	return cmd
}

func newBundleInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <bundle.tgz>",
		Short: "Print a bundle's manifest (does not check the signature — use `bundle verify` for that)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := bundle.Inspect(args[0])
			if err != nil {
				cmd.SilenceUsage = true
				return err
			}
			out, err := json.MarshalIndent(m, "", "  ")
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		},
	}
	return cmd
}

// parseSince parses --since, accepting a trailing "d" for whole days (the
// spec's own example syntax, e.g. "30d") in addition to every unit
// time.ParseDuration already understands. Empty string means "no bound".
func parseSince(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("--since: %q is not a valid duration (e.g. 30d, 720h)", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("--since: %q is not a valid duration (e.g. 30d, 720h): %w", s, err)
	}
	return d, nil
}

func init() { extraCommands = append(extraCommands, newBundleCmd) }
