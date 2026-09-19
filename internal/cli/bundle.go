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
	"github.com/tannernicol/restoregap/internal/contextspec"
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
	var out, since, env, system, host, signingKey, ledgerPath, asOf, label string
	var summaryOnly bool
	var contextPaths []string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export a signed full archive or fixed-field offline JSON summary",
		Long: "By default writes a tar.gz containing manifest.json (host/epoch/policy revision/counts),\n" +
			"the context files in force, a ledger slice (--since bounds it, e.g. 30d), proof-evidence\n" +
			"METADATA only (never a file's contents, and never a path under a secret store), and a\n" +
			"detached Ed25519 signature over the manifest — the same key material `restoregap drill\n" +
			"--signing-key` uses. With --summary-only it instead writes a small signed JSON envelope\n" +
			"containing only opaque proof digests, fixed outcomes, measurements, policy/ledger digests,\n" +
			"and explicit producer limitations; use --expected-key when verifying that summary. Context\n" +
			"discovery is the same as `restoregap status`: " + contextDiscoveryHelpRepeatable + ".",
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
			if summaryOnly {
				if since != "" {
					cmd.SilenceUsage = true
					return fmt.Errorf("bundle export: --since cannot be combined with --summary-only")
				}
				asOfTime, err := parseBundleAsOf(asOf)
				if err != nil {
					cmd.SilenceUsage = true
					return err
				}
				path, err := bundle.ExportSummary(bundle.SummaryExportRequest{
					ContextPaths: paths,
					LedgerPath:   ledgerP,
					SigningKey:   signingKey,
					Out:          out,
					Scope:        bundle.ScopeFilter{Environment: env, System: system, Host: host},
					AsOf:         asOfTime,
					Label:        label,
				})
				if err != nil {
					cmd.SilenceUsage = true
					return err
				}
				printSummaryExportSuccess(cmd, path, signingKey)
				return nil
			}
			if asOf != "" || label != "" {
				cmd.SilenceUsage = true
				return fmt.Errorf("bundle export: --as-of and --label require --summary-only")
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
	cmd.Flags().StringVar(&out, "out", "", "output path: tar.gz archive by default, JSON summary with --summary-only")
	cmd.Flags().BoolVar(&summaryOnly, "summary-only", false, "write a signed fixed-field offline JSON summary without raw context or ledger contents")
	cmd.Flags().StringVar(&since, "since", "", "bound the ledger slice to entries within this window (e.g. 30d, 720h); empty = every entry")
	cmd.Flags().StringVar(&env, "env", "", "narrow proof counts/evidence to this scope.environment")
	cmd.Flags().StringVar(&system, "system", "", "narrow proof counts/evidence to this scope.system")
	cmd.Flags().StringVar(&host, "host", "", "narrow proof counts/evidence to this scope.host")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "hex ed25519 seed to sign the bundle (required)")
	cmd.Flags().StringVar(&asOf, "as-of", "", "evaluate proof outcomes as of this RFC3339 time (summary only; empty = generated time)")
	cmd.Flags().StringVar(&label, "label", "", "optional operator-supplied display label, signed but not independently verified (summary only)")
	cmd.Flags().StringVar(&ledgerPath, "ledger", "", "ledger to slice; "+ledgerDiscoveryHelp)
	cmd.Flags().StringArrayVar(&contextPaths, "context", nil, "path to restoregap.yml / restoregap.local.yml; "+contextDiscoveryHelpRepeatable)
	return cmd
}

func newBundleVerifyCmd() *cobra.Command {
	var expectedKey string
	cmd := &cobra.Command{
		Use:   "verify <bundle.tgz|summary.json>",
		Short: "Verify a full archive or signed offline JSON summary",
		Long: "For a full .tgz, checks the detached Ed25519 signature over manifest.json, recomputes and compares every\n" +
			"context-file and ledger-slice digest the manifest claims, and re-verifies the embedded\n" +
			"ledger slice's own internal hash chain. Exits 0 and prints the host/epoch/policy revision\n" +
			"it vouches for when everything checks out; exits 1 and names the first failed check\n" +
			"otherwise. For a .json summary, --expected-key is mandatory: it checks the fixed schema,\n" +
			"opaque proof/ledger digests, producer limitations, and the signature against that\n" +
			"independently supplied public key; matching the key verifies origin/integrity, not the\n" +
			"truth of the producer's underlying recovery claims.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.HasSuffix(strings.ToLower(args[0]), ".json") {
				if expectedKey == "" {
					cmd.SilenceUsage = true
					return &ExitError{Code: 2, Message: "bundle verify: --expected-key is required for summary JSON"}
				}
				res, err := bundle.VerifySummary(args[0], expectedKey)
				if err != nil {
					cmd.SilenceUsage = true
					return err
				}
				if !res.OK {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "FAIL: %s\n", res.Reason)
					cmd.SilenceUsage = true
					return &ExitError{Code: 1}
				}
				printSummaryVerifySuccess(cmd, res.Summary)
				return nil
			}
			res, err := bundle.VerifyWithExpectedKey(args[0], expectedKey)
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
	cmd.Flags().StringVar(&expectedKey, "expected-key", "", "independently trusted Ed25519 public key in hex; required for summary JSON, optional for full archives")
	return cmd
}

func parseBundleAsOf(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("bundle export: --as-of must be RFC3339: %w", err)
	}
	return parsed, nil
}

func printSummaryExportSuccess(cmd *cobra.Command, path, signingKey string) {
	res, err := bundle.VerifySummary(path, summaryPublicKey(signingKey))
	if err != nil || !res.OK {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\nsummary verification unavailable: %v\n", path, err)
		return
	}
	printSummary(cmd, path, res.Summary, "signer trust: export signing key only · reviewer must verify with an independently trusted --expected-key; underlying claims depend on producer")
}

func printSummaryVerifySuccess(cmd *cobra.Command, summary bundle.SummaryPayload) {
	printSummary(cmd, "", summary, "signer trust: explicit expected key · integrity/origin verified; underlying claims depend on producer")
}

func printSummary(cmd *cobra.Command, path string, summary bundle.SummaryPayload, trust string) {
	if path != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
	}
	counts := map[string]int{}
	for _, proof := range summary.Proofs {
		counts[proof.Outcome]++
	}
	if summary.Label != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "summary %q · ", summary.Label)
	} else {
		_, _ = fmt.Fprint(cmd.OutOrStdout(), "summary · ")
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%d proof(s) · outcomes pass=%d observed=%d expired=%d disputed=%d unreachable=%d · as-of %s\n",
		len(summary.Proofs), counts["pass"], counts["observed"], counts["expired"], counts["disputed"], counts["unreachable"], summary.AsOf.Format(time.RFC3339))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), trust)
}

func summaryPublicKey(signingKey string) string {
	signer, err := contextspec.ParseSigningKeySeed(signingKey)
	if err != nil || signer == nil {
		return ""
	}
	return fmt.Sprintf("%x", signer.Public())
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
