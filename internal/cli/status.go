// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/ledger"
	"github.com/tannernicol/restoregap/internal/mcpserver"
	"github.com/tannernicol/restoregap/internal/status"
)

func newStatusCmd() *cobra.Command {
	req := status.Request{}
	var outPath string
	var last bool
	var fleetDir string
	var layers, states, envs, systems, owners, tags []string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Unified recovery-chain view: guards, proof freshness, ledger health",
		Long: "Gathers guards, proof freshness, and the recovery inventory into one report. --context may be\n" +
			"repeated to view several context files as one machine: real deployments often keep one context\n" +
			"file per drill (its proof-writing timer rewrites that file, so co-mingling several drills in one\n" +
			"file fights the timer that owns it). Every loaded file's guards/proofs/drills are aggregated by\n" +
			"union; a duplicate id across files is an error naming both files, never a silent merge. Omit\n" +
			"--context entirely and status tries $RESTOREGAP_CONTEXT (which may itself hold a colon-separated\n" +
			"list), then ./restoregap.local.yml, then ./restoregap.yml, then every *.yml in the user config\n" +
			"directory ($XDG_CONFIG_HOME/restoregap, or ~/.config/restoregap); only when none of those\n" +
			"exists does it fall back to the built-in zero-config default policy.\n\n" +
			"--layer/--state/--env/--system/--owner/--tag (repeatable, text format only) narrow the taxonomy\n" +
			"tree section to matching proofs — omit all of them to see the full, unfiltered report. --state\n" +
			"accepts restored/observed/accepted/unreviewed, any of disputed/expired/unreachable/lapsed, or\n" +
			"the meta-value \"attention\" (matches all four of those at once). A declared proof with both\n" +
			"observed_at and expires_at reads \"observed\" only while it is still inside its own freshness\n" +
			"window (max(48h, TTL/7) since it was last observed) — a one-off attestation with a long TTL and\n" +
			"nothing re-checking it falls back to \"unreviewed\" well before it technically expires.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if fleetDir != "" {
				return runStatusFleet(cmd, fleetDir, outPath)
			}
			req.ContextPaths = discoverContextPaths(cmd, req.ContextPaths)
			filtered := anyStatusFilterSet(layers, states, envs, systems, owners, tags)
			if last && req.Format != "text" {
				return fmt.Errorf("status: --last is text-only")
			}
			s, err := status.Gather(req)
			if err != nil {
				return err
			}
			if filtered && req.Format != "text" {
				return fmt.Errorf("status: --layer/--state/--env/--system/--owner/--tag are text-only — html filters client-side via its checkbox chips, json always emits everything for a downstream merge")
			}
			rendered, err := renderStatusReport(s, req.Format, last, filtered, status.NewTreeFilter(layers, states, envs, systems, owners, tags))
			if err != nil {
				return err
			}
			if outPath != "" && outPath != "-" {
				return os.WriteFile(outPath, rendered, 0o644)
			}
			_, err = cmd.OutOrStdout().Write(rendered)
			return err
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&req.ContextPaths, "context", nil,
		"path to restoregap.yml / restoregap.local.yml; "+contextDiscoveryHelpRepeatable+
			" (when omitted entirely: "+contextDiscoveryHelp+"; falls back further to the built-in zero-config policy)")
	f.StringVar(&req.LedgerPath, "ledger", "", "path to the decision ledger (JSONL)")
	f.StringVar(&req.Format, "format", "text", "output format: text, html, or json (every proof's full effective layer/category/state/scope)")
	f.StringVar(&req.AsOf, "as-of", "", "evaluate freshness as of this RFC3339 time")
	f.StringVar(&outPath, "out", "", "write the report to this path (- for stdout)")
	f.BoolVar(&last, "last", false, "show the last preflight decision with ordered check durations and tool version")
	f.StringVar(&fleetDir, "fleet", "", "render the merged fleet view from `bundle merge`'s --out dir in the terminal, instead of this host's own status")
	f.StringArrayVar(&layers, "layer", nil, "show only this layer's proofs (repeatable; text format only)")
	f.StringArrayVar(&states, "state", nil, "show only proofs in this state (repeatable; text format only)")
	f.StringArrayVar(&envs, "env", nil, "show only this scope environment's proofs (repeatable; text format only)")
	f.StringArrayVar(&systems, "system", nil, "show only this scope system's proofs (repeatable; text format only)")
	f.StringArrayVar(&owners, "owner", nil, "show only this scope owner's proofs (repeatable; text format only)")
	f.StringArrayVar(&tags, "tag", nil, "show only proofs carrying this scope tag (repeatable; text format only)")
	return cmd
}

// runStatusFleet implements `status --fleet <dir>`: loads a prior `bundle
// merge`'s fleet.json from dir and renders the exact same layer→category→
// proof tree fleet.html shows, as a terminal tree instead — the same
// contract the plain-text taxonomy tree has with the single-host HTML
// dashboard.
func runStatusFleet(cmd *cobra.Command, dir, outPath string) error {
	fleet, err := status.LoadFleet(dir)
	if err != nil {
		cmd.SilenceUsage = true
		return err
	}
	rendered := fleet.RenderText()
	if outPath != "" && outPath != "-" {
		return os.WriteFile(outPath, rendered, 0o644)
	}
	_, err = cmd.OutOrStdout().Write(rendered)
	return err
}

// anyStatusFilterSet reports whether any of --layer/--state/--env/--system/
// --owner/--tag was passed, which switches the report to the filtered
// taxonomy tree.
func anyStatusFilterSet(layers, states, envs, systems, owners, tags []string) bool {
	return len(layers) > 0 || len(states) > 0 || len(envs) > 0 || len(systems) > 0 || len(owners) > 0 || len(tags) > 0
}

// renderStatusReport renders s per --last/filtered/--format precedence:
// --last wins outright, then a taxonomy-tree filter, then the plain
// --format renderer.
func renderStatusReport(s *status.Summary, format string, last, filtered bool, tf status.TreeFilter) ([]byte, error) {
	switch {
	case last:
		return s.RenderLast(), nil
	case filtered:
		return s.RenderTree(tf), nil
	default:
		return s.Render(format)
	}
}

func newLedgerCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ledger", Short: "Inspect and verify the decision ledger"}
	cmd.AddCommand(newLedgerVerifyCmd(), newLedgerAnchorCmd(), newLedgerListCmd(), newLedgerShowCmd())
	return cmd
}

func newLedgerVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify [ledger.jsonl]",
		Short: "Verify the ledger's hash chain end to end",
		Long:  "Verifies the given ledger, or the default one when no path is given: " + ledgerDiscoveryHelp,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := ledgerArg(args)
			if err != nil {
				return err
			}
			res, err := ledger.Verify(path)
			if err != nil {
				return err
			}
			if !res.OK {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "FAIL: chain broken at entry %d: %s\n", res.FailedAt, res.Reason)
				return &ExitError{Code: 1}
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), renderVerifyOK(res))
			return nil
		},
	}
}

func newLedgerAnchorCmd() *cobra.Command {
	var anchorReason, anchorApprovedBy, anchorActor string
	anchor := &cobra.Command{
		Use:   "anchor [ledger.jsonl] <entry-id>",
		Short: "Append an owner-approved attestation vouching for one historical entry's hash mismatch",
		Long: "Records that a specific entry's stored hash no longer matches its content and the\n" +
			"mismatch is accepted, not tampering. Chain anchors do not repair the entry in place —\n" +
			"Prev is part of every entry's hashed content, so an in-place edit would cascade and\n" +
			"break every hash after it. This only ever appends; it refuses if the entry does not\n" +
			"exist, already verifies (nothing to anchor), or already has an anchor.\n\n" +
			"ledger.jsonl may be omitted to use the default ledger: " + ledgerDiscoveryHelp,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if anchorReason == "" || anchorApprovedBy == "" {
				return fmt.Errorf("ledger anchor: --reason and --approved-by are required")
			}
			var path, entryID string
			if len(args) == 2 {
				path, entryID = args[0], args[1]
			} else {
				entryID = args[0]
				p, _, err := resolveLedger("")
				if err != nil {
					return err
				}
				path = p
			}
			actor := anchorActor
			if actor == "" {
				actor = "human/owner"
			}
			entry, err := ledger.AnchorNow(path, entryID, anchorReason, anchorApprovedBy, actor)
			if err != nil {
				return err
			}
			a := entry.Payload.ChainAnchor
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote chain_anchor entry %s for %s (stored hash %s, recomputed hash %s, approved by %s)\n",
				entry.ID, a.EntryID, a.StoredHash, a.RecomputedHash, a.ApprovedBy)
			return nil
		},
	}
	af := anchor.Flags()
	af.StringVar(&anchorReason, "reason", "", "why the mismatch is accepted rather than treated as tampering (required)")
	af.StringVar(&anchorApprovedBy, "approved-by", "", "owner who approved anchoring this entry (required)")
	af.StringVar(&anchorActor, "actor", "", "recording actor (default: human/owner)")
	return anchor
}

func newLedgerListCmd() *cobra.Command {
	list := &cobra.Command{
		Use:   "list [ledger.jsonl]",
		Short: "List ledger entries (id, type, actor, time)",
		Long:  "Lists the given ledger, or the default one when no path is given: " + ledgerDiscoveryHelp,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := ledgerArg(args)
			if err != nil {
				return err
			}
			entries, err := ledger.ReadAll(path)
			if err != nil {
				return err
			}
			for _, e := range entries {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s  %-15s %-20s %s\n",
					e.CreatedAt.Format("2006-01-02 15:04"), e.EntryType, e.Actor, e.ID)
			}
			return nil
		},
	}
	return list
}

func newLedgerShowCmd() *cobra.Command {
	var showLimit int
	var showFormat string
	show := &cobra.Command{
		Use:   "show [ledger.jsonl]",
		Short: "Show recent decisions, drills, overrides, and chain health",
		Long:  "Shows the newest ledger activity first. It reports decisions and proposed intents without executing them: " + ledgerDiscoveryHelp,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if showLimit <= 0 {
				return fmt.Errorf("ledger show: --limit must be positive")
			}
			if showFormat != "text" && showFormat != "json" {
				return fmt.Errorf("ledger show: --format must be text or json")
			}
			path, err := ledgerArg(args)
			if err != nil {
				return err
			}
			out, broken, err := renderLedgerShow(path, showLimit, showFormat)
			if err != nil {
				return err
			}
			if _, err := cmd.OutOrStdout().Write(out); err != nil {
				return err
			}
			if broken {
				return &ExitError{Code: 1}
			}
			return nil
		},
	}
	sf := show.Flags()
	sf.IntVar(&showLimit, "limit", 10, "maximum number of newest ledger entries to inspect")
	sf.StringVar(&showFormat, "format", "text", "output format: text or json")
	return show
}

type ledgerShowOutput struct {
	Path      string                `json:"path"`
	State     string                `json:"state"`
	Chain     ledgerShowChain       `json:"chain"`
	Decisions []ledger.DecisionView `json:"decisions,omitempty"`
	Drills    []ledger.DrillView    `json:"drills,omitempty"`
	Overrides []ledger.OverrideView `json:"overrides,omitempty"`
}

type ledgerShowChain struct {
	OK         bool   `json:"ok"`
	EntryCount int    `json:"entry_count"`
	LastHash   string `json:"last_hash,omitempty"`
	FailedAt   int    `json:"failed_at,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func renderLedgerShow(path string, limit int, format string) ([]byte, bool, error) {
	entries, readErr := ledger.ReadAll(path)
	if readErr != nil {
		return renderLedgerShowBroken(path, format, readErr)
	}
	verify := ledger.VerifyEntries(entries)
	state := "ok"
	broken := !verify.OK
	if len(entries) == 0 {
		state = "empty"
	} else if broken {
		state = "broken"
	}
	recent := ledger.Recent(entries, limit)
	out := ledgerShowOutput{
		Path: path, State: state,
		Chain:     ledgerShowChain{OK: verify.OK, EntryCount: verify.EntryCount, LastHash: verify.LastHash, FailedAt: verify.FailedAt, Reason: verify.Reason},
		Decisions: recent.Decisions, Drills: recent.Drills, Overrides: recent.Overrides,
	}
	if format == "json" {
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return nil, broken, err
		}
		return append(data, '\n'), broken, nil
	}
	return []byte(formatLedgerShowText(out)), broken, nil
}

func renderLedgerShowBroken(path, format string, cause error) ([]byte, bool, error) {
	if format == "json" {
		out := ledgerShowOutput{Path: path, State: "broken", Chain: ledgerShowChain{Reason: cause.Error()}}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return nil, true, err
		}
		return append(data, '\n'), true, nil
	}
	return []byte(fmt.Sprintf("LEDGER: %s\nCHAIN: BROKEN — %s\n", path, cause)), true, nil
}

func formatLedgerShowText(out ledgerShowOutput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "LEDGER: %s\n", out.Path)
	if out.State == "empty" {
		return emptyLedgerShowText(&b, out.Path)
	}
	writeLedgerChainText(&b, out)
	writeLedgerDecisionsText(&b, out.Decisions)
	writeLedgerDrillsText(&b, out.Drills)
	writeLedgerOverridesText(&b, out.Overrides)
	b.WriteString("\nRestore Gap did not execute the change. This is a local decision record.\n")
	return b.String()
}

func emptyLedgerShowText(b *strings.Builder, path string) string {
	b.WriteString("CHAIN: EMPTY — no recorded decisions or proof activity\n")
	b.WriteString("Run `restoregap preflight --intent <intent.yml> --ledger " + path + "` to record a local decision.\n")
	return b.String()
}

func writeLedgerChainText(b *strings.Builder, out ledgerShowOutput) {
	if out.State == "broken" {
		fmt.Fprintf(b, "CHAIN: BROKEN at entry %d — %s\n", out.Chain.FailedAt, out.Chain.Reason)
		return
	}
	fmt.Fprintf(b, "CHAIN: OK — %d entries\n", out.Chain.EntryCount)
}

func writeLedgerDecisionsText(b *strings.Builder, decisions []ledger.DecisionView) {
	if len(decisions) == 0 {
		return
	}
	b.WriteString("\nDECISIONS (newest first)\n")
	for _, d := range decisions {
		state := strings.ToUpper(d.Verdict)
		if d.GateState == "broken" {
			state = "GATE BROKEN"
		}
		fmt.Fprintf(b, "- recorded %s · %s · %s\n", d.CreatedAt.Local().Format("2006-01-02 15:04"), state, d.Actor)
		if d.EvaluatedAt != nil {
			fmt.Fprintf(b, "  evaluated as of: %s\n", d.EvaluatedAt.Local().Format(time.RFC3339))
		}
		if d.Legacy {
			b.WriteString("  legacy decision: proposed change details were not recorded\n")
		} else {
			writeLedgerIntentText(b, d.Intents)
			writeLedgerFindingsText(b, d.Findings)
		}
		if d.BrokenReason != "" {
			fmt.Fprintf(b, "  why: %s\n", d.BrokenReason)
		}
	}
}

func writeLedgerIntentText(b *strings.Builder, intents []ledger.IntentRecord) {
	for _, in := range intents {
		fmt.Fprintf(b, "  proposed: %s%s%s%s\n", in.Action, formatIntentCommand(in), formatIntentPackages(in), formatIntentPaths(in)+formatIntentDescription(in))
	}
}

func writeLedgerFindingsText(b *strings.Builder, findings []ledger.FindingRecord) {
	for _, f := range findings {
		fmt.Fprintf(b, "  finding: %s — %s\n", findingHeadline(f), strings.ToUpper(f.Verdict))
		for _, line := range findingDetailLines(f) {
			fmt.Fprintf(b, "    %s\n", line)
		}
	}
}

func writeLedgerDrillsText(b *strings.Builder, drills []ledger.DrillView) {
	if len(drills) == 0 {
		return
	}
	b.WriteString("\nDRILLS (newest first)\n")
	for _, d := range drills {
		result := "FAIL"
		if d.Verified {
			result = "PASS"
		}
		fmt.Fprintf(b, "- %s · %s · %s · %s · %s\n", d.CreatedAt.Local().Format("2006-01-02 15:04"), d.ProofID, d.Mode, result, d.Level)
	}
}

func writeLedgerOverridesText(b *strings.Builder, overrides []ledger.OverrideView) {
	if len(overrides) == 0 {
		return
	}
	b.WriteString("\nOVERRIDES (newest first)\n")
	for _, o := range overrides {
		expires := "no expiry recorded"
		if o.ExpiresAt != nil {
			expires = o.ExpiresAt.Local().Format(time.RFC3339)
		}
		fmt.Fprintf(b, "- %s · %s · approved by %s · expires %s\n  why: %s\n", o.FindingID, o.EntryID, o.ApprovedBy, expires, o.Reason)
	}
}

func formatIntentCommand(in ledger.IntentRecord) string {
	if in.Command == "" {
		return ""
	}
	return " · command: " + in.Command
}

func formatIntentPackages(in ledger.IntentRecord) string {
	if len(in.Packages) == 0 {
		return ""
	}
	return " · packages: " + strings.Join(in.Packages, ", ")
}

func formatIntentPaths(in ledger.IntentRecord) string {
	if len(in.TargetPaths) > 0 {
		from := strings.Join(in.Paths, ", ")
		to := strings.Join(in.TargetPaths, ", ")
		return " · from: " + from + " · to: " + to
	}
	if len(in.Paths) > 0 {
		return " · paths: " + strings.Join(in.Paths, ", ")
	}
	return ""
}

func formatIntentDescription(in ledger.IntentRecord) string {
	if in.Description == "" {
		return ""
	}
	return " · " + in.Description
}

func findingHeadline(f ledger.FindingRecord) string {
	parts := []string{}
	if f.Actions != nil {
		parts = append(parts, strings.Join(f.Actions, ", "))
	}
	if f.Resource != "" {
		parts = append([]string{f.Resource}, parts...)
	}
	if len(parts) == 0 {
		parts = append(parts, "recovery finding")
	}
	return strings.Join(parts, " · ")
}

func findingDetailLines(f ledger.FindingRecord) []string {
	parts := []string{}
	if f.Why != "" {
		parts = append(parts, "why: "+f.Why)
	}
	if f.Proof != "" {
		parts = append(parts, "proof: "+f.Proof)
	}
	if f.RequiredNextStep != "" {
		parts = append(parts, "next: "+f.RequiredNextStep)
	}
	if f.Override != nil {
		parts = append(parts, "override by "+f.Override.ApprovedBy+": "+f.Override.Reason)
	}
	parts = append(parts, "finding id: "+f.FindingID)
	return parts
}

// ledgerArg resolves the optional single positional ledger-path argument
// shared by `ledger verify`/`ledger list`: args[0] when given, else the
// default ledger path.
func ledgerArg(args []string) (string, error) {
	explicit := ""
	if len(args) == 1 {
		explicit = args[0]
	}
	path, _, err := resolveLedger(explicit)
	return path, err
}

// renderVerifyOK renders a passing VerifyResult. A chain with anchored
// anomalies is still OK (each mismatch was vouched for by an owner-approved
// chain_anchor entry — see docs/ARCHITECTURE.md) but that fact is not
// hidden: the anchored entry ids are called out on the same line as
// acknowledged repairs.
func renderVerifyOK(res ledger.VerifyResult) string {
	if len(res.AnchoredAnomalies) == 0 {
		return fmt.Sprintf("OK: %d entries, chain verified (last hash %s)", res.EntryCount, res.LastHash)
	}
	noun := "repair"
	if len(res.AnchoredAnomalies) != 1 {
		noun = "repairs"
	}
	return fmt.Sprintf("OK — %d entries (%d acknowledged %s: %s)",
		res.EntryCount, len(res.AnchoredAnomalies), noun, strings.Join(res.AnchoredAnomalies, ", "))
}

func newMCPCmd() *cobra.Command {
	var printConfig bool
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "MCP server for agents (preflight, overrides, ledger queries)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !printConfig {
				return cmd.Help()
			}
			cfg, err := mcpConfig()
			if err != nil {
				return err
			}
			out, err := json.MarshalIndent(cfg, "", "  ")
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		},
	}
	cmd.Flags().BoolVar(&printConfig, "print-config", false, "print MCP client configuration JSON")
	serve := &cobra.Command{
		Use:   "serve",
		Short: "Serve MCP over stdio (newline-delimited JSON-RPC)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return mcpserver.Serve(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
	cmd.AddCommand(serve)
	return cmd
}
