package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/ledger"
	"github.com/tannernicol/restoregap/internal/mcpserver"
	"github.com/tannernicol/restoregap/internal/status"
)

func newStatusCmd() *cobra.Command {
	req := status.Request{}
	var outPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Unified recovery-chain view: guards, proof freshness, ledger health",
		Long: "Gathers guards, proof freshness, and the recovery inventory into one report. --context may be\n" +
			"repeated to view several context files as one machine: real deployments often keep one context\n" +
			"file per drill (its proof-writing timer rewrites that file, so co-mingling several drills in one\n" +
			"file fights the timer that owns it). Every loaded file's guards/proofs/drills are aggregated;\n" +
			"a duplicate id across files is never silently merged — the last-loaded file wins and a warning\n" +
			"prints to stderr. Omit --context entirely to see the built-in zero-config default policy.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := status.Gather(req)
			if err != nil {
				return err
			}
			for _, w := range s.Warnings {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), w)
			}
			rendered, err := s.Render(req.Format)
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
		"path to restoregap.yml / restoregap.local.yml; repeatable to view several context files as one machine (default: built-in zero-config policy)")
	f.StringVar(&req.LedgerPath, "ledger", "", "path to the decision ledger (JSONL)")
	f.StringVar(&req.Format, "format", "text", "output format: text or html")
	f.StringVar(&req.AsOf, "as-of", "", "evaluate freshness as of this RFC3339 time")
	f.StringVar(&outPath, "out", "", "write the report to this path (- for stdout)")
	return cmd
}

func newLedgerCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ledger", Short: "Inspect and verify the decision ledger"}
	verify := &cobra.Command{
		Use:   "verify <ledger.jsonl>",
		Short: "Verify the ledger's hash chain end to end",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := ledger.Verify(args[0])
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
	var anchorReason, anchorApprovedBy, anchorActor string
	anchor := &cobra.Command{
		Use:   "anchor <ledger.jsonl> <entry-id>",
		Short: "Append an owner-approved attestation vouching for one historical entry's hash mismatch",
		Long: "Records that a specific entry's stored hash no longer matches its content and the\n" +
			"mismatch is accepted, not tampering. Chain anchors do not repair the entry in place —\n" +
			"Prev is part of every entry's hashed content, so an in-place edit would cascade and\n" +
			"break every hash after it. This only ever appends; it refuses if the entry does not\n" +
			"exist, already verifies (nothing to anchor), or already has an anchor.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if anchorReason == "" || anchorApprovedBy == "" {
				return fmt.Errorf("ledger anchor: --reason and --approved-by are required")
			}
			actor := anchorActor
			if actor == "" {
				actor = "human/owner"
			}
			entry, err := ledger.AnchorNow(args[0], args[1], anchorReason, anchorApprovedBy, actor)
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
	list := &cobra.Command{
		Use:   "list <ledger.jsonl>",
		Short: "List ledger entries (id, type, actor, time)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := ledger.ReadAll(args[0])
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
	cmd.AddCommand(verify, anchor, list)
	return cmd
}

// renderVerifyOK renders a passing VerifyResult. A chain with anchored
// anomalies is still OK (each mismatch was vouched for by an owner-approved
// chain_anchor entry — see docs/ARCHITECTURE.md) but that fact is not
// hidden: the anchored entry ids are called out on the same line.
func renderVerifyOK(res ledger.VerifyResult) string {
	if len(res.AnchoredAnomalies) == 0 {
		return fmt.Sprintf("OK: %d entries, chain verified (last hash %s)", res.EntryCount, res.LastHash)
	}
	noun := "anomaly"
	if len(res.AnchoredAnomalies) != 1 {
		noun = "anomalies"
	}
	return fmt.Sprintf("OK — %d entries (%d anchored %s: %s)",
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
			exe, err := os.Executable()
			if err != nil {
				exe = "restoregap"
			}
			cfg := map[string]any{"mcpServers": map[string]any{
				"restoregap": map[string]any{"command": exe, "args": []string{"mcp", "serve"}},
			}}
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
