// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	commandrunner "github.com/tannernicol/restoregap/internal/command"
	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/evidence"
)

func newEvidenceCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "evidence", Hidden: true, Short: "Record recovery proofs and export an evidence packet"}

	ing := evidence.IngestRequest{}
	var expiresIn string
	var timeout time.Duration
	ingest := &cobra.Command{
		Use:   "ingest",
		Short: "Record/refresh a proof: run an optional verifier command, hash its output, update the context",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if timeout <= 0 {
				return fmt.Errorf("evidence ingest: --timeout must be positive")
			}
			path, err := requireContext(cmd, ing.ContextPath, "evidence ingest")
			if err != nil {
				return err
			}
			ing.ContextPath = path
			ing.Timeout = timeout

			ledgerPath, _, err := resolveLedger(ing.LedgerPath)
			if err != nil {
				return err
			}
			ing.LedgerPath = ledgerPath

			if expiresIn != "" {
				d, err := time.ParseDuration(expiresIn)
				if err != nil {
					return fmt.Errorf("evidence ingest: --expires-in must be a duration like 720h: %w", err)
				}
				ing.ExpiresIn = d
			}
			msg, err := evidence.IngestContext(cmd.Context(), ing)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), msg)
			return nil
		},
	}
	f := ingest.Flags()
	f.StringVar(&ing.ProofID, "proof", "", "proof id to record (required)")
	f.StringVar(&ing.ContextPath, "context", "",
		"v2 context file to update (required; "+contextDiscoveryHelp+")")
	f.StringVar(&ing.Command, "command", "", "verifier command; its output is hashed into the proof")
	f.StringVar(&ing.EvidenceURL, "evidence-url", "", "where the underlying evidence lives")
	f.StringVar(&expiresIn, "expires-in", "", "proof validity window, e.g. 720h")
	f.BoolVar(&ing.Validated, "validated", false, "record as validated (default observed)")
	f.StringVar(&ing.LedgerPath, "ledger", "", "record the ingestion in this ledger; "+ledgerDiscoveryHelp)
	f.StringVar(&ing.Actor, "actor", "", "recording actor")
	f.DurationVar(&timeout, "timeout", commandrunner.DefaultTimeout,
		"maximum runtime for the optional verifier command")

	exp := evidence.ExportRequest{}
	var outPath string
	export := &cobra.Command{
		Use:   "export",
		Short: "Export a self-contained HTML evidence packet: proofs, their freshness, and ledger integrity",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := requireContext(cmd, exp.ContextPath, "evidence export")
			if err != nil {
				return err
			}
			exp.ContextPath = path

			rendered, err := evidence.Export(exp)
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
	g := export.Flags()
	g.StringVar(&exp.ContextPath, "context", "",
		"v2 context file (required; "+contextDiscoveryHelp+")")
	g.StringVar(&exp.LedgerPath, "ledger", "", "decision ledger for the integrity section")
	g.StringVar(&exp.AsOf, "as-of", "", "evaluate freshness as of this RFC3339 time")
	g.StringVar(&outPath, "out", "", "write the packet to this path (- for stdout)")

	cmd.AddCommand(ingest, export)
	return cmd
}

const starterContext = `version: 2
# Declare what must stay recoverable. Docs: docs/ARCHITECTURE.md §5.
guards:
  - id: ssh-keys
    kind: lifeline
    enforcement: block
    match:
      paths: ["**/.ssh/id_*", "**/authorized_keys"]
    requires: {proofs: [ssh-key-recovery-copy]}
proofs: []
  # Record proofs with:
  #   restoregap evidence ingest --proof ssh-key-recovery-copy --context <this file> \
  #     --command "test -f /media/recovery-usb/ssh-backup.tar.age" --expires-in 720h
facts: []
`

func newContextCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "context", Short: "Manage the recovery context (restoregap.yml)"}
	var outPath string
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter v2 context file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := os.Stat(outPath); err == nil {
				return fmt.Errorf("context init: %s already exists — refusing to overwrite", outPath)
			}
			if err := os.WriteFile(outPath, []byte(starterContext), 0o644); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote starter context to %s — declare your lifelines, then record proofs with `restoregap evidence ingest`\n", outPath)
			return nil
		},
	}
	initCmd.Flags().StringVar(&outPath, "out", "restoregap.local.yml", "where to write the starter context")
	cmd.AddCommand(initCmd, newContextLintCmd())
	return cmd
}

// newContextLintCmd reports guards that cannot work as written — most
// importantly blocking lifeline guards with no requires:, which block every
// matching change with an owner override as the only exit. Without this the
// only way to discover one is to be blocked by it mid-change.
func newContextLintCmd() *cobra.Command {
	var contextPath, format string
	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Report guards and proofs that cannot work as written",
		Long: "Finds policy that looks configured but cannot function: guards nothing can satisfy,\n" +
			"guards requiring proofs the document never declares, proofs that gate no guard, and\n" +
			"duplicate guards that report one blocked change several times.\n\n" +
			"Exit 0 when clean or only warnings, 1 when an error-level finding is present.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolved, err := requireContext(cmd, contextPath, "context lint")
			if err != nil {
				return err
			}
			contextPath = resolved

			ctx, err := contextspec.Load(contextPath)
			if err != nil {
				return fmt.Errorf("context lint: %w", err)
			}
			findings := ctx.Lint()
			out := cmd.OutOrStdout()

			if format == "json" {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(findings); err != nil {
					return err
				}
			} else {
				if len(findings) == 0 {
					_, _ = fmt.Fprintf(out, "%s: %d guards, %d proofs — no problems found\n",
						contextPath, len(ctx.Guards), len(ctx.Proofs))
					return nil
				}
				errs := 0
				for _, f := range findings {
					if f.Severity == contextspec.LintError {
						errs++
					}
				}
				_, _ = fmt.Fprintf(out, "%s: %d finding(s), %d error(s)\n\n", contextPath, len(findings), errs)
				for _, f := range findings {
					_, _ = fmt.Fprintf(out, "[%s] %s: %s\n    %s\n    fix: %s\n\n",
						f.Severity, f.Rule, f.Subject, f.Message, f.Fix)
				}
			}

			if contextspec.HasErrors(findings) {
				// SilenceUsage: a policy problem is not a usage problem, and
				// dumping help text here buries the findings above it.
				cmd.SilenceUsage = true
				return fmt.Errorf("context has guards that cannot be satisfied")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&contextPath, "context", "",
		"context file to lint (required; "+contextDiscoveryHelp+")")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}
