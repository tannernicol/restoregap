// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/ledger"
	"github.com/tannernicol/restoregap/internal/saves"
)

// newSavesCmd reports the times the gate actually changed an outcome.
//
// It deliberately reports accepted risks alongside saves. A tool that counted
// only its wins would be marking its own homework, and the ratio between the
// two is the honest measure of whether a gate is respected or routed around.
func newSavesCmd() *cobra.Command {
	var ledgerPath, format string

	cmd := &cobra.Command{
		Use:    "saves",
		Hidden: true,
		Short:  "Provable near-misses: block → remediation → pass chains from the ledger",
		Long: "Coalesces raw evaluations per (guard, resource) into episodes and classifies each by how it\n" +
			"ended: a SAVE (blocked, then passed — the gap was closed), an ACCEPTED RISK (blocked, then\n" +
			"overridden), or an OPEN BLOCK. Repeated checks of one unfixed gap never count as new saves.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := ledger.ReadAll(ledgerPath)
			if err != nil {
				return fmt.Errorf("saves: %w", err)
			}
			rep := saves.Build(entries)
			out := cmd.OutOrStdout()

			if format == "json" {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}

			_, _ = fmt.Fprintf(out, "SAVES — %d saves · %d accepted risks · %d open blocks\n",
				rep.Saves, rep.AcceptedRisks, rep.OpenBlocks)
			if !rep.WindowStart.IsZero() {
				_, _ = fmt.Fprintf(out, "Window: %s → %s\n",
					rep.WindowStart.Format("2006-01-02"), rep.WindowEnd.Format("2006-01-02"))
			}
			_, _ = fmt.Fprintf(out, "%d raw evaluations (%d blocks) coalesced into %d episodes — repeated checks never count as new saves\n",
				rep.RawEvaluations, rep.RawBlocks, len(rep.Episodes))

			for _, ep := range rep.Episodes {
				var label string
				switch ep.Outcome {
				case saves.OutcomeSave:
					label = "SAVE"
				case saves.OutcomeAcceptedRisk:
					label = "ACCEPTED-RISK"
				default:
					label = "OPEN-BLOCK"
				}
				_, _ = fmt.Fprintf(out, "\n%-13s %s · %s\n", label, ep.GuardID, ep.Resource)
				_, _ = fmt.Fprintf(out, "  blocked      %s (%s, proof %s)\n",
					ep.FirstBlock.Local().Format("2006-01-02 15:04"), ep.RiskClass, ep.ProofStatus)
				switch ep.Outcome {
				case saves.OutcomeSave:
					_, _ = fmt.Fprintf(out, "  resolved     %s · gap closed after %d evaluation(s)\n",
						ep.ResolvedAt.Local().Format("2006-01-02 15:04"), ep.Evaluations)
				case saves.OutcomeAcceptedRisk:
					_, _ = fmt.Fprintf(out, "  accepted     %s by %s — %s\n",
						ep.ResolvedAt.Local().Format("2006-01-02 15:04"), ep.ApprovedBy, ep.Reason)
				default:
					_, _ = fmt.Fprintf(out, "  still open   last blocked %s · %d evaluation(s)\n",
						ep.LastBlock.Local().Format("2006-01-02 15:04"), ep.Evaluations)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&ledgerPath, "ledger", "", "path to the append-only decision ledger (JSONL)")
	cmd.Flags().StringVar(&format, "format", "text", "text|json")
	_ = cmd.MarkFlagRequired("ledger")
	return cmd
}

func init() { extraCommands = append(extraCommands, newSavesCmd) }
