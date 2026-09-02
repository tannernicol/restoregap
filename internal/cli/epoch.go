// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/hostid"
	"github.com/tannernicol/restoregap/internal/ledger"
)

// newEpochCmd builds `restoregap epoch`: print this machine's durable
// identity (host name, host id, epoch id), or — via `epoch new "<label>"`
// — record a labelled epoch marker in the ledger. The marker changes no
// behavior; it narrates WHEN a new epoch began (a reinstall, a machine-id
// reset) in a human's words, beside the machine-derived epoch ids every
// stamped entry already carries.
func newEpochCmd() *cobra.Command {
	var actor string
	cmd := &cobra.Command{
		Use:   "epoch",
		Short: "Print this machine's host id and epoch (or record an epoch marker)",
		Long: "Identity & epoch (docs/SCHEMA.md): the host id is sha256(/etc/machine-id) truncated to\n" +
			"16 hex (fallback: hostname + first MAC); the epoch is sha256(machine id + root filesystem\n" +
			"UUID) truncated to 12. Proofs and ledger entries carry both, and a proof whose epoch\n" +
			"differs from the current one is 'from a previous epoch — re-drill' in status: it counts as\n" +
			"unreviewed and is excluded from green, because it was proven on a different install (or a\n" +
			"different machine whose context file was copied here). `epoch new \"<label>\"` appends a\n" +
			"labelled marker entry to the ledger — the narrative anchor for when an epoch began.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id := hostid.Current()
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), id.String())
			return nil
		},
	}
	marker := &cobra.Command{
		Use:   "new <label>",
		Short: "Record a labelled epoch marker in the ledger (no other effect)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			label := args[0]
			path, _, err := resolveLedger("")
			if err != nil {
				return err
			}
			who := actor
			if who == "" {
				who = "human/owner"
			}
			id := hostid.Current()
			stamps := ledger.Stamp(&ledger.HostRecord{Name: id.HostName, ID: id.HostID}, id.Epoch, nil)
			entry, err := ledger.AppendNow(path, ledger.EntryEpoch, who,
				ledger.Payload{Epoch: &ledger.EpochPayload{Label: label}}, stamps...)
			if err != nil {
				return fmt.Errorf("epoch new: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote epoch marker %s %q — %s\n", entry.ID, label, id.String())
			return nil
		},
	}
	marker.Flags().StringVar(&actor, "actor", "", "recording actor (default: human/owner)")
	cmd.AddCommand(marker)
	return cmd
}

func init() { extraCommands = append(extraCommands, newEpochCmd) }
