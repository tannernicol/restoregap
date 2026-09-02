// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/ledger"
)

// newHistoryCmd builds `restoregap history <proof-id> [--since 90d]`: one
// proof's timeline straight off the local ledger (docs/SCHEMA.md §History)
// — every drill/attest/accept/clear naming it, oldest first, with the date,
// recovery level (drill entries only), host, epoch, and policy revision it
// was recorded under. Nothing here re-derives freshness or a recovery
// level; it only reduces ledger.Entry records that already carry them.
func newHistoryCmd() *cobra.Command {
	var ledgerPath, since string
	cmd := &cobra.Command{
		Use:   "history <proof-id>",
		Short: "Print one proof's timeline from the local ledger: every drill/attest/accept/clear",
		Long: "Reads the local ledger (--ledger, or the same discovery `ledger verify` uses) and prints\n" +
			"every entry naming this proof id — a drill or pin_check run (\"attest\"), an owner\n" +
			"acceptance, or an acceptance being cleared — oldest first, each with its date, recovery\n" +
			"level (drill entries only), host, epoch, and policy revision. --since bounds the window\n" +
			"(e.g. 90d, 720h); omitted means the whole ledger.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			proofID := args[0]
			path, _, err := resolveLedger(ledgerPath)
			if err != nil {
				return err
			}
			sinceDur, err := parseSince(since)
			if err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "history: " + err.Error()}
			}
			entries, err := ledger.ReadAll(path)
			if err != nil {
				cmd.SilenceUsage = true
				return err
			}
			lines := proofHistoryLines(entries, proofID, sinceDur)
			if len(lines) == 0 {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "no history for %s\n", proofID)
				return nil
			}
			for _, line := range lines {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&ledgerPath, "ledger", "", "ledger to read; "+ledgerDiscoveryHelp)
	cmd.Flags().StringVar(&since, "since", "", "bound the timeline to entries within this window (e.g. 90d, 720h); empty = the whole ledger")
	return cmd
}

func init() { extraCommands = append(extraCommands, newHistoryCmd) }

// historyEvent is one ledger entry reduced to `history`'s one-line shape.
type historyEvent struct {
	when   time.Time
	kind   string
	level  string
	host   string
	epoch  string
	policy string
}

// proofHistoryLines extracts every ledger entry naming proofID, bounded by
// since (zero means unbounded), oldest first, each rendered as one display
// line.
func proofHistoryLines(entries []ledger.Entry, proofID string, since time.Duration) []string {
	var cutoff time.Time
	if since > 0 {
		cutoff = time.Now().UTC().Add(-since)
	}
	var events []historyEvent
	for _, e := range entries {
		ev, ok := historyEventFor(e, proofID)
		if !ok || (!cutoff.IsZero() && ev.when.Before(cutoff)) {
			continue
		}
		events = append(events, ev)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].when.Before(events[j].when) })
	lines := make([]string, len(events))
	for i, ev := range events {
		lines[i] = ev.String()
	}
	return lines
}

// historyEventFor reduces one ledger entry to a historyEvent when its
// payload names proofID, else reports ok=false. The vocabulary is exactly
// drill/attest/accept/clear: a pin_check drill run (evidence the pinned
// recovery source still exists, without recovering — internal/cli/drill.go)
// is what "attest" names here, since the ledger has no separate entry type
// for it.
func historyEventFor(e ledger.Entry, proofID string) (historyEvent, bool) {
	switch {
	case e.Payload.Drill != nil && e.Payload.Drill.ProofID == proofID:
		kind := "drill"
		if e.Payload.Drill.Mode == "pin_check" {
			kind = "attest"
		}
		return newHistoryEvent(e, kind, e.Payload.Drill.Level), true
	case e.Payload.Accept != nil && e.Payload.Accept.ProofID == proofID:
		return newHistoryEvent(e, "accept", ""), true
	case e.Payload.AcceptClear != nil && e.Payload.AcceptClear.ProofID == proofID:
		return newHistoryEvent(e, "clear", ""), true
	default:
		return historyEvent{}, false
	}
}

// newHistoryEvent builds a historyEvent from an entry's shared portability
// stamps (host/epoch/policy — docs/SCHEMA.md §Identity & epoch / §Policy
// revisions) plus its kind/level.
func newHistoryEvent(e ledger.Entry, kind, level string) historyEvent {
	ev := historyEvent{when: e.CreatedAt.UTC(), kind: kind, level: level, epoch: e.Epoch}
	if e.Host != nil {
		ev.host = e.Host.Name
	}
	if e.Policy != nil {
		ev.policy = e.Policy.Revision
	}
	return ev
}

// String renders one history line: date, kind, level (when a drill/attest
// carries one), host, epoch, policy revision.
func (ev historyEvent) String() string {
	parts := []string{ev.when.Format(time.RFC3339), ev.kind}
	if ev.level != "" {
		parts = append(parts, "level:"+ev.level)
	}
	parts = append(parts, "host:"+orDash(ev.host), "epoch:"+orDash(ev.epoch), "policy:"+orDash(ev.policy))
	return strings.Join(parts, "  ")
}

// orDash renders s, or emDash when empty — history's own copy of explain's
// convention for "this stamp was not recorded" (older ledger entries
// predate host/epoch/policy stamping).
func orDash(s string) string {
	if s == "" {
		return emDash
	}
	return s
}
