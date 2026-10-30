// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/dora"
	"github.com/tannernicol/restoregap/internal/ledger"
)

// newDoraCmd builds `restoregap dora`: the four keys, for recovery.
//
// Why it exists: "is our recovery posture good?" has been answerable only by
// reading the ledger by hand. These four numbers are the ones a stranger
// understands — how often it is exercised, how long a restore takes, how often
// an exercise fails, how long a broken lifeline stays broken — and they come
// from the gate's own records, not from anybody's summary of them.
func newDoraCmd() *cobra.Command {
	var days int
	var asJSON, asProm bool
	var ledgerPath string

	cmd := &cobra.Command{
		Use:    "dora",
		Hidden: true,
		Short:  "Recovery's four keys: drill frequency, time to restore, drill failure rate, lifeline MTTR",
		Long: "The DORA four keys, asked of recovery instead of delivery, computed from the\n" +
			"ledger. Every metric is a proxy and the code says which; a window with no data\n" +
			"reports n/a, never a flattering zero.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, _, err := resolveLedger(ledgerPath)
			if err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: err.Error()}
			}
			entries, err := ledger.ReadAll(path)
			if err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: "dora: reading ledger: " + err.Error()}
			}
			m := dora.Compute(entries, time.Duration(days)*24*time.Hour, time.Now().UTC())
			out := cmd.OutOrStdout()
			switch {
			case asJSON:
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(doraJSON(m))
			case asProm:
				writeDoraProm(out, m)
			default:
				writeDoraTable(out, m)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&days, "days", 30, "window in days")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	cmd.Flags().BoolVar(&asProm, "prom", false, "emit Prometheus text-format gauges")
	cmd.Flags().StringVar(&ledgerPath, "ledger", "", "ledger file (default: discovered)")
	return cmd
}

func doraJSON(m dora.Metrics) map[string]any {
	out := map[string]any{
		"window_days":             m.WindowDays,
		"from":                    m.From.Format(time.RFC3339),
		"to":                      m.To.Format(time.RFC3339),
		"drills":                  m.Drills,
		"drills_failed":           m.DrillsFailed,
		"drill_frequency":         m.DrillFrequency,
		"unrecovered":             m.Unrecovered,
		"drill_failure_rate":      nil,
		"time_to_restore_seconds": nil,
		"lifeline_mttr_seconds":   nil,
	}
	if m.DrillFailureRate != nil {
		out["drill_failure_rate"] = *m.DrillFailureRate
	}
	if m.TimeToRestore != nil {
		out["time_to_restore_seconds"] = m.TimeToRestore.Seconds()
	}
	if m.LifelineMTTR != nil {
		out["lifeline_mttr_seconds"] = m.LifelineMTTR.Seconds()
	}
	return out
}

func writeDoraTable(w io.Writer, m dora.Metrics) {
	_, _ = fmt.Fprintf(w, "recovery four keys — trailing %d days\n", m.WindowDays)
	_, _ = fmt.Fprintf(w, "(proxies, computed from the ledger: drills exercised, restores timed, gates recorded)\n\n")
	_, _ = fmt.Fprintf(w, "  drill frequency     %.2f/day  (%d drill(s), %d failed)\n", m.DrillFrequency, m.Drills, m.DrillsFailed)
	_, _ = fmt.Fprintf(w, "  time to restore     %s\n", durationOrNA(m.TimeToRestore))
	_, _ = fmt.Fprintf(w, "  drill failure rate  %s\n", rateOrNA(m.DrillFailureRate))
	_, _ = fmt.Fprintf(w, "  lifeline MTTR       %s\n", durationOrNA(m.LifelineMTTR))
	if len(m.Unrecovered) > 0 {
		_, _ = fmt.Fprintf(w, "\n  STILL BROKEN (not in the MTTR median): %v\n", m.Unrecovered)
	}
	if m.Drills == 0 {
		_, _ = fmt.Fprintf(w, "\n  no drills in this window — a recovery you never rehearse is a claim, not a capability\n")
	}
}

func writeDoraProm(w io.Writer, m dora.Metrics) {
	label := fmt.Sprintf("{window_days=\"%d\"}", m.WindowDays)
	_, _ = fmt.Fprintf(w, "# HELP restoregap_dora_drill_frequency_per_day Verified and failed drills per day over the window.\n")
	_, _ = fmt.Fprintf(w, "# TYPE restoregap_dora_drill_frequency_per_day gauge\n")
	_, _ = fmt.Fprintf(w, "restoregap_dora_drill_frequency_per_day%s %g\n", label, m.DrillFrequency)
	_, _ = fmt.Fprintf(w, "# HELP restoregap_dora_drills_total Drills recorded in the window.\n")
	_, _ = fmt.Fprintf(w, "# TYPE restoregap_dora_drills_total gauge\n")
	_, _ = fmt.Fprintf(w, "restoregap_dora_drills_total%s %d\n", label, m.Drills)
	_, _ = fmt.Fprintf(w, "restoregap_dora_drills_failed%s %d\n", label, m.DrillsFailed)
	if m.DrillFailureRate != nil {
		_, _ = fmt.Fprintf(w, "restoregap_dora_drill_failure_rate%s %g\n", label, *m.DrillFailureRate)
	}
	if m.TimeToRestore != nil {
		_, _ = fmt.Fprintf(w, "restoregap_dora_time_to_restore_seconds%s %g\n", label, m.TimeToRestore.Seconds())
	}
	if m.LifelineMTTR != nil {
		_, _ = fmt.Fprintf(w, "restoregap_dora_lifeline_mttr_seconds%s %g\n", label, m.LifelineMTTR.Seconds())
	}
	_, _ = fmt.Fprintf(w, "restoregap_dora_lifelines_unrecovered%s %d\n", label, len(m.Unrecovered))
}

func durationOrNA(d *time.Duration) string {
	if d == nil {
		return "n/a  (nothing measured in this window)"
	}
	return d.Round(time.Second).String()
}

func rateOrNA(r *float64) string {
	if r == nil {
		return "n/a  (no drills in this window)"
	}
	return fmt.Sprintf("%.0f%%", *r*100)
}
