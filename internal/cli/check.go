package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/copycheck"
)

// newCheckCmd compares a live location to its recovery copy.
//
// Exit codes are part of the contract, not decoration: 0 faithful, 1 drifted,
// 2 error. Callers gate on them, so "I could not compare" must never be
// mistaken for "nothing to report" — an unreadable recovery copy is itself a
// recovery gap.
func newCheckCmd() *cobra.Command {
	var format, as, project string

	cmd := &cobra.Command{
		Use:   "check <live> <recovery>",
		Short: "Compare a live location to its recovery copy and report what is missing",
		Long: "Backups rarely fail loudly — they go quietly out of date while the nightly job keeps\n" +
			"succeeding. check compares what you have now against what you could actually recover,\n" +
			"and names the entries that exist in exactly one place. No configuration required.\n\n" +
			"Exit 0 when the recovery copy is faithful, 1 when it is not, 2 on error.\n" +
			"Entry content is never read: names and fingerprints only.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			live, recovery := args[0], args[1]

			kind := copycheck.Kind(as)
			if as == "" {
				kind = copycheck.Detect(live)
			}

			res, err := copycheck.Compare(live, recovery, kind)
			if err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: err.Error()}
			}

			out := cmd.OutOrStdout()
			if format == "json" {
				payload := map[string]any{
					"kind":           string(res.Kind),
					"live_count":     res.LiveCount,
					"recovery_count": res.RecoveryCount,
					"only_live":      res.OnlyLive,
					"only_recovery":  res.OnlyRecovery,
					"differing":      res.Differing,
					"faithful":       res.Faithful(),
				}
				if project != "" {
					payload["project"] = project
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(payload); err != nil {
					return &ExitError{Code: 2, Message: err.Error()}
				}
			} else {
				_, _ = fmt.Fprint(out, res.Text())
				if !res.Faithful() {
					_, _ = fmt.Fprintf(out, "next: turn this into a proof — restoregap drill propose %s\n", live)
				}
			}

			if !res.Faithful() {
				cmd.SilenceUsage = true
				return &ExitError{Code: 1, Message: "recovery copy is not faithful"}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "text", "text|json")
	cmd.Flags().StringVar(&as, "as", "", "force a comparator instead of detecting one")
	cmd.Flags().StringVar(&project, "project", "", "label this result (for later cross-machine aggregation)")
	return cmd
}

// Self-register so adding a command never edits root.go (the convention noted
// on extraCommands).
func init() { extraCommands = append(extraCommands, newCheckCmd) }
