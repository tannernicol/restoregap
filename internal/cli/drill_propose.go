package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/drill"
)

// newDrillProposeCmd builds `restoregap drill propose <artifact>`: measure a
// live artifact and print a draft drills: entry for it, never writing into
// an existing context file — a generator that edits declarations in place
// is a generator that eats hand-written intent.
func newDrillProposeCmd() *cobra.Command {
	var source, out, proofOverride string

	cmd := &cobra.Command{
		Use:   "propose <artifact>",
		Short: "Measure a live artifact and print a draft drills: entry",
		Long: "Reads the LIVE artifact, measures it, and prints a paste-ready drills: YAML entry: type\n" +
			"detection by content (sqlite magic bytes, a git worktree/bare repo, an ssh/gnupg key\n" +
			"directory, any other directory or file), then real invariants measured from what's actually\n" +
			"there — table row counts, git ref counts, file counts, key fingerprints. sqlite table row\n" +
			"counts default to a floor relative to the live count at drill time (\">= 90%\") rather than a\n" +
			"fixed number, so a legitimate cleanup doesn't rot the floor into a false red; switch a table\n" +
			"to an absolute floor by hand when it needs a hard minimum regardless of live. Every other\n" +
			"measured count constraint (refs, files) is given ~15% headroom below the measured value,\n" +
			"then rounded DOWN to something a human would write (2 significant figures; under 10, just\n" +
			"\">= 1\") — the floor() rule, documented once in internal/drill.Floor: hand-authored budgets\n" +
			"on a real system came in 44x-8333x looser than the worst observed run, because eyeballing\n" +
			"headroom by hand doesn't work. No budgets: block is emitted — run the drill a few times,\n" +
			"then `drill --calibrate`.\n" +
			"With --source, the recovery source is classified (restic/borg repo, a dated-snapshot dir, an\n" +
			"archive dir, or a plain path) and a matching recover:/pin_check: stub is emitted, clearly\n" +
			"marked # TODO for the operator to verify — this tool never scans the filesystem hunting for\n" +
			"backups. Without --source, recover: is a placeholder and pin_check: is omitted.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			abs, err := filepath.Abs(args[0])
			if err != nil {
				return fmt.Errorf("drill propose: %s: %w", args[0], err)
			}
			if _, err := os.Stat(abs); err != nil {
				cmd.SilenceUsage = true
				return &ExitError{Code: 2, Message: fmt.Sprintf("drill propose: %s: %v", args[0], err)}
			}

			doc, err := drill.Propose(drill.ProposeOptions{
				Artifact: abs,
				Source:   source,
				Proof:    proofOverride,
				Now:      time.Now(),
			})
			if err != nil {
				return fmt.Errorf("drill propose: %w", err)
			}

			if out != "" {
				return os.WriteFile(out, []byte(doc), 0o644)
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), doc)
			return err
		},
	}

	cmd.Flags().StringVar(&source, "source", "",
		"recovery source to classify (restic/borg repo, dated-snapshot dir, archive dir, plain path) "+
			"and stub recover:/pin_check: for")
	cmd.Flags().StringVar(&out, "out", "", "write the draft to this file instead of stdout")
	cmd.Flags().StringVar(&proofOverride, "proof", "", "proof id for the draft (default: <artifact basename>-recovery, sanitized to [a-z0-9-])")
	return cmd
}
