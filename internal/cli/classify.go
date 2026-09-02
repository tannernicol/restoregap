// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/classify"
)

// newClassifyCmd builds `restoregap classify`: proposes (and, with --apply,
// writes) a recovery-domain layer for every guard and every unattached
// proof across the discovered context files, from the taxonomy spec's fixed
// keyword table (internal/classify). `--suggest` (the default) only prints
// the table; `--apply` writes layer: onto entries that have no layer yet,
// never overriding one already declared.
func newClassifyCmd() *cobra.Command {
	var contextPaths []string
	var apply bool

	cmd := &cobra.Command{
		Use:   "classify",
		Short: "Suggest (or apply) a recovery-domain layer for every guard and unattached proof",
		Long: "Proposes a layer for every guard and every proof no guard requires (an attached proof\n" +
			"inherits its layer from the guard(s) requiring it instead — see `restoregap status`), from a\n" +
			"fixed keyword table over each entry's id plus its artifact/evidence path. `--suggest`\n" +
			"(default) prints `id  current  suggested  reason` and exits 1 if anything shown currently has\n" +
			"no layer. `--apply` writes layer: onto exactly those entries, backing each touched file up to\n" +
			"a sibling .bak.<UTC-timestamp> first, and NEVER overrides an entry that already declares a\n" +
			"layer. Context discovery is the same as `restoregap status`: " + contextDiscoveryHelpRepeatable + ".",
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths := discoverContextPaths(cmd, contextPaths)
			suggestions, err := classify.Suggest(paths)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			if apply {
				applied, err := classify.Apply(suggestions)
				if err != nil {
					return err
				}
				if len(applied) == 0 {
					_, _ = fmt.Fprintln(out, "nothing to apply — every guard and unattached proof already has a layer and category")
					return nil
				}
				for _, a := range applied {
					var wrote []string
					if a.Layer != "" {
						wrote = append(wrote, "layer: "+a.Layer)
					}
					if a.Category != "" {
						wrote = append(wrote, "category: "+a.Category)
					}
					_, _ = fmt.Fprintf(out, "wrote %s: %s  (%s, %s)\n", a.ID, strings.Join(wrote, ", "), a.Kind, a.File)
				}
				return nil
			}

			printSuggestTable(out, suggestions)
			if classify.AnyUnfiled(suggestions) {
				cmd.SilenceUsage = true
				return &ExitError{Code: 1, Message: "one or more entries are unfiled — run `restoregap classify --apply` or set layer: by hand"}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&contextPaths, "context", nil,
		"path to restoregap.yml / restoregap.local.yml; "+contextDiscoveryHelpRepeatable)
	f.BoolVar(&apply, "apply", false, "write the suggested layer onto entries that have no layer yet")
	f.Bool("suggest", true, "print the suggestion table without writing anything (default)")
	return cmd
}

func init() { extraCommands = append(extraCommands, newClassifyCmd) }

// printSuggestTable renders the `id  current  suggested  category  reason`
// table, column-aligned to the longest value in each column — the same
// no-dependency alignment approach status.go's inventory table uses.
func printSuggestTable(out io.Writer, suggestions []classify.Suggestion) {
	if len(suggestions) == 0 {
		_, _ = fmt.Fprintln(out, "nothing to classify — no guards or unattached proofs declared")
		return
	}
	rows := make([][]string, 0, len(suggestions)+1)
	rows = append(rows, []string{"ID", "CURRENT", "SUGGESTED", "CATEGORY", "SUGGESTED CAT", "REASON"})
	for _, s := range suggestions {
		current := s.Current
		if current == "" {
			current = "unfiled"
		}
		category := s.CurrentCategory
		if category == "" {
			category = "(uncategorized)"
		}
		rows = append(rows, []string{s.ID, current, s.Suggested, category, s.SuggestedCategory, s.Reason})
	}
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	var b strings.Builder
	for _, row := range rows {
		for i, cell := range row {
			if i == len(row)-1 {
				b.WriteString(cell)
				continue
			}
			fmt.Fprintf(&b, "%-*s  ", widths[i], cell)
		}
		b.WriteString("\n")
	}
	_, _ = fmt.Fprint(out, b.String())
}
