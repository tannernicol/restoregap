// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"fmt"
	"strings"
	"time"
)

// promptDisplayLimit is how many uncovered candidates `discover --prompt`
// lists before folding the rest behind "--all" — the same
// uncoveredDisplayLimit convention RenderText already uses for the plain
// text view.
const promptDisplayLimit = 20

// PromptRules is the rules block `restoregap discover --prompt` (and
// status.html's "Fix this" coverage block, via RenderPrompt) prints
// verbatim: a declared proof with no drill has a known fix
// (`restoregap drill`/`restoregap accept` — see status.PromptRules for
// that half); an UNDECLARED candidate has no mechanical fix at all — someone
// has to decide what "recovered" means for it, author a drill, and prove it
// — which is exactly why this is a brief for an agent rather than a single
// command. Kept in exactly one place and reused by both the CLI and the
// HTML page so they can never drift on the wording.
const PromptRules = "For agent wiring gaps, run the listed installer; this is configuration, not recovery proof. For each artifact item above, propose a Restore Gap drill: a `recover:` command that " +
	"reconstructs it into a sandbox from an off-box copy, and a `validate:` check that proves the " +
	"RESTORED copy is actually usable — not merely present. Model the validators on the ones already " +
	"in this estate: a database check opens the db, runs an integrity check, and asserts row counts " +
	"against counts recorded at snapshot time; a config check asserts the file parses and contains " +
	"the keys that matter. Write the drill into its own context file next to the others, run " +
	"`restoregap drill --context <file>`, and iterate until it passes for the right reason. Never " +
	"hand-edit a proof. Never mark anything covered — only a real drill run creates a proof. If " +
	"something genuinely should not be protected, add it to `.restoregapignore` with a reason rather " +
	"than leaving it to nag."

// RenderPrompt renders discover's ready-to-hand agent brief: a header
// (host, coverage summary, generated-at, scope), one bullet per uncovered
// candidate — kind, name, path, size — ranked by consequence (weight, then
// size; report.Candidates already comes pre-sorted that way, see
// sortCandidates), capped at promptDisplayLimit unless all is true, and
// PromptRules verbatim. Suppressed-as-noise candidates are left out of the
// default (all=false) view, same as RenderText's default uncovered section
// — noise is noise whether an agent or a human is reading it.
func RenderPrompt(report *Report, all bool, scope string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "restoregap discover — scope: %s\n", scope)
	fmt.Fprintf(&b, "host: %s\n", report.Host)
	fmt.Fprintf(&b, "coverage: %d of %d candidates covered\n", report.Counts.Covered, report.Counts.Candidates)
	fmt.Fprintf(&b, "generated: %s\n\n", report.GeneratedAt.UTC().Format(time.RFC3339))

	var uncovered []Candidate
	for _, c := range report.Candidates {
		if c.Covered {
			continue
		}
		if !all && c.Suppressed {
			continue
		}
		uncovered = append(uncovered, c)
	}

	shown := uncovered
	remaining := 0
	if !all && len(shown) > promptDisplayLimit {
		remaining = len(shown) - promptDisplayLimit
		shown = shown[:promptDisplayLimit]
	}
	if len(shown) == 0 {
		b.WriteString("nothing uncovered — every discovered candidate is covered\n\n")
	}
	for _, c := range shown {
		if c.Agent != nil {
			fmt.Fprintln(&b, "- agent  "+AgentCoverageLine(c))
			continue
		}
		fmt.Fprintf(&b, "- %s  %s  %s  %d bytes\n", c.Kind, c.Name, c.Path, c.SizeBytes)
	}
	if remaining > 0 {
		fmt.Fprintf(&b, "... and %d more (--all)\n", remaining)
	}
	b.WriteString("\n" + PromptRules + "\n")
	return b.String()
}
