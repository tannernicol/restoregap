// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package report

import (
	"fmt"
	"strings"
)

// Markdown renders r with the verdict banner first (BLOCK/WARN/PASS plus
// required next steps), a findings table second, and dense per-finding
// prose last — docs/ARCHITECTURE.md §UI: "verdict banner first... dense
// prose only inside folds." Markdown has no folds, so dense detail is
// simply ordered last instead.
func (r Report) Markdown() []byte {
	var b strings.Builder

	writeBanner(&b, r)
	b.WriteString("\n")

	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n")
		return []byte(b.String())
	}

	b.WriteString("| Verdict | Risk class | Proof | Guard | Resource |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			strings.ToUpper(f.Verdict), f.RiskClass, f.ProofStatus, f.GuardID, mdEscape(f.Resource))
	}
	b.WriteString("\n## Detail\n\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "### %s\n\n", findingHeadline(f))
		fmt.Fprintf(&b, "- **Why:** %s\n", f.Title)
		fmt.Fprintf(&b, "- **Proof:** %s\n", f.Proof)
		if f.RequiredNextStep != "" {
			fmt.Fprintf(&b, "- **Required next step:** %s\n", f.RequiredNextStep)
		}
		fmt.Fprintf(&b, "- **Guard:** `%s`\n", f.GuardID)
		fmt.Fprintf(&b, "- **Finding ID:** `%s`\n", f.ID)
		b.WriteString("\n")
	}
	return []byte(b.String())
}

func writeBanner(b *strings.Builder, r Report) {
	if r.GateState == "broken" {
		b.WriteString("# GATE BROKEN\n")
		b.WriteString("Restore Gap could not complete this gate. Treat this as blocked until the gate is repaired.\n")
		if r.BrokenReason != "" {
			fmt.Fprintf(b, "- **Could not run:** %s\n", r.BrokenReason)
		}
		for _, c := range r.Checks {
			if c.Outcome == "broken" {
				fmt.Fprintf(b, "- **Broken check:** `%s` (%dms)\n", c.ID, c.DurationMS)
			}
		}
		writeMarkdownDecisionScope(b, r)
		return
	}
	verdict := strings.ToUpper(r.Verdict)
	fmt.Fprintf(b, "# %s\n", verdict)
	b.WriteString(summarySentence(r.Verdict) + "\n")
	writeMarkdownDecisionScope(b, r)
	for _, f := range r.Findings {
		if f.Verdict == "pass" || f.RequiredNextStep == "" {
			continue
		}
		fmt.Fprintf(b, "- %s\n", f.RequiredNextStep)
	}
}

// summarySentence is the one-line verdict explanation shared by every
// rendering (Markdown's banner, Text's headline, HTML's summary).
func summarySentence(verdict string) string {
	switch verdict {
	case "block":
		return "Restore Gap blocked this proposed change. Supply proof, change the plan, or record an owner override."
	case "warn":
		return "Restore Gap found findings that need review before proceeding."
	default:
		return "Restore Gap found no unresolved recovery finding for the supplied change."
	}
}

func writeMarkdownDecisionScope(b *strings.Builder, r Report) {
	fmt.Fprintf(b, "\n**Decision:** %s\n", strings.ToUpper(r.Verdict))
	b.WriteString("**Execution:** Restore Gap did not execute the change.\n\n")
	b.WriteString("**Proposed change:**\n")
	if len(r.Proposed) == 0 {
		b.WriteString("- Not recorded in this report.\n")
		return
	}
	for _, p := range r.Proposed {
		fmt.Fprintf(b, "- `%s`\n", mdEscape(proposedChangeText(p)))
	}
}

func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
