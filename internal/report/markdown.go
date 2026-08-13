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
		fmt.Fprintf(&b, "### %s (%s)\n\n", f.Title, strings.ToUpper(f.Verdict))
		fmt.Fprintf(&b, "- **Guard:** `%s`\n", f.GuardID)
		fmt.Fprintf(&b, "- **Resource:** `%s`\n", f.Resource)
		fmt.Fprintf(&b, "- **Proof:** %s\n", f.Proof)
		if f.RequiredNextStep != "" {
			fmt.Fprintf(&b, "- **Required next step:** %s\n", f.RequiredNextStep)
		}
		b.WriteString("\n")
	}
	return []byte(b.String())
}

func writeBanner(b *strings.Builder, r Report) {
	verdict := strings.ToUpper(r.Verdict)
	fmt.Fprintf(b, "# %s\n", verdict)
	switch r.Verdict {
	case "block":
		b.WriteString("Restore Gap blocked this change. Supply proof, change the plan, or record an owner override.\n")
	case "warn":
		b.WriteString("Restore Gap found findings that need review before proceeding.\n")
	default:
		b.WriteString("Restore Gap found no unresolved recovery risk.\n")
	}
	for _, f := range r.Findings {
		if f.Verdict == "pass" || f.RequiredNextStep == "" {
			continue
		}
		fmt.Fprintf(b, "- %s\n", f.RequiredNextStep)
	}
}

func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
