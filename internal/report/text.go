package report

import (
	"fmt"
	"strings"
	"text/tabwriter"
)

// Text renders r as plain lines for a human sitting at a terminal: no
// markdown syntax (no pipe tables, no #/**), so an interactively run
// preflight isn't dumped as source for a renderer nobody is piping it to.
// Structure mirrors Markdown's: verdict headline with its summary sentence
// on one line, required-next-step bullets, an aligned findings table, then
// dense per-finding detail last — docs/ARCHITECTURE.md §UI: "verdict
// banner first... dense prose only inside folds." Text has no folds, so
// dense detail is simply ordered last, same as Markdown.
func (r Report) Text() []byte {
	var b strings.Builder
	if r.GateState == "broken" {
		b.WriteString("GATE BROKEN\n")
		b.WriteString("Restore Gap could not complete this gate. Treat this as blocked until the gate is repaired.\n")
		if r.BrokenReason != "" {
			fmt.Fprintf(&b, "could not run: %s\n", r.BrokenReason)
		}
		for _, c := range r.Checks {
			if c.Outcome == "broken" {
				fmt.Fprintf(&b, "broken check: %s (%dms)\n", c.ID, c.DurationMS)
			}
		}
		return []byte(b.String())
	}

	verdict := strings.ToUpper(r.Verdict)
	fmt.Fprintf(&b, "%s — %s\n", verdict, summarySentence(r.Verdict))
	for _, f := range r.Findings {
		if f.Verdict == "pass" || f.RequiredNextStep == "" {
			continue
		}
		fmt.Fprintf(&b, "  - %s\n", f.RequiredNextStep)
	}

	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n")
		return []byte(b.String())
	}

	tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "Verdict\tRisk class\tProof\tGuard\tResource\n")
	for _, f := range r.Findings {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(f.Verdict), f.RiskClass, f.ProofStatus, f.GuardID, f.Resource)
	}
	_ = tw.Flush()

	b.WriteString("\nDetail\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "%s\n", f.Title)
		fmt.Fprintf(&b, "  Guard: %s\n", f.GuardID)
		fmt.Fprintf(&b, "  Resource: %s\n", f.Resource)
		fmt.Fprintf(&b, "  Proof: %s\n", f.Proof)
		if f.RequiredNextStep != "" {
			fmt.Fprintf(&b, "  Next: %s\n", f.RequiredNextStep)
		}
	}
	return []byte(b.String())
}
