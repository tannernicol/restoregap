package report

import (
	"fmt"
	"strings"
	"text/tabwriter"
)

// Text renders r as plain lines for a human sitting at a terminal: no
// markdown syntax (no pipe tables, no #/**), so an interactively run
// preflight isn't dumped as source for a renderer nobody is piping it to.
// Order matches Markdown's: verdict headline, summary sentence, one aligned
// line per finding, then the required-next-step lines.
func (r Report) Text() []byte {
	var b strings.Builder

	fmt.Fprintf(&b, "%s\n", strings.ToUpper(r.Verdict))
	b.WriteString(summarySentence(r.Verdict) + "\n")

	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n")
		return []byte(b.String())
	}

	tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
	for _, f := range r.Findings {
		_, _ = fmt.Fprintf(tw, "  guard\t%s\tresource\t%s\tproof\t%s\n", f.GuardID, f.Resource, f.ProofStatus)
	}
	_ = tw.Flush()

	for _, f := range r.Findings {
		if f.RequiredNextStep == "" {
			continue
		}
		fmt.Fprintf(&b, "next: %s\n", f.RequiredNextStep)
	}
	return []byte(b.String())
}
