// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/ui"
)

// The status colors are fixed in both light and dark modes (see statusCSS) —
// every use pairs one of these with an icon glyph and a text label, never
// color alone.
const (
	glyphGood     = "✓"
	glyphWarning  = "⚠"
	glyphCritical = "✕"
)

// toGreenShown caps how many to-green lines the panel shows before folding
// the rest behind a <details> — a machine with dozens of unreviewed
// attestations must not push the whole dashboard below its own headline.
const toGreenShown = 8

// RenderHTML renders the recovery-status dashboard: a dedicated,
// self-contained page (its own template and CSS) rather than the shared
// report.KVSection shell every other artifact uses — a heartbeat tick
// strip, an RTO sparkline, and an expandable per-row detail card have no
// KVSection analog, and stretching one onto them would read worse than a
// purpose-built layout.
func (s *Summary) RenderHTML() ([]byte, error) {
	data := buildStatusPage(s)
	var buf bytes.Buffer
	if err := statusPageTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("status: render html: %w", err)
	}
	return buf.Bytes(), nil
}

// statusPageData is everything statusPageTemplate needs. Every field is a
// plain string/int/bool (auto-escaped by html/template) except the *SVG
// fields and FaviconHref: those are template.HTML/template.URL built
// entirely from typed data (ints, times, and our own fixed embedded asset)
// in this file — never from a user string.
type statusPageData struct {
	GeneratedAt string
	// Origin is the header's one-line summary ("13 contexts · a.yml + 12
	// more" for a multi-context run, or the plain origin unchanged for the
	// common single-context/default case); OriginTitle is always the full,
	// untruncated origin string, carried in a title attribute so nothing is
	// actually lost — see summarizeOrigin.
	Origin      string
	OriginTitle string
	MarkInline  template.HTML
	FaviconHref template.URL

	VerdictClass     string // good | warning | critical
	VerdictIcon      string
	VerdictLabel     string // PASS | WARN | BLOCK
	VerdictHeadline  string
	InventorySummary string
	RecentDecision   *decisionCardData

	// ToGreen is the convergence panel directly under the banner (question
	// 1, "can I recover right now" — its non-green half): one line per
	// not-green proof (same lines `restoregap next` prints), the first
	// toGreenShown visible; ToGreenRest holds the remainder, folded behind a
	// <details> (ToGreenMore is len(ToGreenRest), precomputed so the
	// template never does arithmetic). ToGreenTotal is len(ToGreen)+
	// len(ToGreenRest) — the panel heading's step count. ToGreenNote is the
	// panel's line when there is nothing to do ("Green. Next expiry: <proof>
	// on <date>"), set only when ToGreen is empty. ToGreenPrompt is the
	// `next --prompt` agent brief, folded into its own <details> alongside
	// the per-item commands already shown — empty whenever ToGreenTotal is
	// 0 (nothing to fix, nothing to hand an agent).
	ToGreen       []string
	ToGreenRest   []string
	ToGreenMore   int
	ToGreenTotal  int
	ToGreenNote   string
	ToGreenPrompt string

	// Coverage is question 2 ("what is not protected at all") — the
	// discover-snapshot coverage block, top uncovered candidates by
	// consequence, and (when there is something to fix) the Fix-this
	// remediation prompt.
	Coverage coverageBlockData

	// Estate is question 3 ("how is my estate organized and where is it
	// weak") — the unified layer/category/proof tree (and its by-system
	// regrouping), replacing the old two-group inventory split and the
	// checkbox-wall taxonomy section with ONE organization of the data,
	// STATE as the one vocabulary shown everywhere.
	Estate EstateData

	// LevelLegend explains the recovery ladder once, under the estate heading.
	LevelLegend []levelLegendItem

	Footer statusFooter

	// RecoveryChain mirrors the plain-text renderer's legacy "Recovery
	// chain" section (Summary.sections) — the same context/guards/ledger
	// overview, folded into a closed <details> here rather than left
	// text-only. The text renderer's other legacy section, "Proofs" (one
	// line per proof), is deliberately NOT duplicated here: this page
	// already has a hard rule against a per-proof row for every healthy
	// proof at scale (buildFooterFreshness's doc comment, and
	// TestRenderHTMLRealScaleFooterHasNoPerProofRowsForHealthyProofs) —
	// even closed, a full per-proof dump would be exactly that.
	RecoveryChain []kvPair
}

// kvPair is one plain key/value line — the "Recovery chain" legacy
// section's shape, without pulling in the internal/report package just for
// one small key/value dump.
type kvPair struct {
	Key   string
	Value string
}

type decisionCardData struct {
	When         string
	Evaluated    string
	Verdict      string
	Actor        string
	Operation    string
	BrokenReason string
	Proposed     []string
	Findings     []decisionFindingData
	Legacy       bool
	ProposedMore int
	FindingsMore int
	Disclaimer   string
	LedgerHint   string
}

type decisionFindingData struct {
	ID       string
	Action   string
	Verdict  string
	Resource string
	Why      string
	Proof    string
	Next     string
	Override string
}

// freshnessChip is one proof-freshness state's count ("28 present"),
// compact enough for a whole footer section — 30+ healthy proofs must never
// each get their own row (see buildFooterFreshness).
type freshnessChip struct {
	Label string // present | expiring | expired | stale | disputed | unreachable
	Count int
	Warn  bool // every state except "present" is a warn-tinted chip
}

// footerProof is one problem proof (stale/expired/disputed/unreachable) in
// the footer's short list — name and state only, no "valid until" detail:
// with the state already in FreshnessChips, the detail is noise for a
// footer.
type footerProof struct {
	ID     string
	Status string
}

// statusFooter carries the compact footer sections: guards and lifelines,
// proof freshness (chips + only the problem proofs), ledger health, and the
// expiring-soon count.
type statusFooter struct {
	Lifelines      int
	Guards         int
	FreshnessChips []freshnessChip
	ProblemProofs  []footerProof
	LedgerEntries  int
	LedgerOK       bool
	LedgerDetail   string
	LastDecision   string
	ExpiringSoon   int
}

// buildStatusPage converts a gathered Summary into template data. Pure and
// deterministic — no I/O — so it's directly unit-testable without a real
// ledger or context file.
// levelLegendItem is one rung of the recovery ladder and what it actually
// means. Restored after the estate redesign dropped the per-row meaning line:
// the page still needs to explain what "restores" vs "data-valid" vs "serves"
// claim, or a reader has to already know the vocabulary to read the estate at
// all. Rendered ONCE as a collapsed legend instead of repeated on every row —
// the density the redesign wanted, without losing the explanation.
type levelLegendItem struct {
	Level   string
	Meaning string
}

var levelMeaning = map[string]string{
	"declared": "Drill declared, but no live verified proof exists yet — nothing has actually " +
		"been reconstructed and checked.",
	"restores": "Restored from its recovery source in a sandbox and the recovered bytes matched " +
		"— the artifact itself comes back.",
	"data-valid": "Restored and validated: the recovered database or repository opens and its " +
		"integrity checks hold, not just present bytes.",
	"serves": "Restored, validated, and booted: the recovered artifact ran as a live process and " +
		"answered its readiness probes.",
}

// buildLevelLegend returns the ladder weakest-first, the order the rungs are
// climbed.
func buildLevelLegend() []levelLegendItem {
	out := make([]levelLegendItem, 0, len(levelMeaning))
	for _, lvl := range []string{"declared", "restores", "data-valid", "serves"} {
		out = append(out, levelLegendItem{Level: lvl, Meaning: levelMeaning[lvl]})
	}
	return out
}

func buildStatusPage(s *Summary) statusPageData {
	originLabel, originTitle := summarizeOrigin(s.Origin)
	chips, problems := buildFooterFreshness(s.Proofs)
	steps := s.NextSteps()
	toGreenShownLines, toGreenRest, toGreenNote := buildToGreen(s)

	return statusPageData{
		GeneratedAt:      s.GeneratedAt.UTC().Format(time.RFC3339),
		Origin:           originLabel,
		OriginTitle:      originTitle,
		MarkInline:       inlineMark(),
		FaviconHref:      faviconDataURI(),
		VerdictClass:     verdictClass(s.Verdict),
		VerdictIcon:      verdictIcon(s.Verdict),
		VerdictLabel:     strings.ToUpper(s.Verdict),
		VerdictHeadline:  verdictHeadline(s, countDeclared(s.Inventory)),
		InventorySummary: s.InventorySummary,
		RecentDecision:   buildRecentDecision(s.Last),
		ToGreen:          toGreenShownLines,
		ToGreenRest:      toGreenRest,
		ToGreenMore:      len(toGreenRest),
		ToGreenTotal:     len(toGreenShownLines) + len(toGreenRest),
		ToGreenNote:      toGreenNote,
		ToGreenPrompt:    buildToGreenPrompt(s, steps),
		Coverage:         buildCoverageBlock(s.Discover),
		Estate:           buildEstateData(s),
		LevelLegend:      buildLevelLegend(),
		Footer: statusFooter{
			Lifelines: s.Lifelines, Guards: s.Guards,
			FreshnessChips: chips, ProblemProofs: problems,
			LedgerEntries: s.LedgerEntries, LedgerOK: s.LedgerOK, LedgerDetail: s.LedgerDetail,
			LastDecision: s.LastDecision, ExpiringSoon: s.ExpiringSoon,
		},
		RecoveryChain: buildRecoveryChainKV(s),
	}
}

func buildRecentDecision(d *DecisionSummary) *decisionCardData {
	if d == nil {
		return nil
	}
	out := &decisionCardData{
		When: d.When.Local().Format("2006-01-02 15:04"), Verdict: formatDecisionOutcome(*d),
		Actor: d.Actor, Operation: d.Operation, BrokenReason: d.BrokenReason, Legacy: d.Legacy,
		Disclaimer: "Restore Gap did not execute the change.", LedgerHint: "See restoregap ledger show --limit 10 for the recent record.",
	}
	if d.EvaluatedAt != nil {
		out.Evaluated = d.EvaluatedAt.Local().Format("2006-01-02 15:04")
	}
	for i, in := range d.Intents {
		if i >= 3 {
			out.ProposedMore = len(d.Intents) - i
			break
		}
		value := in.Action
		if in.Command != "" {
			value += " · command: " + in.Command
		}
		if len(in.Packages) > 0 {
			value += " · packages: " + strings.Join(in.Packages, ", ")
		}
		if len(in.TargetPaths) > 0 {
			value += " · from: " + strings.Join(in.Paths, ", ") + " · to: " + strings.Join(in.TargetPaths, ", ")
		} else if len(in.Paths) > 0 {
			value += " · paths: " + strings.Join(in.Paths, ", ")
		}
		if in.Description != "" {
			value += " — " + in.Description
		}
		out.Proposed = append(out.Proposed, value)
	}
	for i, f := range d.Findings {
		if i >= 3 {
			out.FindingsMore = len(d.Findings) - i
			break
		}
		action := ""
		if len(f.Actions) > 0 {
			action = strings.Join(f.Actions, ", ")
		}
		fd := decisionFindingData{ID: f.FindingID, Action: action, Verdict: f.Verdict, Resource: f.Resource, Why: f.Why, Proof: f.Proof, Next: f.RequiredNextStep}
		if f.Override != nil {
			fd.Override = "approved by " + f.Override.ApprovedBy + ": " + f.Override.Reason
		}
		out.Findings = append(out.Findings, fd)
	}
	return out
}

// buildToGreenPrompt renders the To-green panel's folded `next --prompt`
// agent brief — the exact text `restoregap next --prompt` prints — empty
// whenever there is nothing to do (a green page carries no remediation
// scaffolding). Host is best-effort (os.Hostname()), the same fallback
// internal/cli's own promptHeader uses.
func buildToGreenPrompt(s *Summary, steps []NextStep) string {
	if len(steps) == 0 {
		return ""
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return RenderPrompt(steps, PromptHeader{Host: host, GeneratedAt: s.GeneratedAt, Scope: "all"})
}

// buildRecoveryChainKV mirrors Summary.sections' "Recovery chain" block
// (the text renderer's overview: context, guard counts, ledger health,
// last decision) — the HTML page's closed-by-default parity section.
func buildRecoveryChainKV(s *Summary) []kvPair {
	kv := []kvPair{
		{Key: "Context", Value: s.Origin},
		{Key: "Guards declared", Value: fmt.Sprintf("%d (%d lifelines, %d guards)", s.Lifelines+s.Guards, s.Lifelines, s.Guards)},
	}
	if s.LedgerEntries > 0 || s.LedgerDetail != "" {
		v := s.LedgerDetail
		if s.LedgerEntries > 0 {
			chain := "verified"
			if !s.LedgerOK {
				chain = "BROKEN: " + s.LedgerDetail
			}
			v = fmt.Sprintf("%d entries · chain %s", s.LedgerEntries, chain)
		}
		kv = append(kv, kvPair{Key: "Ledger", Value: v})
	}
	if s.LastDecision != "" {
		kv = append(kv, kvPair{Key: "Last decision", Value: s.LastDecision})
	}
	return kv
}

// countDeclared counts inventory rows at the declared rung — the "not yet
// provable" total the verdict banner headline quotes.
func countDeclared(rows []InventoryRow) int {
	n := 0
	for _, r := range rows {
		if r.Level == contextspec.LevelDeclared.String() {
			n++
		}
	}
	return n
}

// summarizeOrigin turns Origin — a single path/label, or joinOrigins's
// ", "-joined multi-context list — into a one-line header label plus the
// full string for a title-attribute tooltip. The common case (one context
// file, or the built-in default policy) has no ", " in it and passes
// through unchanged; only a real multi-context list gets compressed, so a
// 13-path comma run never wraps the header across several lines.
func summarizeOrigin(origin string) (label, full string) {
	parts := strings.Split(origin, ", ")
	if len(parts) <= 1 {
		return origin, origin
	}
	return fmt.Sprintf("%d contexts · %s + %d more", len(parts), filepath.Base(parts[0]), len(parts)-1), origin
}

// buildFooterFreshness reduces the (possibly 30+ entry) proof list to a
// compact state-count summary plus a short list of ONLY the problem proofs
// (stale/expired/disputed/unreachable) — a healthy proof gets counted, never
// its own row. "expiring" is a chip here but not a problem row: it already
// has its own "Expiring soon" footer tile, so listing it again here would be
// the same redundancy this rework exists to remove. "unreachable" stays a
// distinct label from "disputed" — the whole point of the split is that a
// sleeping NAS and a corrupt copy must not read the same.
func buildFooterFreshness(proofs []ProofState) ([]freshnessChip, []footerProof) {
	order := []string{"present", "expiring", "expired", "stale", "disputed", "unreachable"}
	counts := make(map[string]int, len(order))
	var problems []footerProof
	for _, p := range proofs {
		counts[p.Status]++
		switch p.Status {
		case "stale", "expired", "disputed", "unreachable":
			problems = append(problems, footerProof{ID: p.ID, Status: p.Status})
		}
	}
	var chips []freshnessChip
	for _, st := range order {
		if n := counts[st]; n > 0 {
			chips = append(chips, freshnessChip{Label: st, Count: n, Warn: st != "present"})
		}
	}
	return chips, problems
}

// nextStepCommand is the literal re-drill command for a drilled row that is
// not currently good (declared rung) and has a known source context file —
// restoregap drill --context requires a real file, so a row with no
// SourceFile (never realistically reachable for a drilled row: the
// built-in default declares no drills) gets no command rather than a
// broken one. Used by nextStepCommandFor (next.go) — the single source for
// `restoregap next`, the To-green panel, and the estate tree's per-row
// inline next-action all agreeing on the same command.
func nextStepCommand(r InventoryRow) string {
	if !r.IsDrilled || r.Level != contextspec.LevelDeclared.String() || r.SourceFile == "" {
		return ""
	}
	return fmt.Sprintf("restoregap drill --context %s --proof %s", r.SourceFile, r.Proof)
}

// buildToGreen renders the convergence panel's lines — exactly what
// `restoregap next` prints — split into the first toGreenShown (shown) and
// the remainder (rest, folded behind a <details>) — plus the note that
// replaces them all when the machine is already green: the next proof
// expiry on the clock, so "green" still comes with a date. note is empty
// (and shown non-empty) whenever work is left, and vice versa.
func buildToGreen(s *Summary) (shown, rest []string, note string) {
	lines := ToGreenLines(s.NextSteps())
	if len(lines) == 0 {
		if s.NextExpiryID != "" {
			return nil, nil, fmt.Sprintf("Green. Next expiry: %s on %s", s.NextExpiryID, s.NextExpiryAt.UTC().Format(dateOnly))
		}
		return nil, nil, "Green."
	}
	if len(lines) > toGreenShown {
		return lines[:toGreenShown], lines[toGreenShown:], ""
	}
	return lines, nil, ""
}

// verdictClass maps a posture to the page's fixed status token.
func verdictClass(v string) string {
	switch v {
	case "block":
		return "critical"
	case "warn":
		return "warning"
	default:
		return "good"
	}
}

// verdictIcon returns the glyph paired with verdictClass's color.
func verdictIcon(v string) string {
	switch v {
	case "block":
		return glyphCritical
	case "warn":
		return glyphWarning
	default:
		return glyphGood
	}
}

// verdictHeadline is the banner's plain-language line, derived only from
// counted data — never a canned "all good" that could overclaim past what
// the inventory actually shows.
func verdictHeadline(s *Summary, declared int) string {
	switch s.Verdict {
	case "block":
		return "Ledger chain integrity is broken — decisions cannot be trusted"
	case "warn":
		if declared > 0 {
			return fmt.Sprintf("%d of %d recovery lifeline(s) are not currently provable", declared, len(s.Inventory))
		}
		return "Recovery posture needs attention"
	default:
		if len(s.Inventory) > 0 {
			return fmt.Sprintf("%d recovery lifeline(s) checked, none blocking", len(s.Inventory))
		}
		return "Recovery chain checks are passing"
	}
}

// inlineMark returns the embedded brand mark for inline placement beside
// the wordmark text: sized via the rgs-mark CSS class and marked
// aria-hidden (the wordmark text right beside it already carries the name).
// Built from ui.Mark, our own committed asset — not user input.
func inlineMark() template.HTML {
	svg := strings.Replace(ui.Mark, "<svg ", `<svg class="rgs-mark" aria-hidden="true" `, 1)
	return template.HTML(strings.TrimSpace(svg))
}

// faviconDataURI turns the embedded brand mark into a raw (non-base64)
// data: URI. Double quotes become single quotes and the handful of
// characters that would otherwise break out of the href attribute or the
// URI itself are percent-encoded; everything else — including the SVG's
// own whitespace — is left readable, per RFC 2397's "utf8, no base64" form.
func faviconDataURI() template.URL {
	r := strings.NewReplacer(
		"%", "%25",
		`"`, "'",
		"<", "%3C",
		">", "%3E",
		"#", "%23",
		"&", "%26",
		"\n", "",
		"\t", "",
	)
	return template.URL("data:image/svg+xml," + r.Replace(strings.TrimSpace(ui.Mark)))
}

// estateRowTemplate is the ONE row partial the estate tree's two parallel
// groupings (by-layer, by-system — the "By system"/"By layer" view switch)
// both render through, so a proof's row markup is defined exactly once
// however many times it is regrouped. A plain (non-<details>) row on
// purpose: the mobile gate's `--views 'details'` sweep clicks every
// <details> on the page cumulatively (it never re-closes one before
// clicking the next), so a per-proof expandable detail card would let a
// real, ~40-proof estate open dozens of cards simultaneously and blow the
// 8,000px height budget. Each row instead shows everything the redesign's
// question 3 asks for directly — state, id, artifact, level, why — plus,
// for a genuine gap, its single exact remediation command right there
// (NextAction, from the SAME nextStepCommandFor `restoregap next` and the
// To-green panel already use), so nothing about "how do I fix this one" is
// hidden behind a click at all.
const estateRowTemplate = `{{define "estateRow"}}
<div class="rgs-row" data-state="{{.State}}" data-bucket="{{.Bucket}}">
  <span class="rgs-taxrow">
    <span class="rgs-taxstate" data-bucket="{{.Bucket}}">{{.State}}</span>
    <span class="rgs-taxproof"><code>{{.Proof}}</code><span class="rgs-taxsub">{{.Artifact}}</span></span>
    <span class="rgs-taxlevel">{{.Level}}</span>
    <span class="rgs-taxwhy">{{.Why}}{{if .Binding}} <small class="rgs-taxbinding">{{.Binding}}</small>{{end}}</span>
  </span>
  {{- if .NextAction}}
  <pre class="rgs-rownext"><code>{{.NextAction}}</code></pre>
  {{- end}}
</div>
{{end}}`

// statusPageTemplate is the ENTIRE HTML dashboard: header, verdict banner,
// the to-green convergence panel, the coverage block (question 2: what is
// not protected at all), the unified estate tree (question 3: how is the
// estate organized and where is it weak — one layer/category/proof tree,
// STATE as the one vocabulary, a four-way view switch instead of a wall of
// per-layer/per-state/per-env/per-system checkboxes), the value/integration
// strip, and the footer. It does not use report.pageTemplate — none of this
// has a KVSection analog, and reusing that shell would mean bolting custom
// markup onto a generic key-value dump.
var statusPageTemplate = template.Must(template.New("status").Parse(estateRowTemplate + `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recovery status · Restore Gap</title>
<meta name="color-scheme" content="dark">
<link rel="icon" type="image/svg+xml" href="{{.FaviconHref}}">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#12161c">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<style>` + statusCSS + `</style>
</head>
<body>
<a class="ui-kit-skip" href="#recovery-status">Skip to recovery status</a>
<main class="rgs-shell" id="recovery-status">
  <header class="rgs-header">
    {{.MarkInline}}
    <span class="rgs-wordmark">Restore Gap</span>
    <span class="rgs-tagline">Recovery status</span>
    <span class="rgs-spacer"></span>
    <span class="rgs-meta" title="{{.OriginTitle}}">{{.Origin}}</span>
  </header>

  <div class="rgs-page-title"><h1>Is there a way back?</h1><p>Evidence snapshot · <time datetime="{{.GeneratedAt}}">{{.GeneratedAt}}</time></p></div>
  <section class="rgs-banner" data-status="{{.VerdictClass}}">
    <span class="rgs-vicon" aria-hidden="true">{{.VerdictIcon}}</span>
    <span class="rgs-vlabel">{{.VerdictLabel}}</span>
    <span class="rgs-vheadline">{{.VerdictHeadline}}</span>
    {{if .InventorySummary}}<span class="rgs-vsub">{{.InventorySummary}}</span>{{end}}
  </section>

  {{- if .RecentDecision}}
  <section class="rgs-decision" aria-labelledby="recent-decision-title">
    <div class="rgs-decision-head"><h2 id="recent-decision-title">Decision ledger · latest</h2><span class="rgs-decision-state">{{.RecentDecision.Verdict}}</span></div>
    <p class="rgs-muted">Recorded {{.RecentDecision.When}}{{if .RecentDecision.Evaluated}} · evaluated as of {{.RecentDecision.Evaluated}}{{end}}{{if .RecentDecision.Actor}} · {{.RecentDecision.Actor}}{{end}}{{if .RecentDecision.Operation}} · {{.RecentDecision.Operation}}{{end}}</p>
    {{if .RecentDecision.BrokenReason}}<p class="rgs-decision-broken">why gate is unavailable: {{.RecentDecision.BrokenReason}}</p>{{end}}
    {{- if .RecentDecision.Legacy}}
    <p>Legacy record: proposed change details were not recorded.</p>
    {{- end}}
    <h3>Proposed change</h3>
    {{- if .RecentDecision.Proposed}}
    <ul class="rgs-decision-list">{{range .RecentDecision.Proposed}}<li><code>{{.}}</code></li>{{end}}</ul>
    {{- if .RecentDecision.ProposedMore}}<p class="rgs-muted">{{.RecentDecision.ProposedMore}} more proposed operation(s). {{.RecentDecision.LedgerHint}}</p>{{end}}
    {{- else}}<p class="rgs-muted">No proposed intent was recorded.</p>{{end}}
    {{- if .RecentDecision.Findings}}
    <h3>Why and next step</h3>
    <div class="rgs-decision-findings">
      {{- range .RecentDecision.Findings}}
      <div class="rgs-decision-finding"><strong>{{if .Action}}{{.Action}} · {{end}}{{if .Resource}}{{.Resource}} · {{end}}{{.Verdict}}</strong>{{if .Why}}<span>why: {{.Why}}</span>{{end}}{{if .Proof}}<span>proof: {{.Proof}}</span>{{end}}{{if .Next}}<span>next: {{.Next}}</span>{{end}}{{if .Override}}<span>override: {{.Override}}</span>{{end}}<small>finding id: {{.ID}}</small></div>
      {{- end}}
    </div>
    {{- if .RecentDecision.FindingsMore}}<p class="rgs-muted">{{.RecentDecision.FindingsMore}} more finding(s). {{.RecentDecision.LedgerHint}}</p>{{end}}
    {{- end}}
    <p class="rgs-decision-note">{{.RecentDecision.Disclaimer}}</p>
  </section>
  {{- end}}

  <section class="rgs-togreen">
    {{- if .ToGreen}}
    <h2>To green: {{.ToGreenTotal}} step{{if ne .ToGreenTotal 1}}s{{end}}</h2>
    <ol class="rgs-togreen-list">
      {{- range .ToGreen}}
      <li><code>{{.}}</code></li>
      {{- end}}
    </ol>
    {{- if .ToGreenRest}}
    <details class="rgs-togreen-more">
      <summary>{{.ToGreenMore}} more step{{if ne .ToGreenMore 1}}s{{end}}</summary>
      <ol class="rgs-togreen-list">
        {{- range .ToGreenRest}}
        <li><code>{{.}}</code></li>
        {{- end}}
      </ol>
    </details>
    {{- end}}
    {{- if .ToGreenPrompt}}
    <details class="rgs-togreen-more">
      <summary>Agent brief (<code>restoregap next --prompt</code>)</summary>
      <pre class="rgs-promptblock"><code>{{.ToGreenPrompt}}</code></pre>
    </details>
    {{- end}}
    {{- else}}
    <h2>To green: 0 steps</h2>
    <p class="rgs-togreen-green">{{.ToGreenNote}}</p>
    {{- end}}
  </section>

  {{- if .Coverage.Line}}
  <section class="rgs-coverage">
    <h2>Outside your declared coverage</h2>
    <p class="rgs-coverage-line">{{.Coverage.Line}}</p>
    {{- if .Coverage.ShowDetail}}
    <details class="rgs-candidates"><summary>Review discovered candidates</summary>
    <p class="rgs-muted">Discovery is an inventory, not a requirement to protect every file. Review what matters before adding guards.</p>
    <div class="rgs-covlist">
      {{- range .Coverage.Top}}
      <div class="rgs-covrow">
        <span class="rgs-covkind">{{.Kind}}</span>
        <span class="rgs-taxproof"><code>{{.Name}}</code><span class="rgs-taxsub">{{.Path}}</span></span>
        <span class="rgs-covsize">{{.Size}}</span>
      </div>
      {{- end}}
    </div>
    {{- if .Coverage.Rest}}
    <details class="rgs-cov-more">
      <summary>{{.Coverage.RestCount}} more uncovered candidate{{if ne .Coverage.RestCount 1}}s{{end}}</summary>
      <div class="rgs-covlist">
        {{- range .Coverage.Rest}}
        <div class="rgs-covrow">
          <span class="rgs-covkind">{{.Kind}}</span>
          <span class="rgs-taxproof"><code>{{.Name}}</code><span class="rgs-taxsub">{{.Path}}</span></span>
          <span class="rgs-covsize">{{.Size}}</span>
        </div>
        {{- end}}
      </div>
    </details>
    {{- end}}
    <details class="rgs-fixthis">
      <summary>Fix this</summary>
      <p class="rgs-fix-regen">Regenerate: <code>restoregap discover</code></p>
      <pre class="rgs-promptblock"><code>{{.Coverage.Prompt}}</code></pre>
    </details>
    </details>
    {{- end}}
  </section>
  {{- end}}

  {{- if .Estate.HasAny}}
  <section class="rgs-estate">
    <h2>Your recovery evidence</h2>
    <details class="rgs-levels">
      <summary>What the levels mean</summary>
      <dl>
        {{- range .LevelLegend}}
        <dt>{{.Level}}</dt><dd>{{.Meaning}}</dd>
        {{- end}}
      </dl>
    </details>
    <div class="rgs-viewswitch">
      <fieldset><legend>Show</legend>
        <label class="rgs-view-toggle ui-kit-button"><input type="radio" name="rgs-view" id="rgs-view-attention"{{if .Estate.DefaultAttention}} checked{{end}}> Needs attention</label>
        <label class="rgs-view-toggle ui-kit-button"><input type="radio" name="rgs-view" id="rgs-view-all"{{if not .Estate.DefaultAttention}} checked{{end}}> All proofs</label>
      </fieldset>
      <fieldset><legend>Group by</legend>
        <label class="rgs-view-toggle ui-kit-button"><input type="radio" name="rgs-group" id="rgs-view-layer" checked> Layer</label>
        <label class="rgs-view-toggle ui-kit-button"><input type="radio" name="rgs-group" id="rgs-view-system"> System</label>
      </fieldset>
    </div>

    <div class="rgs-estate-panel" data-panel="layer">
      {{- range .Estate.LayerSections}}
      <details class="rgs-taxlayer" data-group="{{.GroupID}}" data-hasgap="{{.HasGap}}"{{if .Open}} open{{end}}>
        <summary>{{.Header}}</summary>
        {{- range .ConflictNotes}}
        <div class="rgs-conflict">⚠ {{.}}</div>
        {{- end}}
        {{- $showCat := .ShowCategoryHeaders}}
        {{- range .Categories}}
        {{- if $showCat}}
        <h4 class="rgs-taxcat">{{.Category}}</h4>
        {{- end}}
        {{- range .Rows}}
        {{template "estateRow" .}}
        {{- end}}
        {{- end}}
      </details>
      {{- end}}
    </div>

    <div class="rgs-estate-panel" data-panel="system">
      {{- range .Estate.SystemSections}}
      <details class="rgs-taxlayer" data-group="{{.GroupID}}" data-hasgap="{{.HasGap}}"{{if .Open}} open{{end}}>
        <summary>{{.Header}}</summary>
        {{- range .ConflictNotes}}
        <div class="rgs-conflict">⚠ {{.}}</div>
        {{- end}}
        {{- $showCat := .ShowCategoryHeaders}}
        {{- range .Categories}}
        {{- if $showCat}}
        <h4 class="rgs-taxcat">{{.Category}}</h4>
        {{- end}}
        {{- range .Rows}}
        {{template "estateRow" .}}
        {{- end}}
        {{- end}}
      </details>
      {{- end}}
    </div>
  </section>
  {{- else}}
  <p class="rgs-muted">No declared drills or proofs yet.</p>
  {{- end}}

  <details class="rgs-integration">
    <summary><h2 style="display:inline">What this proves · how it plugs in</h2></summary>
    <div class="rgs-integration-cols">
      <div>
        <h3>Any backup tool</h3>
        <p>restic, borg, tarballs, S3/Gitea dumps, terraform state, k8s etcd snapshots — anything scriptable is drillable. Checks validate the OUTCOME, not the tool.</p>
      </div>
      <div>
        <h3>Gates, not reports</h3>
        <p>Preflight blocks risky changes until proof exists. Agents drive it the same way, via the CLI or MCP.</p>
      </div>
      <div>
        <h3>Evidence you can hand over</h3>
        <p>Proofs may be signed; checks, measurements, scope, and expiry remain visible in the local hash-chained record. Trust the signer separately.</p>
      </div>
    </div>
  </details>

  <section class="rgs-footer-grid">
    <div class="rgs-footer-section">
      <h3>Guards &amp; lifelines</h3>
      <dl class="rgs-kv">
        <dt>Lifelines</dt><dd>{{.Footer.Lifelines}}</dd>
        <dt>Guards</dt><dd>{{.Footer.Guards}}</dd>
      </dl>
    </div>
    {{- if .Footer.FreshnessChips}}
    <div class="rgs-footer-section">
      <h3>Proof freshness</h3>
      <div class="rgs-chips">
        {{- range .Footer.FreshnessChips}}
        <span class="rgs-chip"{{if .Warn}} data-warn="true"{{end}}>{{.Count}} {{.Label}}</span>
        {{- end}}
      </div>
      {{- if .Footer.ProblemProofs}}
      <dl class="rgs-kv rgs-kv-compact">
        {{- range .Footer.ProblemProofs}}<dt>{{.ID}}</dt><dd>{{.Status}}</dd>{{end}}
      </dl>
      {{- end}}
    </div>
    {{- end}}
    <div class="rgs-footer-section">
      <h3>Ledger health</h3>
      <dl class="rgs-kv">
        <dt>Entries</dt><dd>{{.Footer.LedgerEntries}}</dd>
        <dt>Chain</dt><dd>{{if .Footer.LedgerOK}}OK{{else}}BROKEN: {{.Footer.LedgerDetail}}{{end}}</dd>
        {{if .Footer.LastDecision}}<dt>Last decision</dt><dd>{{.Footer.LastDecision}}</dd>{{end}}
      </dl>
    </div>
    <div class="rgs-footer-section">
      <h3{{if .Footer.ExpiringSoon}} class="rgs-warn-title"{{end}}>Expiring soon</h3>
      <dl class="rgs-kv"><dt>Proofs</dt><dd>{{.Footer.ExpiringSoon}}</dd></dl>
    </div>
  </section>

  {{- if .RecoveryChain}}
  <details class="rgs-legacy">
    <summary>Recovery chain</summary>
    <dl class="rgs-kv">
      {{- range .RecoveryChain}}
      <dt>{{.Key}}</dt><dd>{{.Value}}</dd>
      {{- end}}
    </dl>
  </details>
  {{- end}}

  <footer class="rgs-footnote">Restore Gap · Offline evidence snapshot · A status page does not intercept commands. Run preflight through a configured hook before a guarded change.</footer>
</main>
</body>
</html>
`))

// statusCSS is the dashboard's entire stylesheet: the validated reference
// palette (light default, dark via prefers-color-scheme — selected steps,
// not an automatic flip), system-ui type, no animation or transition of
// any kind, and wide content that scrolls inside its own container so the
// page body never scrolls horizontally.
var statusCSS = ui.CSS + `
:root {
  --surface: var(--ui-bg); --surface-2: var(--ui-surface); --text-1: var(--ui-text); --text-2: var(--ui-muted);
  --line: var(--ui-border); --accent: var(--ui-accent); --aqua: var(--ui-success);
  --good: var(--ui-success); --warning: var(--ui-warning); --serious: var(--ui-warning); --critical: var(--ui-danger);
  color-scheme: dark;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--surface); color: var(--text-1);
  font-family: var(--ui-font-sans);
  line-height: 1.5;
}
.rgs-shell { max-width: 72rem; margin: 0 auto; padding: 1.5rem 1.25rem 3rem; }
code, .rgs-mono { font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, "Liberation Mono", monospace; }

.rgs-header { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; color: var(--text-2); margin-bottom: 1.25rem; }
.rgs-mark { width: 26px; height: 26px; flex: none; }
.rgs-wordmark { color: var(--text-1); font-weight: 700; font-size: 1.1rem; }
.rgs-wordmark b { font-weight: 800; }
.rgs-tagline { font-size: 0.85rem; }
.rgs-spacer { flex: 1 1 auto; }
.rgs-meta { font-size: 0.8rem; }

.rgs-banner {
  display: flex; align-items: baseline; flex-wrap: wrap; gap: 0.6rem;
  background: var(--surface-2); border: 1px solid var(--line); border-left: 4px solid var(--text-2);
  border-radius: 6px; padding: 0.9rem 1.1rem; margin-bottom: 1.25rem;
}
.rgs-banner[data-status="good"] { border-left-color: var(--good); }
.rgs-banner[data-status="warning"] { border-left-color: var(--warning); }
.rgs-banner[data-status="critical"] { border-left-color: var(--critical); }
.rgs-vicon { font-size: 1.2rem; }
.rgs-banner[data-status="good"] .rgs-vicon { color: var(--good); }
.rgs-banner[data-status="warning"] .rgs-vicon { color: var(--warning); }
.rgs-banner[data-status="critical"] .rgs-vicon { color: var(--critical); }
.rgs-vlabel { font-weight: 700; letter-spacing: 0.04em; }
.rgs-vheadline { font-weight: 600; }
.rgs-vsub { color: var(--text-2); flex-basis: 100%; }

.rgs-decision { margin-top: 1rem; padding: 1rem 1.2rem; border: 1px solid var(--line); border-radius: var(--ui-radius); background: var(--surface-2); }
.rgs-decision-head { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
.rgs-decision h2 { margin: 0; font-size: 1rem; }
.rgs-decision h3 { margin: 0.85rem 0 0.35rem; font-size: 0.85rem; }
.rgs-decision-state { color: var(--accent); font-family: ui-monospace, monospace; font-size: 0.8rem; font-weight: 700; }
.rgs-decision-list { margin: 0; padding-left: 1.2rem; }
.rgs-decision-list li { margin: 0.25rem 0; overflow-wrap: anywhere; }
.rgs-decision-findings { display: grid; gap: 0.5rem; }
.rgs-decision-finding { display: grid; gap: 0.15rem; padding: 0.55rem 0.7rem; border-left: 2px solid var(--line); font-size: 0.82rem; overflow-wrap: anywhere; }
.rgs-decision-finding strong { font-family: ui-monospace, monospace; }
.rgs-decision-finding span { color: var(--text-2); }
.rgs-decision-finding small { color: var(--text-2); font-size: 0.8rem; }
.rgs-decision-note { margin: 0.9rem 0 0; color: var(--text-2); font-size: 0.78rem; }

.rgs-togreen {
  background: var(--surface-2); border: 1px solid var(--line); border-radius: 6px;
  padding: 0.9rem 1.1rem; margin-bottom: 1.25rem;
}
.rgs-togreen h2 { margin: 0 0 0.5rem; font-size: 0.95rem; }
.rgs-togreen-list { margin: 0; padding-left: 1.4rem; font-size: 0.85rem; }
.rgs-togreen-list li { margin-bottom: 0.25rem; }
.rgs-togreen-list code { font-size: 0.8rem; }
.rgs-togreen-more { margin-top: 0.5rem; font-size: 0.85rem; }
.rgs-togreen-more summary { cursor: pointer; color: var(--text-2); }
.rgs-togreen-more .rgs-togreen-list { margin-top: 0.5rem; }
.rgs-togreen-green { margin: 0; color: var(--good); font-weight: 500; }

h2 { font-size: 1.05rem; margin: 1.75rem 0 0.6rem; }
h3 { font-size: 0.9rem; margin: 0 0 0.4rem; color: var(--text-2); }
.rgs-warn-title { color: var(--warning); }
.rgs-muted { color: var(--text-2); }

/* fleet.html's own conflict banner (fleet_html.go's template) also uses
   .rgs-gap — kept here even though the single-host page no longer has a
   caller of its own. */
.rgs-gap {
  display: flex; align-items: baseline; gap: 0.5rem; color: var(--warning);
  background: var(--surface-2); border: 1px solid var(--line); border-radius: 6px;
  padding: 0.5rem 0.8rem; margin-bottom: 0.75rem; font-size: 0.85rem;
}
.rgs-gap span:last-child { color: var(--text-1); }

/* Question 2 — coverage: what is not protected at all. A plain headline
   line always; the candidate list, its folded remainder, and the Fix-this
   remediation prompt appear only when there is something to fix (buildCoverageBlock's
   ShowDetail) — a green coverage block carries no scaffolding. */
.rgs-coverage { margin-top: 1.25rem; }
.rgs-coverage-line { margin: 0 0 0.5rem; font-weight: 500; }
.rgs-covlist { display: flex; flex-direction: column; gap: 0.15rem; margin-bottom: 0.5rem; }
.rgs-covrow {
  display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.2rem 0.75rem;
  padding: 0.25rem 0; border-bottom: 1px dashed var(--line); font-size: 0.85rem;
}
.rgs-covrow:last-child { border-bottom: none; }
.rgs-covkind { color: var(--text-2); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.03em; min-width: 5rem; }
.rgs-covsize { color: var(--text-2); }
.rgs-cov-more { margin: 0.4rem 0; font-size: 0.85rem; }
.rgs-cov-more summary { cursor: pointer; color: var(--text-2); }
.rgs-fixthis { margin-top: 0.6rem; font-size: 0.85rem; }
.rgs-fixthis summary { cursor: pointer; font-weight: 600; }
.rgs-fix-regen { color: var(--text-2); margin: 0.5rem 0 0; }

/* A discover/next --prompt agent brief can run to dozens of lines — capped
   and internally scrollable so one expanded <details> can never itself
   push the page past the mobile gate's 8,000px budget, regardless of how
   many gaps or uncovered candidates it lists. */
.rgs-promptblock {
  background: var(--surface-2); border: 1px solid var(--line); border-radius: 4px;
  padding: 0.6rem 0.8rem; margin: 0.4rem 0 0; font-size: 0.78rem;
  white-space: pre-wrap; overflow-wrap: anywhere;
  max-height: 16rem; overflow-y: auto;
}

/* Question 3 — the unified estate tree (layer -> category -> proof) and its
   four-way view switch, replacing the old per-layer/per-state/per-env/
   per-system checkbox wall. Systems are a VIEW (regrouping the same rows),
   never a flat chip list. */
.rgs-estate { margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid var(--line); }
.rgs-viewswitch { display: flex; flex-wrap: wrap; gap: 0.5rem 0.75rem; margin-bottom: 1rem; }
.rgs-view-toggle {
  display: inline-flex; align-items: center; gap: 0.4rem; min-height: 36px;
  padding: 0.3rem 0.8rem; border: 1px solid var(--line); border-radius: 999px;
  font-size: 0.85rem; color: var(--text-2); cursor: pointer; background: var(--surface-2);
}
.rgs-viewswitch input { width: 16px; height: 16px; accent-color: var(--accent); }
.rgs-view-toggle:has(input:checked) { color: var(--text-1); font-weight: 600; border-color: var(--accent); }

/* Only one of the two panels is ever visible — CSS :has() driven by the
   view-switch radios, zero JavaScript. The "All" and "By layer" radios
   share this exact same panel/content; only "By system" swaps it out. */
.rgs-estate-panel { height: 34rem; overflow-y: auto; scrollbar-gutter: stable; overscroll-behavior: contain; padding-right: 0.25rem; }
.rgs-estate-panel[data-panel="system"] { display: none; }
body:has(#rgs-view-system:checked) .rgs-estate-panel[data-panel="layer"] { display: none; }
body:has(#rgs-view-system:checked) .rgs-estate-panel[data-panel="system"] { display: block; }
/* "Needs attention": hide settled rows (restored/observed/accepted) and
   collapse away any layer left with no genuine gap — an all-clear layer
   disappears entirely rather than showing an empty shell. */
body:has(#rgs-view-attention:checked) .rgs-estate-panel .rgs-row[data-bucket="restored"],
body:has(#rgs-view-attention:checked) .rgs-estate-panel .rgs-row[data-bucket="observed"],
body:has(#rgs-view-attention:checked) .rgs-estate-panel .rgs-row[data-bucket="accepted"] { display: none; }
body:has(#rgs-view-attention:checked) .rgs-estate-panel .rgs-taxlayer[data-hasgap="false"] { display: none; }

/* Each estate row is a plain element, never a <details> — the mobile
   gate's --views 'details' sweep clicks every <details> on the page
   cumulatively (it never re-closes one before the next), so an
   individually-expandable per-proof card would let a ~40-proof estate open
   dozens of cards at once and blow the 8,000px height budget. Everything
   question 3 asks for (state, id, artifact, level, why) is shown directly;
   a genuine gap's exact remediation command is its own visible line
   (.rgs-rownext), never behind a click. */
.rgs-row { border-bottom: 1px dashed var(--line); padding: 0.15rem 0; }
.rgs-row:last-child { border-bottom: none; }
.rgs-rownext {
  background: var(--surface-2); border: 1px solid var(--line); border-radius: 4px;
  padding: 0.35rem 0.6rem; margin: 0.2rem 0 0.4rem; font-size: 0.78rem;
  white-space: pre-wrap; overflow-wrap: anywhere;
}

/* Static explanatory copy, identical on every render — closed by default
   so it never competes with actual recovery data for page height. */
.rgs-integration { margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid var(--line); }
.rgs-integration summary { cursor: pointer; list-style: none; margin: 0 0 0.85rem; }
.rgs-integration summary::-webkit-details-marker { display: none; }
.rgs-integration h2 { margin: 0; }
.rgs-integration-cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr)); gap: 1.25rem; }
.rgs-integration-cols h3 { color: var(--text-1); font-size: 0.88rem; margin: 0 0 0.35rem; }
.rgs-integration-cols p { color: var(--text-2); font-size: 0.82rem; margin: 0; line-height: 1.5; }

/* align-items:start + grid-auto-rows:min-content keep each footer section's
   own height and never stretch/interleave with a neighbor's content;
   min-width:0 on the section itself is load-bearing — without it a grid
   item refuses to shrink below its content's min-content width (a long
   proof id in a .rgs-kv dt) and overflows sideways into the next column
   instead of wrapping. */
.rgs-footer-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
  gap: 1.25rem 1.75rem; margin-top: 2rem; align-items: start; grid-auto-rows: min-content;
}
.rgs-footer-section { min-width: 0; }
.rgs-kv { display: grid; grid-template-columns: minmax(0, max-content) minmax(0, 1fr); gap: 0.15rem 0.75rem; margin: 0; font-size: 0.85rem; }
.rgs-kv dt { color: var(--text-2); overflow-wrap: anywhere; }
/* dd carries everything from a short state word to a full recover command
   or evidence URL — nowrap clipped the long ones at a narrow viewport
   (the fleet mobile gate's "dd.rgs-kv clips" failure). anywhere-wrapping a
   short word occasionally breaks it mid-syllable ("disp/ute/d"); a clipped,
   unreadable command is worse. */
.rgs-kv dd { margin: 0; overflow-wrap: anywhere; }
.rgs-kv-compact { margin-top: 0.5rem; }

.rgs-chips { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.rgs-chip {
  display: inline-block; border: 1px solid var(--line); border-radius: 999px;
  padding: 0.1rem 0.55rem; font-size: 0.78rem; color: var(--text-2); white-space: nowrap;
}
.rgs-chip[data-warn="true"] { color: var(--warning); border-color: var(--warning); }

.rgs-footnote { margin-top: 2rem; color: var(--text-2); font-size: 0.75rem; }

/* Legacy text-renderer parity section (Recovery chain) — closed by
   default: everything in it already lives elsewhere on the page (the
   header origin line, Footer's Guards/Ledger tiles), so this is a
   full-detail fallback, not primary reading, and must not add to the
   page's default height. */
.rgs-legacy { margin-top: 1.25rem; padding-top: 1rem; border-top: 1px solid var(--line); }
.rgs-legacy summary { cursor: pointer; font-weight: 600; font-size: 0.9rem; color: var(--text-2); list-style: none; }
.rgs-legacy summary::-webkit-details-marker { display: none; }
.rgs-legacy dl.rgs-kv { margin-top: 0.75rem; }

/* Taxonomy tree: layer -> category -> proof, with a zero-JavaScript
   checkbox filter bar (:has() only — see buildFilterCSS) and, on a
   multi-environment/multi-system estate, a compact roll-up table. */
.rgs-tax { margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid var(--line); }
.rgs-filterbar { display: flex; flex-wrap: wrap; gap: 0.5rem 0.75rem; margin-bottom: 1rem; }
.rgs-chip-toggle {
  display: inline-flex; align-items: center; gap: 0.35rem; min-height: 36px;
  padding: 0.25rem 0.7rem; border: 1px solid var(--line); border-radius: 999px;
  font-size: 0.82rem; color: var(--text-2); cursor: pointer; background: var(--surface-2);
}
.rgs-chip-toggle input { width: 16px; height: 16px; accent-color: var(--accent); }
.rgs-levels { margin: 0 0 1rem; font-size: 0.85rem; }
.rgs-levels summary { cursor: pointer; color: var(--text-2); }
.rgs-levels dl { margin: 0.5rem 0 0; display: grid; grid-template-columns: auto 1fr; gap: 0.25rem 0.75rem; }
.rgs-levels dt { font-weight: 600; white-space: nowrap; }
.rgs-levels dd { margin: 0; color: var(--text-2); }
.rgs-taxlayer { border: 1px solid var(--line); border-radius: 6px; padding: 0.6rem 0.9rem; margin-bottom: 0.6rem; }
.rgs-taxlayer summary { cursor: pointer; font-weight: 600; font-size: 0.9rem; }
.rgs-conflict { color: var(--warning); font-size: 0.8rem; margin: 0.4rem 0; }
.rgs-taxcat { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-2); margin: 0.75rem 0 0.35rem; font-weight: 600; }
.rgs-taxrow {
  display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.2rem 0.75rem;
  padding: 0.25rem 0; border-bottom: 1px dashed var(--line); font-size: 0.85rem;
}
.rgs-taxrow:last-child { border-bottom: none; }
/* min-width is deliberately small (not the usual ~12rem "don't shrink
   below this" pattern): at a narrow viewport, every extra pixel forced
   here pushes state/level/why onto their own wrapped lines and multiplies
   total page height across dozens of rows — a long proof id already wraps
   fine on its own (see .rgs-taxproof code's overflow-wrap), so this only
   needs to be wide enough to keep a short id from looking cramped. */
.rgs-taxproof { display: flex; flex-direction: column; gap: 0.1rem; min-width: 6rem; max-width: 100%; }
.rgs-taxproof code { overflow-wrap: anywhere; }
/* Artifact is often a full filesystem path with no spaces (a proof id can
   run just as long) — anywhere-wrapping is the only thing that keeps
   either from pushing the row off a narrow viewport (the fleet mobile
   gate's "code right edge at 651px" failure). */
.rgs-taxsub { color: var(--text-2); font-size: 0.75rem; overflow-wrap: anywhere; }
.rgs-taxstate { font-weight: 600; }
.rgs-taxstate[data-bucket="attention"] { color: var(--warning); }
.rgs-taxstate[data-bucket="unreviewed"] { color: var(--warning); }
.rgs-taxstate[data-bucket="observed"] { color: var(--accent); }
.rgs-taxstate[data-bucket="accepted"] { color: var(--accent); }
.rgs-taxstate[data-bucket="restored"] { color: var(--good); }
.rgs-taxlevel { color: var(--text-2); }
.rgs-taxwhy { color: var(--text-2); flex: 1 1 12rem; }
.rgs-taxbinding { color: var(--text-2); font-family: ui-monospace, monospace; white-space: nowrap; }


.rgs-page-title { margin: 2rem 0 1rem; }
.rgs-page-title h1 { font-size: clamp(1.65rem, 5vw, 2.4rem); letter-spacing: -0.035em; line-height: 1.15; margin: 0 0 0.6rem; }
.rgs-page-title p { color: var(--text-2); font-size: 0.8rem; margin: 0; overflow-wrap: anywhere; }
.rgs-shell { max-width: 68rem; }
.rgs-header { border-bottom: 1px solid var(--line); padding-bottom: 1rem; }
.rgs-meta { overflow-wrap: anywhere; }
.ui-kit-skip { min-height: 44px; padding: 10px 16px; }
.rgs-banner { padding: 1.2rem; border-radius: var(--ui-radius); }
.rgs-vheadline { font-size: 1.1rem; }
.rgs-togreen { border-radius: var(--ui-radius); }
.rgs-togreen-list { line-height: 1.7; }
.rgs-togreen-list code { overflow-wrap: anywhere; }
.rgs-viewswitch { justify-content: space-between; }
.rgs-viewswitch fieldset { border: 0; padding: 0; margin: 0; min-width: 0; display: flex; flex-wrap: wrap; gap: 0.4rem; }
.rgs-viewswitch legend { font-size: 0.75rem; color: var(--text-2); margin-bottom: 0.5rem; }
.rgs-view-toggle { border-radius: 8px; font-size: 0.8125rem; }
.rgs-view-toggle:has(input:checked) { background: var(--ui-accent-soft); border-color: var(--ui-accent-strong); }
summary { min-height: 36px; padding: 0.5rem 0; cursor: pointer; overflow-wrap: anywhere; }
summary:focus-visible, .rgs-view-toggle:has(input:focus-visible) { outline: 2px solid var(--accent); outline-offset: 3px; }
.rgs-candidates { margin-top: 0.5rem; }
.rgs-candidates > p { font-size: 0.8125rem; max-width: 70ch; }
.rgs-candidates > .rgs-covlist { max-height: 22rem; overflow-y: auto; }
.rgs-taxlayer { background: var(--surface-2); padding: 0.5rem 0.9rem; }
.rgs-taxrow { gap: 0.4rem 1rem; padding: 0.65rem 0; }
.rgs-taxproof { flex: 1 1 15rem; min-width: 0; }
.rgs-rownext { margin-bottom: 0.85rem; }
.rgs-coverage { padding: 0.2rem 0 1rem; }
.rgs-integration-cols, .rgs-footer-grid { grid-template-columns: repeat(auto-fit, minmax(min(100%, 14rem), 1fr)); }
.rgs-levels dl { grid-template-columns: minmax(0, max-content) minmax(0, 1fr); }
.rgs-levels dd { overflow-wrap: anywhere; }
.rgs-footnote { padding-top: 1rem; border-top: 1px solid var(--line); line-height: 1.7; }
@media (max-width: 480px) { .rgs-shell { padding: 1rem 1rem 2rem; } .rgs-meta { flex-basis: 100%; } .rgs-banner { gap: 0.5rem; } .rgs-vheadline { flex-basis: 100%; } .rgs-estate-panel { height: 30rem; } }
@media print { :root { --surface: #fff; --surface-2: #fff; --text-1: #111; --text-2: #444; --line: #ccc; } .rgs-estate-panel { height: auto; overflow: visible; } }
@media print {
  .rgs-shell { max-width: none; }
}
`
