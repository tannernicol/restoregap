package status

import (
	"bytes"
	"fmt"
	"html/template"
	"path/filepath"
	"sort"
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

// tick strip and sparkline geometry — the validated reference values from
// the dashboard spec (4x14px ticks, 2px gaps, a 60x16 sparkline).
const (
	tickWidth   = 4
	tickHeight  = 14
	tickGap     = 2
	sparkWidth  = 60
	sparkHeight = 16
	// minSparklinePoints is the fewest RTO measurements a sparkline draws;
	// below this a trend line reads as noise, not a trend.
	minSparklinePoints = 3
	// recentRunsShown caps the expanded row detail card's "recent runs"
	// list — 5 is enough to see a trend without reprinting the whole
	// (already-visible-as-ticks) history.
	recentRunsShown = 5
)

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

	KPITiles []kpiTile

	// HasInventory is false only when there are no declared drills and no
	// proofs at all — the one case where the two groups below collapse to
	// a single "nothing yet" line instead of two zero-count headers.
	HasInventory bool
	Groups       []groupData

	Footer statusFooter
}

// kpiTile is one of the four recovery-ladder stat tiles.
type kpiTile struct {
	Label   string
	Count   int
	Meaning string
	Accent  string // good | neutral | muted
}

// groupData is one of the inventory's two explicit groups — "Provably
// recoverable" (level >= restores, strongest first) and "Not proven"
// (declared, with the gaps callout as its subhead) — rendered through the
// same row-grid markup via one template block.
type groupData struct {
	Title      string
	Count      int
	SubMessage string // only "Not proven" sets this (buildGapMessage)
	Rows       []statusRow
}

// checkRow is one drill validate: check's outcome, ready for the row detail
// card: a status glyph, the check type, and its already-human-written
// detail string ("integrity ok; transactions=2372 (>= 2000)").
type checkRow struct {
	Pass   bool
	Type   string
	Detail string
}

// recentRun is one ledger drill entry for the row detail card's "recent
// runs" list — last recentRunsShown, newest first (History itself stays
// oldest-to-newest, which is what the tick strip/sparkline need).
type recentRun struct {
	When     string
	Verified bool
	RTO      string
}

// statusRow is one recovery-inventory row, pre-rendered for the template:
// the tick strip/sparkline (if any) are already built as template.HTML, and
// every field the expandable detail card needs is precomputed here so the
// template stays free of derivation logic.
type statusRow struct {
	LevelLabel string
	LevelDot   string // declared | restores | data-valid | serves
	LevelRank  int    // contextspec.RecoveryLevel.Rung(); groups sort by this, never by string
	Proof      string
	IsDrilled  bool

	HistorySVG template.HTML
	HasHistory bool
	RTO        string
	SparkSVG   template.HTML
	HasSpark   bool

	RPO      string
	ProofAge string
	// MergedReason is set only for attestation-only (!IsDrilled) rows: the
	// one explanation ("attested, no drill", "stale", …), shown ONCE in a
	// single cell spanning History+RTO+RPO — those columns never have
	// anything to draw for a proof that was never drilled. ProofAge is then
	// left as emDash rather than repeating the same text a second time.
	MergedReason string

	// ---- expandable detail card ----

	// Meaning is the one-sentence, level-keyed plain-language line (written
	// once in levelMeaning) — what this row's current rung actually means.
	Meaning string
	Checks  []checkRow

	// Declaration (IsDrilled rows only).
	RecoverCmd     string
	RecoverySource string
	PinCheckCmd    string
	HasPinCheck    bool
	BudgetRTO      string
	BudgetRPO      string

	// Evidence (whenever a proof record exists, either kind of row).
	ObservedAtDisplay string
	ExpiresAtDisplay  string
	ExpiresInDisplay  string
	SignaturePresent  bool
	SigPubKeyPrefix   string

	RecentRuns []recentRun

	// NextStepCommand is set only for a drilled row that is not currently
	// good (declared rung) and has a known source file — the literal
	// re-drill command.
	NextStepCommand string

	// Attestation-only (!IsDrilled) rows only.
	AttestCommand     string
	AttestEvidenceURL string
	// ProposeCommand is always set for an attestation-only row: the
	// conversion-path hint, with a real artifact path when inferArtifactPath
	// found one, a placeholder otherwise.
	ProposeCommand string
}

// levelMeaning is the expandable detail card's plain-language line, written
// once per rung and keyed by the same declared|restores|data-valid|serves
// vocabulary as LevelDot — never re-derived per row.
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

// freshnessChip is one proof-freshness state's count ("28 present"),
// compact enough for a whole footer section — 30+ healthy proofs must never
// each get their own row (see buildFooterFreshness).
type freshnessChip struct {
	Label string // present | expiring | expired | stale | disputed
	Count int
	Warn  bool // every state except "present" is a warn-tinted chip
}

// footerProof is one problem proof (stale/expired/disputed) in the footer's
// short list — name and state only, no "valid until" detail: with the
// state already in FreshnessChips, the detail is noise for a footer.
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
func buildStatusPage(s *Summary) statusPageData {
	rows := make([]statusRow, len(s.Inventory))
	for i, r := range s.Inventory {
		rows[i] = buildStatusRow(r)
	}
	recoverable, notProven := splitInventoryGroups(rows)
	originLabel, originTitle := summarizeOrigin(s.Origin)
	chips, problems := buildFooterFreshness(s.Proofs)

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
		KPITiles:         buildKPITiles(s.Inventory),
		HasInventory:     len(s.Inventory) > 0,
		Groups: []groupData{
			{Title: "Provably recoverable", Count: len(recoverable), Rows: recoverable},
			{Title: "Not proven", Count: len(notProven), SubMessage: buildGapMessage(s.Inventory), Rows: notProven},
		},
		Footer: statusFooter{
			Lifelines: s.Lifelines, Guards: s.Guards,
			FreshnessChips: chips, ProblemProofs: problems,
			LedgerEntries: s.LedgerEntries, LedgerOK: s.LedgerOK, LedgerDetail: s.LedgerDetail,
			LastDecision: s.LastDecision, ExpiringSoon: s.ExpiringSoon,
		},
	}
}

// splitInventoryGroups partitions rows into "provably recoverable" (level
// >= restores) and "not proven" (declared), matching Statuspage-style
// component grouping — an explicit split instead of one sorted table. The
// recoverable group is re-sorted strongest-first (the opposite of the
// weakest-first order buildInventory produces for the text renderer/overall
// gap-first reading); the not-proven group keeps its incoming (proof-id)
// order.
func splitInventoryGroups(rows []statusRow) (recoverable, notProven []statusRow) {
	for _, r := range rows {
		if r.LevelDot == "declared" {
			notProven = append(notProven, r)
		} else {
			recoverable = append(recoverable, r)
		}
	}
	sort.SliceStable(recoverable, func(i, j int) bool { return recoverable[i].LevelRank > recoverable[j].LevelRank })
	return recoverable, notProven
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

// buildGapMessage is the "Not proven" group's subhead: split by IsDrilled,
// since "attested but never drilled" is only true for a proof that never
// had a drill at all — a declared drill whose proof merely expired or came
// back disputed WAS drilled, and saying otherwise overclaims in the other
// direction. Empty when there are no declared rows at all. A zero-count
// clause is suppressed rather than printed ("0 never drilled" says nothing
// true).
func buildGapMessage(rows []InventoryRow) string {
	neverDrilled, drilledUnproven := 0, 0
	for _, r := range rows {
		if r.Level != contextspec.LevelDeclared.String() {
			continue
		}
		if r.IsDrilled {
			drilledUnproven++
		} else {
			neverDrilled++
		}
	}
	if neverDrilled == 0 && drilledUnproven == 0 {
		return ""
	}
	var parts []string
	if neverDrilled > 0 {
		parts = append(parts, fmt.Sprintf("%d never drilled", neverDrilled))
	}
	if drilledUnproven > 0 {
		parts = append(parts, fmt.Sprintf("%d drilled but currently unproven", drilledUnproven))
	}
	return strings.Join(parts, ", ") + " — these are beliefs, not capabilities."
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
// (stale/expired/disputed) — a healthy proof gets counted, never its own
// row. "expiring" is a chip here but not a problem row: it already has its
// own "Expiring soon" footer tile, so listing it again here would be the
// same redundancy this rework exists to remove.
func buildFooterFreshness(proofs []ProofState) ([]freshnessChip, []footerProof) {
	order := []string{"present", "expiring", "expired", "stale", "disputed"}
	counts := make(map[string]int, len(order))
	var problems []footerProof
	for _, p := range proofs {
		counts[p.Status]++
		switch p.Status {
		case "stale", "expired", "disputed":
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

// buildStatusRow renders one inventory row's SVGs and detail-card fields,
// deciding between the normal History/RTO/RPO columns and an
// attestation-only row's single merged reason cell. A merged row's
// ProofAge column is left as emDash — MergedReason already carries that
// same string once, in the cell where History/RTO/RPO would otherwise sit,
// and repeating it in ProofAge too is exactly the redundancy that shape
// exists to avoid.
func buildStatusRow(r InventoryRow) statusRow {
	dot := levelDotClass(r.LevelRank)
	row := statusRow{
		LevelLabel: r.Level,
		LevelDot:   dot,
		LevelRank:  r.LevelRank,
		Proof:      r.Proof,
		IsDrilled:  r.IsDrilled,
		Meaning:    levelMeaning[dot],
		RecentRuns: recentRunsFromHistory(r.History),

		ObservedAtDisplay: r.ObservedAtDisplay,
		ExpiresAtDisplay:  r.ExpiresAtDisplay,
		ExpiresInDisplay:  r.ExpiresInDisplay,
		SignaturePresent:  r.SignaturePresent,
		SigPubKeyPrefix:   r.SigPubKeyPrefix,
	}
	if !r.IsDrilled {
		row.MergedReason = r.ProofAge
		row.ProofAge = emDash
		row.AttestCommand = r.AttestCommand
		row.AttestEvidenceURL = r.AttestEvidenceURL
		row.ProposeCommand = proposeCommand(r)
		return row
	}
	row.RPO = r.RPO
	row.RTO = r.RTO
	row.ProofAge = r.ProofAge
	row.RecoverCmd = r.RecoverCmd
	row.RecoverySource = r.RecoverySource
	row.PinCheckCmd = r.PinCheckCmd
	row.HasPinCheck = r.PinCheckCmd != ""
	row.BudgetRTO = r.BudgetRTO
	row.BudgetRPO = r.BudgetRPO
	row.NextStepCommand = nextStepCommand(r)
	for _, c := range r.Checks {
		row.Checks = append(row.Checks, checkRow{Pass: c.Pass, Type: c.Type, Detail: c.Detail})
	}
	if svg, ok := renderHistoryStrip(r.History); ok {
		row.HistorySVG, row.HasHistory = svg, true
	}
	if svg, ok := renderSparkline(r.History); ok {
		row.SparkSVG, row.HasSpark = svg, true
	}
	return row
}

// recentRunsFromHistory takes the last recentRunsShown entries of a
// proof's (oldest-to-newest) drill history and returns them newest-first —
// the detail card's "recent runs" list reads top-down as "most recent
// first", the opposite order from the tick strip/sparkline it sits beside.
func recentRunsFromHistory(history []RunTick) []recentRun {
	n := len(history)
	if n == 0 {
		return nil
	}
	start := 0
	if n > recentRunsShown {
		start = n - recentRunsShown
	}
	tail := history[start:]
	out := make([]recentRun, len(tail))
	for i, t := range tail {
		out[len(tail)-1-i] = recentRun{
			When:     t.When.UTC().Format("2006-01-02"),
			Verified: t.Verified,
			RTO:      formatMs(t.RTOMs),
		}
	}
	return out
}

// nextStepCommand is the literal re-drill command shown in a drilled row's
// detail card, but only when that row is not currently good (declared
// rung) and its source context file is known — restoregap drill --context
// requires a real file, so a row with no SourceFile (never realistically
// reachable for a drilled row: the built-in default declares no drills)
// gets no command rather than a broken one.
func nextStepCommand(r InventoryRow) string {
	if !r.IsDrilled || r.Level != contextspec.LevelDeclared.String() || r.SourceFile == "" {
		return ""
	}
	return fmt.Sprintf("restoregap drill --context %s --proof %s", r.SourceFile, r.Proof)
}

// proposeCommand is the attestation-only row's conversion-path hint, always
// present: a real artifact path when inferArtifactPath found one, an
// <artifact> placeholder otherwise. --source has no way to be inferred (an
// attestation declares no recovery source at all), so it is always a
// literal <recovery-source> placeholder for the operator to fill in.
func proposeCommand(r InventoryRow) string {
	artifact := "<artifact>"
	if r.ProposeArtifact != "" {
		artifact = r.ProposeArtifact
	}
	return fmt.Sprintf("restoregap drill propose %s --source <recovery-source>", artifact)
}

// buildKPITiles counts inventory rows per recovery rung. The order is
// fixed: declared (the gap signal) through serves (the loudest win).
func buildKPITiles(rows []InventoryRow) []kpiTile {
	counts := make(map[string]int, 4)
	for _, r := range rows {
		counts[r.Level]++
	}
	return []kpiTile{
		{
			Label: "Declared", Count: counts[contextspec.LevelDeclared.String()],
			Meaning: "drill declared, no live verified proof — not proven", Accent: "muted",
		},
		{
			Label: "Restores", Count: counts[contextspec.LevelRestores.String()],
			Meaning: "recover produced validated content", Accent: "neutral",
		},
		{
			Label: "Data-valid", Count: counts[contextspec.LevelDataValid.String()],
			Meaning: "verified, incl. a sqlite/git integrity check", Accent: "neutral",
		},
		{
			Label: "Serves", Count: counts[contextspec.LevelServes.String()],
			Meaning: "boots and answers probes", Accent: "good",
		},
	}
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

// levelDotClass maps a row's raw LevelRank (contextspec.RecoveryLevel.Rung())
// to its badge dot color class, so the template never string-matches the
// display label to pick a color.
func levelDotClass(levelRank int) string {
	switch levelRank {
	case contextspec.LevelRestores.Rung():
		return "restores"
	case contextspec.LevelDataValid.Rung():
		return "data-valid"
	case contextspec.LevelServes.Rung():
		return "serves"
	default:
		return "declared"
	}
}

// formatMs renders a millisecond duration the way contextspec.FormatRTO
// renders seconds ("1.1s"), so a tick's title and the RTO column read the
// same way. Non-positive is "not recorded" (rto_ms is omitempty on the
// ledger payload), never a misleading "0s".
func formatMs(ms int64) string {
	if ms <= 0 {
		return emDash
	}
	return time.Duration(ms * int64(time.Millisecond)).Round(100 * time.Millisecond).String()
}

// renderHistoryStrip builds the heartbeat tick strip for one proof's drill
// runs, oldest to newest: one 4x14 rounded rect per run, verified green /
// not-verified red, a native <title> tooltip carrying the date, outcome,
// and RTO. Returns ok=false when there is nothing to draw.
func renderHistoryStrip(ticks []RunTick) (svg template.HTML, ok bool) {
	if len(ticks) == 0 {
		return "", false
	}
	n := len(ticks)
	width := n*tickWidth + (n-1)*tickGap
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="rgs-ticks" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="drill history, %d run(s)">`,
		width, tickHeight, width, tickHeight, n)
	for i, t := range ticks {
		x := i * (tickWidth + tickGap)
		color, state := "var(--critical)", "not verified"
		if t.Verified {
			color, state = "var(--good)", "verified"
		}
		title := fmt.Sprintf("%s · %s · %s", t.When.UTC().Format("2006-01-02"), state, formatMs(t.RTOMs))
		fmt.Fprintf(&b, `<rect x="%d" y="0" width="%d" height="%d" rx="1" fill="%s"><title>%s</title></rect>`,
			x, tickWidth, tickHeight, color, template.HTMLEscapeString(title))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()), true
}

// renderSparkline builds a single-series RTO-over-time line for one proof's
// drill runs, oldest to newest. Only emitted at >= minSparklinePoints
// measured points; the caller falls back to just the RTO string otherwise.
func renderSparkline(ticks []RunTick) (svg template.HTML, ok bool) {
	pts := make([]int64, 0, len(ticks))
	for _, t := range ticks {
		if t.RTOMs > 0 {
			pts = append(pts, t.RTOMs)
		}
	}
	if len(pts) < minSparklinePoints {
		return "", false
	}
	lo, hi := pts[0], pts[0]
	for _, v := range pts {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	var coords strings.Builder
	span := hi - lo
	for i, v := range pts {
		x := float64(i) * float64(sparkWidth) / float64(len(pts)-1)
		y := float64(sparkHeight) / 2
		if span != 0 {
			y = float64(sparkHeight) - (float64(v-lo)/float64(span))*float64(sparkHeight)
		}
		if i > 0 {
			coords.WriteByte(' ')
		}
		fmt.Fprintf(&coords, "%.1f,%.1f", x, y)
	}
	title := template.HTMLEscapeString(fmt.Sprintf("RTO trend: min %s, max %s", formatMs(lo), formatMs(hi)))
	svgStr := fmt.Sprintf(
		`<svg class="rgs-spark" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="%s">`+
			`<polyline points="%s" fill="none" stroke="var(--accent)" stroke-width="2"><title>%s</title></polyline></svg>`,
		sparkWidth, sparkHeight, sparkWidth, sparkHeight, title, coords.String(), title)
	return template.HTML(svgStr), true
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

// statusPageTemplate is the ENTIRE HTML dashboard: header, verdict banner,
// KPI tiles, the two-group recovery inventory (each row a native
// <details>/<summary> disclosure), the value/integration strip, and the
// footer. It does not use report.pageTemplate — none of this has a
// KVSection analog, and reusing that shell would mean bolting custom markup
// onto a generic key-value dump.
//
// The inventory is a CSS-grid "table" (role="table"/"row"/"cell"), not a
// real <table>: <details> is not valid HTML as a direct <table>/<tbody>
// child, and a native, zero-JS expand/collapse per row needs <details>. One
// shared grid-template-columns (.rgs-cols) keeps the header and every row's
// columns aligned; an attestation-only row's merged cell spans three
// tracks with grid-column instead of a <td colspan>.
var statusPageTemplate = template.Must(template.New("status").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>restoregap status</title>
<link rel="icon" type="image/svg+xml" href="{{.FaviconHref}}">
<style>` + statusCSS + `</style>
</head>
<body>
<div class="rgs-shell">
  <header class="rgs-header">
    {{.MarkInline}}
    <span class="rgs-wordmark">restore<b>gap</b></span>
    <span class="rgs-tagline">Recovery-chain status</span>
    <span class="rgs-spacer"></span>
    <span class="rgs-meta" title="{{.OriginTitle}}">generated {{.GeneratedAt}} · {{.Origin}}</span>
  </header>

  <section class="rgs-banner" data-status="{{.VerdictClass}}">
    <span class="rgs-vicon" aria-hidden="true">{{.VerdictIcon}}</span>
    <span class="rgs-vlabel">{{.VerdictLabel}}</span>
    <span class="rgs-vheadline">{{.VerdictHeadline}}</span>
    {{if .InventorySummary}}<span class="rgs-vsub">{{.InventorySummary}}</span>{{end}}
  </section>

  <section class="rgs-kpis">
    {{- range .KPITiles}}
    <div class="rgs-tile" data-accent="{{.Accent}}">
      <div class="rgs-tile-num">{{.Count}}</div>
      <div class="rgs-tile-label">{{.Label}}</div>
      <div class="rgs-tile-meaning">{{.Meaning}}</div>
    </div>
    {{- end}}
  </section>

  <h2>Recovery inventory</h2>
  {{- if .HasInventory}}
  {{- range .Groups}}
  <h3 class="rgs-group-header">{{.Title}} <span class="rgs-group-count">— {{.Count}}</span></h3>
  {{- if .SubMessage}}
  <div class="rgs-gap" data-status="warning">
    <span aria-hidden="true">⚠</span> <span>{{.SubMessage}}</span>
  </div>
  {{- end}}
  {{- if .Rows}}
  <div class="rgs-rowgrid" role="table" aria-label="{{.Title}}">
    <div class="rgs-cols rgs-rowgrid-head" role="row">
      <div role="columnheader" aria-hidden="true"></div>
      <div role="columnheader">Level</div>
      <div role="columnheader">Proof</div>
      <div role="columnheader">History</div>
      <div role="columnheader">RTO</div>
      <div role="columnheader">RPO</div>
      <div role="columnheader">Proof age</div>
    </div>
    {{- range .Rows}}
    <details class="rgs-row">
      <summary class="rgs-cols rgs-row-summary" role="row">
        <span class="rgs-chevron" aria-hidden="true">&#9656;</span>
        <span role="cell"><span class="rgs-dot" data-level="{{.LevelDot}}"></span> {{.LevelLabel}}</span>
        <span role="cell"><code>{{.Proof}}</code></span>
        {{- if .IsDrilled}}
        <span role="cell">{{if .HasHistory}}{{.HistorySVG}}{{else}}<span class="rgs-muted">—</span>{{end}}</span>
        <span role="cell">{{.RTO}}{{if .HasSpark}} {{.SparkSVG}}{{end}}</span>
        <span role="cell">{{.RPO}}</span>
        {{- else}}
        <span role="cell" class="rgs-cell-merged rgs-muted">{{.MergedReason}}</span>
        {{- end}}
        <span role="cell">{{.ProofAge}}</span>
      </summary>
      <div class="rgs-row-detail">
        <p class="rgs-meaning">{{.Meaning}}</p>
        {{- if .IsDrilled}}
        {{- if .Checks}}
        <div class="rgs-detail-block">
          <h4>Checks</h4>
          {{- range .Checks}}
          <div class="rgs-check" data-pass="{{.Pass}}"><span aria-hidden="true">{{if .Pass}}✓{{else}}✕{{end}}</span> <code class="rgs-check-type">{{.Type}}</code> — {{.Detail}}</div>
          {{- end}}
        </div>
        {{- end}}
        <div class="rgs-detail-block">
          <h4>Declaration</h4>
          <dl class="rgs-kv">
            <dt>Recover</dt><dd><code>{{.RecoverCmd}}</code></dd>
            {{- if .HasPinCheck}}
            <dt>Pin check</dt><dd><code>{{.PinCheckCmd}}</code></dd>
            {{- end}}
            <dt>Recovery source</dt><dd><code>{{.RecoverySource}}</code></dd>
            <dt>RTO budget</dt><dd>declared {{.BudgetRTO}} · measured {{.RTO}}</dd>
            <dt>RPO budget</dt><dd>declared {{.BudgetRPO}} · measured {{.RPO}}</dd>
          </dl>
        </div>
        <div class="rgs-detail-block">
          <h4>Evidence</h4>
          <dl class="rgs-kv">
            <dt>Proof id</dt><dd><code>{{.Proof}}</code></dd>
            <dt>Observed</dt><dd>{{.ObservedAtDisplay}}</dd>
            <dt>Expires</dt><dd>{{.ExpiresAtDisplay}} ({{.ExpiresInDisplay}})</dd>
            <dt>Signature</dt><dd>{{if .SignaturePresent}}yes ({{.SigPubKeyPrefix}}…){{else}}no{{end}}</dd>
          </dl>
        </div>
        {{- if .RecentRuns}}
        <div class="rgs-detail-block">
          <h4>Recent runs</h4>
          {{- range .RecentRuns}}
          <div class="rgs-run">{{.When}} · <span class="rgs-run-verdict" data-pass="{{.Verified}}">{{if .Verified}}✓ verified{{else}}✕ failed{{end}}</span> · {{.RTO}}</div>
          {{- end}}
        </div>
        {{- end}}
        {{- if .NextStepCommand}}
        <div class="rgs-detail-block rgs-nextstep">
          <h4>Next step</h4>
          <pre><code>{{.NextStepCommand}}</code></pre>
        </div>
        {{- end}}
        {{- else}}
        <div class="rgs-detail-block">
          <h4>What this attestation asserts</h4>
          <dl class="rgs-kv">
            <dt>Command</dt><dd><code>{{.AttestCommand}}</code></dd>
            <dt>Evidence URL</dt><dd>{{.AttestEvidenceURL}}</dd>
          </dl>
        </div>
        <div class="rgs-detail-block">
          <h4>Evidence</h4>
          <dl class="rgs-kv">
            <dt>Proof id</dt><dd><code>{{.Proof}}</code></dd>
            <dt>Observed</dt><dd>{{.ObservedAtDisplay}}</dd>
            <dt>Expires</dt><dd>{{.ExpiresAtDisplay}} ({{.ExpiresInDisplay}})</dd>
            <dt>Signature</dt><dd>{{if .SignaturePresent}}yes ({{.SigPubKeyPrefix}}…){{else}}no{{end}}</dd>
          </dl>
        </div>
        <div class="rgs-detail-block rgs-nextstep">
          <h4>Convert to a real drill</h4>
          <pre><code>{{.ProposeCommand}}</code></pre>
        </div>
        {{- end}}
      </div>
    </details>
    {{- end}}
  </div>
  {{- else}}
  <p class="rgs-muted">None.</p>
  {{- end}}
  {{- end}}
  {{- else}}
  <p class="rgs-muted">No declared drills or proofs yet.</p>
  {{- end}}

  <section class="rgs-integration">
    <h2>What this proves · how it plugs in</h2>
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
        <p>Ed25519-signed proofs carry real measurements, expire on a schedule, and land in a hash-chained ledger.</p>
      </div>
    </div>
  </section>

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

  <footer class="rgs-footnote">Generated by restoregap · self-contained evidence artifact</footer>
</div>
</body>
</html>
`))

// statusCSS is the dashboard's entire stylesheet: the validated reference
// palette (light default, dark via prefers-color-scheme — selected steps,
// not an automatic flip), system-ui type, no animation or transition of
// any kind, and wide content that scrolls inside its own container so the
// page body never scrolls horizontally.
const statusCSS = `
:root {
  --surface: #fcfcfb; --surface-2: #f4f4f2; --text-1: #0b0b0b; --text-2: #52514e;
  --line: #e4e4e0; --accent: #2a78d6; --aqua: #1baf7a;
  --good: #0ca30c; --warning: #fab219; --serious: #ec835a; --critical: #d03b3b;
}
@media (prefers-color-scheme: dark) {
  :root {
    --surface: #1a1a19; --surface-2: #232322; --text-1: #ffffff; --text-2: #c3c2b7;
    --line: #343432; --accent: #3987e5; --aqua: #199e70;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--surface); color: var(--text-1);
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
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

.rgs-kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem; }
.rgs-tile { background: var(--surface-2); border: 1px solid var(--line); border-radius: 6px; padding: 0.85rem 1rem; }
.rgs-tile-num { font-size: 1.75rem; font-weight: 700; color: var(--text-1); }
.rgs-tile[data-accent="good"] .rgs-tile-num { color: var(--good); }
.rgs-tile[data-accent="muted"] .rgs-tile-num { color: var(--text-2); }
.rgs-tile-label { font-weight: 600; font-size: 0.85rem; margin-top: 0.2rem; }
.rgs-tile-meaning { color: var(--text-2); font-size: 0.8rem; margin-top: 0.15rem; }

h2 { font-size: 1.05rem; margin: 1.75rem 0 0.6rem; }
h3 { font-size: 0.9rem; margin: 0 0 0.4rem; color: var(--text-2); }
.rgs-warn-title { color: var(--warning); }
.rgs-muted { color: var(--text-2); }

.rgs-group-header { margin: 1.5rem 0 0.4rem; font-size: 0.95rem; color: var(--text-1); }
.rgs-group-count { color: var(--text-2); font-weight: 400; }

.rgs-gap {
  display: flex; align-items: baseline; gap: 0.5rem; color: var(--warning);
  background: var(--surface-2); border: 1px solid var(--line); border-radius: 6px;
  padding: 0.5rem 0.8rem; margin-bottom: 0.75rem; font-size: 0.85rem;
}
.rgs-gap span:last-child { color: var(--text-1); }

/* The inventory is a CSS-grid "table", not a real <table>: <details> is
   invalid as a direct <table>/<tbody> child, and a native, zero-JS
   expand/collapse per row needs <details>. One shared grid-template-columns
   keeps the header and every row aligned; it scrolls in its own container
   on narrow viewports so the page body never scrolls horizontally. */
.rgs-cols {
  display: grid;
  grid-template-columns: 1.1rem 8rem minmax(9rem, 1fr) 6.5rem 6.5rem 5.5rem 9rem;
  column-gap: 0.75rem;
  align-items: center;
}
.rgs-rowgrid { border: 1px solid var(--line); border-radius: 6px; overflow-x: auto; margin-bottom: 0.5rem; }
.rgs-rowgrid-head { min-width: 54rem; padding: 0.5rem 0.75rem; background: var(--surface-2); color: var(--text-2); font-weight: 600; font-size: 0.8rem; border-bottom: 1px solid var(--line); }
.rgs-row { border-bottom: 1px solid var(--line); }
.rgs-row:last-child { border-bottom: none; }
.rgs-row-summary {
  min-width: 54rem; padding: 0.5rem 0.75rem; font-size: 0.85rem; cursor: pointer; list-style: none;
}
.rgs-row-summary::-webkit-details-marker { display: none; }
.rgs-row-summary::marker { content: ""; }
.rgs-chevron { color: var(--text-2); }
.rgs-row[open] > .rgs-row-summary .rgs-chevron { transform: rotate(90deg); }
.rgs-cell-merged { grid-column: span 3; }

.rgs-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 0.3rem; background: var(--text-2); }
.rgs-dot[data-level="declared"] { background: var(--text-2); }
.rgs-dot[data-level="restores"] { background: var(--accent); }
.rgs-dot[data-level="data-valid"] { background: var(--aqua); }
.rgs-dot[data-level="serves"] { background: var(--good); }

.rgs-ticks, .rgs-spark { vertical-align: middle; }

.rgs-row-detail { padding: 0.25rem 1rem 1rem 2.6rem; font-size: 0.85rem; border-top: 1px dashed var(--line); }
.rgs-meaning { color: var(--text-1); font-weight: 500; margin: 0.5rem 0 0.9rem; max-width: 46rem; }
.rgs-detail-block { margin-bottom: 0.85rem; }
.rgs-detail-block h4 { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-2); margin: 0 0 0.35rem; font-weight: 600; }
.rgs-check, .rgs-run { padding: 0.1rem 0; }
.rgs-check[data-pass="true"] span:first-child { color: var(--good); }
.rgs-check[data-pass="false"] span:first-child { color: var(--critical); }
/* Text wears text tokens; only the verdict word (with its glyph) carries
   status color — a fully status-colored line makes dates read as alerts. */
.rgs-run { color: var(--text-2); }
.rgs-run-verdict[data-pass="true"] { color: var(--good); }
.rgs-run-verdict[data-pass="false"] { color: var(--critical); }
.rgs-nextstep pre, .rgs-detail-block pre {
  background: var(--surface-2); border: 1px solid var(--line); border-radius: 4px;
  padding: 0.5rem 0.7rem; overflow-x: auto; margin: 0;
}
.rgs-nextstep pre code, .rgs-detail-block pre code { font-size: 0.8rem; }

.rgs-integration { margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid var(--line); }
.rgs-integration h2 { margin: 0 0 0.85rem; }
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
/* dd values are short state words/counts — anywhere-wrapping breaks them
   letter-by-letter in a tight column, which reads as "disp/ute/d". */
.rgs-kv dd { margin: 0; white-space: nowrap; }
.rgs-kv-compact { margin-top: 0.5rem; }

.rgs-chips { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.rgs-chip {
  display: inline-block; border: 1px solid var(--line); border-radius: 999px;
  padding: 0.1rem 0.55rem; font-size: 0.78rem; color: var(--text-2); white-space: nowrap;
}
.rgs-chip[data-warn="true"] { color: var(--warning); border-color: var(--warning); }

.rgs-footnote { margin-top: 2rem; color: var(--text-2); font-size: 0.75rem; }

@media print {
  .rgs-shell { max-width: none; }
  .rgs-rowgrid { overflow-x: visible; border: none; }
  .rgs-row-summary, .rgs-rowgrid-head { min-width: 0; }
  /* A collapsed <details> is exactly the "hidden on paper" case the calm
     design otherwise avoids — force every row's detail card open so a
     printed/exported page still shows everything. */
  .rgs-row-detail { display: block !important; }
  .rgs-chevron { display: none; }
}
`
