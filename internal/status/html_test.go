// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/ledger"
)

// mkDrillEntry builds a minimal ledger drill entry for history tests — only
// the fields drillHistoryByProof reads.
func mkDrillEntry(when time.Time, proofID, mode string, verified bool, rtoMs int64) ledger.Entry {
	return ledger.Entry{
		EntryType: ledger.EntryDrill,
		CreatedAt: when,
		Payload: ledger.Payload{Drill: &ledger.DrillPayload{
			ProofID: proofID, Mode: mode, Verified: verified, RTOMs: rtoMs,
		}},
	}
}

// ---- history collection (drillHistoryByProof) ---------------------------

func TestDrillHistoryByProofExcludesPinCheckAndKeepsOrder(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		mkDrillEntry(base, "p", "drill", true, 100),
		mkDrillEntry(base.Add(time.Hour), "p", "pin_check", true, 999),
		mkDrillEntry(base.Add(2*time.Hour), "p", "drill", false, 200),
	}
	hist := drillHistoryByProof(entries, map[string]bool{"p": true})
	got := hist["p"]
	if len(got) != 2 {
		t.Fatalf("got %d ticks, want 2 (pin_check excluded): %+v", len(got), got)
	}
	for _, tick := range got {
		if tick.RTOMs == 999 {
			t.Errorf("pin_check entry leaked into history: %+v", got)
		}
	}
	if got[0].RTOMs != 100 || got[1].RTOMs != 200 {
		t.Errorf("not oldest->newest: %+v", got)
	}
	if !got[0].Verified || got[1].Verified {
		t.Errorf("verified flags wrong: %+v", got)
	}
}

func TestDrillHistoryByProofCapsAtMaxAndIgnoresUnknownIDs(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	var entries []ledger.Entry
	for i := 0; i < 25; i++ {
		entries = append(entries, mkDrillEntry(base.Add(time.Duration(i)*24*time.Hour), "p", "drill", i%2 == 0, int64(1000+i)))
	}
	entries = append(entries, mkDrillEntry(base.Add(100*24*time.Hour), "unknown-proof", "drill", true, 1))

	hist := drillHistoryByProof(entries, map[string]bool{"p": true})
	got := hist["p"]
	if len(got) != maxHistoryTicks {
		t.Fatalf("got %d ticks, want cap %d", len(got), maxHistoryTicks)
	}
	if got[0].RTOMs != 1005 {
		t.Errorf("first kept tick RTOMs = %d, want 1005 (oldest of the last %d)", got[0].RTOMs, maxHistoryTicks)
	}
	if got[len(got)-1].RTOMs != 1024 {
		t.Errorf("last tick RTOMs = %d, want 1024 (newest)", got[len(got)-1].RTOMs)
	}
	if _, ok := hist["unknown-proof"]; ok {
		t.Errorf("a drill entry for an id not in the known set must be ignored, got an entry for it")
	}
}

// TestGatherAttachesDrillHistoryFromLedger is the full Gather -> processLedger
// -> attachDrillHistory pipeline against a real ledger file, not just the
// in-process drillHistoryByProof unit tests above.
func TestGatherAttachesDrillHistoryFromLedger(t *testing.T) {
	dir := t.TempDir()
	ctxPath := writeContextFile(t, dir, "ctx.yml", `version: 2
drills:
  - proof: money-db-recovery
    artifact: /fake
    recover: "true"
proofs:
  - id: money-db-recovery
    status: validated
    observed_at: "2026-08-20T00:00:00Z"
    verified: true
    measurements:
      rto_seconds: 2.1
      checks: [{type: serve, pass: true, detail: "ready"}]
`)
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	for i, verified := range []bool{true, true, false} {
		if _, err := ledger.AppendNow(ledgerPath, ledger.EntryDrill, "agent/test", ledger.Payload{
			Drill: &ledger.DrillPayload{ProofID: "money-db-recovery", Mode: "drill", Verified: verified, RTOMs: int64(1000 + i*100)},
		}); err != nil {
			t.Fatalf("append drill %d: %v", i, err)
		}
	}
	if _, err := ledger.AppendNow(ledgerPath, ledger.EntryDrill, "agent/test", ledger.Payload{
		Drill: &ledger.DrillPayload{ProofID: "money-db-recovery", Mode: "pin_check", Verified: true, RTOMs: 1},
	}); err != nil {
		t.Fatalf("append pin_check: %v", err)
	}

	s, err := Gather(Request{ContextPaths: []string{ctxPath}, LedgerPath: ledgerPath, AsOf: "2026-08-20T12:00:00Z"})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if len(s.Inventory) != 1 {
		t.Fatalf("got %d rows, want 1", len(s.Inventory))
	}
	hist := s.Inventory[0].History
	if len(hist) != 3 {
		t.Fatalf("got %d history ticks, want 3 (pin_check excluded): %+v", len(hist), hist)
	}
	if !hist[0].Verified || !hist[1].Verified || hist[2].Verified {
		t.Errorf("verified flags out of order: %+v", hist)
	}
	if hist[0].RTOMs != 1000 || hist[2].RTOMs != 1200 {
		t.Errorf("unexpected RTOMs ordering: %+v", hist)
	}
}

// ---- SVG builders ---------------------------------------------------------

func TestRenderHistoryStripTicksInOrderWithClasses(t *testing.T) {
	ticks := []RunTick{
		{When: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), Verified: true, RTOMs: 1100},
		{When: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC), Verified: false, RTOMs: 1300},
		{When: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC), Verified: true, RTOMs: 900},
	}
	svg, ok := renderHistoryStrip(ticks)
	if !ok {
		t.Fatal("expected a strip for 3 ticks")
	}
	html := string(svg)
	if n := strings.Count(html, "<rect"); n != 3 {
		t.Fatalf("got %d rects, want 3, svg:\n%s", n, html)
	}
	idx := 0
	for _, want := range []string{"var(--good)", "var(--critical)", "var(--good)"} {
		i := strings.Index(html[idx:], want)
		if i < 0 {
			t.Fatalf("missing %q in tick order starting at %d, svg:\n%s", want, idx, html)
		}
		idx += i + len(want)
	}
	if !strings.Contains(html, "2026-08-01 · verified · 1.1s") {
		t.Errorf("missing verified tick title, svg:\n%s", html)
	}
	if !strings.Contains(html, "2026-08-02 · not verified") {
		t.Errorf("missing not-verified tick title, svg:\n%s", html)
	}
}

func TestRenderHistoryStripEmptyWhenNoTicks(t *testing.T) {
	if svg, ok := renderHistoryStrip(nil); ok || svg != "" {
		t.Errorf("expected ok=false, empty svg for no ticks, got %v %q", ok, svg)
	}
}

func TestRenderSparklineOnlyAtThreeOrMorePoints(t *testing.T) {
	two := []RunTick{{RTOMs: 100}, {RTOMs: 200}}
	if _, ok := renderSparkline(two); ok {
		t.Errorf("2 measured points should not draw a sparkline")
	}
	three := []RunTick{{RTOMs: 100}, {RTOMs: 200}, {RTOMs: 150}}
	svg, ok := renderSparkline(three)
	if !ok {
		t.Fatal("3 measured points should draw a sparkline")
	}
	if !strings.Contains(string(svg), "<polyline") {
		t.Errorf("missing polyline, svg:\n%s", svg)
	}
	if !strings.Contains(string(svg), "min") || !strings.Contains(string(svg), "max") {
		t.Errorf("missing min/max title, svg:\n%s", svg)
	}
}

// ---- attestation-only rows -----------------------------------------------

func TestBuildStatusRowAttestedOnlyRendersReasonNoStrip(t *testing.T) {
	row := buildStatusRow(InventoryRow{
		Level: "declared", Proof: "manual-key", IsDrilled: false,
		RPO: emDash, RTO: emDash, ProofAge: "attested, no drill",
	})
	if row.MergedReason != "attested, no drill" {
		t.Errorf("MergedReason = %q, want %q", row.MergedReason, "attested, no drill")
	}
	if row.HasHistory || row.HasSpark || row.HistorySVG != "" || row.SparkSVG != "" {
		t.Errorf("attested-only row must render no strip/sparkline, got %+v", row)
	}
	// The reason must be shown exactly once: MergedReason carries it, so the
	// Proof age column (which used to repeat the same string) must not.
	if row.ProofAge != emDash {
		t.Errorf("ProofAge = %q, want emDash (the reason already shown once in MergedReason)", row.ProofAge)
	}
}

// TestRenderHTMLAttestedRowShowsReasonExactlyOnce is the full-page
// regression for the "attested, no drill" x3 redundancy: the merged cell
// spans History+RTO+RPO (via the row-grid's rgs-cell-merged class, a
// grid-column: span 3, since the inventory is a CSS grid "table" now — see
// TestRenderHTMLInventoryUsesNoTableElement) and the reason string appears
// exactly once in the row summary, not repeated in a separate Proof age
// cell (MergedReason spans it; ProofAge itself renders emDash — see
// TestBuildStatusRowAttestedOnlyRendersReasonNoStrip for the unit-level
// assertion on that).
func TestRenderHTMLAttestedRowShowsReasonExactlyOnce(t *testing.T) {
	s := &Summary{Verdict: "pass", Inventory: []InventoryRow{
		{Level: "declared", Proof: "manual-key-attestation", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: "attested, no drill"},
	}}
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	if !strings.Contains(html, `class="rgs-cell-merged`) {
		t.Errorf("expected the merged History+RTO+RPO cell (rgs-cell-merged), got:\n%s", html)
	}
	summaryStart := strings.Index(html, "<summary")
	summaryEnd := strings.Index(html, "</summary>")
	if summaryStart < 0 || summaryEnd < 0 {
		t.Fatalf("missing <summary>...</summary>, got:\n%s", html)
	}
	if n := strings.Count(html[summaryStart:summaryEnd], "attested, no drill"); n != 1 {
		t.Errorf("reason text should appear exactly once in the row summary, found %d times, got:\n%s", n, html[summaryStart:summaryEnd])
	}
}

// ---- full-page rendering ---------------------------------------------------

func TestRenderHTMLVerdictBannerClassAndLabel(t *testing.T) {
	cases := []struct{ verdict, class, label string }{
		{"pass", "good", "PASS"},
		{"warn", "warning", "WARN"},
		{"block", "critical", "BLOCK"},
	}
	for _, c := range cases {
		s := &Summary{Verdict: c.verdict}
		out, err := s.Render("html")
		if err != nil {
			t.Fatalf("%s: Render: %v", c.verdict, err)
		}
		html := string(out)
		if want := fmt.Sprintf(`data-status="%s"`, c.class); !strings.Contains(html, want) {
			t.Errorf("%s: missing banner class %q", c.verdict, want)
		}
		if !strings.Contains(html, ">"+c.label+"<") {
			t.Errorf("%s: missing verdict label %q", c.verdict, c.label)
		}
	}
}

func TestGapCalloutAppearsIffDeclaredRowsExist(t *testing.T) {
	withDeclared := &Summary{Verdict: "pass", Inventory: []InventoryRow{
		{Level: "declared", Proof: "p", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: "attested, no drill"},
	}}
	out, err := withDeclared.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "1 never drilled") {
		t.Errorf("expected gap callout when declared rows exist, got:\n%s", out)
	}

	withoutDeclared := &Summary{Verdict: "pass", Inventory: []InventoryRow{
		{Level: "serves", Proof: "p", IsDrilled: true, RPO: "1h", RTO: "2s", ProofAge: "1d"},
	}}
	out2, err := withoutDeclared.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out2), "never drilled") {
		t.Errorf("gap callout should not appear when no declared rows exist")
	}
}

// TestGapMessageSplitsNeverDrilledFromDrilledButUnproven: a declared row
// that WAS drilled (its proof merely expired/is disputed) is not "attested
// but never drilled" — that phrase overclaims in the other direction. The
// callout must count the two cases separately.
func TestGapMessageSplitsNeverDrilledFromDrilledButUnproven(t *testing.T) {
	rows := []InventoryRow{
		{Level: "declared", Proof: "a", IsDrilled: false, ProofAge: "attested, no drill"},
		{Level: "declared", Proof: "b", IsDrilled: false, ProofAge: "attested, no drill"},
		{Level: "declared", Proof: "c", IsDrilled: true, ProofAge: "proof expired 3d ago"},
		{Level: "serves", Proof: "d", IsDrilled: true, ProofAge: "0d"},
	}
	got := buildGapMessage(rows)
	if !strings.Contains(got, "2 never drilled") {
		t.Errorf("expected '2 never drilled', got %q", got)
	}
	if !strings.Contains(got, "1 drilled but currently unproven") {
		t.Errorf("expected '1 drilled but currently unproven', got %q", got)
	}
}

func TestGapMessageSuppressesZeroClause(t *testing.T) {
	rows := []InventoryRow{{Level: "declared", Proof: "c", IsDrilled: true, ProofAge: "proof expired 3d ago"}}
	got := buildGapMessage(rows)
	if strings.Contains(got, "never drilled") {
		t.Errorf("a zero never-drilled count must be suppressed, not printed; got %q", got)
	}
	if !strings.Contains(got, "1 drilled but currently unproven") {
		t.Errorf("expected the drilled-but-unproven count, got %q", got)
	}
}

// ---- footer: real-scale proof freshness (the footer-collision fix) -------

// mkPresentProofs builds n healthy "present" proofs — the case that used to
// each get their own tall, wrapping dt/dd row and collide with neighboring
// footer sections.
func mkPresentProofs(n int) []ProofState {
	proofs := make([]ProofState, n)
	for i := range proofs {
		proofs[i] = ProofState{ID: fmt.Sprintf("proof-%02d", i), Status: "present", Detail: "no expiry declared"}
	}
	return proofs
}

func TestBuildFooterFreshnessRealScaleNoPerProofRowsForHealthy(t *testing.T) {
	proofs := mkPresentProofs(30)
	proofs = append(proofs,
		ProofState{ID: "z-stale-one", Status: "stale", Detail: "stale detail text"},
		ProofState{ID: "z-expired-one", Status: "expired", Detail: "expired detail text"},
		ProofState{ID: "z-disputed-one", Status: "disputed", Detail: "disputed detail text"},
	)

	chips, problems := buildFooterFreshness(proofs)

	var presentChip *freshnessChip
	for i := range chips {
		if chips[i].Label == "present" {
			presentChip = &chips[i]
		}
	}
	if presentChip == nil || presentChip.Count != 30 {
		t.Fatalf("expected a present chip with count 30, got chips=%+v", chips)
	}
	if len(problems) != 3 {
		t.Fatalf("got %d problem proofs, want 3 (stale/expired/disputed only), problems=%+v", len(problems), problems)
	}
	for _, p := range problems {
		if p.Status == "present" {
			t.Errorf("a healthy proof must never appear in the problem list, got %+v", p)
		}
	}
}

// TestRenderHTMLRealScaleFooterHasNoPerProofRowsForHealthyProofs is the
// full-page regression the coordinator asked for: render a 30+ proof
// fixture and assert no per-proof "present · ..." row exists anywhere in
// the rendered footer — only the compact chip summary and the (few)
// problem-proof rows.
func TestRenderHTMLRealScaleFooterHasNoPerProofRowsForHealthyProofs(t *testing.T) {
	proofs := mkPresentProofs(32)
	proofs = append(proofs, ProofState{ID: "the-stale-one", Status: "stale", Detail: "stale detail text"})

	s := &Summary{Verdict: "pass", Proofs: proofs}
	out, err := s.Render("html")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := string(out)

	if !strings.Contains(html, "32 present") {
		t.Errorf("expected a compact '32 present' chip, got:\n%s", html)
	}
	if strings.Contains(html, "no expiry declared") {
		t.Errorf("a healthy proof's detail text must not appear anywhere on the page, got:\n%s", html)
	}
	for i := 0; i < 32; i++ {
		if strings.Contains(html, fmt.Sprintf("proof-%02d", i)) {
			t.Errorf("healthy proof id proof-%02d must not get its own footer row, got:\n%s", i, html)
		}
	}
	if !strings.Contains(html, "the-stale-one") || !strings.Contains(html, "<dd>stale</dd>") {
		t.Errorf("the one problem proof must still be listed by name and state, got:\n%s", html)
	}
}

// ---- header: multi-context origin summarization ---------------------------

func TestSummarizeOriginCompressesMultiContextList(t *testing.T) {
	paths := make([]string, 13)
	for i := range paths {
		paths[i] = fmt.Sprintf("/home/user/contexts/ctx-%02d.yml", i)
	}
	origin := strings.Join(paths, ", ")

	label, full := summarizeOrigin(origin)
	want := fmt.Sprintf("13 contexts · %s + 12 more", filepath.Base(paths[0]))
	if label != want {
		t.Errorf("label = %q, want %q", label, want)
	}
	if full != origin {
		t.Errorf("full = %q, want the untruncated origin %q", full, origin)
	}
}

func TestSummarizeOriginPassesThroughSingleOrigin(t *testing.T) {
	single := "/home/user/contexts/only.yml"
	label, full := summarizeOrigin(single)
	if label != single || full != single {
		t.Errorf("a single origin must pass through unchanged, got label=%q full=%q", label, full)
	}
}

// TestRenderHTMLHeaderCompressesManyContextsIntoOneLine is the full-page
// regression: a 13-path comma run must not appear verbatim in the header
// text (it used to wrap across several lines), but the full list must still
// be recoverable from the title attribute.
func TestRenderHTMLHeaderCompressesManyContextsIntoOneLine(t *testing.T) {
	paths := make([]string, 13)
	for i := range paths {
		paths[i] = fmt.Sprintf("/home/user/contexts/ctx-%02d.yml", i)
	}
	origin := strings.Join(paths, ", ")

	s := &Summary{Verdict: "pass", Origin: origin}
	out, err := s.Render("html")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := string(out)

	if !strings.Contains(html, origin) {
		t.Errorf("expected the full origin to still be present (in the title attribute), got:\n%s", html)
	}
	if !strings.Contains(html, "13 contexts ·") {
		t.Errorf("expected the compact '13 contexts · ...' header label, got:\n%s", html)
	}
	metaStart := strings.Index(html, `<span class="rgs-meta"`)
	metaTagEnd := strings.Index(html[metaStart:], ">")
	metaTextEnd := strings.Index(html[metaStart:], "</span>")
	if metaStart < 0 || metaTagEnd < 0 || metaTextEnd < 0 {
		t.Fatalf("missing <span class=\"rgs-meta\">...</span>, got:\n%s", html)
	}
	metaAttrs := html[metaStart : metaStart+metaTagEnd]
	metaText := html[metaStart+metaTagEnd+1 : metaStart+metaTextEnd]
	if !strings.Contains(metaAttrs, "title=") {
		t.Errorf("expected a title attribute carrying the full origin, tag:\n%s", metaAttrs)
	}
	if strings.Count(metaText, "/home/user/contexts/ctx-") > 1 {
		t.Errorf("the header's VISIBLE text should name only the first context path, not all 13; text:\n%s", metaText)
	}
}

func TestRenderHTMLEscapesProofIDMetacharacters(t *testing.T) {
	s := &Summary{Verdict: "pass", Inventory: []InventoryRow{{
		Level: "declared", Proof: `<script>alert(1)</script>`, IsDrilled: false,
		RPO: emDash, RTO: emDash, ProofAge: "attested, no drill",
	}}}
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatalf("proof id was not escaped, raw script tag present:\n%s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("expected escaped proof id, got:\n%s", html)
	}
}

func TestRenderHTMLEmptySummaryRendersCompletePage(t *testing.T) {
	s := &Summary{Verdict: "pass"}
	out, err := s.Render("html")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := string(out)
	for _, want := range []string{
		"<!doctype html>", "restoregap", "Recovery inventory",
		"No declared drills or proofs yet.", "Declared", "Serves",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q in empty-summary page, got:\n%s", want, html)
		}
	}
}

// ---- brand mark: header inline + favicon data URI -------------------------

// markPathData is the shield's path geometry from the addendum's exact
// source (ui/mark.svg) — no quotes/angle-brackets, so it survives both the
// raw inline copy and the percent-encoded favicon data URI unchanged.
const markPathData = `M16 3l11 3.9v9.4c0 6.7-4.9 10.7-11 12.9-6.1-2.2-11-6.2-11-12.9V6.9z`

func TestRenderHTMLIncludesBrandMarkInHeaderAndFavicon(t *testing.T) {
	s := &Summary{Verdict: "pass"}
	out, err := s.Render("html")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := string(out)

	headerStart := strings.Index(html, "<header")
	headerEnd := strings.Index(html, "</header>")
	if headerStart < 0 || headerEnd < 0 {
		t.Fatalf("missing <header>...</header>, got:\n%s", html)
	}
	header := html[headerStart:headerEnd]
	if n := strings.Count(header, markPathData); n != 1 {
		t.Errorf("expected the shield path exactly once in the header, found %d, header:\n%s", n, header)
	}
	if !strings.Contains(header, `aria-hidden="true"`) {
		t.Errorf("inline header mark must be aria-hidden, header:\n%s", header)
	}

	faviconStart := strings.Index(html, `<link rel="icon"`)
	if faviconStart < 0 {
		t.Fatalf("missing favicon link, got:\n%s", html)
	}
	faviconTagEnd := strings.Index(html[faviconStart:], ">")
	if faviconTagEnd < 0 {
		t.Fatalf("unterminated favicon link tag, got:\n%s", html)
	}
	favicon := html[faviconStart : faviconStart+faviconTagEnd]
	// html/template's own URL normalizer additionally percent-encodes the
	// raw spaces our faviconDataURI left alone (valid, correctly-decoded
	// data-URI syntax either way), so compare against that form here.
	wantPath := strings.ReplaceAll(markPathData, " ", "%20")
	if !strings.Contains(favicon, wantPath) {
		t.Errorf("favicon href missing the shield path, got:\n%s", favicon)
	}
}

// ---- expandable row detail (feat/dashboard-detail) -------------------------

// TestRenderHTMLInventoryUsesNoTableElement guards the HTML-validity
// requirement <details> forces: it is not valid HTML as a direct
// <table>/<tbody> child, so the inventory renders as a CSS-grid "table"
// (role="table"/"row"/"cell") instead of a real <table>. If a future change
// ever reintroduces one, this must catch it.
func TestRenderHTMLInventoryUsesNoTableElement(t *testing.T) {
	s := &Summary{Verdict: "pass", Inventory: []InventoryRow{
		{Level: "declared", Proof: "p", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: "attested, no drill"},
	}}
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	if strings.Contains(html, "<table") {
		t.Errorf("the inventory must not use a <table> element (details is invalid inside one), got:\n%s", html)
	}
	if !strings.Contains(html, "<details") {
		t.Errorf("expected <details> rows, got:\n%s", html)
	}
}

// TestRenderHTMLDetailsSummaryCountMatchesRowCount: every inventory row is
// its own expand/collapse disclosure — one <details>/<summary> pair each,
// across both groups.
func TestRenderHTMLDetailsSummaryCountMatchesRowCount(t *testing.T) {
	s := &Summary{Verdict: "warn", Inventory: []InventoryRow{
		{Level: "declared", Proof: "a", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: "attested, no drill"},
		{Level: "declared", Proof: "b", IsDrilled: true, RPO: emDash, RTO: emDash, ProofAge: "disputed"},
		{Level: "serves", Proof: "c", IsDrilled: true, RPO: "1h", RTO: "2s", ProofAge: "1d"},
	}}
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	details := strings.Count(html, `<details class="rgs-row">`)
	summaries := strings.Count(html, `<summary class="rgs-cols rgs-row-summary"`)
	if details != 3 || summaries != 3 {
		t.Errorf("got %d <details>, %d <summary>, want 3 each (one per row), got:\n%s", details, summaries, html)
	}
}

// TestBuildStatusRowMeaningLinePerLevel: every rung gets its own
// non-empty, distinct plain-language meaning line (levelMeaning), written
// once and looked up — never derived per row.
func TestBuildStatusRowMeaningLinePerLevel(t *testing.T) {
	cases := []struct {
		level string
		rank  int
	}{
		{contextspec.LevelDeclared.String(), contextspec.LevelDeclared.Rung()},
		{contextspec.LevelRestores.String(), contextspec.LevelRestores.Rung()},
		{contextspec.LevelDataValid.String(), contextspec.LevelDataValid.Rung()},
		{contextspec.LevelServes.String(), contextspec.LevelServes.Rung()},
	}
	seen := make(map[string]string, len(cases))
	for _, c := range cases {
		row := buildStatusRow(InventoryRow{Level: c.level, LevelRank: c.rank, Proof: "p", IsDrilled: true, RPO: emDash, RTO: emDash})
		if row.Meaning == "" {
			t.Errorf("level %s: empty meaning line", c.level)
			continue
		}
		if other, dup := seen[row.Meaning]; dup {
			t.Errorf("level %s: meaning line reused from level %s: %q", c.level, other, row.Meaning)
		}
		seen[row.Meaning] = c.level
	}
}

// TestRenderHTMLNextStepAppearsForDisputedNotForVerified is the full
// Gather -> Render("html") regression the coordinator asked for: a
// disputed drilled proof gets the literal re-drill command, a currently
// good (verified) one does not.
func TestRenderHTMLNextStepAppearsForDisputedNotForVerified(t *testing.T) {
	dir := t.TempDir()
	ctxPath := writeContextFile(t, dir, "ctx.yml", `version: 2
drills:
  - proof: disputed-proof
    artifact: /fake
    recover: "true"
  - proof: verified-proof
    artifact: /fake
    recover: "true"
proofs:
  - id: disputed-proof
    status: disputed
    observed_at: "2026-08-01T00:00:00Z"
  - id: verified-proof
    status: validated
    observed_at: "2026-08-20T00:00:00Z"
    verified: true
    measurements:
      rto_seconds: 1.0
      checks: [{type: byte_identical, pass: true}]
`)
	s, err := Gather(Request{ContextPaths: []string{ctxPath}, AsOf: "2026-08-20T12:00:00Z"})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	out, err := s.Render("html")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := string(out)
	wantCmd := fmt.Sprintf("restoregap drill --context %s --proof disputed-proof", ctxPath)
	if !strings.Contains(html, wantCmd) {
		t.Errorf("expected the next-step command %q for the disputed proof, got:\n%s", wantCmd, html)
	}
	if strings.Contains(html, "--proof verified-proof") {
		t.Errorf("a currently-good (verified) row must not show a next-step command, got:\n%s", html)
	}
}

// TestNextStepCommandUnitCases covers nextStepCommand directly: only a
// drilled, not-currently-good row with a known source file gets a command.
func TestNextStepCommandUnitCases(t *testing.T) {
	cases := []struct {
		name string
		row  InventoryRow
		want string
	}{
		{"disputed drilled row", InventoryRow{Level: "declared", Proof: "p", IsDrilled: true, SourceFile: "/ctx/a.yml"},
			"restoregap drill --context /ctx/a.yml --proof p"},
		{"currently good row", InventoryRow{Level: "serves", Proof: "p", IsDrilled: true, SourceFile: "/ctx/a.yml"}, ""},
		{"attestation-only row", InventoryRow{Level: "declared", Proof: "p", IsDrilled: false, SourceFile: "/ctx/a.yml"}, ""},
		{"no source file", InventoryRow{Level: "declared", Proof: "p", IsDrilled: true}, ""},
	}
	for _, c := range cases {
		if got := nextStepCommand(c.row); got != c.want {
			t.Errorf("%s: nextStepCommand = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestRenderHTMLGroupHeadersShowCorrectCounts covers the explicit
// recoverable/not-proven split: correct counts in each header, and the
// recoverable group sorted strongest-first (the opposite of the
// weakest-first order the text renderer/text table uses).
func TestRenderHTMLGroupHeadersShowCorrectCounts(t *testing.T) {
	s := &Summary{Verdict: "warn", Inventory: []InventoryRow{
		{Level: "declared", Proof: "a", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: "attested, no drill"},
		{Level: "declared", Proof: "b", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: "attested, no drill"},
		{Level: "restores", Proof: "c", IsDrilled: true, LevelRank: contextspec.LevelRestores.Rung(), RPO: emDash, RTO: "1s", ProofAge: "0d"},
		{Level: "serves", Proof: "d", IsDrilled: true, LevelRank: contextspec.LevelServes.Rung(), RPO: "1h", RTO: "2s", ProofAge: "0d"},
	}}
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	if !strings.Contains(html, `Provably recoverable <span class="rgs-group-count">— 2</span>`) {
		t.Errorf("expected 'Provably recoverable — 2', got:\n%s", html)
	}
	if !strings.Contains(html, `Not proven <span class="rgs-group-count">— 2</span>`) {
		t.Errorf("expected 'Not proven — 2', got:\n%s", html)
	}
	cIdx := strings.Index(html, "<code>c</code>")
	dIdx := strings.Index(html, "<code>d</code>")
	if cIdx < 0 || dIdx < 0 {
		t.Fatalf("missing proof ids in output, got:\n%s", html)
	}
	if dIdx > cIdx {
		t.Errorf("expected strongest-first: serves (d) before restores (c) within the recoverable group")
	}
}

// TestRenderHTMLIncludesIntegrationStrip covers the value/integration
// strip's presence and its honesty constraint: it must never imply cloud
// scanning or terraform-plan analysis, which were deliberately cut.
func TestRenderHTMLIncludesIntegrationStrip(t *testing.T) {
	s := &Summary{Verdict: "pass"}
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	for _, want := range []string{
		"What this proves", "Any backup tool", "Gates, not reports", "Evidence you can hand over",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing integration strip content %q, got:\n%s", want, html)
		}
	}
	lower := strings.ToLower(html)
	for _, mustNotImply := range []string{"terraform plan", "cloud scan", "scans your cloud", "plan analysis"} {
		if strings.Contains(lower, mustNotImply) {
			t.Errorf("integration strip must not imply %q — cloud scanning/plan analysis were deliberately cut, got:\n%s", mustNotImply, html)
		}
	}
}

// TestRenderHTMLEscapesDeclarationAndAttestationFields extends the
// escaping coverage to the new detail-card fields: a drill's own recover
// command/recovery source/pin check are user-authored YAML, same as an
// attestation's asserted command/evidence URL, and none of them are
// exempted from html/template's auto-escaping.
func TestRenderHTMLEscapesDeclarationAndAttestationFields(t *testing.T) {
	s := &Summary{Verdict: "pass", Inventory: []InventoryRow{
		{
			Level: "declared", Proof: "p", IsDrilled: true, RPO: emDash, RTO: emDash, ProofAge: "not verified",
			RecoverCmd: `echo <script>x</script>`, RecoverySource: `<img src=x>`, PinCheckCmd: `<b>pin</b>`,
			BudgetRTO: emDash, BudgetRPO: emDash,
		},
		{
			Level: "declared", Proof: "q", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: "attested, no drill",
			AttestCommand: `<script>y</script>`, AttestEvidenceURL: `<img src=y>`,
		},
	}}
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	for _, raw := range []string{`<script>x</script>`, `<img src=x>`, `<b>pin</b>`, `<script>y</script>`, `<img src=y>`} {
		if strings.Contains(html, raw) {
			t.Fatalf("unescaped content leaked into HTML: %q, got:\n%s", raw, html)
		}
	}
	if !strings.Contains(html, "&lt;script&gt;x&lt;/script&gt;") {
		t.Errorf("expected RecoverCmd to be escaped, got:\n%s", html)
	}
}
