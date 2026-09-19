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

// ---- estate row: single next-action, no per-row expand --------------------

// estatePanel returns just one panel's markup ("layer" or "system"). The estate
// deliberately renders TWICE — the same proofs grouped two ways — so any
// assertion of the form "the page contains X once" is meaningless without
// naming the panel. Every estate assertion below scopes itself this way.
func estatePanel(t *testing.T, html, panel string) string {
	t.Helper()
	open := `<div class="rgs-estate-panel" data-panel="` + panel + `">`
	i := strings.Index(html, open)
	if i < 0 {
		t.Fatalf("no %q estate panel in page, got:\n%s", panel, html)
	}
	rest := html[i+len(open):]
	end := len(rest)
	for _, marker := range []string{`<div class="rgs-estate-panel"`, "</section>"} {
		if j := strings.Index(rest, marker); j >= 0 && j < end {
			end = j
		}
	}
	return rest[:end]
}

// TestRenderHTMLAttestedRowShowsReasonExactlyOnce: an attestation's reason is
// shown once per panel — not twice within one panel. The page total is two
// because the estate is rendered twice by design.
func TestRenderHTMLAttestedRowShowsReasonExactlyOnce(t *testing.T) {
	const reason = "owner attests weekly restore, evidence in vault"
	s := &Summary{Verdict: "warn", Inventory: []InventoryRow{
		{Level: "declared", Proof: "p", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: reason},
	}}
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	for _, panel := range []string{"layer", "system"} {
		if n := strings.Count(estatePanel(t, html, panel), reason); n != 1 {
			t.Errorf("%s panel: reason should appear exactly once, found %d", panel, n)
		}
	}
}

// TestRenderHTMLGroupsAndRecoveryChainAreClosedByDefault: the estate tree's
// layer groups and the legacy Recovery chain section render as <details>
// with no `open` attribute when every row in them is already settled
// (restored/observed/accepted) — closed by default, so a machine with many
// proofs does not pay for them
// in default page height (mobile-ui-check's ≤8,000px budget).
func TestRenderHTMLGroupsAndRecoveryChainAreClosedByDefault(t *testing.T) {
	s := &Summary{
		Verdict: "pass", Origin: "restoregap.yml", Lifelines: 2, Guards: 1,
		Inventory: []InventoryRow{
			{Level: "restores", Proof: "a", IsDrilled: true, LevelRank: contextspec.LevelRestores.Rung(), RPO: emDash, RTO: "1s", ProofAge: "0d"},
		},
	}
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	for _, want := range []string{`<details class="rgs-taxlayer"`, `<details class="rgs-legacy">`, "Recovery chain"} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q, got:\n%s", want, html)
		}
	}
	// An all-restored layer group must not carry an `open` attribute, and
	// neither must the legacy <details>.
	if strings.Contains(html, `<details class="rgs-legacy"> open>`) || strings.Contains(html, `<details class="rgs-legacy" open>`) {
		t.Errorf("legacy details must not be open by default, got:\n%s", html)
	}
	layerStart := strings.Index(html, `<details class="rgs-taxlayer"`)
	layerTagEnd := strings.Index(html[layerStart:], ">")
	if layerStart < 0 || layerTagEnd < 0 {
		t.Fatalf("missing the layer group's opening tag, got:\n%s", html)
	}
	layerTag := html[layerStart : layerStart+layerTagEnd]
	if strings.Contains(layerTag, " open") {
		t.Errorf("an all-restored layer group must not be open by default, tag: %s", layerTag)
	}
}

// TestRenderHTMLLayerGroupOpensWhenItHasAGap: unlike the old fixed-closed
// group <details>, an estate layer group auto-expands when it holds a real
// gap (unreviewed/attention) — a machine with problems should not require
// an extra click to see them.
func TestRenderHTMLLayerGroupOpensWhenItHasAGap(t *testing.T) {
	s := &Summary{Verdict: "warn", Inventory: []InventoryRow{
		{Level: "declared", Proof: "b", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: "attested, no drill"},
	}}
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	layerStart := strings.Index(html, `<details class="rgs-taxlayer"`)
	layerTagEnd := strings.Index(html[layerStart:], ">")
	if layerStart < 0 || layerTagEnd < 0 {
		t.Fatalf("missing the layer group's opening tag, got:\n%s", html)
	}
	if !strings.Contains(html[layerStart:layerStart+layerTagEnd], " open") {
		t.Errorf("a layer group holding a gap must be open by default, tag: %s", html[layerStart:layerStart+layerTagEnd])
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

// TestEstateRowShowsInlineNextActionForGapNotForGreen: a not-proven row
// (declared, never drilled) shows its own single remediation command right
// on the page — no click needed, and no separate "N never drilled" callout
// duplicating what the To-green panel and the row already say. A currently
// good row shows no such command.
func TestEstateRowShowsInlineNextActionForGapNotForGreen(t *testing.T) {
	withDeclared := &Summary{Verdict: "pass", Inventory: []InventoryRow{
		{Level: "declared", Proof: "p", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: "attested, no drill"},
	}}
	out, err := withDeclared.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `class="rgs-rownext"`) || !strings.Contains(string(out), "restoregap accept p --reason") {
		t.Errorf("expected an inline next-action command for the not-proven row, got:\n%s", out)
	}

	withoutDeclared := &Summary{Verdict: "pass", Inventory: []InventoryRow{
		{Level: "serves", Proof: "p", IsDrilled: true, RPO: "1h", RTO: "2s", ProofAge: "1d"},
	}}
	out2, err := withoutDeclared.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out2), `class="rgs-rownext"`) {
		t.Errorf("a currently-good row must not show a next-action line, got:\n%s", out2)
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
		"<!doctype html>", "Restore Gap", "No declared drills or proofs yet.",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q in empty-summary page, got:\n%s", want, html)
		}
	}
	// An estate with nothing in it renders no estate section at all
	// ({{if .Estate.HasAny}}) — an empty shell with a heading and no rows is
	// worse than its absence, and "No declared drills or proofs yet." above
	// already says the true thing.
	if strings.Contains(html, "Your recovery evidence") {
		t.Errorf("an empty estate must not render a heading, got:\n%s", html)
	}
	if strings.Contains(html, "<script") {
		t.Errorf("the page must never contain a <script> tag, got:\n%s", html)
	}
}

// ---- brand mark: header inline + favicon data URI -------------------------

// markPathData is the stopwatch hand geometry from the addendum's exact
// source (ui/mark.svg) — no quotes/angle-brackets, so it survives both the
// raw inline copy and the percent-encoded favicon data URI unchanged.
const markPathData = `M16 17.5L21.2 14.5`

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
		t.Errorf("expected the stopwatch hand exactly once in the header, found %d, header:\n%s", n, header)
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
		t.Errorf("favicon href missing the stopwatch hand, got:\n%s", favicon)
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

// TestRenderHTMLEstateRowsAreNotIndividuallyExpandable guards the reason the
// per-proof detail card was removed: the mobile gate's `--views details` sweep
// clicks every <details> cumulatively without re-closing, so one card per proof
// would let a ~40-proof estate open dozens at once and blow the 8,000px height
// budget. Only the layer sections may be <details>; rows must stay plain.
func TestRenderHTMLEstateRowsAreNotIndividuallyExpandable(t *testing.T) {
	s := &Summary{Verdict: "warn", Inventory: []InventoryRow{
		{Level: "declared", Proof: "a", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: "attested, no drill"},
		{Level: "restores", Proof: "b", IsDrilled: true, LevelRank: contextspec.LevelRestores.Rung(), RPO: emDash, RTO: "1s", ProofAge: "0d"},
	}}
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	panel := estatePanel(t, string(out), "layer")
	if got := strings.Count(panel, `<div class="rgs-row"`); got != 2 {
		t.Errorf("expected 2 plain rows in the layer panel, got %d:\n%s", got, panel)
	}
	// Every <details> here must be a layer section, never a row.
	if opens, layers := strings.Count(panel, "<details"), strings.Count(panel, `class="rgs-taxlayer"`); opens != layers {
		t.Errorf("every <details> must be a layer section: %d <details> vs %d layer sections", opens, layers)
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
			Level: "declared", Proof: "q", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: `<img src=z>`,
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
	// The estate row renders state/proof/artifact/level/why rather than the old
	// detail card's recover command, so assert escaping on a field it shows:
	// ProofAge becomes the row's "why".
	if !strings.Contains(html, "&lt;img src=z&gt;") {
		t.Errorf("expected the why field to be escaped, got:\n%s", html)
	}
}

// ---- to-green convergence panel (feat/accept-next) -----------------------

// TestRenderHTMLToGreenPanelListsStepsUnderHeadline: the panel sits right
// after the verdict banner and lists exactly `restoregap next`'s lines when
// there is work left.
func TestRenderHTMLToGreenPanelListsStepsUnderHeadline(t *testing.T) {
	s := &Summary{Verdict: "warn", Inventory: []InventoryRow{
		{Level: "declared", Proof: "phone-reprovision-path", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: "attested, no drill"},
	}}
	out, err := s.Render("html")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := string(out)
	bannerEnd := strings.Index(html, "</section>")
	toGreenIdx := strings.Index(html, `class="rgs-togreen"`)
	if bannerEnd < 0 || toGreenIdx < bannerEnd {
		t.Fatalf("to-green panel must appear directly after the verdict banner, got:\n%s", html)
	}
	for _, want := range []string{
		"To green: 1 step</h2>",
		"phone-reprovision-path",
		"restoregap accept phone-reprovision-path",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("to-green panel missing %q, got:\n%s", want, html)
		}
	}
}

// TestRenderHTMLToGreenPanelFoldsBeyondEightSteps: only the first 8 lines
// show directly; the rest fold behind a <details>, and the heading still
// counts the true total.
func TestRenderHTMLToGreenPanelFoldsBeyondEightSteps(t *testing.T) {
	rows := make([]InventoryRow, 10)
	for i := range rows {
		rows[i] = InventoryRow{
			Level: "declared", Proof: fmt.Sprintf("proof-%02d", i), IsDrilled: false,
			RPO: emDash, RTO: emDash, ProofAge: "attested, no drill",
		}
	}
	s := &Summary{Verdict: "warn", Inventory: rows}
	out, err := s.Render("html")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, "To green: 10 steps</h2>") {
		t.Errorf("expected the heading to count all 10 steps, got:\n%s", html)
	}
	if !strings.Contains(html, "2 more steps") {
		t.Errorf("expected a '2 more steps' <details> summary, got:\n%s", html)
	}
	detailsStart := strings.Index(html, `class="rgs-togreen-more"`)
	if detailsStart < 0 {
		t.Fatalf("expected a rgs-togreen-more <details>, got:\n%s", html)
	}
	if !strings.Contains(html[detailsStart:], "proof-09") {
		t.Errorf("expected the 10th step (proof-09) inside the folded <details>, got:\n%s", html[detailsStart:])
	}
}

// TestRenderHTMLToGreenPanelShowsGreenNote: with nothing left to do, the
// panel shows "0 steps" and, when a future expiry exists, names it.
func TestRenderHTMLToGreenPanelShowsGreenNote(t *testing.T) {
	s := &Summary{
		Verdict: "pass",
		Inventory: []InventoryRow{
			{Level: "serves", Proof: "money-db-recovery", IsDrilled: true, RPO: "16h0m0s", RTO: "2.1s", ProofAge: "3d ago"},
		},
		NextExpiryID: "money-db-recovery",
		NextExpiryAt: mustParseTime(t, "2026-09-01T00:00:00Z"),
	}
	out, err := s.Render("html")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, "To green: 0 steps</h2>") {
		t.Errorf("expected the zero-steps heading, got:\n%s", html)
	}
	if !strings.Contains(html, "Green. Next expiry: money-db-recovery on 2026-09-01") {
		t.Errorf("expected the green note naming the next expiry, got:\n%s", html)
	}
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return tm
}

// TestLevelLegendExplainsEveryRungExactlyOnce revives the invariant the
// deleted TestBuildStatusRowMeaningLinePerLevel guarded: every rung of the
// recovery ladder gets its own non-empty, distinct plain-language line. The
// redesign dropped the per-row meaning; this asserts the explanation survives
// as a single legend instead of vanishing.
func TestLevelLegendExplainsEveryRungExactlyOnce(t *testing.T) {
	legend := buildLevelLegend()
	if len(legend) != 4 {
		t.Fatalf("expected 4 rungs, got %d: %+v", len(legend), legend)
	}
	seen := make(map[string]string, len(legend))
	for _, item := range legend {
		if item.Meaning == "" {
			t.Errorf("level %s: empty meaning line", item.Level)
			continue
		}
		if other, dup := seen[item.Meaning]; dup {
			t.Errorf("level %s: meaning line reused from level %s: %q", item.Level, other, item.Meaning)
		}
		seen[item.Meaning] = item.Level
	}

	s := &Summary{Verdict: "warn", Inventory: []InventoryRow{
		{Level: "declared", Proof: "p", IsDrilled: false, RPO: emDash, RTO: emDash, ProofAge: "attested, no drill"},
	}}
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	// Rendered once for the whole page — not once per estate panel, and
	// certainly not once per row.
	if n := strings.Count(html, "What the levels mean"); n != 1 {
		t.Errorf("legend should appear exactly once, found %d", n)
	}
	for _, item := range legend {
		if !strings.Contains(html, item.Meaning) {
			t.Errorf("legend missing the %s meaning in rendered page", item.Level)
		}
	}
}
