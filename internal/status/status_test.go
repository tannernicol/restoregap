// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/ledger"
)

func writeContextFile(t *testing.T, dir, name, yaml string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestStatusSeparatesGateBrokenFromBlockedAndRendersLast(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")
	when := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	if _, err := ledger.Append(ledgerPath, ledger.EntryDecision, "agent/test", ledger.Payload{Decision: &ledger.DecisionPayload{
		Verdict: "block", GateState: "ran", DurationMS: 11,
		Checks: []ledger.DecisionCheckRecord{{ID: "evaluate_policy", Outcome: "fail", DurationMS: 7}},
	}}, when, "01J000000000000000000000010"); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Append(ledgerPath, ledger.EntryDecision, "agent/test", ledger.Payload{Decision: &ledger.DecisionPayload{
		Verdict: "block", GateState: "broken", BrokenReason: "load_context: permission denied", DurationMS: 4, ToolVersion: "v0.9.3",
		Checks: []ledger.DecisionCheckRecord{{ID: "load_context", Outcome: "broken", DurationMS: 3}},
	}}, when.Add(time.Minute), "01J000000000000000000000011"); err != nil {
		t.Fatal(err)
	}

	s, err := Gather(Request{LedgerPath: ledgerPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.GateBroken) != 1 || len(s.Blocked) != 1 {
		t.Fatalf("gate broken = %d, blocked = %d; want one each", len(s.GateBroken), len(s.Blocked))
	}
	out, err := s.Render("text")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "GATE BROKEN (1)") || !strings.Contains(string(out), "BLOCKED (1)") {
		t.Errorf("status must render separate headings, got:\n%s", out)
	}
	last := string(s.RenderLast())
	for _, want := range []string{"GATE BROKEN", "load_context: permission denied", "tool version: v0.9.3", "BROKEN  load_context (3ms)"} {
		if !strings.Contains(last, want) {
			t.Errorf("last decision missing %q:\n%s", want, last)
		}
	}
}

func t3339(t *testing.T, s string) *time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return &tm
}

func rpoPtr(f float64) *float64 { return &f }

// syntheticInventoryContext mirrors the docs/spec worked example: one drill
// at each rung, plus one that never got a proof at all.
func syntheticInventoryContext(t *testing.T) contextspec.Context {
	observed := t3339(t, "2026-08-20T00:00:00Z")
	expired := t3339(t, "2026-08-02T00:00:00Z")
	return contextspec.Context{
		Drills: []contextspec.Drill{
			{Proof: "never-drilled", Artifact: "/fake", Recover: "true"},
			{Proof: "nas-outofband-tailscale", Artifact: "/fake", Recover: "true"},
			{Proof: "obsidian-vault-recovery", Artifact: "/fake", Recover: "true"},
			{Proof: "assistant-conversations-recovery", Artifact: "/fake", Recover: "true"},
			{Proof: "money-db-recovery", Artifact: "/fake", Recover: "true"},
		},
		Proofs: []contextspec.Proof{
			{
				ID: "nas-outofband-tailscale", Status: contextspec.ProofRecordValidated,
				ObservedAt: observed, ExpiresAt: expired, Verified: true,
				Measurements: &contextspec.Measurements{RTOSeconds: 1.0, Checks: []contextspec.CheckOutcome{{Type: "byte_identical", Pass: true}}},
			},
			{
				ID: "obsidian-vault-recovery", Status: contextspec.ProofRecordValidated,
				ObservedAt: observed, Verified: true,
				Measurements: &contextspec.Measurements{RTOSeconds: 1.3, Checks: []contextspec.CheckOutcome{{Type: "byte_identical", Pass: true}}},
			},
			{
				ID: "assistant-conversations-recovery", Status: contextspec.ProofRecordValidated,
				ObservedAt: observed, Verified: true,
				Measurements: &contextspec.Measurements{RTOSeconds: 0.1, Checks: []contextspec.CheckOutcome{{Type: "sqlite", Pass: true}}},
			},
			{
				ID: "money-db-recovery", Status: contextspec.ProofRecordValidated,
				ObservedAt: observed, Verified: true,
				Measurements: &contextspec.Measurements{
					RTOSeconds: 2.1, RPOSeconds: rpoPtr(57600),
					Checks: []contextspec.CheckOutcome{{Type: "serve", Pass: true}},
				},
			},
		},
	}
}

func TestBuildInventorySortedWeakestFirst(t *testing.T) {
	ctx := syntheticInventoryContext(t)
	now := *t3339(t, "2026-08-20T12:00:00Z")

	rows := buildInventory(ctx, nil, now, "")
	if len(rows) != 5 {
		t.Fatalf("got %d rows, want 5", len(rows))
	}

	wantOrder := []struct {
		level string
		proof string
	}{
		{"declared", "nas-outofband-tailscale"}, // expired
		{"declared", "never-drilled"},           // no proof at all — same rung, tiebreak by proof id
		{"restores", "obsidian-vault-recovery"},
		{"data-valid", "assistant-conversations-recovery"},
		{"serves", "money-db-recovery"},
	}
	for i, want := range wantOrder {
		if rows[i].Level != want.level || rows[i].Proof != want.proof {
			t.Errorf("row[%d] = %+v, want level=%s proof=%s", i, rows[i], want.level, want.proof)
		}
	}
}

// TestStatusShowsLegacyOverrideMigrationWarning makes the compatibility path
// visible: a no-expiry entry from an older binary is readable during grace,
// but status must make the required re-approval impossible to miss.
func TestStatusShowsLegacyOverrideMigrationWarning(t *testing.T) {
	created := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")
	if _, err := ledger.Append(ledgerPath, ledger.EntryOverride, "agent/old", ledger.Payload{
		Override: &ledger.OverridePayload{FindingID: "finding-old", ApprovedBy: "tanner", Reason: "old binary"},
	}, created, "legacy-override"); err != nil {
		t.Fatalf("Append legacy override: %v", err)
	}

	s := &Summary{Verdict: "pass", LedgerOK: true}
	if err := processLedger(ledgerPath, s, created.Add(23*24*time.Hour)); err != nil {
		t.Fatalf("processLedger: %v", err)
	}
	if s.Verdict != "warn" {
		t.Errorf("Verdict = %q, want warn for a legacy no-expiry override", s.Verdict)
	}
	if len(s.ActiveOverrides) != 1 || !s.ActiveOverrides[0].LegacyNoExpiry {
		t.Fatalf("ActiveOverrides = %+v, want one legacy override", s.ActiveOverrides)
	}
	text, err := s.Render("text")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(text), "override legacy-override has no expiry — re-approve with --expires-in") {
		t.Errorf("status must name the migration action, got:\n%s", text)
	}
}

func TestBuildInventoryNoProofRecorded(t *testing.T) {
	ctx := contextspec.Context{Drills: []contextspec.Drill{{Proof: "orphan", Artifact: "/fake", Recover: "true"}}}
	rows := buildInventory(ctx, nil, time.Now(), "")
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	r := rows[0]
	if r.Level != "declared" || r.RPO != emDash || r.RTO != emDash || r.ProofAge != "no proof recorded yet" {
		t.Errorf("unexpected row for a drill with no proof: %+v", r)
	}
}

// TestBuildInventoryHidesMeasurementsWhenNotCurrentlyGood: an expired proof
// keeps its old Measurements on disk, but the inventory must not show them
// as if they still meant something — that's exactly the false confidence
// the level collapse exists to prevent.
func TestBuildInventoryHidesMeasurementsWhenNotCurrentlyGood(t *testing.T) {
	observed := t3339(t, "2026-08-01T00:00:00Z")
	expired := t3339(t, "2026-08-02T00:00:00Z")
	ctx := contextspec.Context{
		Drills: []contextspec.Drill{{Proof: "p", Artifact: "/fake", Recover: "true"}},
		Proofs: []contextspec.Proof{{
			ID: "p", Status: contextspec.ProofRecordValidated, ObservedAt: observed, ExpiresAt: expired, Verified: true,
			Measurements: &contextspec.Measurements{RTOSeconds: 1.3, RPOSeconds: rpoPtr(60)},
		}},
	}
	now := *t3339(t, "2026-08-20T00:00:00Z")
	rows := buildInventory(ctx, nil, now, "")
	if rows[0].RTO != emDash || rows[0].RPO != emDash {
		t.Errorf("an expired proof's stale measurements must not be shown as current: %+v", rows[0])
	}
	if !strings.Contains(rows[0].ProofAge, "expired") {
		t.Errorf("ProofAge should carry the expiry reason: %q", rows[0].ProofAge)
	}
}

// TestRenderTextIncludesInventoryTable is a golden-ish assertion on the text
// block: the taxonomy tree header is present, rows are grouped by layer
// (defaulting to "unfiled" when no layer is declared) and sorted
// problems-first within a category, em dashes stand in for an absent
// artifact, and it appears before the pre-existing "Recovery chain" section
// (additive, nothing reordered). Updated 2026-08 for the layer/category
// taxonomy tree (taxonomy spec section C), which replaces the old flat
// LEVEL/PROOF/RPO/RTO/PROOF AGE table as the text renderer's primary
// inventory view.
func TestRenderTextIncludesInventoryTable(t *testing.T) {
	ctx := syntheticInventoryContext(t)
	now := *t3339(t, "2026-08-20T12:00:00Z")
	s := &Summary{Verdict: "pass", Inventory: buildInventory(ctx, nil, now, ""), Context: ctx}

	out, err := s.Render("text")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	text := string(out)

	if !strings.Contains(text, "Recovery taxonomy — layer -> category -> proof") {
		t.Fatalf("missing taxonomy tree header, got:\n%s", text)
	}
	if !strings.Contains(text, "unfiled — ") {
		t.Errorf("expected an unfiled layer header (nothing in this fixture declares a layer), got:\n%s", text)
	}

	invIdx := strings.Index(text, "Recovery taxonomy")
	chainIdx := strings.Index(text, "Recovery chain")
	if invIdx < 0 || chainIdx < 0 || invIdx > chainIdx {
		t.Errorf("taxonomy tree should appear before the pre-existing Recovery chain section, got:\n%s", text)
	}

	declaredIdx := strings.Index(text, "declared")
	servesIdx := strings.Index(text, "serves")
	if declaredIdx < 0 || servesIdx < 0 || declaredIdx > servesIdx {
		t.Errorf("expected declared before serves (problems first), got:\n%s", text)
	}
	if !strings.Contains(text, "artifact: /fake") {
		t.Errorf("expected each row's declared drill artifact as its subtitle, got:\n%s", text)
	}
}

func TestRenderTextOmitsInventoryWhenNoDrills(t *testing.T) {
	s := &Summary{Verdict: "pass"}
	out, err := s.Render("text")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(string(out), "Recovery inventory") {
		t.Errorf("no declared drills should mean no inventory block, got:\n%s", out)
	}
}

func TestRenderHTMLIncludesInventorySection(t *testing.T) {
	ctx := syntheticInventoryContext(t)
	now := *t3339(t, "2026-08-20T12:00:00Z")
	s := &Summary{Verdict: "pass", Inventory: buildInventory(ctx, nil, now, "")}

	out, err := s.Render("html")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, "Recovery estate") {
		t.Errorf("missing estate section in HTML output")
	}
	if !strings.Contains(html, "money-db-recovery") || !strings.Contains(html, "serves") {
		t.Errorf("missing a synthesized row in HTML output")
	}
}

// ---- attestation-only proofs (proofs with no matching drill) -----------

// TestBuildInventoryIncludesAttestationOnlyProof: a proof with no matching
// drill (evidence-ingested, never drilled) must still appear — omitting it
// would invert the section's purpose, since that undrilled mass is usually
// the majority in a real deployment.
func TestBuildInventoryIncludesAttestationOnlyProof(t *testing.T) {
	observed := t3339(t, "2026-08-20T00:00:00Z")
	ctx := contextspec.Context{
		// no Drills at all — every proof here is attestation-only.
		Proofs: []contextspec.Proof{
			{ID: "verified-attestation", Status: contextspec.ProofRecordValidated, ObservedAt: observed, Verified: true},
			{ID: "unverified-attestation", Status: contextspec.ProofRecordObserved, ObservedAt: observed, Verified: false},
		},
	}
	now := *t3339(t, "2026-08-20T12:00:00Z")
	rows := buildInventory(ctx, nil, now, "")
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}

	byProof := map[string]InventoryRow{}
	for _, r := range rows {
		byProof[r.Proof] = r
	}

	verified := byProof["verified-attestation"]
	if verified.Level != "restores" {
		t.Errorf("a verified attestation must legitimately show restores, got %+v", verified)
	}

	unverified := byProof["unverified-attestation"]
	if unverified.Level != "declared" {
		t.Errorf("unverified attestation level = %s, want declared", unverified.Level)
	}
	if unverified.ProofAge != "attested, no drill" {
		t.Errorf("unverified attestation reason = %q, want %q (distinct from a drill's generic 'not verified')",
			unverified.ProofAge, "attested, no drill")
	}
}

// TestBuildInventoryDrilledProofKeepsNotVerifiedReason: the "attested, no
// drill" substitution must NOT leak onto a drill-backed proof — a drill
// that exists and simply hasn't verified yet should still say exactly that.
func TestBuildInventoryDrilledProofKeepsNotVerifiedReason(t *testing.T) {
	observed := t3339(t, "2026-08-20T00:00:00Z")
	ctx := contextspec.Context{
		Drills: []contextspec.Drill{{Proof: "p", Artifact: "/fake", Recover: "true"}},
		Proofs: []contextspec.Proof{{ID: "p", Status: contextspec.ProofRecordObserved, ObservedAt: observed, Verified: false}},
	}
	now := *t3339(t, "2026-08-20T12:00:00Z")
	rows := buildInventory(ctx, nil, now, "")
	if len(rows) != 1 || rows[0].ProofAge != "not verified" {
		t.Errorf("a drill-backed unverified proof should keep the plain 'not verified' reason, got %+v", rows)
	}
}

func TestInventorySummaryLine(t *testing.T) {
	ctx := syntheticInventoryContext(t) // declared, declared, restores, data-valid, serves
	now := *t3339(t, "2026-08-20T12:00:00Z")
	rows := buildInventory(ctx, nil, now, "")
	got := inventorySummaryLine(rows)
	want := "3 of 5 provably restorable (restores or better) · 1 boot and serve"
	if got != want {
		t.Errorf("inventorySummaryLine = %q, want %q", got, want)
	}
}

// TestPartitionCounts: syntheticInventoryContext's 4 proofs are
// nas-outofband-tailscale (expired -> declared/unreviewed, no acceptance
// recorded), obsidian-vault-recovery (restores), assistant-conversations-
// recovery (data-valid), money-db-recovery (serves) — 3 restored, 0
// observed, 0 accepted, 1 unreviewed. The never-drilled drill has no
// matching proof at all, so it must not be counted here (Restored+
// Observed+Accepted+Unreviewed always equals the proof count, not the
// inventory row count).
func TestPartitionCounts(t *testing.T) {
	ctx := syntheticInventoryContext(t)
	now := *t3339(t, "2026-08-20T12:00:00Z")
	restored, observed, accepted, unreviewed := partitionCounts(ctx.Proofs, now, "")
	if restored != 3 || observed != 0 || accepted != 0 || unreviewed != 1 {
		t.Errorf("partitionCounts = (%d, %d, %d, %d), want (3, 0, 0, 1)", restored, observed, accepted, unreviewed)
	}
	if restored+observed+accepted+unreviewed != len(ctx.Proofs) {
		t.Errorf("restored+observed+accepted+unreviewed = %d, want len(Proofs) = %d", restored+observed+accepted+unreviewed, len(ctx.Proofs))
	}
}

// TestPartitionCountsSplitsActiveAcceptance verifies an active (review_by in
// the future) acceptance counts as accepted, not unreviewed, while a lapsed
// one (review_by in the past) falls back to unreviewed.
func TestPartitionCountsSplitsActiveAcceptance(t *testing.T) {
	now := *t3339(t, "2026-08-20T12:00:00Z")
	active := contextspec.Proof{ID: "a", Status: contextspec.ProofRecordObserved, Accepted: &contextspec.Acceptance{
		By: "owner/tanner", At: now.Add(-time.Hour), Reason: "cannot be drilled unattended", ReviewBy: now.Add(24 * time.Hour),
	}}
	lapsed := contextspec.Proof{ID: "b", Status: contextspec.ProofRecordObserved, Accepted: &contextspec.Acceptance{
		By: "owner/tanner", At: now.Add(-100 * 24 * time.Hour), Reason: "cannot be drilled unattended", ReviewBy: now.Add(-time.Hour),
	}}
	restored, observed, accepted, unreviewed := partitionCounts([]contextspec.Proof{active, lapsed}, now, "")
	if restored != 0 || observed != 0 || accepted != 1 || unreviewed != 1 {
		t.Errorf("partitionCounts = (%d, %d, %d, %d), want (0, 0, 1, 1)", restored, observed, accepted, unreviewed)
	}
}

// TestPartitionCountsObservedVsUnreviewed: a declared/attested proof with
// BOTH observed_at and expires_at, still inside its own TTL window, counts
// as observed (fresh, actively re-observed evidence) — not unreviewed. A
// sibling proof with no expiry declared at all stays unreviewed, and an
// EXPIRED proof (past its own TTL window) is also unreviewed, not observed,
// even though it too carries both timestamps.
func TestPartitionCountsObservedVsUnreviewed(t *testing.T) {
	now := *t3339(t, "2026-08-20T12:00:00Z")
	fresh := t3339(t, "2026-08-19T00:00:00Z")
	freshExpires := t3339(t, "2026-08-22T00:00:00Z") // future, within its own TTL
	stalePast := t3339(t, "2026-01-01T00:00:00Z")
	staleExpires := t3339(t, "2026-01-03T00:00:00Z") // already expired

	observedProof := contextspec.Proof{ID: "o", Status: contextspec.ProofRecordObserved, ObservedAt: fresh, ExpiresAt: freshExpires}
	noExpiryProof := contextspec.Proof{ID: "u1", Status: contextspec.ProofRecordObserved, ObservedAt: fresh}
	expiredProof := contextspec.Proof{ID: "u2", Status: contextspec.ProofRecordObserved, ObservedAt: stalePast, ExpiresAt: staleExpires}

	restored, observed, accepted, unreviewed := partitionCounts(
		[]contextspec.Proof{observedProof, noExpiryProof, expiredProof}, now, "")
	if restored != 0 || observed != 1 || accepted != 0 || unreviewed != 2 {
		t.Errorf("partitionCounts = (%d, %d, %d, %d), want (0, 1, 0, 2)", restored, observed, accepted, unreviewed)
	}
}

// TestFreshnessWindowThirtyDayTTLGoesUnreviewedAfterAboutFourDays: a
// one-off attestation with a long declared TTL (30 days) must not read
// "observed" for nearly a month just because it has not technically
// expired — freshnessWindow floors it at max(48h, TTL/7) ≈ 4.3 days for a
// 30-day TTL, so an attestation observed 6 days ago is unreviewed again,
// and one observed only 1 day ago is still observed.
func TestFreshnessWindowThirtyDayTTLGoesUnreviewedAfterAboutFourDays(t *testing.T) {
	now := *t3339(t, "2026-08-20T00:00:00Z")
	sixDaysAgo := t3339(t, "2026-08-14T00:00:00Z")
	oneDayAgo := t3339(t, "2026-08-19T00:00:00Z")
	expires30dFromSixDaysAgo := t3339(t, "2026-09-13T00:00:00Z") // 30d TTL from sixDaysAgo
	expires30dFromOneDayAgo := t3339(t, "2026-09-18T00:00:00Z")  // 30d TTL from oneDayAgo

	staleAttestation := contextspec.Proof{ID: "recovery-usb-bootstrap", Status: contextspec.ProofRecordObserved,
		ObservedAt: sixDaysAgo, ExpiresAt: expires30dFromSixDaysAgo}
	freshAttestation := contextspec.Proof{ID: "daily-refresh", Status: contextspec.ProofRecordObserved,
		ObservedAt: oneDayAgo, ExpiresAt: expires30dFromOneDayAgo}

	if isObservedProof(staleAttestation, now) {
		t.Error("a 30d-TTL attestation observed 6 days ago must be unreviewed (outside its ~4.3d freshness window), got observed")
	}
	if !isObservedProof(freshAttestation, now) {
		t.Error("a 30d-TTL attestation observed 1 day ago must still be observed (inside its ~4.3d freshness window)")
	}

	restored, observed, accepted, unreviewed := partitionCounts([]contextspec.Proof{staleAttestation, freshAttestation}, now, "")
	if restored != 0 || observed != 1 || accepted != 0 || unreviewed != 1 {
		t.Errorf("partitionCounts = (%d, %d, %d, %d), want (0, 1, 0, 1)", restored, observed, accepted, unreviewed)
	}
}

// TestGetProofsFreshnessWindowRowText pins the row text the freshness
// window drives: "observed · refreshed <age> ago · valid until <date>" for
// a proof inside its window, "unreviewed · last observed <age> ago (window
// <w>)" once it has fallen outside it.
func TestGetProofsFreshnessWindowRowText(t *testing.T) {
	now := *t3339(t, "2026-08-20T00:00:00Z")
	sixDaysAgo := t3339(t, "2026-08-14T00:00:00Z")
	oneDayAgo := t3339(t, "2026-08-19T00:00:00Z")
	expires30dFromSixDaysAgo := t3339(t, "2026-09-13T00:00:00Z")
	expires30dFromOneDayAgo := t3339(t, "2026-09-18T00:00:00Z")

	ctx := contextspec.Context{Proofs: []contextspec.Proof{
		{ID: "stale", Status: contextspec.ProofRecordObserved, ObservedAt: sixDaysAgo, ExpiresAt: expires30dFromSixDaysAgo},
		{ID: "fresh", Status: contextspec.ProofRecordObserved, ObservedAt: oneDayAgo, ExpiresAt: expires30dFromOneDayAgo},
	}}
	verdict := "pass"
	var expiring int
	proofs := getProofs(ctx, now, "", &verdict, &expiring)
	byID := map[string]ProofState{}
	for _, p := range proofs {
		byID[p.ID] = p
	}

	fresh := byID["fresh"]
	if fresh.Status != "observed" {
		t.Errorf("fresh.Status = %q, want observed", fresh.Status)
	}
	if !strings.Contains(fresh.Detail, "refreshed 1d ago") || !strings.Contains(fresh.Detail, "valid until") {
		t.Errorf("fresh.Detail = %q, want it to mention \"refreshed 1d ago\" and \"valid until\"", fresh.Detail)
	}

	stale := byID["stale"]
	if stale.Status != "unreviewed" {
		t.Errorf("stale.Status = %q, want unreviewed", stale.Status)
	}
	if !strings.Contains(stale.Detail, "last observed 6d ago") || !strings.Contains(stale.Detail, "window 4d") {
		t.Errorf("stale.Detail = %q, want it to mention \"last observed 6d ago\" and \"window 4d\"", stale.Detail)
	}
}

// TestRenderTextHeaderShowsRestoredObservedAcceptedUnreviewed: the header
// line names how many of the declared proofs are provably restored,
// observed, accepted, or unreviewed, alongside the pre-existing guard/
// proof/expiring-soon counts.
func TestRenderTextHeaderShowsRestoredObservedAcceptedUnreviewed(t *testing.T) {
	s := &Summary{
		Verdict: "pass", Lifelines: 20, Guards: 19, LedgerOK: true,
		Proofs:   make([]ProofState, 39),
		Restored: 16, Observed: 4, Accepted: 5, Unreviewed: 14, ExpiringSoon: 0,
	}
	out, err := s.Render("text")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := "PASS — 39 guards · 39 proofs (16 restored · 4 observed · 5 accepted · 14 unreviewed · 0 expiring soon)\n"
	if !strings.HasPrefix(string(out), want) {
		t.Errorf("got header %q, want prefix %q", out, want)
	}
}

func TestInventorySummaryLineEmptyWhenNoRows(t *testing.T) {
	if got := inventorySummaryLine(nil); got != "" {
		t.Errorf("inventorySummaryLine(nil) = %q, want empty", got)
	}
}

// ---- multi-context aggregation (Gather over repeatable --context) ------

const invContextA = `version: 2
drills:
  - proof: vault-recovery
    artifact: /fake/vault
    recover: "true"
proofs:
  - id: vault-recovery
    status: validated
    observed_at: "2026-08-20T00:00:00Z"
    verified: true
`

const invContextB = `version: 2
drills:
  - proof: money-db-recovery
    artifact: /fake/money.db
    recover: "true"
proofs:
  - id: money-db-recovery
    status: validated
    observed_at: "2026-08-20T00:00:00Z"
    verified: true
    measurements:
      rto_seconds: 2.1
      checks: [{type: serve, pass: true, detail: "ready"}]
`

func TestGatherAggregatesMultipleContexts(t *testing.T) {
	dir := t.TempDir()
	pathA := writeContextFile(t, dir, "a.yml", invContextA)
	pathB := writeContextFile(t, dir, "b.yml", invContextB)

	s, err := Gather(Request{ContextPaths: []string{pathA, pathB}, AsOf: "2026-08-20T12:00:00Z"})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if len(s.Inventory) != 2 {
		t.Fatalf("got %d inventory rows, want 2 (one per file's drill): %+v", len(s.Inventory), s.Inventory)
	}
	if s.Inventory[0].Proof != "vault-recovery" || s.Inventory[0].Level != "restores" {
		t.Errorf("row[0] = %+v, want vault-recovery/restores (weakest first)", s.Inventory[0])
	}
	if s.Inventory[1].Proof != "money-db-recovery" || s.Inventory[1].Level != "serves" {
		t.Errorf("row[1] = %+v, want money-db-recovery/serves", s.Inventory[1])
	}
	if !strings.Contains(s.Origin, pathA) || !strings.Contains(s.Origin, pathB) {
		t.Errorf("Origin should name both files, got %q", s.Origin)
	}
}

// TestGatherAggregatesAttestationOnlyProofAcrossFiles: a proof declared with
// no drill in ONE file must still surface in the aggregated inventory built
// from ALL loaded files — the full load -> merge -> build pipeline, not
// just the in-process buildInventory unit tests above.
func TestGatherAggregatesAttestationOnlyProofAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	pathA := writeContextFile(t, dir, "a.yml", invContextA)
	pathAttestation := writeContextFile(t, dir, "attestation.yml", `version: 2
proofs:
  - id: manual-key-attestation
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
`)

	s, err := Gather(Request{ContextPaths: []string{pathA, pathAttestation}, AsOf: "2026-08-20T12:00:00Z"})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if len(s.Inventory) != 2 {
		t.Fatalf("got %d rows, want 2 (one drilled, one attestation-only): %+v", len(s.Inventory), s.Inventory)
	}
	var attestation *InventoryRow
	for i := range s.Inventory {
		if s.Inventory[i].Proof == "manual-key-attestation" {
			attestation = &s.Inventory[i]
		}
	}
	if attestation == nil {
		t.Fatal("attestation-only proof from a second file did not reach the aggregated inventory")
	}
	if attestation.Level != "declared" || attestation.ProofAge != "attested, no drill" {
		t.Errorf("unexpected attestation row: %+v", attestation)
	}
}

func TestGatherDuplicateProofIDAcrossFilesErrors(t *testing.T) {
	dir := t.TempDir()
	pathA := writeContextFile(t, dir, "a.yml", `version: 2
proofs:
  - id: shared-proof
    status: observed
    observed_at: "2026-08-01T00:00:00Z"
`)
	pathB := writeContextFile(t, dir, "b.yml", `version: 2
proofs:
  - id: shared-proof
    status: validated
    observed_at: "2026-08-20T00:00:00Z"
    verified: true
`)

	_, err := Gather(Request{ContextPaths: []string{pathA, pathB}, AsOf: "2026-08-20T12:00:00Z"})
	if err == nil {
		t.Fatal("expected an error for a duplicate proof id across files, not a silent merge")
	}
	if !strings.Contains(err.Error(), "shared-proof") || !strings.Contains(err.Error(), pathA) || !strings.Contains(err.Error(), pathB) {
		t.Errorf("error should name the id and both files, got %q", err.Error())
	}
}

// TestGatherSingleContextByteIdenticalToPreMultiContext pins the exact
// output shape for the one-file case, which must be unaffected by
// --context becoming repeatable.
func TestGatherSingleContextByteIdenticalToPreMultiContext(t *testing.T) {
	dir := t.TempDir()
	path := writeContextFile(t, dir, "solo.yml", invContextA)

	s, err := Gather(Request{ContextPaths: []string{path}, AsOf: "2026-08-20T12:00:00Z"})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if s.Origin != path {
		t.Errorf("Origin = %q, want exactly %q (no joining/formatting for a single file)", s.Origin, path)
	}
	if len(s.Inventory) != 1 || s.Inventory[0].Proof != "vault-recovery" {
		t.Fatalf("unexpected inventory: %+v", s.Inventory)
	}
}

func TestGatherZeroContextsUsesBuiltInDefault(t *testing.T) {
	s, err := Gather(Request{})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if s.Origin != contextspec.DefaultOrigin {
		t.Errorf("Origin = %q, want the built-in default policy string", s.Origin)
	}
	if s.Verdict != "warn" {
		t.Errorf("Verdict = %q, want warn (zero-config: nothing is provable yet)", s.Verdict)
	}
}

// TestGetProofsUnreachableAndDisputedRenderDifferently: an unreachable proof
// ("could not even try — the source was asleep") and a disputed one ("the
// recovery ran and did not verify") must produce visibly different
// operator-facing lines, each carrying its own remediation, and both must
// degrade the verdict. Neither wording may imply data loss for the
// unreachable case.
func TestGetProofsUnreachableAndDisputedRenderDifferently(t *testing.T) {
	now := *t3339(t, "2026-08-18T12:00:00Z")
	observed := t3339(t, "2026-08-18T00:00:00Z")
	ctx := contextspec.Context{Proofs: []contextspec.Proof{
		{ID: "nas-sleeping", Status: contextspec.ProofRecordUnreachable, ObservedAt: observed},
		{ID: "corrupt-copy", Status: contextspec.ProofRecordDisputed, ObservedAt: observed},
	}}
	verdict := "pass"
	var expiring int
	proofs := getProofs(ctx, now, "", &verdict, &expiring)

	byID := map[string]ProofState{}
	for _, p := range proofs {
		byID[p.ID] = p
	}
	unreach, dispute := byID["nas-sleeping"], byID["corrupt-copy"]
	if unreach.Status != "unreachable" {
		t.Errorf("unreachable proof rendered as %q, want \"unreachable\"", unreach.Status)
	}
	if dispute.Status != "disputed" {
		t.Errorf("disputed proof rendered as %q, want \"disputed\"", dispute.Status)
	}
	if unreach.Status == dispute.Status || unreach.Detail == dispute.Detail {
		t.Errorf("the two statuses must render differently: %+v vs %+v", unreach, dispute)
	}
	if !strings.Contains(unreach.Detail, "re-run the drill once the source is reachable") {
		t.Errorf("unreachable remediation should say to re-run once reachable, got %q", unreach.Detail)
	}
	if strings.Contains(unreach.Detail, "investigate the copy") {
		t.Errorf("unreachable remediation must not imply the copy is bad, got %q", unreach.Detail)
	}
	if !strings.Contains(dispute.Detail, "investigate the copy") {
		t.Errorf("disputed remediation should say to investigate the copy, got %q", dispute.Detail)
	}
	if verdict != "warn" {
		t.Errorf("verdict = %q, want warn (unreachable must degrade posture, not pass it)", verdict)
	}
}

// TestExpiringSoonIsRelativeToProofLifetime pins the fix for a warning that
// could never clear: the context-control-plane proofs are re-attested on a
// timer with a 48h TTL, and a flat 7-day "expiring soon" window meant they
// were ALWAYS expiring, however healthy the refresh. That warning sat in the
// fixit queue for weeks meaning nothing.
func TestExpiringSoonIsRelativeToProofLifetime(t *testing.T) {
	now := *t3339(t, "2026-08-19T12:00:00Z")

	// Freshly refreshed, 48h TTL: 47h left of a 48h life — not expiring.
	fresh := contextspec.Proof{
		ID:         "context-plane",
		ObservedAt: t3339(t, "2026-08-19T11:00:00Z"),
		ExpiresAt:  t3339(t, "2026-08-21T11:00:00Z"),
	}
	// Same proof, now in the last third of its life: nothing renewed it.
	stalling := contextspec.Proof{
		ID:         "context-plane",
		ObservedAt: t3339(t, "2026-08-18T00:00:00Z"),
		ExpiresAt:  t3339(t, "2026-08-20T00:00:00Z"),
	}
	// A long-lived proof still uses the flat 7-day window.
	longLived := contextspec.Proof{
		ID:         "annual-attestation",
		ObservedAt: t3339(t, "2026-01-01T00:00:00Z"),
		ExpiresAt:  t3339(t, "2026-08-24T00:00:00Z"),
	}

	for _, tc := range []struct {
		name  string
		proof contextspec.Proof
		want  string
	}{
		{"fresh 48h proof is not expiring", fresh, "observed"},
		{"48h proof in its last third is expiring", stalling, "expiring"},
		{"long-lived proof inside 7 days is expiring", longLived, "expiring"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict := "pass"
			var expiring int
			got := getProofs(contextspec.Context{Proofs: []contextspec.Proof{tc.proof}}, now, "", &verdict, &expiring)
			if len(got) != 1 {
				t.Fatalf("expected one proof, got %d", len(got))
			}
			if got[0].Status != tc.want {
				t.Fatalf("status = %q, want %q (%s)", got[0].Status, tc.want, got[0].Detail)
			}
		})
	}
}

// ---- acceptance: verdict transitions + NextSteps (accept/next feature) --

// acceptedActiveContext declares one never-drilled proof with an active
// acceptance (review_by in the future) — the "cannot be drilled unattended"
// case `restoregap accept` exists for. No expiry is declared, so the only
// thing that could still warn the verdict is an unreviewed proof, and this
// one is not unreviewed.
const acceptedActiveContext = `version: 2
proofs:
  - id: phone-reprovision-path
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
    accepted:
      by: owner/tanner
      at: "2026-08-20T00:00:00Z"
      reason: cannot be drilled unattended
      review_by: "2026-11-20T00:00:00Z"
`

// acceptedLapsedContext is the same proof, but its acceptance's review_by
// has already passed — a decision that came due and nobody looked at it
// again, which counts as unreviewed, not accepted.
const acceptedLapsedContext = `version: 2
proofs:
  - id: phone-reprovision-path
    status: observed
    observed_at: "2026-05-01T00:00:00Z"
    accepted:
      by: owner/tanner
      at: "2026-05-01T00:00:00Z"
      reason: cannot be drilled unattended
      review_by: "2026-08-01T00:00:00Z"
`

func TestGatherActiveAcceptanceYieldsPass(t *testing.T) {
	dir := t.TempDir()
	path := writeContextFile(t, dir, "restoregap.yml", acceptedActiveContext)

	s, err := Gather(Request{ContextPaths: []string{path}, AsOf: "2026-08-24T00:00:00Z"})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if s.Verdict != "pass" {
		t.Errorf("Verdict = %q, want pass (active acceptance is a decision, not a gap)", s.Verdict)
	}
	if s.Accepted != 1 || s.Unreviewed != 0 {
		t.Errorf("Accepted/Unreviewed = %d/%d, want 1/0", s.Accepted, s.Unreviewed)
	}
	row, ok := findRow(s.Inventory, "phone-reprovision-path")
	if !ok {
		t.Fatal("phone-reprovision-path missing from inventory")
	}
	want := "attested · accepted: cannot be drilled unattended (review by 2026-11-20)"
	if row.ProofAge != want {
		t.Errorf("ProofAge = %q, want %q", row.ProofAge, want)
	}
	if row.AcceptedReason != "cannot be drilled unattended" || row.AcceptedBy != "owner/tanner" {
		t.Errorf("unexpected acceptance fields: %+v", row)
	}
}

func TestGatherLapsedAcceptanceYieldsWarn(t *testing.T) {
	dir := t.TempDir()
	path := writeContextFile(t, dir, "restoregap.yml", acceptedLapsedContext)

	s, err := Gather(Request{ContextPaths: []string{path}, AsOf: "2026-08-24T00:00:00Z"})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if s.Verdict != "warn" {
		t.Errorf("Verdict = %q, want warn (lapsed acceptance is a gap again)", s.Verdict)
	}
	if s.Accepted != 0 || s.Unreviewed != 1 {
		t.Errorf("Accepted/Unreviewed = %d/%d, want 0/1", s.Accepted, s.Unreviewed)
	}
	row, ok := findRow(s.Inventory, "phone-reprovision-path")
	if !ok {
		t.Fatal("phone-reprovision-path missing from inventory")
	}
	if row.AcceptanceLapsedOn != "2026-08-01" {
		t.Errorf("AcceptanceLapsedOn = %q, want 2026-08-01", row.AcceptanceLapsedOn)
	}
	if !strings.Contains(row.ProofAge, "acceptance lapsed 2026-08-01") {
		t.Errorf("ProofAge = %q, want it to mention the lapse", row.ProofAge)
	}
}

func findRow(rows []InventoryRow, proof string) (InventoryRow, bool) {
	for _, r := range rows {
		if r.Proof == proof {
			return r, true
		}
	}
	return InventoryRow{}, false
}

// TestNextStepsOrdering: worst first — a disputed/expired/unreachable proof
// outranks a lapsed acceptance, which outranks a never-drilled attestation,
// which outranks a drilled proof that simply has not verified yet. An
// active (non-lapsed) acceptance is a decision, not a gap, and must not
// appear at all.
func TestNextStepsOrdering(t *testing.T) {
	dir := t.TempDir()
	path := writeContextFile(t, dir, "restoregap.yml", `version: 2
drills:
  - proof: drilled-unproven
    artifact: /fake
    recover: "true"
proofs:
  - id: expired-proof
    status: validated
    observed_at: "2026-01-01T00:00:00Z"
    expires_at: "2026-01-02T00:00:00Z"
    verified: true
  - id: lapsed-acceptance
    status: observed
    observed_at: "2026-05-01T00:00:00Z"
    accepted:
      by: owner/tanner
      at: "2026-05-01T00:00:00Z"
      reason: cannot be drilled unattended
      review_by: "2026-08-01T00:00:00Z"
  - id: never-drilled
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
  - id: active-acceptance
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
    accepted:
      by: owner/tanner
      at: "2026-08-20T00:00:00Z"
      reason: cannot be drilled unattended
      review_by: "2026-11-20T00:00:00Z"
`)

	s, err := Gather(Request{ContextPaths: []string{path}, AsOf: "2026-08-24T00:00:00Z"})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	steps := s.NextSteps()
	var got []string
	for _, step := range steps {
		got = append(got, step.Proof)
	}
	want := []string{"expired-proof", "lapsed-acceptance", "never-drilled", "drilled-unproven"}
	if len(got) != len(want) {
		t.Fatalf("NextSteps proofs = %v, want %v (active-acceptance must be excluded entirely)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("NextSteps[%d] = %q, want %q (full order %v)", i, got[i], want[i], got)
		}
	}
	for _, step := range steps {
		if step.Proof == "active-acceptance" {
			t.Error("an active acceptance must not appear in NextSteps")
		}
	}
}

// TestNextStepsEffectiveOrderingEnvThenLayerThenProblemsFirst: taxonomy
// spec section F's fixed "effective ordering everywhere" — environment
// criticality first, then layer (vocabulary order), then problems-first —
// applied to the flat `next` list, which (unlike the status tree's Layer/
// category grouping) has no structural grouping of its own to fall back on.
func TestNextStepsEffectiveOrderingEnvThenLayerThenProblemsFirst(t *testing.T) {
	dir := t.TempDir()
	path := writeContextFile(t, dir, "restoregap.yml", `version: 2
guards:
  - id: gLab
    kind: guard
    match: {paths: ["/lab/**"]}
    requires: {proofs: [pLab]}
    layer: git-code
    scope: {environment: lab}
  - id: gProd
    kind: guard
    match: {paths: ["/prod-git/**"]}
    requires: {proofs: [pProd]}
    layer: git-code
    scope: {environment: prod}
  - id: gProdDataApps
    kind: guard
    match: {paths: ["/prod-apps/**"]}
    requires: {proofs: [pProdDataApps]}
    layer: data-apps
    scope: {environment: prod}
  - id: gProdIdentity
    kind: guard
    match: {paths: ["/prod-id/**"]}
    requires: {proofs: [pProdIdentity]}
    layer: identity-secrets
    scope: {environment: prod}
proofs:
  - id: pLab
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
  - id: pProd
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
  - id: pProdDataApps
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
  - id: pProdIdentity
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
`)
	s, err := Gather(Request{ContextPaths: []string{path}, AsOf: "2026-08-24T00:00:00Z"})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	steps := s.NextSteps()
	var got []string
	for _, step := range steps {
		got = append(got, step.Proof)
	}
	// prod outranks lab regardless of layer; within prod, identity-secrets
	// outranks git-code, which outranks data-apps (LayerOrder); lab's
	// git-code proof comes last regardless of its layer.
	want := []string{"pProdIdentity", "pProd", "pProdDataApps", "pLab"}
	if len(got) != len(want) {
		t.Fatalf("NextSteps proofs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("NextSteps[%d] = %q, want %q (full order %v)", i, got[i], want[i], got)
		}
	}
}

func TestNextStepsEmptyWhenAllGreen(t *testing.T) {
	dir := t.TempDir()
	path := writeContextFile(t, dir, "restoregap.yml", invContextB)
	s, err := Gather(Request{ContextPaths: []string{path}, AsOf: "2026-08-20T12:00:00Z"})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if steps := s.NextSteps(); len(steps) != 0 {
		t.Errorf("NextSteps = %+v, want empty (invContextB's one proof serves)", steps)
	}
}
