package status

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

func writeContextFile(t *testing.T, dir, name, yaml string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
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

	rows := buildInventory(ctx, nil, now)
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

func TestBuildInventoryNoProofRecorded(t *testing.T) {
	ctx := contextspec.Context{Drills: []contextspec.Drill{{Proof: "orphan", Artifact: "/fake", Recover: "true"}}}
	rows := buildInventory(ctx, nil, time.Now())
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
	rows := buildInventory(ctx, nil, now)
	if rows[0].RTO != emDash || rows[0].RPO != emDash {
		t.Errorf("an expired proof's stale measurements must not be shown as current: %+v", rows[0])
	}
	if !strings.Contains(rows[0].ProofAge, "expired") {
		t.Errorf("ProofAge should carry the expiry reason: %q", rows[0].ProofAge)
	}
}

// TestRenderTextIncludesInventoryTable is a golden-ish assertion on the text
// block: header row present, sorted weakest-first, em dashes for absent
// measurements, and it appears before the pre-existing "Recovery chain"
// section (additive, nothing reordered).
func TestRenderTextIncludesInventoryTable(t *testing.T) {
	ctx := syntheticInventoryContext(t)
	now := *t3339(t, "2026-08-20T12:00:00Z")
	s := &Summary{Verdict: "pass", Inventory: buildInventory(ctx, nil, now)}

	out, err := s.Render("text")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	text := string(out)

	if !strings.Contains(text, "Recovery inventory — what provably comes back, and to what point") {
		t.Fatalf("missing inventory header, got:\n%s", text)
	}
	if !strings.Contains(text, "LEVEL") || !strings.Contains(text, "PROOF") ||
		!strings.Contains(text, "RPO") || !strings.Contains(text, "RTO") || !strings.Contains(text, "PROOF AGE") {
		t.Errorf("missing a column header, got:\n%s", text)
	}

	invIdx := strings.Index(text, "Recovery inventory")
	chainIdx := strings.Index(text, "Recovery chain")
	if invIdx < 0 || chainIdx < 0 || invIdx > chainIdx {
		t.Errorf("inventory should appear before the pre-existing Recovery chain section, got:\n%s", text)
	}

	declaredIdx := strings.Index(text, "declared")
	servesIdx := strings.Index(text, "serves")
	if declaredIdx < 0 || servesIdx < 0 || declaredIdx > servesIdx {
		t.Errorf("expected declared before serves (weakest first), got:\n%s", text)
	}
	if !strings.Contains(text, emDash) {
		t.Errorf("expected an em dash for an absent RPO/RTO, got:\n%s", text)
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
	s := &Summary{Verdict: "pass", Inventory: buildInventory(ctx, nil, now)}

	out, err := s.Render("html")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := string(out)
	if !strings.Contains(html, "Recovery inventory") {
		t.Errorf("missing inventory section in HTML output")
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
	rows := buildInventory(ctx, nil, now)
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
	rows := buildInventory(ctx, nil, now)
	if len(rows) != 1 || rows[0].ProofAge != "not verified" {
		t.Errorf("a drill-backed unverified proof should keep the plain 'not verified' reason, got %+v", rows)
	}
}

func TestInventorySummaryLine(t *testing.T) {
	ctx := syntheticInventoryContext(t) // declared, declared, restores, data-valid, serves
	now := *t3339(t, "2026-08-20T12:00:00Z")
	rows := buildInventory(ctx, nil, now)
	got := inventorySummaryLine(rows)
	want := "3 of 5 provably restorable (level >= restores); 1 serve"
	if got != want {
		t.Errorf("inventorySummaryLine = %q, want %q", got, want)
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
	if len(s.Warnings) != 0 {
		t.Errorf("no duplicates across these two files, expected no warnings, got %v", s.Warnings)
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

func TestGatherDuplicateProofIDWarnsAndLastLoadedWins(t *testing.T) {
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

	s, err := Gather(Request{ContextPaths: []string{pathA, pathB}, AsOf: "2026-08-20T12:00:00Z"})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if len(s.Warnings) != 1 {
		t.Fatalf("got %d warnings, want 1: %v", len(s.Warnings), s.Warnings)
	}
	w := s.Warnings[0]
	if !strings.Contains(w, "shared-proof") || !strings.Contains(w, "last-loaded wins") {
		t.Errorf("unexpected warning text: %q", w)
	}
	if !strings.Contains(w, pathB) {
		t.Errorf("warning should name the file it kept (last-loaded, %s), got %q", pathB, w)
	}
	// last-loaded (b.yml, verified) must be the one that survived — not a
	// silent merge of both declarations.
	if len(s.Proofs) != 1 || s.Proofs[0].Status != "present" {
		t.Fatalf("unexpected merged proofs: %+v", s.Proofs)
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
	if len(s.Warnings) != 0 {
		t.Errorf("a single file can never produce a cross-file duplicate warning, got %v", s.Warnings)
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
	if len(s.Warnings) != 0 {
		t.Errorf("unexpected warnings on the default policy: %v", s.Warnings)
	}
}
