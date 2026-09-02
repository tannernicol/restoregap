// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// buildTaxonomyFixture makes a small context with one guard per layer
// signal plus one deliberately unfiled proof, and gathers it — the same
// path production code uses (Gather), so BuildLayerTree is exercised
// end-to-end rather than by hand-constructed rows.
func buildTaxonomyFixture(t *testing.T) (*Summary, contextspec.Context) {
	t.Helper()
	now := mustTime(t, "2026-08-24T00:00:00Z")
	future := now.Add(720 * time.Hour)
	ctx := contextspec.Context{
		Version: 2,
		Guards: []contextspec.Guard{
			{ID: "ssh-guard", Kind: contextspec.GuardKindLifeline, Match: contextspec.Matcher{Paths: []string{"~/.ssh/id_ed25519"}},
				Requires: contextspec.Requirement{Proofs: []string{"ssh-key-recovery"}}, Layer: contextspec.LayerIdentitySecrets, Category: "ssh-keys"},
			{ID: "git-guard", Kind: contextspec.GuardKindGuard, Match: contextspec.Matcher{Paths: []string{"/repo/**"}},
				Requires: contextspec.Requirement{Proofs: []string{"git-estate-recovery"}}, Layer: contextspec.LayerGitCode},
		},
		Proofs: []contextspec.Proof{
			{ID: "ssh-key-recovery", Status: contextspec.ProofRecordValidated, ObservedAt: &now, ExpiresAt: &future, Verified: true},
			{ID: "git-estate-recovery", Status: contextspec.ProofRecordDisputed, ObservedAt: &now},
			{ID: "orphan-proof", Status: contextspec.ProofRecordObserved, ObservedAt: &now, ExpiresAt: &future},
		},
	}
	// Gather only knows how to load from context PATHS; build the Summary
	// pieces directly here instead so the fixture stays self-contained (no
	// temp files) while still exercising buildInventory/BuildLayerTree the
	// same way Gather wires them together.
	s := &Summary{Verdict: "pass"}
	s.Inventory = buildInventory(ctx, nil, now, "")
	s.Proofs = getProofs(ctx, now, "", &s.Verdict, &s.ExpiringSoon)
	s.Context = ctx
	return s, ctx
}

func TestBuildLayerTreeGroupsByLayerAndCategory(t *testing.T) {
	s, ctx := buildTaxonomyFixture(t)
	groups := BuildLayerTree(ctx, s, TreeFilter{})

	byLayer := map[string]LayerGroup{}
	for _, g := range groups {
		byLayer[g.Layer] = g
	}

	idsg, ok := byLayer[contextspec.LayerIdentitySecrets]
	if !ok {
		t.Fatalf("expected an identity-secrets layer group, got %+v", byLayer)
	}
	if len(idsg.Categories) != 1 || idsg.Categories[0].Category != "ssh-keys" {
		t.Errorf("expected the ssh-keys category under identity-secrets, got %+v", idsg.Categories)
	}

	git, ok := byLayer[contextspec.LayerGitCode]
	if !ok {
		t.Fatalf("expected a git-code layer group, got %+v", byLayer)
	}
	if len(git.Categories) != 1 || len(git.Categories[0].Rows) != 1 || git.Categories[0].Rows[0].State != StateDisputed {
		t.Errorf("expected git-estate-recovery disputed under git-code, got %+v", git.Categories)
	}

	unfiled, ok := byLayer[contextspec.LayerUnfiled]
	if !ok {
		t.Fatalf("expected an unfiled layer group for orphan-proof, got %+v", byLayer)
	}
	found := false
	for _, cg := range unfiled.Categories {
		for _, r := range cg.Rows {
			if r.Proof == "orphan-proof" {
				found = true
			}
		}
	}
	if !found {
		t.Error("orphan-proof (no layer, no requiring guard) should land in the unfiled layer")
	}
}

func TestBuildLayerTreeLayerOrderIsVocabularyOrder(t *testing.T) {
	s, ctx := buildTaxonomyFixture(t)
	groups := BuildLayerTree(ctx, s, TreeFilter{})
	var seen []string
	for _, g := range groups {
		seen = append(seen, g.Layer)
	}
	rankOf := func(l string) int { return contextspec.LayerRank(l) }
	for i := 1; i < len(seen); i++ {
		if rankOf(seen[i-1]) >= rankOf(seen[i]) {
			t.Fatalf("layer groups out of vocabulary order: %v", seen)
		}
	}
}

func TestBuildLayerTreeFilterByLayer(t *testing.T) {
	s, ctx := buildTaxonomyFixture(t)
	groups := BuildLayerTree(ctx, s, NewTreeFilter([]string{contextspec.LayerGitCode}, nil, nil, nil, nil, nil))
	if len(groups) != 1 || groups[0].Layer != contextspec.LayerGitCode {
		t.Fatalf("expected exactly the git-code group, got %+v", groups)
	}
}

func TestBuildLayerTreeFilterByState(t *testing.T) {
	s, ctx := buildTaxonomyFixture(t)
	groups := BuildLayerTree(ctx, s, NewTreeFilter(nil, []string{StateDisputed}, nil, nil, nil, nil))
	total := 0
	for _, g := range groups {
		for _, cg := range g.Categories {
			total += len(cg.Rows)
		}
	}
	if total != 1 {
		t.Fatalf("expected exactly 1 disputed row across all layers, got %d (%+v)", total, groups)
	}
}

func TestBuildLayerHeaderFormat(t *testing.T) {
	rows := []TreeRow{
		{Proof: "a", State: StateRestored},
		{Proof: "b", State: StateRestored},
		{Proof: "c", State: StateRestored},
		{Proof: "d", State: StateAccepted},
		{Proof: "e", State: StateUnreviewed},
		{Proof: "f", State: StateUnreviewed},
	}
	got := buildLayerHeader(contextspec.LayerIdentitySecrets, rows)
	want := "identity-secrets — 6 proofs · 2 unreviewed · 1 accepted · 3 restored · worst: unreviewed"
	if got != want {
		t.Errorf("buildLayerHeader = %q, want %q", got, want)
	}
}

func TestClassifyLayerConflictNoteMentionsBothGuards(t *testing.T) {
	ctx := contextspec.Context{
		Guards: []contextspec.Guard{
			{ID: "gA", Requires: contextspec.Requirement{Proofs: []string{"p1"}}, Layer: contextspec.LayerDataApps},
			{ID: "gB", Requires: contextspec.Requirement{Proofs: []string{"p1"}}, Layer: contextspec.LayerIdentitySecrets},
		},
		Proofs: []contextspec.Proof{{ID: "p1", Status: contextspec.ProofRecordObserved}},
	}
	row := InventoryRow{Proof: "p1", Level: contextspec.LevelDeclared.String()}
	c := Classify(ctx, "p1", row, ProofState{}, false)
	if c.Layer != contextspec.LayerIdentitySecrets {
		t.Errorf("Layer = %q, want identity-secrets (earliest wins)", c.Layer)
	}
	if !c.Conflict || !strings.Contains(c.ConflictDetail, "gA") || !strings.Contains(c.ConflictDetail, "gB") {
		t.Errorf("expected a conflict note naming both guards, got conflict=%v detail=%q", c.Conflict, c.ConflictDetail)
	}
}

// buildHostFixture builds a one-guard, one-proof Summary for a single host,
// scoped to env/system/host — the shape a real per-host context file
// declares (taxonomy spec section F: scope defaults at the file level).
func buildHostFixture(t *testing.T, host string, now time.Time) *Summary {
	t.Helper()
	future := now.Add(720 * time.Hour)
	ctx := contextspec.Context{
		Version: 2,
		Scope:   contextspec.Scope{Environment: "prod", System: "money", Host: host},
		Guards: []contextspec.Guard{
			{ID: "restic-guard", Kind: contextspec.GuardKindLifeline,
				Match:    contextspec.Matcher{Paths: []string{"/data/money/**"}},
				Requires: contextspec.Requirement{Proofs: []string{"restic-proof"}}, Layer: contextspec.LayerBackupsOffsite},
		},
		Proofs: []contextspec.Proof{
			{ID: "restic-proof", Status: contextspec.ProofRecordValidated, ObservedAt: &now, ExpiresAt: &future, Verified: true},
		},
	}
	s := &Summary{Verdict: "pass", Context: ctx}
	s.Inventory = buildInventory(ctx, nil, now, "")
	s.Proofs = getProofs(ctx, now, "", &s.Verdict, &s.ExpiringSoon)
	return s
}

// TestScopeRowsTwoHostMergeByKeyGolden is the taxonomy spec section F golden
// test: "a two-host merge is possible by key without loss (pure data test,
// no aggregator)". The SAME guard id ("restic-guard") is declared
// independently on two hosts (a real deployment: one context file per
// machine, each rewritten by that machine's own drill timer — see
// newStatusCmd's --context doc). A later hosted-tier aggregator (not built
// here, durable decision 2026-07-26) would ingest both hosts' `status
// --format json` documents and merge them; this test proves that merge is
// lossless and collision-free using nothing but ScopeRow.MergeKey, with no
// aggregator code at all.
func TestScopeRowsTwoHostMergeByKeyGolden(t *testing.T) {
	now := mustTime(t, "2026-08-24T00:00:00Z")
	hostA := buildHostFixture(t, "host-nas", now)
	hostB := buildHostFixture(t, "host-b", now)

	rowsA := BuildScopeRows(hostA.Context, hostA, TreeFilter{})
	rowsB := BuildScopeRows(hostB.Context, hostB, TreeFilter{})
	if len(rowsA) != 1 || len(rowsB) != 1 {
		t.Fatalf("expected exactly one scope row per host, got %d and %d", len(rowsA), len(rowsB))
	}
	if rowsA[0].Proof != "restic-proof" || rowsB[0].Proof != "restic-proof" {
		t.Fatalf("expected the same guard id (restic-proof) on both hosts, got %q and %q", rowsA[0].Proof, rowsB[0].Proof)
	}
	if rowsA[0].Scope.Host == rowsB[0].Scope.Host {
		t.Fatalf("fixture bug: both hosts resolved to the same Scope.Host %q", rowsA[0].Scope.Host)
	}

	// A hosted aggregator merges by (id, environment, system, host) — exactly
	// what MergeKey encodes. Simulate that merge with nothing but a map.
	merged := map[string]ScopeRow{}
	var collisions int
	for _, r := range append(append([]ScopeRow{}, rowsA...), rowsB...) {
		if _, exists := merged[r.MergeKey()]; exists {
			collisions++
		}
		merged[r.MergeKey()] = r
	}
	if collisions != 0 {
		t.Errorf("expected zero key collisions merging two distinct hosts, got %d", collisions)
	}
	if len(merged) != 2 {
		t.Fatalf("expected both hosts' rows to survive the merge under distinct keys, got %d entries: %+v", len(merged), merged)
	}
	if merged[rowsA[0].MergeKey()].Scope.Host != "host-nas" {
		t.Error("host A's row lost or overwritten after merge — same guard id must not collide across hosts")
	}
	if merged[rowsB[0].MergeKey()].Scope.Host != "host-b" {
		t.Error("host B's row lost or overwritten after merge — same guard id must not collide across hosts")
	}

	// Same guard id + same env/system + same host (e.g. re-ingesting host A's
	// own document twice) DOES collide — that's the intended identity, not a
	// bug: it is the same fact reported twice, not two facts.
	dup := map[string]ScopeRow{}
	for _, r := range append(append([]ScopeRow{}, rowsA...), rowsA...) {
		dup[r.MergeKey()] = r
	}
	if len(dup) != 1 {
		t.Errorf("expected re-ingesting the same host's document to collapse to one entry by key, got %d", len(dup))
	}
}

// TestBuildLayerTreeRowsOrderedByEnvThenProblemsFirst: taxonomy spec
// section F's fixed effective ordering, applied within one layer/category
// grouping (the tree's own grouping already fixes layer — see section C —
// so environment then problems-first is what remains to order the rows
// themselves).
func TestBuildLayerTreeRowsOrderedByEnvThenProblemsFirst(t *testing.T) {
	now := mustTime(t, "2026-08-24T00:00:00Z")
	ctx := contextspec.Context{
		Guards: []contextspec.Guard{
			{ID: "gLabGreen", Requires: contextspec.Requirement{Proofs: []string{"pLabGreen"}}, Layer: contextspec.LayerGitCode,
				Scope: contextspec.Scope{Environment: "lab"}},
			{ID: "gProdBad", Requires: contextspec.Requirement{Proofs: []string{"pProdBad"}}, Layer: contextspec.LayerGitCode,
				Scope: contextspec.Scope{Environment: "prod"}},
		},
		Proofs: []contextspec.Proof{
			{ID: "pLabGreen", Status: contextspec.ProofRecordObserved, ObservedAt: &now},
			{ID: "pProdBad", Status: contextspec.ProofRecordDisputed, ObservedAt: &now},
		},
	}
	s := &Summary{Verdict: "warn", Context: ctx}
	s.Inventory = buildInventory(ctx, nil, now, "")
	s.Proofs = getProofs(ctx, now, "", &s.Verdict, &s.ExpiringSoon)

	groups := BuildLayerTree(ctx, s, TreeFilter{})
	var git LayerGroup
	for _, g := range groups {
		if g.Layer == contextspec.LayerGitCode {
			git = g
		}
	}
	if len(git.Categories) != 1 || len(git.Categories[0].Rows) != 2 {
		t.Fatalf("expected both git-code rows in one category, got %+v", git.Categories)
	}
	rows := git.Categories[0].Rows
	if rows[0].Proof != "pProdBad" || rows[1].Proof != "pLabGreen" {
		t.Errorf("rows = %v, want prod (higher env criticality) before lab even though prod's state is worse and lab's is green",
			[]string{rows[0].Proof, rows[1].Proof})
	}
}

// TestBuildSystemTreeGroupsBySystemNotLayer: the same classified proofs
// BuildLayerTree groups by layer must come back grouped by scope.system
// instead — the HTML dashboard's "By system" view is a regrouping of the
// identical data, never a second classification pass.
func TestBuildSystemTreeGroupsBySystemNotLayer(t *testing.T) {
	s := buildMultiEnvSummary(t) // pA: system money; pB: system obsidian; both layer data-apps
	groups := BuildSystemTree(s.Context, s, TreeFilter{})

	bySystem := map[string]LayerGroup{}
	for _, g := range groups {
		bySystem[g.Layer] = g
	}
	if _, ok := bySystem["money"]; !ok {
		t.Fatalf("expected a 'money' system group, got %+v", groups)
	}
	if _, ok := bySystem["obsidian"]; !ok {
		t.Fatalf("expected an 'obsidian' system group, got %+v", groups)
	}
	moneyRows := bySystem["money"].EnvSystemRows
	if len(moneyRows) != 1 || moneyRows[0].Proof != "pA" {
		t.Errorf("money group should hold exactly pA, got %+v", moneyRows)
	}
	obsidianRows := bySystem["obsidian"].EnvSystemRows
	if len(obsidianRows) != 1 || obsidianRows[0].Proof != "pB" {
		t.Errorf("obsidian group should hold exactly pB, got %+v", obsidianRows)
	}
	// Both proofs share one layer (data-apps) — BuildLayerTree would have
	// produced a single group; BuildSystemTree must produce two.
	if len(groups) != 2 {
		t.Errorf("expected 2 system groups, got %d: %+v", len(groups), groups)
	}
}

// TestBuildSystemTreeUnsetSystemSortsLastAsUnset: a proof with no declared
// scope.system lands in its own group, alphabetically last, labeled
// "(unset)" rather than sorted in among real system names.
func TestBuildSystemTreeUnsetSystemSortsLastAsUnset(t *testing.T) {
	s, ctx := buildTaxonomyFixture(t) // no scope declared anywhere -> system ""
	groups := BuildSystemTree(ctx, s, TreeFilter{})
	if len(groups) != 1 {
		t.Fatalf("expected exactly 1 (unset) system group, got %d: %+v", len(groups), groups)
	}
	if groups[0].Layer != "" {
		t.Errorf("the group's raw key should stay the empty string, got %q", groups[0].Layer)
	}
	if !strings.Contains(groups[0].Header, "(unset)") {
		t.Errorf("expected the header to label the empty system as (unset), got %q", groups[0].Header)
	}
}

func TestRenderTreeOmitsEmptyResult(t *testing.T) {
	s := &Summary{}
	out := s.RenderTree(TreeFilter{})
	if len(out) != 0 {
		t.Errorf("RenderTree on an empty summary = %q, want empty", out)
	}
}

// TestRenderTreeTextShowsScopeRollupOnlyForMultiEnv (taxonomy spec section
// F): the env × (restored · accepted · unreviewed · expired) roll-up table
// appears above the layer sections exactly when the estate spans more than
// one environment or system — a single-env/single-system estate must keep
// today's unchanged output.
func TestRenderTreeTextShowsScopeRollupOnlyForMultiEnv(t *testing.T) {
	multi := buildMultiEnvSummary(t)
	out := string(multi.RenderTree(TreeFilter{}))
	for _, want := range []string{
		"Scope roll-up — environments × proof state",
		"ENVIRONMENT  RESTORED  OBSERVED  ACCEPTED  UNREVIEWED  EXPIRED/LAPSED",
		"prod",
		"lab",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("multi-env tree missing %q, got:\n%s", want, out)
		}
	}
	rollupIdx := strings.Index(out, "Scope roll-up")
	layersIdx := strings.Index(out, "data-apps —")
	if rollupIdx < 0 || layersIdx < 0 || rollupIdx > layersIdx {
		t.Errorf("roll-up must appear above the layer sections, got:\n%s", out)
	}

	single, _ := buildTaxonomyFixture(t)
	singleOut := string(single.RenderTree(TreeFilter{}))
	if strings.Contains(singleOut, "Scope roll-up") {
		t.Errorf("a single-env/single-system estate must not print a roll-up, got:\n%s", singleOut)
	}
}
