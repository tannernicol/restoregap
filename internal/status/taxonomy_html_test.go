// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

func TestSlugSanitizesFreeFormScope(t *testing.T) {
	cases := map[string]string{
		"prod":            "prod",
		"Prod US-East 1!": "prod-us-east-1",
		"":                "unset",
		"   ":             "unset",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFilterBucketCollapsesToFiveStates(t *testing.T) {
	cases := map[string]string{
		StateDisputed:    BucketAttention,
		StateExpired:     BucketAttention,
		StateUnreachable: BucketAttention,
		StateLapsed:      BucketAttention,
		StateUnreviewed:  BucketUnreviewed,
		StateObserved:    BucketObserved,
		StateAccepted:    BucketAccepted,
		StateRestored:    BucketRestored,
	}
	for state, want := range cases {
		if got := filterBucket(state); got != want {
			t.Errorf("filterBucket(%q) = %q, want %q", state, got, want)
		}
	}
}

// TestIsAttentionStateMatchesTheFourAttentionStates: the "attention"
// --state/chip meta-value must expand to exactly disputed/expired/
// unreachable/lapsed — restored/observed/accepted/unreviewed are not
// attention states.
func TestIsAttentionStateMatchesTheFourAttentionStates(t *testing.T) {
	attention := map[string]bool{StateDisputed: true, StateExpired: true, StateUnreachable: true, StateLapsed: true}
	for _, s := range []string{StateDisputed, StateExpired, StateUnreachable, StateLapsed, StateUnreviewed, StateObserved, StateAccepted, StateRestored} {
		if got := isAttentionState(s); got != attention[s] {
			t.Errorf("isAttentionState(%q) = %v, want %v", s, got, attention[s])
		}
	}
}

// TestShowCategoryHeadersHiddenForSingleCategoryLayer: a layer where every
// row shares one category (including the "uncategorized" non-category)
// must not show a category subheader at all — only a layer with two or
// more distinct categories does.
func TestShowCategoryHeadersHiddenForSingleCategoryLayer(t *testing.T) {
	now := mustTime(t, "2026-08-24T00:00:00Z")
	ctx := contextspec.Context{
		Guards: []contextspec.Guard{
			{ID: "gA", Requires: contextspec.Requirement{Proofs: []string{"pA"}}, Layer: contextspec.LayerDataApps, Category: "money"},
			{ID: "gB", Requires: contextspec.Requirement{Proofs: []string{"pB"}}, Layer: contextspec.LayerDataApps, Category: "obsidian"},
			{ID: "gC", Requires: contextspec.Requirement{Proofs: []string{"pC"}}, Layer: contextspec.LayerGitCode, Category: "git-estate"},
		},
		Proofs: []contextspec.Proof{
			{ID: "pA", Status: contextspec.ProofRecordObserved, ObservedAt: &now},
			{ID: "pB", Status: contextspec.ProofRecordObserved, ObservedAt: &now},
			{ID: "pC", Status: contextspec.ProofRecordObserved, ObservedAt: &now},
		},
	}
	s := &Summary{Verdict: "warn", Context: ctx}
	s.Inventory = buildInventory(ctx, nil, now, "")
	s.Proofs = getProofs(ctx, now, "", &s.Verdict, &s.ExpiringSoon)

	data := buildEstateData(s)
	byLayer := map[string]EstateLayer{}
	for _, l := range data.LayerSections {
		byLayer[l.GroupID] = l
	}
	if got := byLayer[contextspec.LayerDataApps]; !got.ShowCategoryHeaders {
		t.Errorf("data-apps has 2 distinct categories (money, obsidian) — ShowCategoryHeaders should be true, got %+v", got)
	}
	if got := byLayer[contextspec.LayerGitCode]; got.ShowCategoryHeaders {
		t.Errorf("git-code has exactly 1 category (git-estate) — ShowCategoryHeaders should be false, got %+v", got)
	}

	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	// Scope to the layer panel: the system panel regroups the SAME proofs, so a
	// category legitimately hidden under layer grouping can be shown under
	// system grouping. Asserting across the whole page compares two groupings.
	panel := estatePanel(t, string(out), "layer")
	if !strings.Contains(panel, `<h4 class="rgs-taxcat">money</h4>`) {
		t.Errorf("expected the money category header (multi-category layer), got:\n%s", panel)
	}
	if strings.Contains(panel, `<h4 class="rgs-taxcat">git-estate</h4>`) {
		t.Errorf("git-code has only 1 category — its category header must be hidden, got:\n%s", panel)
	}
}

// TestRenderHTMLSingleHostOmitsRollupAndEnvSystemChips is the negative case
// for the same fixture family: a single-env/single-system estate must not
// grow empty env/system chip rows or an empty roll-up table in the actual
// rendered page.
func TestRenderHTMLSingleHostOmitsRollupAndEnvSystemChips(t *testing.T) {
	s, _ := buildTaxonomyFixture(t)
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	for _, notWant := range []string{`class="rgs-rollup"`, `id="f-env-`, `id="f-system-`} {
		if strings.Contains(html, notWant) {
			t.Errorf("single-host HTML must not contain %q, got:\n%s", notWant, html)
		}
	}
}

// TestRenderHTMLEstateHasViewSwitchAndRowAttributes: the redesign replaced the
// wall of per-layer/per-state/per-env/per-system filter checkboxes with a
// four-way view switch, so the assertion is that the switch exists and that
// rows still carry the data- attributes the CSS filters on.
func TestRenderHTMLEstateHasViewSwitchAndRowAttributes(t *testing.T) {
	s, _ := buildTaxonomyFixture(t)
	out, err := s.Render("html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	for _, want := range []string{
		`class="rgs-estate"`,
		`class="rgs-viewswitch"`,
		`id="rgs-view-attention"`,
		`id="rgs-view-all"`,
		`id="rgs-view-system"`,
		`id="rgs-view-layer"`,
		`data-panel="layer"`,
		`data-panel="system"`,
		`data-group="` + contextspec.LayerGitCode + `"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q in estate section, got:\n%s", want, html)
		}
	}
	// Rows must stay filterable by state and by the coarser bucket.
	panel := estatePanel(t, html, "layer")
	for _, want := range []string{`data-state=`, `data-bucket=`} {
		if !strings.Contains(panel, want) {
			t.Errorf("estate rows must carry %s, got:\n%s", want, panel)
		}
	}
	for _, b := range []string{BucketAttention, BucketUnreviewed, BucketObserved, BucketAccepted, BucketRestored} {
		if !strings.Contains(html, `data-bucket="`+b+`"`) && !strings.Contains(html, b) {
			t.Errorf("bucket %q should be representable in the estate markup", b)
		}
	}
}

// buildMultiEnvSummary is a two-env/two-system fixture (prod/money and
// lab/obsidian). The env/system chips and roll-up it used to drive on the
// status page now live on the fleet page, but layers_test still builds its
// tree assertions on this shape.
func buildMultiEnvSummary(t *testing.T) *Summary {
	t.Helper()
	now := mustTime(t, "2026-08-24T00:00:00Z")
	future := now.Add(720 * time.Hour)
	ctx := contextspec.Context{
		Guards: []contextspec.Guard{
			{ID: "gA", Requires: contextspec.Requirement{Proofs: []string{"pA"}}, Layer: contextspec.LayerDataApps,
				Scope: contextspec.Scope{Environment: "prod", System: "money"}},
			{ID: "gB", Requires: contextspec.Requirement{Proofs: []string{"pB"}}, Layer: contextspec.LayerDataApps,
				Scope: contextspec.Scope{Environment: "lab", System: "obsidian"}},
		},
		Proofs: []contextspec.Proof{
			{ID: "pA", Status: contextspec.ProofRecordValidated, ObservedAt: &now, ExpiresAt: &future, Verified: true},
			{ID: "pB", Status: contextspec.ProofRecordObserved, ObservedAt: &now, ExpiresAt: &future},
		},
	}
	s := &Summary{Verdict: "pass", Context: ctx}
	s.Inventory = buildInventory(ctx, nil, now, "")
	s.Proofs = getProofs(ctx, now, "", &s.Verdict, &s.ExpiringSoon)
	return s
}
