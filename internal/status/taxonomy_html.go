// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"fmt"
	"html/template"
	"regexp"
	"sort"
	"strings"
)

// The five chip-filter buckets the HTML dashboard's state checkboxes use —
// coarser than the eight-value State vocabulary each row still displays as
// text (plus the "attention" meta-value the `--state` flag/these chips
// accept): the four attention states (disputed/expired/unreachable/lapsed)
// collapse into one BucketAttention chip, the remaining four states
// (unreviewed/observed/accepted/restored) each get their own chip. The
// bucket only decides which chip a row's visibility is wired to; data-state
// on the row itself still carries the exact, granular state name.
const (
	BucketAttention  = "attention"
	BucketUnreviewed = "unreviewed"
	BucketObserved   = "observed"
	BucketAccepted   = "accepted"
	BucketRestored   = "restored"
)

// defaultStateChips is the fixed five-bucket state filter row (single-host
// status.html's taxonomy section and fleet.html both use exactly this set,
// in exactly this order) — a shared definition so the two pages can never
// drift apart on which buckets exist or how they are labelled.
func defaultStateChips() []FilterChip {
	return []FilterChip{
		{ID: BucketAttention, Label: "attention"},
		{ID: BucketUnreviewed, Label: "unreviewed"},
		{ID: BucketObserved, Label: "observed"},
		{ID: BucketAccepted, Label: "accepted"},
		{ID: BucketRestored, Label: "restored"},
	}
}

// filterBucket collapses a row's fine-grained State into the HTML filter
// bar's five buckets.
func filterBucket(state string) string {
	switch state {
	case StateUnreviewed:
		return BucketUnreviewed
	case StateObserved:
		return BucketObserved
	case StateAccepted:
		return BucketAccepted
	case StateRestored:
		return BucketRestored
	default: // StateDisputed, StateExpired, StateUnreachable, StateLapsed
		return BucketAttention
	}
}

// slugRe matches every character NOT safe to use unescaped in an HTML id
// attribute and a CSS attribute-selector value. Free-form scope fields
// (environment/system) are user-authored strings; a chip id built from one
// must not depend on the string being "well-behaved".
var slugRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// slug renders s as a safe id/selector fragment, "unset" for an empty
// string (a proof with no declared scope field still needs a stable,
// non-empty chip to attach to).
func slug(s string) string {
	if s == "" {
		return "unset"
	}
	out := slugRe.ReplaceAllString(strings.ToLower(s), "-")
	out = strings.Trim(out, "-")
	if out == "" {
		return "unset"
	}
	return out
}

// FilterChip is one HTML filter-bar checkbox: a safe id (used in both the
// checkbox's DOM id and the generated :has() selector) and its human label.
type FilterChip struct {
	ID    string
	Label string
}

// EstateRow is one proof's row in the single-host dashboard's unified
// estate tree — the ONE organization of the estate's proofs (the redesign's
// defect #3: the old page rendered the same data twice, once as a
// recoverable/not-proven group split, once as a layer/category/state
// taxonomy). Every field comes from the SAME Classify call
// BuildLayerTree/BuildSystemTree already made (TreeRow) — never a second
// classification pass.
type EstateRow struct {
	Proof    string
	State    string
	Bucket   string
	Artifact string
	Level    string
	// Why is TreeRow.Why (InventoryRow.ProofAge unmodified) — the row's
	// single age/expiry field, shown for every row regardless of whether it
	// was drilled or is attestation-only, never in two vocabularies.
	Why string
	// NextAction is the single exact remediation command
	// (next.go's nextStepCommandFor — the SAME command `restoregap next`/
	// the To-green panel already show for this proof) for a genuine gap row
	// (bucket attention or unreviewed) — empty for a restored/observed/
	// accepted row, so a settled decision never gets nagged again.
	NextAction string
}

// EstateCategory is one category's rows within an EstateLayer.
type EstateCategory struct {
	Category string
	Rows     []EstateRow
}

// EstateLayer is one <details> section of the unified estate tree — a
// layer (BuildLayerTree) or a system (BuildSystemTree); LayerGroup.Layer
// (renamed GroupID here since it names either a layer or a system
// depending which tree built it) stays the raw, unescaped key for chip
// ids/data- attributes.
type EstateLayer struct {
	GroupID       string
	Header        string
	Open          bool
	ConflictNotes []string
	Categories    []EstateCategory
	// ShowCategoryHeaders is true only when this group has more than one
	// distinct category — a single-category (or wholly uncategorized)
	// group's own header already says everything the category subhead
	// would.
	ShowCategoryHeaders bool
	// HasGap is true when this group holds at least one row genuinely
	// needing attention (bucket attention or unreviewed — NOT accepted,
	// which is a decision already made) — the "Needs attention" view hides
	// every group where this is false, so an all-clear layer disappears
	// entirely instead of showing an empty shell.
	HasGap bool
}

// RollupRow is one row of the environment roll-up table (section F): one
// environment's counts across every system, restored/observed/accepted/
// unreviewed/expired — "expired" here folds together every attention state
// (disputed/expired/unreachable/lapsed).
type RollupRow struct {
	Env        string
	Restored   int
	Observed   int
	Accepted   int
	Unreviewed int
	Expired    int
}

// EstateData is everything the HTML dashboard's unified estate-tree section
// (question 3: "how is my estate organized and where is it weak") needs,
// pre-rendered so the template stays free of derivation logic
// (buildStatusPage's own convention). It replaces the old checkbox-wall's
// TaxonomyData: no per-layer/per-state/per-env/per-system chip lists — a
// single four-way view switch (DefaultAttention picks which of "Needs
// attention"/"All" starts checked) plus two parallel groupings of the
// identical row data, LayerSections (BuildLayerTree) and SystemSections
// (BuildSystemTree), toggled by radio + CSS :has() with no JavaScript.
type EstateData struct {
	HasAny bool
	// DefaultAttention is true when at least one row anywhere needs
	// attention (bucket attention or unreviewed) — the view switch defaults
	// to "Needs attention" then, "All" otherwise.
	DefaultAttention bool
	LayerSections    []EstateLayer
	SystemSections   []EstateLayer
}

// buildEstateData converts BuildLayerTree's and BuildSystemTree's results
// — the SAME classified proofs, organized two different ways — into the
// unified estate tree's template data.
func buildEstateData(s *Summary) EstateData {
	layerGroups := BuildLayerTree(s.Context, s, TreeFilter{})
	if len(layerGroups) == 0 {
		return EstateData{}
	}
	systemGroups := BuildSystemTree(s.Context, s, TreeFilter{})

	byProof := make(map[string]InventoryRow, len(s.Inventory))
	for _, r := range s.Inventory {
		byProof[r.Proof] = r
	}

	hasGapAnywhere := false
	layerSections := make([]EstateLayer, 0, len(layerGroups))
	for _, g := range layerGroups {
		el := buildEstateLayer(g, byProof)
		if el.HasGap {
			hasGapAnywhere = true
		}
		layerSections = append(layerSections, el)
	}
	systemSections := make([]EstateLayer, 0, len(systemGroups))
	for _, g := range systemGroups {
		systemSections = append(systemSections, buildEstateLayer(g, byProof))
	}

	return EstateData{
		HasAny: true, DefaultAttention: hasGapAnywhere,
		LayerSections: layerSections, SystemSections: systemSections,
	}
}

// buildEstateLayer converts one LayerGroup (from either BuildLayerTree or
// BuildSystemTree — the grouping key, layer or system, is opaque here) into
// one EstateLayer: every row's taxonomy classification plus its single
// inline next-action command where one exists, an auto-expand Open flag
// (any row not restored/observed), and HasGap (any row genuinely needing
// attention — attention or unreviewed, not accepted) for the "Needs
// attention" view's layer-collapse.
func buildEstateLayer(g LayerGroup, byProof map[string]InventoryRow) EstateLayer {
	open, hasGap := false, false
	var cats []EstateCategory
	for _, cg := range g.Categories {
		rows := make([]EstateRow, 0, len(cg.Rows))
		for _, r := range cg.Rows {
			bucket := filterBucket(r.State)
			if bucket != BucketRestored && bucket != BucketObserved {
				open = true
			}
			isGap := bucket == BucketAttention || bucket == BucketUnreviewed
			if isGap {
				hasGap = true
			}
			row := EstateRow{
				Proof: r.Proof, State: r.State, Bucket: bucket,
				Artifact: orEmDashTax(r.Artifact), Level: r.Level, Why: r.Why,
			}
			if isGap {
				row.NextAction = nextStepCommandFor(byProof[r.Proof])
			}
			rows = append(rows, row)
		}
		cats = append(cats, EstateCategory{Category: categoryLabel(cg.Category), Rows: rows})
	}
	return EstateLayer{
		GroupID: g.Layer, Header: g.Header, Open: open, HasGap: hasGap,
		ConflictNotes: g.ConflictNotes, Categories: cats, ShowCategoryHeaders: len(cats) > 1,
	}
}

func orEmDashTax(s string) string {
	if s == "" {
		return emDash
	}
	return s
}

func categoryLabel(c string) string {
	if c == "" {
		return "(uncategorized)"
	}
	return c
}

func envLabel(e string) string {
	if e == "" {
		return "(unset)"
	}
	return e
}

func sysLabel(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// rollupTouch increments the roll-up counter for env/state, creating the
// row (and recording its first-seen order) on first touch. Unlike the HTML
// filter bar's five-bucket collapse (filterBucket), the roll-up keeps its
// own documented five-way split (RollupRow's doc comment): the four
// attention states all count as Expired, restored/observed/accepted/
// unreviewed each map one-to-one — a state passed through filterBucket
// first would flatten Expired into Unreviewed and leave the Expired column
// permanently zero.
func rollupTouch(byEnv map[string]*RollupRow, order *[]string, env, state string) {
	if _, ok := byEnv[env]; !ok {
		byEnv[env] = &RollupRow{Env: envLabel(env)}
		*order = append(*order, env)
	}
	row := byEnv[env]
	switch state {
	case StateRestored:
		row.Restored++
	case StateObserved:
		row.Observed++
	case StateAccepted:
		row.Accepted++
	case StateUnreviewed:
		row.Unreviewed++
	default: // StateDisputed, StateExpired, StateUnreachable, StateLapsed
		row.Expired++
	}
}

// chipsFromSet renders a slug->label map as chips, sorted by label for a
// stable, readable chip order.
func chipsFromSet(m map[string]string) []FilterChip {
	chips := make([]FilterChip, 0, len(m))
	for id, label := range m {
		chips = append(chips, FilterChip{ID: id, Label: label})
	}
	sort.Slice(chips, func(i, j int) bool { return chips[i].Label < chips[j].Label })
	return chips
}

// buildFilterCSS generates one `:has()` display:none rule per chip — the
// zero-JavaScript filter mechanism (taxonomy spec section C). Every id used
// here came from either the fixed layer/state vocabulary or slug() (see
// slugRe), so the generated selectors are safe without further escaping.
func buildFilterCSS(layerChips, stateChips, envChips, systemChips []FilterChip) template.CSS {
	var b strings.Builder
	rule := func(inputID, attr, value string) {
		fmt.Fprintf(&b, `body:has(#f-%s:not(:checked)) [%s="%s"]{display:none}`+"\n", inputID, attr, value)
	}
	for _, c := range layerChips {
		rule("layer-"+c.ID, "data-layer", c.ID)
	}
	for _, c := range stateChips {
		rule("state-"+c.ID, "data-bucket", c.ID)
	}
	for _, c := range envChips {
		rule("env-"+c.ID, "data-envslug", c.ID)
	}
	for _, c := range systemChips {
		rule("system-"+c.ID, "data-systemslug", c.ID)
	}
	return template.CSS(b.String())
}
