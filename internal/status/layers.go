// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// The proof-state vocabulary (taxonomy spec, refined state model):
//   - StateRestored: the proof's recovery LEVEL reaches restores/data-valid/
//     serves — provably restorable, at least once.
//   - StateObserved: still at the declared level, but a declared/attested
//     proof carries BOTH observed_at and expires_at and now falls within
//     that observation's own TTL window — something keeps re-observing it,
//     so it is fresh evidence, not an open gap.
//   - StateAccepted: still declared, but an active (not lapsed) owner
//     acceptance is recorded.
//   - StateUnreviewed: everything else at the declared level — no expiry
//     declared, an expiry that has fallen out of its own TTL window, or a
//     proof that was simply never observed at all.
//   - The four attention states (StateDisputed/StateExpired/
//     StateUnreachable/StateLapsed): the proof's own record says something
//     is actively wrong, or a recorded acceptance's review window has
//     passed. "stale" folds into StateExpired — both mean the same thing
//     (evidence too old to trust) and carried the same urgency even before
//     this refinement.
//
// "attention" is a valid meta-value (not a state itself): the `--state`
// filter and the HTML state chips accept it to mean "any of the four
// attention states" (see TreeFilter.matches / isAttentionState).
const (
	StateDisputed    = "disputed"
	StateExpired     = "expired"
	StateUnreachable = "unreachable"
	StateLapsed      = "lapsed"
	StateUnreviewed  = "unreviewed"
	StateObserved    = "observed"
	StateAccepted    = "accepted"
	StateRestored    = "restored"

	// stateAttentionMeta is the `--state`/chip meta-value matching any of
	// the four attention states — never a state a row itself carries.
	stateAttentionMeta = "attention"
)

// isAttentionState reports whether state is one of the four attention
// states (disputed/expired/unreachable/lapsed) — the set the "attention"
// meta-value expands to.
func isAttentionState(state string) bool {
	switch state {
	case StateDisputed, StateExpired, StateUnreachable, StateLapsed:
		return true
	}
	return false
}

// drilledUnprovenRank is the `next`/NextStep ordering rank for a drilled
// proof that simply has not produced a verified proof yet — worse than a
// plain unreviewed attestation only in that a drill EXISTS and could be
// re-run right now (taxonomy spec: "next lists attention → lapsed →
// unreviewed → drilled-unproven"). It is a next-ordering distinction only:
// both cases carry the same exposed State string, StateUnreviewed.
const drilledUnprovenRank = 3

// stateRank orders the state vocabulary problems-first for the taxonomy
// tree's within-category row sort and buildLayerHeader's "worst" pick;
// ties within one rank are broken by proof id.
func stateRank(state string) int {
	switch state {
	case StateDisputed, StateExpired, StateUnreachable:
		return 0
	case StateLapsed:
		return 1
	case StateUnreviewed:
		return 2
	case StateObserved:
		return 3
	case StateAccepted:
		return 4
	default: // StateRestored
		return 5
	}
}

// treeRowLess orders two rows already known to share one layer and category
// by the taxonomy spec's fixed effective ordering (section F): environment
// criticality first (contextspec.EnvironmentLess), then problems-first
// (stateRank — layer and category are already fixed by the caller's
// grouping, so they contribute nothing further here), then proof id for a
// deterministic tie-break.
func treeRowLess(a, b TreeRow) bool {
	if a.Scope.Environment != b.Scope.Environment {
		if contextspec.EnvironmentLess(a.Scope.Environment, b.Scope.Environment) {
			return true
		}
		if contextspec.EnvironmentLess(b.Scope.Environment, a.Scope.Environment) {
			return false
		}
	}
	if ra, rb := stateRank(a.State), stateRank(b.State); ra != rb {
		return ra < rb
	}
	return a.Proof < b.Proof
}

// ProofClassification is one proof's full taxonomy placement: where it
// belongs (Layer/Category) and how urgently (State/Rank) — computed once so
// the layer tree, `next`, and the MCP next_steps tool all agree on exactly
// one answer.
type ProofClassification struct {
	Layer          string
	Category       string
	Conflict       bool
	ConflictDetail string
	State          string
	Rank           int
	// Artifact is the row subtitle: the drill's declared artifact path, else
	// the evidence file basename, else "" — "which ssh key" must be
	// answerable from this field alone.
	Artifact string
	// ContextFile is the source file for the drilled proof's re-drill
	// command (InventoryRow.SourceFile) — empty for an attestation-only
	// proof.
	ContextFile string
	Scope       contextspec.Scope
}

// classifyProofState derives the state/rank half of a ProofClassification
// from the same InventoryRow/ProofState status.Gather already built —
// nothing here re-derives a recovery level or a freshness verdict; it only
// buckets what LevelOf/Gather already decided into the taxonomy's refined
// state vocabulary (restored/observed/accepted/unreviewed, plus the four
// attention states).
func classifyProofState(r InventoryRow, ps ProofState, hasState bool) (state string, rank int) {
	if hasState {
		switch ps.Status {
		case "disputed":
			return StateDisputed, 0
		case "unreachable":
			return StateUnreachable, 0
		case "expired", "stale":
			return StateExpired, 0
		}
	}
	// A previous epoch's evidence is never "restored" here, whatever level
	// it claims: it was proven on a different install (or machine) and says
	// nothing about this one. It lands in unreviewed — with the "from a
	// previous epoch — re-drill" reason the inventory row already carries —
	// ahead of a plain unreviewed only in that the re-drill is mandatory.
	if r.PreviousEpoch {
		return StateUnreviewed, drilledUnprovenRank
	}
	if r.Level != contextspec.LevelDeclared.String() {
		return StateRestored, 5
	}
	if r.AcceptanceLapsedOn != "" {
		return StateLapsed, 1
	}
	if r.AcceptedReason != "" {
		return StateAccepted, 4
	}
	// Observed: a declared/attested proof carrying both observed_at and
	// expires_at, still inside that observation's own freshness window
	// (r.IsObserved — see isObservedProof/freshnessWindow: max(48h, TTL/7),
	// not the full TTL — a one-off attestation with a long declared TTL
	// and nothing re-checking it is unreviewed again once that window
	// passes, well before it technically expires).
	if r.IsObserved {
		return StateObserved, 4
	}
	if r.IsDrilled {
		return StateUnreviewed, drilledUnprovenRank
	}
	return StateUnreviewed, 2
}

// artifactFor is the row subtitle: a declared drill's artifact path, else
// the evidence file basename, else "" — "which ssh key" must be answerable
// from this alone.
func artifactFor(ctx contextspec.Context, proofID string) string {
	for _, d := range ctx.Drills {
		if d.Proof == proofID {
			return d.Artifact
		}
	}
	for _, p := range ctx.Proofs {
		if p.ID == proofID && p.EvidenceURL != "" {
			return filepath.Base(p.EvidenceURL)
		}
	}
	return ""
}

// Classify computes proofID's full taxonomy placement against ctx, using
// row/ps/hasState for state (already-gathered inventory data — see
// classifyProofState) and contextspec.EffectiveProofLayer for layer/
// category/scope.
func Classify(ctx contextspec.Context, proofID string, row InventoryRow, ps ProofState, hasState bool) ProofClassification {
	state, rank := classifyProofState(row, ps, hasState)
	c := ProofClassification{State: state, Rank: rank, Artifact: artifactFor(ctx, proofID), ContextFile: row.SourceFile}
	for _, p := range ctx.Proofs {
		if p.ID != proofID {
			continue
		}
		lr := contextspec.EffectiveProofLayer(ctx, p)
		c.Layer, c.Category, c.Conflict, c.ConflictDetail = lr.Layer, lr.Category, lr.Conflict, lr.ConflictDetail
		c.Scope = contextspec.EffectiveProofScope(ctx, p)
		return c
	}
	c.Layer = contextspec.LayerUnfiled
	return c
}

// TreeRow is one proof, positioned in the layer tree.
type TreeRow struct {
	Proof    string
	State    string
	Level    string // display level (declared/restores/data-valid/serves)
	Why      string // same text as the inventory's ProofAge/reason column
	Artifact string
	Scope    contextspec.Scope
}

// CategoryGroup is one category's rows within a layer, "" meaning no
// category was ever assigned.
type CategoryGroup struct {
	Category string
	Rows     []TreeRow
}

// LayerGroup is one layer's whole section: a summary header line, any
// conflict notes for proofs whose requiring guards disagreed, and the rows
// grouped by category.
type LayerGroup struct {
	Layer         string
	Header        string
	ConflictNotes []string
	Categories    []CategoryGroup
	// EnvSystemRows exposes each row's scope for the HTML env/system filter
	// chips and the roll-up table (buildScopeRollup) without re-walking
	// Categories.
	EnvSystemRows []TreeRow
}

// BuildLayerTree groups every proof in s.Inventory into the taxonomy tree:
// Layer (vocabulary order) → Category (declared order of first appearance)
// → proof (state rank, problems first, then proof id). filterLayers/
// filterStates/filterEnvs/filterSystems/filterOwners/filterTags, when
// non-empty, keep only rows matching at least one value in each given set
// (an empty filter set matches everything) — the same filters `status
// --layer/--state/--env/--system/--owner/--tag` and the HTML CSS chips
// apply.
func BuildLayerTree(ctx contextspec.Context, s *Summary, f TreeFilter) []LayerGroup {
	return buildGroupedTree(ctx, s, f, func(c ProofClassification) string { return c.Layer }, contextspec.LayerOrder, identityLabel)
}

// BuildSystemTree groups the SAME classified proofs BuildLayerTree does —
// Classify runs exactly once per proof either way — by scope.system instead
// of layer: system (declared systems, alphabetical, "" sorting last as
// "(unset)") → category (the proof's taxonomy category, unchanged) → proof,
// same problems-first/env-criticality row ordering (treeRowLess) as
// BuildLayerTree. This is the HTML dashboard's "by system" view: the same
// estate data, organized around "which system is this" instead of "which
// recovery layer is this" — never a second, independent classification.
func BuildSystemTree(ctx contextspec.Context, s *Summary, f TreeFilter) []LayerGroup {
	return buildGroupedTree(ctx, s, f, func(c ProofClassification) string { return c.Scope.System }, nil, sysLabel)
}

// identityLabel is buildGroupedTree's labelFn for BuildLayerTree: a layer
// name is never empty, so it needs no "(unset)" substitution.
func identityLabel(s string) string { return s }

// buildGroupedTree is BuildLayerTree/BuildSystemTree's shared engine: it
// classifies every proof exactly once (Classify) and groups the results by
// keyFn(classification) → category → proof. When keyOrder is non-nil, top-
// level groups appear in that fixed order (BuildLayerTree's vocabulary
// order); when nil, groups are sorted alphabetically by their (possibly
// empty) key, with "" sorted last (BuildSystemTree's declared-systems
// order). labelFn renders a group's key as its header's display label
// (identityLabel for a layer name, sysLabel's "(unset)" substitution for an
// empty system) — LayerGroup.Layer itself stays the raw key, since callers
// (chip ids, data- attributes) need the unescaped value.
// placedRow is one inventory row already classified and bucketed.
type placedRow struct {
	row TreeRow
	c   ProofClassification
}

// treePlacement is the intermediate result of bucketing the inventory: which
// rows landed in which group, each group's conflicts, its categories in
// first-seen order, and (when the caller did not supply a fixed key order) the
// groups themselves in first-seen order.
type treePlacement struct {
	byGroup    map[string][]placedRow
	conflicts  map[string][]string
	catOrder   map[string][]string
	groupOrder []string
}

func buildGroupedTree(ctx contextspec.Context, s *Summary, f TreeFilter, keyFn func(ProofClassification) string, keyOrder []string, labelFn func(string) string) []LayerGroup {
	p := placeTreeRows(ctx, s, f, keyFn, keyOrder == nil)
	order := keyOrder
	if order == nil {
		order = sortedGroupOrder(p.groupOrder)
	}
	return assembleGroups(order, p, labelFn)
}

// placeTreeRows classifies every inventory row and buckets it under keyFn.
// trackOrder is set when the caller has no fixed key order and needs the
// first-seen sequence recorded.
func placeTreeRows(ctx contextspec.Context, s *Summary, f TreeFilter, keyFn func(ProofClassification) string, trackOrder bool) treePlacement {
	stateByProof := make(map[string]ProofState, len(s.Proofs))
	for _, p := range s.Proofs {
		stateByProof[p.ID] = p
	}
	out := treePlacement{
		byGroup:   map[string][]placedRow{},
		conflicts: map[string][]string{},
		catOrder:  map[string][]string{},
	}
	catSeen := map[string]map[string]bool{}
	var groupSeen map[string]bool
	if trackOrder {
		groupSeen = map[string]bool{}
	}

	for _, r := range s.Inventory {
		ps, hasState := stateByProof[r.Proof]
		c := Classify(ctx, r.Proof, r, ps, hasState)
		if !f.matches(c) {
			continue
		}
		key := keyFn(c)
		row := TreeRow{Proof: r.Proof, State: c.State, Level: r.Level, Why: r.ProofAge, Artifact: c.Artifact, Scope: c.Scope}
		out.byGroup[key] = append(out.byGroup[key], placedRow{row: row, c: c})
		if c.Conflict {
			out.conflicts[key] = append(out.conflicts[key], c.ConflictDetail)
		}
		if catSeen[key] == nil {
			catSeen[key] = map[string]bool{}
		}
		if !catSeen[key][c.Category] {
			catSeen[key][c.Category] = true
			out.catOrder[key] = append(out.catOrder[key], c.Category)
		}
		if groupSeen != nil && !groupSeen[key] {
			groupSeen[key] = true
			out.groupOrder = append(out.groupOrder, key)
		}
	}
	return out
}

// sortedGroupOrder sorts first-seen group keys alphabetically, except that ""
// (unset) always sorts last — an unset system/owner reads worse buried
// alphabetically among real ones than named at the end.
func sortedGroupOrder(groupOrder []string) []string {
	sort.SliceStable(groupOrder, func(i, j int) bool {
		if groupOrder[i] == "" {
			return false
		}
		if groupOrder[j] == "" {
			return true
		}
		return groupOrder[i] < groupOrder[j]
	})
	return groupOrder
}

// assembleGroups turns the placement into the ordered LayerGroups the tree
// renders, sorting each category's rows and skipping keys nothing landed in.
func assembleGroups(order []string, p treePlacement, labelFn func(string) string) []LayerGroup {
	var groups []LayerGroup
	for _, key := range order {
		items, ok := p.byGroup[key]
		if !ok {
			continue
		}
		byCat := map[string][]TreeRow{}
		for _, it := range items {
			byCat[it.c.Category] = append(byCat[it.c.Category], it.row)
		}
		var cats []CategoryGroup
		for _, cat := range p.catOrder[key] {
			rows := byCat[cat]
			sort.SliceStable(rows, func(i, j int) bool { return treeRowLess(rows[i], rows[j]) })
			cats = append(cats, CategoryGroup{Category: cat, Rows: rows})
		}
		allRows := make([]TreeRow, 0, len(items))
		for _, cg := range cats {
			allRows = append(allRows, cg.Rows...)
		}
		groups = append(groups, LayerGroup{
			Layer: key, Header: buildLayerHeader(labelFn(key), allRows),
			ConflictNotes: p.conflicts[key], Categories: cats, EnvSystemRows: allRows,
		})
	}
	return groups
}

// buildLayerHeader renders "identity-secrets — 6 proofs · 3 restored · 1
// accepted · 2 unreviewed · worst: unreviewed" — only the non-zero state
// buckets are listed, in problems-first order, and "worst" names the
// lowest-rank (most urgent) state present.
func buildLayerHeader(layer string, rows []TreeRow) string {
	order := []string{StateDisputed, StateExpired, StateUnreachable, StateLapsed, StateUnreviewed, StateObserved, StateAccepted, StateRestored}
	label := map[string]string{
		StateDisputed: "disputed", StateExpired: "expired", StateUnreachable: "unreachable",
		StateLapsed: "lapsed", StateUnreviewed: "unreviewed", StateObserved: "observed",
		StateAccepted: "accepted", StateRestored: "restored",
	}
	counts := map[string]int{}
	worst := ""
	for _, r := range rows {
		counts[r.State]++
		if worst == "" || stateRank(r.State) < stateRank(worst) {
			worst = r.State
		}
	}
	var parts []string
	for _, st := range order {
		if n := counts[st]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, label[st]))
		}
	}
	head := fmt.Sprintf("%s — %d proof", layer, len(rows))
	if len(rows) != 1 {
		head += "s"
	}
	if len(parts) > 0 {
		head += " · " + strings.Join(parts, " · ")
	}
	if worst != "" {
		head += " · worst: " + label[worst]
	}
	return head
}

// TreeFilter selects which rows BuildLayerTree keeps. Every field is a set
// of allowed values; an empty set matches everything (no filtering on that
// axis) — the default "all checked" state of both the text --layer/--state/
// --env/--system/--owner/--tag flags and the HTML filter chips.
type TreeFilter struct {
	Layers  map[string]bool
	States  map[string]bool
	Envs    map[string]bool
	Systems map[string]bool
	Owners  map[string]bool
	Tags    map[string]bool
}

// NewTreeFilter builds a TreeFilter from repeatable flag values (nil/empty
// slice means "no filter on this axis").
func NewTreeFilter(layers, states, envs, systems, owners, tags []string) TreeFilter {
	return TreeFilter{
		Layers: toSet(layers), States: toSet(states), Envs: toSet(envs),
		Systems: toSet(systems), Owners: toSet(owners), Tags: toSet(tags),
	}
}

func toSet(vs []string) map[string]bool {
	if len(vs) == 0 {
		return nil
	}
	out := make(map[string]bool, len(vs))
	for _, v := range vs {
		out[v] = true
	}
	return out
}

// renderTreeText writes the whole layer → category → proof tree, plus its
// trailing InventorySummary line, into b. Nothing is written when the
// filtered tree is empty (mirrors the flat table it replaced: no drills, no
// proofs, or a filter matching nothing all print no section at all).
func renderTreeText(b *strings.Builder, s *Summary, f TreeFilter) {
	groups := BuildLayerTree(s.Context, s, f)
	if len(groups) == 0 {
		return
	}
	fmt.Fprintf(b, "\nRecovery taxonomy — layer -> category -> proof\n")
	renderScopeRollupText(b, groups)
	for _, g := range groups {
		fmt.Fprintf(b, "\n%s\n", g.Header)
		for _, note := range g.ConflictNotes {
			fmt.Fprintf(b, "  ! %s\n", note)
		}
		for _, cat := range g.Categories {
			label := cat.Category
			if label == "" {
				label = "(uncategorized)"
			}
			fmt.Fprintf(b, "  %s\n", label)
			for _, row := range cat.Rows {
				artifact := row.Artifact
				if artifact == "" {
					artifact = "—"
				}
				fmt.Fprintf(b, "    %-45s %-9s %-18s %s\n", row.Proof, row.State, row.Level, row.Why)
				fmt.Fprintf(b, "    %45s   artifact: %s\n", "", artifact)
			}
		}
	}
	if s.InventorySummary != "" {
		fmt.Fprintf(b, "\n  %s\n", s.InventorySummary)
	}
}

// renderScopeRollupText prints the environment roll-up table (taxonomy spec
// section F: "env × restored · accepted · unreviewed · expired") above the
// layer sections, but ONLY when the estate spans more than one environment
// or more than one system — a single-env/single-system estate keeps today's
// unchanged headline. It reuses rollupTouch (taxonomy_html.go) so the text
// and HTML roll-ups can never disagree about which state lands in which
// column.
func renderScopeRollupText(b *strings.Builder, groups []LayerGroup) {
	envs, systems := map[string]bool{}, map[string]bool{}
	byEnv := map[string]*RollupRow{}
	var order []string
	for _, g := range groups {
		for _, r := range g.EnvSystemRows {
			envs[r.Scope.Environment] = true
			systems[r.Scope.System] = true
			rollupTouch(byEnv, &order, r.Scope.Environment, r.State)
		}
	}
	if len(envs) <= 1 && len(systems) <= 1 {
		return
	}
	sort.SliceStable(order, func(i, j int) bool {
		return contextspec.EnvironmentLess(order[i], order[j])
	})

	table := [][]string{{"ENVIRONMENT", "RESTORED", "OBSERVED", "ACCEPTED", "UNREVIEWED", "EXPIRED/LAPSED"}}
	for _, env := range order {
		r := byEnv[env]
		table = append(table, []string{r.Env,
			fmt.Sprintf("%d", r.Restored), fmt.Sprintf("%d", r.Observed), fmt.Sprintf("%d", r.Accepted),
			fmt.Sprintf("%d", r.Unreviewed), fmt.Sprintf("%d", r.Expired)})
	}
	widths := make([]int, len(table[0]))
	for _, row := range table {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	fmt.Fprintf(b, "\n  Scope roll-up — environments × proof state\n")
	for _, row := range table {
		b.WriteString("    ")
		for i, cell := range row {
			fmt.Fprintf(b, "%-*s  ", widths[i], cell)
		}
		b.WriteString("\n")
	}
}

// RenderTree renders just the layer tree (no verdict banner, no footer
// sections) filtered by f — the shape `restoregap status --layer <name>` /
// `--state <name>` prints.
func (s *Summary) RenderTree(f TreeFilter) []byte {
	var b strings.Builder
	renderTreeText(&b, s, f)
	return []byte(strings.TrimPrefix(b.String(), "\n"))
}

// ScopeRow is one proof's full effective placement, machine-readable: the
// taxonomy spec section F shape for `status --format json` — every proof's
// effective layer/category/state plus its full effective scope (including
// host), so a later aggregator (not built here) can merge documents from
// many hosts by (id, environment, system, host) without loss. Unlike
// NextStep, ScopeRow covers EVERY proof, not only the not-green ones.
type ScopeRow struct {
	Proof       string            `json:"id"`
	Layer       string            `json:"layer"`
	Category    string            `json:"category"`
	State       string            `json:"state"`
	Level       string            `json:"level"`
	Why         string            `json:"why"`
	ContextFile string            `json:"context_file"`
	Artifact    string            `json:"artifact"`
	Scope       contextspec.Scope `json:"scope"`
}

// MergeKey is the (id, environment, system, host) identity a multi-host
// aggregator keys on — section F: "merge documents from many hosts by
// (guard id, env, system, host)".
func (r ScopeRow) MergeKey() string {
	return strings.Join([]string{r.Proof, r.Scope.Environment, r.Scope.System, r.Scope.Host}, "\x1f")
}

// BuildScopeRows builds one ScopeRow per proof in s.Inventory, filtered by
// f (an empty TreeFilter keeps everything) — the shared data behind
// `status --format json` and the two-host merge golden test.
func BuildScopeRows(ctx contextspec.Context, s *Summary, f TreeFilter) []ScopeRow {
	stateByProof := make(map[string]ProofState, len(s.Proofs))
	for _, p := range s.Proofs {
		stateByProof[p.ID] = p
	}
	var rows []ScopeRow
	for _, r := range s.Inventory {
		ps, hasState := stateByProof[r.Proof]
		c := Classify(ctx, r.Proof, r, ps, hasState)
		if !f.matches(c) {
			continue
		}
		rows = append(rows, ScopeRow{
			Proof: r.Proof, Layer: c.Layer, Category: c.Category, State: c.State,
			Level: r.Level, Why: r.ProofAge, ContextFile: c.ContextFile, Artifact: c.Artifact,
			Scope: c.Scope,
		})
	}
	return rows
}

// RenderJSON is `status --format json`'s body: every proof, its full
// effective layer/category/state/scope, JSON-encoded. Always the FULL set —
// text-only --layer/--state/--env/--system/--owner/--tag filters are meant
// for a human glancing at a terminal; a machine consuming this for a
// multi-host merge gets everything and filters itself.
func (s *Summary) RenderJSON() ([]byte, error) {
	rows := BuildScopeRows(s.Context, s, TreeFilter{})
	if rows == nil {
		rows = []ScopeRow{}
	}
	return json.MarshalIndent(rows, "", "  ")
}

// IsEmpty reports whether f filters nothing on any axis — the default
// "all checked" state.
func (f TreeFilter) IsEmpty() bool {
	return f.Layers == nil && f.States == nil && f.Envs == nil && f.Systems == nil && f.Owners == nil && f.Tags == nil
}

func (f TreeFilter) matches(c ProofClassification) bool {
	if f.Layers != nil && !f.Layers[c.Layer] {
		return false
	}
	if !f.matchesState(c.State) {
		return false
	}
	if f.Envs != nil && !f.Envs[c.Scope.Environment] {
		return false
	}
	if f.Systems != nil && !f.Systems[c.Scope.System] {
		return false
	}
	if f.Owners != nil && !f.Owners[c.Scope.Owner] {
		return false
	}
	return f.matchesTags(c.Scope.Tags)
}

// matchesState reports whether state passes f's --state filter, treating the
// "attention" meta-state as matching any of the four attention states.
func (f TreeFilter) matchesState(state string) bool {
	if f.States == nil {
		return true
	}
	return f.States[state] || (f.States[stateAttentionMeta] && isAttentionState(state))
}

// matchesTags reports whether tags passes f's --tag filter, where any single
// overlapping tag counts as a match.
func (f TreeFilter) matchesTags(tags []string) bool {
	if f.Tags == nil {
		return true
	}
	for _, t := range tags {
		if f.Tags[t] {
			return true
		}
	}
	return false
}
