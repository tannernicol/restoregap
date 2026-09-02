// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// FleetTaxRow is one fleet.html/`status --fleet` taxonomy row: TaxRow
// (taxonomy_html.go) plus the HOST column the single-host page has no need
// for.
type FleetTaxRow struct {
	Proof      string
	Artifact   string
	State      string
	Bucket     string
	Why        string
	Level      string
	Host       string
	EnvSlug    string
	SystemSlug string
	HostSlug   string
}

// FleetTaxCategory is one category's rows within a FleetTaxLayer.
type FleetTaxCategory struct {
	Category string
	Rows     []FleetTaxRow
}

// FleetTaxLayer is one <details> layer section of fleet.html — the same
// shape as TaxLayer (taxonomy_html.go), rendered by a separate template
// only because its rows carry a host column and its chip set adds a host
// axis.
type FleetTaxLayer struct {
	LayerID             string
	Header              string
	Open                bool
	Categories          []FleetTaxCategory
	ShowCategoryHeaders bool
}

// FleetRollupRow is one (environment, system) pair's counts — fleet.html's
// roll-up table is env × system, unlike the single-host page's env-only
// roll-up (RollupRow), since a fleet's whole point is comparing systems
// across environments.
type FleetRollupRow struct {
	Env        string
	System     string
	Restored   int
	Observed   int
	Accepted   int
	Unreviewed int
	Expired    int
}

// FleetBundleSummary is one merged-in bundle, display-formatted for
// fleet.html's "bundles merged" list.
type FleetBundleSummary struct {
	Host        string
	Epoch       string
	GeneratedAt string
	Path        string
}

// FleetPageData is everything fleet.html's template (and, via RenderText,
// the terminal renderer) needs — pre-rendered so the template stays free of
// derivation logic, same convention as statusPageData/TaxonomyData.
type FleetPageData struct {
	GeneratedAt string
	Bundles     []FleetBundleSummary
	Conflicts   []string
	LayerChips  []FilterChip
	StateChips  []FilterChip
	EnvChips    []FilterChip
	SystemChips []FilterChip
	HostChips   []FilterChip
	Rollup      []FleetRollupRow
	Layers      []FleetTaxLayer
	FilterCSS   template.CSS
	HasAny      bool
}

// fleetGrouping is fleet.Proofs bucketed by layer, with each layer's
// categories kept in declared (first-seen) order — the same grouping
// BuildLayerTree does for a single host's inventory, computed here directly
// over []FleetProof instead.
type fleetGrouping struct {
	byLayer  map[string][]FleetProof
	catOrder map[string][]string
}

func groupFleetProofsByLayer(proofs []FleetProof) fleetGrouping {
	g := fleetGrouping{byLayer: map[string][]FleetProof{}, catOrder: map[string][]string{}}
	seen := map[string]map[string]bool{}
	for _, p := range proofs {
		g.byLayer[p.Layer] = append(g.byLayer[p.Layer], p)
		if seen[p.Layer] == nil {
			seen[p.Layer] = map[string]bool{}
		}
		if !seen[p.Layer][p.Category] {
			seen[p.Layer][p.Category] = true
			g.catOrder[p.Layer] = append(g.catOrder[p.Layer], p.Category)
		}
	}
	return g
}

// fleetScopeSets accumulates the env/system/host chip label sets and the
// env×system roll-up counts while the layer tree is being walked, so both
// are built in the same single pass over every row.
type fleetScopeSets struct {
	envs, systems, hosts map[string]string // slug -> display label
	rollup               map[string]*FleetRollupRow
	rollupOrder          []string
}

func newFleetScopeSets() *fleetScopeSets {
	return &fleetScopeSets{
		envs: map[string]string{}, systems: map[string]string{}, hosts: map[string]string{},
		rollup: map[string]*FleetRollupRow{},
	}
}

// rollupKey pairs (environment, system) into one map key.
func rollupKey(env, system string) string { return env + "\x1f" + system }

func (s *fleetScopeSets) touch(env, system, state string) {
	key := rollupKey(env, system)
	row, ok := s.rollup[key]
	if !ok {
		row = &FleetRollupRow{Env: envLabel(env), System: sysLabel(system)}
		s.rollup[key] = row
		s.rollupOrder = append(s.rollupOrder, key)
	}
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

// hostLabelFor renders a proof's resolved host for display, "(unset)" for
// the rare case a merged row carries no host at all.
func hostLabelFor(host string) string {
	if host == "" {
		return "(unset)"
	}
	return host
}

// fleetProofLess orders two rows already known to share one layer and
// category: environment criticality first (contextspec.EnvironmentLess,
// same as the single-host tree's treeRowLess), then problems-first
// (stateRank), then host, then proof id — the fleet page's one addition
// over the single-host ordering is the host tie-break, since many hosts can
// now share an otherwise-identical row.
func fleetProofLess(a, b FleetProof) bool {
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
	if a.Host != b.Host {
		return a.Host < b.Host
	}
	return a.Proof < b.Proof
}

// buildFleetTaxRow converts one merged FleetProof into its HTML row,
// recording its env/system/host slugs and roll-up contribution into sets as
// a side effect. Returns whether this row's bucket should force its layer
// <details> open (any bucket other than restored/observed — same rule
// buildTaxonomyData uses for the single-host page).
func buildFleetTaxRow(p FleetProof, sets *fleetScopeSets) (FleetTaxRow, bool) {
	bucket := filterBucket(p.State)
	open := bucket != BucketRestored && bucket != BucketObserved
	envSlug, sysSlug, hostSlug := slug(p.Scope.Environment), slug(p.Scope.System), slug(p.Host)
	sets.envs[envSlug] = envLabel(p.Scope.Environment)
	sets.systems[sysSlug] = sysLabel(p.Scope.System)
	sets.hosts[hostSlug] = hostLabelFor(p.Host)
	sets.touch(p.Scope.Environment, p.Scope.System, p.State)
	return FleetTaxRow{
		Proof: p.Proof, Artifact: orEmDashTax(p.Artifact), State: p.State, Bucket: bucket,
		Why: p.Why, Level: p.Level, Host: hostLabelFor(p.Host),
		EnvSlug: envSlug, SystemSlug: sysSlug, HostSlug: hostSlug,
	}, open
}

// buildFleetTaxLayer builds one layer's whole section: its header (via the
// shared buildLayerHeader — taxonomy_html.go/layers.go's own header line
// generator, reused verbatim rather than re-implemented for the fleet
// shape), its categories, and whether it opens by default.
func buildFleetTaxLayer(layer string, items []FleetProof, catOrder []string, sets *fleetScopeSets) FleetTaxLayer {
	byCat := map[string][]FleetProof{}
	for _, p := range items {
		byCat[p.Category] = append(byCat[p.Category], p)
	}
	open := false
	var cats []FleetTaxCategory
	var headerRows []TreeRow
	for _, cat := range catOrder {
		rows := byCat[cat]
		sort.SliceStable(rows, func(i, j int) bool { return fleetProofLess(rows[i], rows[j]) })
		taxRows := make([]FleetTaxRow, 0, len(rows))
		for _, p := range rows {
			row, becameOpen := buildFleetTaxRow(p, sets)
			if becameOpen {
				open = true
			}
			taxRows = append(taxRows, row)
			headerRows = append(headerRows, TreeRow{
				Proof: p.Proof, State: p.State, Level: p.Level, Why: p.Why, Artifact: p.Artifact, Scope: p.Scope,
			})
		}
		cats = append(cats, FleetTaxCategory{Category: categoryLabel(cat), Rows: taxRows})
	}
	return FleetTaxLayer{
		LayerID: layer, Header: buildLayerHeader(layer, headerRows), Open: open,
		Categories: cats, ShowCategoryHeaders: len(cats) > 1,
	}
}

// fleetConflictLines renders every merge-key collision as one human-readable
// line, for both fleet.html's warning banner and the terminal renderer.
func fleetConflictLines(cs []FleetConflict) []string {
	lines := make([]string, 0, len(cs))
	for _, c := range cs {
		lines = append(lines, fmt.Sprintf("%s: kept %s over %s (%s)", c.Key, c.KeptBundle, c.DroppedBundle, c.Reason))
	}
	return lines
}

// fleetBundleSummaries display-formats every merged-in bundle for
// fleet.html's "bundles merged" list.
func fleetBundleSummaries(bs []FleetBundleInfo) []FleetBundleSummary {
	out := make([]FleetBundleSummary, 0, len(bs))
	for _, b := range bs {
		out = append(out, FleetBundleSummary{
			Host: b.Host, Epoch: b.Epoch, GeneratedAt: b.GeneratedAt.Format(time.RFC3339), Path: b.Path,
		})
	}
	return out
}

// rollupEnv extracts the environment half of a rollupKey — the sort key
// buildFleetPageData orders the roll-up table by (environment criticality,
// then the full key for a stable tie-break).
func rollupEnv(key string) string {
	env, _, _ := strings.Cut(key, "\x1f")
	return env
}

// buildFleetPageData converts a merged Fleet into fleet.html's/`status
// --fleet`'s shared page data: filter chips (layer/state always; env/
// system/host chip sets are built from whatever the merged proofs actually
// carry), the env×system roll-up, and the layer→category→proof tree itself.
func buildFleetPageData(fleet Fleet) FleetPageData {
	base := FleetPageData{
		GeneratedAt: fleet.GeneratedAt.Format(time.RFC3339),
		Bundles:     fleetBundleSummaries(fleet.Bundles),
		Conflicts:   fleetConflictLines(fleet.Conflicts),
	}
	if len(fleet.Proofs) == 0 {
		return base
	}

	grouped := groupFleetProofsByLayer(fleet.Proofs)
	sets := newFleetScopeSets()
	var layerChips []FilterChip
	var taxLayers []FleetTaxLayer
	for _, layer := range contextspec.LayerOrder {
		items, ok := grouped.byLayer[layer]
		if !ok {
			continue
		}
		layerChips = append(layerChips, FilterChip{ID: layer, Label: layer})
		taxLayers = append(taxLayers, buildFleetTaxLayer(layer, items, grouped.catOrder[layer], sets))
	}

	sort.SliceStable(sets.rollupOrder, func(i, j int) bool {
		ei, ej := rollupEnv(sets.rollupOrder[i]), rollupEnv(sets.rollupOrder[j])
		if ei != ej {
			return contextspec.EnvironmentLess(ei, ej)
		}
		return sets.rollupOrder[i] < sets.rollupOrder[j]
	})
	rollup := make([]FleetRollupRow, 0, len(sets.rollupOrder))
	for _, k := range sets.rollupOrder {
		rollup = append(rollup, *sets.rollup[k])
	}

	stateChips := defaultStateChips()
	envChips, systemChips, hostChips := chipsFromSet(sets.envs), chipsFromSet(sets.systems), chipsFromSet(sets.hosts)

	base.LayerChips, base.StateChips = layerChips, stateChips
	base.EnvChips, base.SystemChips, base.HostChips = envChips, systemChips, hostChips
	base.Rollup, base.Layers = rollup, taxLayers
	base.FilterCSS = buildFleetFilterCSS(layerChips, stateChips, envChips, systemChips, hostChips)
	base.HasAny = true
	return base
}

// RenderText renders `status --fleet <dir>`'s terminal tree: the same
// layer→category→proof grouping fleet.html shows, with the host that owns
// each row, problems ordered first within a category, and merge conflicts
// (if any) called out up front.
func (f Fleet) RenderText() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "Fleet — %d bundle(s), generated %s\n", len(f.Bundles), f.GeneratedAt.Format(time.RFC3339))
	for _, bnd := range f.Bundles {
		fmt.Fprintf(&b, "  %-24s epoch %-14s generated %s  (%s)\n", bnd.Host, bnd.Epoch, bnd.GeneratedAt.Format(time.RFC3339), bnd.Path)
	}

	data := buildFleetPageData(f)
	if len(data.Conflicts) > 0 {
		fmt.Fprintf(&b, "\n%d merge conflict(s) — later generated_at won:\n", len(data.Conflicts))
		for _, c := range data.Conflicts {
			fmt.Fprintf(&b, "  ! %s\n", c)
		}
	}
	if !data.HasAny {
		b.WriteString("\nNo proofs in this fleet.\n")
		return []byte(b.String())
	}

	renderFleetRollupText(&b, data.Rollup)
	for _, layer := range data.Layers {
		fmt.Fprintf(&b, "\n%s\n", layer.Header)
		for _, cat := range layer.Categories {
			fmt.Fprintf(&b, "  %s\n", cat.Category)
			for _, row := range cat.Rows {
				fmt.Fprintf(&b, "    %-40s %-9s %-9s host:%-18s %s\n", row.Proof, row.State, row.Level, row.Host, row.Why)
				if row.Artifact != emDash {
					fmt.Fprintf(&b, "    %40s   artifact: %s\n", "", row.Artifact)
				}
			}
		}
	}
	return []byte(b.String())
}

// renderFleetRollupText prints the environment × system roll-up table —
// fleet.html's own roll-up, always shown (unlike the single-host page's
// threshold-gated one) since a fleet's whole point is comparing scope.
func renderFleetRollupText(b *strings.Builder, rows []FleetRollupRow) {
	if len(rows) == 0 {
		return
	}
	table := [][]string{{"ENVIRONMENT", "SYSTEM", "RESTORED", "OBSERVED", "ACCEPTED", "UNREVIEWED", "EXPIRED/LAPSED"}}
	for _, r := range rows {
		table = append(table, []string{
			r.Env, r.System, fmt.Sprintf("%d", r.Restored), fmt.Sprintf("%d", r.Observed),
			fmt.Sprintf("%d", r.Accepted), fmt.Sprintf("%d", r.Unreviewed), fmt.Sprintf("%d", r.Expired),
		})
	}
	widths := make([]int, len(table[0]))
	for _, row := range table {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	fmt.Fprintf(b, "\nEnvironment x system roll-up\n")
	for _, row := range table {
		for i, cell := range row {
			fmt.Fprintf(b, "%-*s  ", widths[i], cell)
		}
		b.WriteString("\n")
	}
}
