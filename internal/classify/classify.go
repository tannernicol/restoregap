// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package classify proposes (and, on request, writes) a recovery-domain
// Layer AND Category for every guard and every unattached proof in a set
// of context files. Layer comes from the fixed keyword rule table over id
// + artifact/evidence path (docs: taxonomy spec section B), shared with
// contextspec.EffectiveProofLayer's own proof-first classification via
// contextspec.KeywordLayer so `classify` and `status`/`next` never
// disagree about a proof's own layer. Category is a lighter-weight
// suggestion: the id's leading stem against a fixed list (section B) —
// still a free-form field an owner may always set by hand, and classify
// never overrides an explicit value either way.
package classify

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// Kind distinguishes a guard row from a proof row in a Suggestion table —
// the two are classified from different search text (a guard's match
// surface vs. a proof's own id/artifact/evidence) but share one table.
type Kind string

// The Kind values.
const (
	KindGuard Kind = "guard"
	KindProof Kind = "proof"
)

// Suggestion is one classify table row: what an entry is currently
// classified as (Current/CurrentCategory, "" meaning unfiled/uncategorized)
// and what the fixed rules would set it to (Suggested/SuggestedCategory),
// with Reason naming the layer rule that fired. A guard whose required
// proofs' own-classified layers span two or more layers overrides the
// keyword-based Suggested/Reason with the cross-cutting call — see
// suggestGuardLayer.
type Suggestion struct {
	Kind              Kind
	ID                string
	File              string // the context file this entry is declared in
	Current           string
	Suggested         string
	Reason            string
	CurrentCategory   string
	SuggestedCategory string
}

// Unfiled reports whether this entry currently has no declared layer — the
// condition `classify --suggest` exits 1 on when true for any row.
func (s Suggestion) Unfiled() bool { return s.Current == "" }

// UncategorizedField reports whether this entry currently has no declared
// category and a category suggestion exists to fill it.
func (s Suggestion) UncategorizedField() bool {
	return s.CurrentCategory == "" && s.SuggestedCategory != ""
}

// suggestLayer wraps contextspec.KeywordLayer, falling back to
// contextspec.LayerDataApps when nothing in the fixed rule table fires —
// classify's suggestion table always shows SOME concrete value (never
// "unfiled"), unlike contextspec.EffectiveProofLayer's own runtime
// fallback chain (which continues to guard inheritance, then unfiled).
func suggestLayer(search string) (layer, reason string) {
	if layer, reason, matched := contextspec.KeywordLayer(search); matched {
		return layer, reason
	}
	return contextspec.LayerDataApps, "no keyword matched → data-apps (default)"
}

// categoryStems is the taxonomy spec's fixed leading-stem list (section B):
// the FIRST stem an id has as a prefix becomes its suggested category, so
// "(uncategorized)" mostly disappears from the taxonomy tree. Order matters
// only in that it is the tie-break when an id could plausibly read as more
// than one stem; none of these stems is itself a prefix of another, so in
// practice at most one ever matches.
var categoryStems = []string{
	"ssh-key", "secret-store", "vaultwarden", "nas", "private-app", "tailnet",
	"os", "context", "codex", "claude", "agent", "money", "obsidian", "assistant",
	"recovery-bootstrap", "recovery-usb", "phone", "restic", "offsite", "git-estate",
}

// suggestCategory returns the first categoryStems entry id has as a
// (case-insensitive) leading prefix, ok=false when none matches.
func suggestCategory(id string) (category string, ok bool) {
	s := strings.ToLower(id)
	for _, stem := range categoryStems {
		if strings.HasPrefix(s, stem) {
			return stem, true
		}
	}
	return "", false
}

// guardSearchText is a guard's classify surface: its id alone.
//
// The taxonomy spec's "id + artifact/evidence path" phrase is well-defined
// for a proof (id + its drill's Artifact + its evidence_url — see
// contextspec.ProofKeywordSearchText) but a Guard has no single analogous
// field. An earlier version of this function also searched
// Match.Paths/Commands/Packages and RecoveryCopy, reasoning those were the
// closest a guard has to an "artifact" surface; in practice, against the
// real estate this spec ships with, that made results WORSE, not better: a
// guard's declared path or recovery destination is often an incidental
// substring match with nothing to do with the guard's actual domain
// (recovery_copy "ssh://admin@…/codex-state/latest" contains "ssh" and
// misclassified a codex-related guard as identity-secrets; a match path
// "/home/example/bin/codex-routed" contains "route" and misclassified an
// agents-context guard as infra-network). Guard id alone is the more
// literal, lower-invention reading of the spec and produces fewer, more
// legible false positives (a guard whose id carries no domain hint simply
// falls to the data-apps default, which is an honest, reportable gap rather
// than a confidently wrong answer).
func guardSearchText(g contextspec.Guard) string {
	return contextspec.GuardKeywordSearchText(g)
}

// requiredProofOwnLayers returns the DISTINCT own-classified layers
// (explicit p.layer if set, else a keyword match on the proof's own id/
// artifact/evidence surface — never guard inheritance, to avoid a
// guard<->proof classification cycle) among a guard's required proofs that
// merged declares, in first-seen order.
func requiredProofOwnLayers(merged contextspec.Context, g contextspec.Guard) []string {
	byID := make(map[string]contextspec.Proof, len(merged.Proofs))
	for _, p := range merged.Proofs {
		byID[p.ID] = p
	}
	seen := map[string]bool{}
	var layers []string
	for _, want := range g.Requires.Proofs {
		p, ok := byID[want]
		if !ok {
			continue
		}
		layer := p.Layer
		if layer == "" {
			if l, _, matched := contextspec.KeywordLayer(contextspec.ProofKeywordSearchText(merged, p)); matched {
				layer = l
			}
		}
		if layer == "" || seen[layer] {
			continue
		}
		seen[layer] = true
		layers = append(layers, layer)
	}
	return layers
}

// suggestGuardLayer is a guard's layer suggestion: cross-cutting when its
// required proofs' own-classified layers span two or more distinct layers
// (docs: taxonomy spec section B — a guard protecting resources in more
// than one domain should say so rather than picking one arbitrarily), else
// the ordinary keyword-based suggestLayer over the guard's own id.
func suggestGuardLayer(merged contextspec.Context, g contextspec.Guard) (layer, reason string) {
	if spanned := requiredProofOwnLayers(merged, g); len(spanned) >= 2 {
		return contextspec.LayerCrossCutting, fmt.Sprintf(
			"required proofs span %d layers (%s) → cross-cutting", len(spanned), strings.Join(spanned, ", "))
	}
	return suggestLayer(guardSearchText(g))
}

// attachedProofIDs is the set of every proof id named in some guard's
// requires.proofs, across the whole (merged) context — a proof in this set
// is "attached" and gets its effective layer from that guard instead of a
// direct classify suggestion (contextspec.EffectiveProofLayer).
func attachedProofIDs(ctx contextspec.Context) map[string]bool {
	out := map[string]bool{}
	for _, g := range ctx.Guards {
		for _, id := range g.Requires.Proofs {
			out[id] = true
		}
	}
	return out
}

// fileOf locates which of the individually-loaded per-file contexts
// declares a guard or proof id, for Suggestion.File and for Apply's
// per-file write. Empty when not found (should not happen for an id that
// came from the merged context in the first place).
func fileOf(loaded []loadedFile, kind Kind, id string) string {
	for _, lf := range loaded {
		switch kind {
		case KindGuard:
			for _, g := range lf.ctx.Guards {
				if g.ID == id {
					return lf.path
				}
			}
		case KindProof:
			for _, p := range lf.ctx.Proofs {
				if p.ID == id {
					return lf.path
				}
			}
		}
	}
	return ""
}

type loadedFile struct {
	path string
	ctx  contextspec.Context
}

// loadFiles loads every path individually (for provenance) and returns them
// alongside the merged context (for cross-file guard/proof relationships —
// attachment and layer inheritance are not confined to one file).
func loadFiles(paths []string) ([]loadedFile, contextspec.Context, error) {
	if len(paths) == 0 {
		return nil, contextspec.Context{}, fmt.Errorf("classify: at least one --context path is required")
	}
	loaded := make([]loadedFile, 0, len(paths))
	for _, p := range paths {
		ctx, err := contextspec.Load(p)
		if err != nil {
			return nil, contextspec.Context{}, err
		}
		loaded = append(loaded, loadedFile{path: p, ctx: ctx})
	}
	merged, err := contextspec.LoadAll(paths)
	if err != nil {
		return nil, contextspec.Context{}, err
	}
	return loaded, merged, nil
}

// Suggest builds the classify table: one row per guard, plus one row per
// UNATTACHED proof (a proof no guard requires — an attached proof inherits
// its layer from the guard(s) requiring it instead, contextspec.
// EffectiveProofLayer, and classify does not separately suggest one).
// Guard rows are listed first, in declared order, then proof rows, in
// declared order. Every row also carries a category suggestion (the id's
// leading stem, suggestCategory) independent of the layer/attachment
// logic — a proof's category suggestion is proposed even when the proof
// itself is attached and gets no layer row of its own... except attached
// proofs get no row at all here (unchanged from before): only the layer
// axis distinguishes attached from unattached; category suggestions ride
// along on whatever rows already exist.
func Suggest(paths []string) ([]Suggestion, error) {
	loaded, merged, err := loadFiles(paths)
	if err != nil {
		return nil, err
	}
	attached := attachedProofIDs(merged)

	var out []Suggestion
	for _, g := range merged.Guards {
		layer, reason := suggestGuardLayer(merged, g)
		cat, _ := suggestCategory(g.ID)
		out = append(out, Suggestion{
			Kind: KindGuard, ID: g.ID, File: fileOf(loaded, KindGuard, g.ID),
			Current: g.Layer, Suggested: layer, Reason: reason,
			CurrentCategory: g.Category, SuggestedCategory: cat,
		})
	}
	for _, p := range merged.Proofs {
		if attached[p.ID] {
			continue
		}
		layer, reason := suggestLayer(contextspec.ProofKeywordSearchText(merged, p))
		cat, _ := suggestCategory(p.ID)
		out = append(out, Suggestion{
			Kind: KindProof, ID: p.ID, File: fileOf(loaded, KindProof, p.ID),
			Current: p.Layer, Suggested: layer, Reason: reason,
			CurrentCategory: p.Category, SuggestedCategory: cat,
		})
	}
	return out, nil
}

// AnyUnfiled reports whether any suggestion currently has no declared
// layer — `classify --suggest`'s exit-1 condition.
func AnyUnfiled(suggestions []Suggestion) bool {
	for _, s := range suggestions {
		if s.Unfiled() {
			return true
		}
	}
	return false
}

// Applied is one entry classify --apply actually wrote.
type Applied struct {
	Kind     Kind
	ID       string
	File     string
	Layer    string // "" when this entry already had an explicit layer
	Category string // "" when this entry already had an explicit category
}

// Apply writes layer: and/or category: onto every entry in suggestions
// that lacks one, grouped and written per file — never touching a field
// that already has an explicit value, matching the "never override" rule
// classify_test.go exercises. Each touched file is backed up to a sibling
// .bak.<UTC-timestamp> first. Returns what was written, in the same order
// as suggestions; an entry that needed neither field written is omitted.
func Apply(suggestions []Suggestion) ([]Applied, error) {
	byFile := map[string][]Suggestion{}
	var fileOrder []string
	needsWrite := func(s Suggestion) bool { return s.Unfiled() || s.UncategorizedField() }
	for _, s := range suggestions {
		if !needsWrite(s) {
			continue
		}
		if _, seen := byFile[s.File]; !seen {
			fileOrder = append(fileOrder, s.File)
		}
		byFile[s.File] = append(byFile[s.File], s)
	}

	var applied []Applied
	for _, file := range fileOrder {
		toWrite := byFile[file]
		if file == "" {
			return nil, fmt.Errorf("classify: apply: %d entr(ies) have no known source file", len(toWrite))
		}
		if err := applyToFile(file, toWrite); err != nil {
			return nil, err
		}
		for _, s := range toWrite {
			a := Applied{Kind: s.Kind, ID: s.ID, File: s.File}
			if s.Unfiled() {
				a.Layer = s.Suggested
			}
			if s.UncategorizedField() {
				a.Category = s.SuggestedCategory
			}
			applied = append(applied, a)
		}
	}
	return applied, nil
}

// applyToFile backs path up, then writes layer: and/or category: onto each
// named guard/proof — the same generic map[string]any round-trip
// internal/cli/accept.go's writeAcceptance uses, so every field this
// command does not own (including scope:, and any field classify itself
// has never heard of) survives untouched.
func applyToFile(path string, entries []Suggestion) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	bakPath := path + ".bak." + time.Now().UTC().Format("20060102T150405Z")
	if err := os.WriteFile(bakPath, raw, 0o644); err != nil {
		return fmt.Errorf("classify: backup %s: %w", bakPath, err)
	}
	doc := map[string]any{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return err
	}

	wantLayer := map[Kind]map[string]string{KindGuard: {}, KindProof: {}}
	wantCategory := map[Kind]map[string]string{KindGuard: {}, KindProof: {}}
	for _, s := range entries {
		if s.Unfiled() {
			wantLayer[s.Kind][s.ID] = s.Suggested
		}
		if s.UncategorizedField() {
			wantCategory[s.Kind][s.ID] = s.SuggestedCategory
		}
	}

	writeField(doc, "guards", "layer", wantLayer[KindGuard])
	writeField(doc, "proofs", "layer", wantLayer[KindProof])
	writeField(doc, "guards", "category", wantCategory[KindGuard])
	writeField(doc, "proofs", "category", wantCategory[KindProof])

	encoded, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return fmt.Errorf("classify: %w (backup preserved at %s)", err, bakPath)
	}
	return nil
}

// writeField sets field: on every map entry of doc[section] whose id: is a
// key of want — never touching an entry not in want (an entry that already
// has an explicit value for this field is simply never passed in).
func writeField(doc map[string]any, section, field string, want map[string]string) {
	if len(want) == 0 {
		return
	}
	items, _ := doc[section].([]any)
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		if value, ok := want[id]; ok {
			m[field] = value
		}
	}
}
