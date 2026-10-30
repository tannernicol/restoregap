// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package contextspec

import "fmt"

// The Layer vocabulary, in blast-radius order — this order is the sort
// order everywhere a layer-grouped view is rendered (classify, status,
// next). LayerUnfiled is never a settable value in YAML; it is only ever a
// COMPUTED effective layer (see EffectiveProofLayer) for a proof with no
// declared layer and no requiring guard. LayerCrossCutting IS a settable
// YAML value, but guard-only (see ValidGuardLayer): a guard whose required
// proofs span two or more layers declares (or is suggested) cross-cutting
// rather than picking one arbitrarily, and a cross-cutting guard never
// propagates a layer onto the proofs it requires (see
// nonCrossCuttingRequiringGuards).
const (
	LayerRecoveryKit     = "recovery-kit"
	LayerIdentitySecrets = "identity-secrets"
	LayerSystemOS        = "system-os"
	LayerInfraNetwork    = "infra-network"
	LayerBackupsOffsite  = "backups-offsite"
	LayerGitCode         = "git-code"
	LayerDataApps        = "data-apps"
	LayerAgentsContext   = "agents-context"
	LayerCrossCutting    = "cross-cutting"
	LayerUnfiled         = "unfiled"
)

// LayerOrder is the fixed vocabulary in its declared blast-radius order,
// LayerCrossCutting sorted last before the always-last LayerUnfiled.
var LayerOrder = []string{
	LayerRecoveryKit,
	LayerIdentitySecrets,
	LayerSystemOS,
	LayerInfraNetwork,
	LayerBackupsOffsite,
	LayerGitCode,
	LayerDataApps,
	LayerAgentsContext,
	LayerCrossCutting,
	LayerUnfiled,
}

// ValidLayer reports whether s is one of the eight proof/guard-declarable
// domain layers. LayerUnfiled is deliberately excluded: it is a fallback
// state a document can fall INTO, never one it declares. LayerCrossCutting
// is also excluded here — it is a valid explicit value for a GUARD only
// (see ValidGuardLayer); a proof never declares cross-cutting.
func ValidLayer(s string) bool {
	for _, l := range LayerOrder {
		if l == LayerUnfiled || l == LayerCrossCutting {
			continue
		}
		if l == s {
			return true
		}
	}
	return false
}

// ValidGuardLayer reports whether s is a value a GUARD may declare: any of
// the eight domain layers ValidLayer accepts, plus LayerCrossCutting.
func ValidGuardLayer(s string) bool {
	return ValidLayer(s) || s == LayerCrossCutting
}

// LayerRank returns a layer's position in LayerOrder — lower sorts first.
// An unrecognized string (should not happen once parse.go has validated it,
// but a computed "" reaches here too) ranks as LayerUnfiled, i.e. last.
func LayerRank(layer string) int {
	for i, l := range LayerOrder {
		if l == layer {
			return i
		}
	}
	return len(LayerOrder) - 1
}

// EffectiveGuardLayer is a guard's own declared Layer, or LayerUnfiled when
// never classified. Guards are the roots of layer inheritance — they never
// inherit from anything else.
func EffectiveGuardLayer(g Guard) string {
	if g.Layer != "" {
		return g.Layer
	}
	return LayerUnfiled
}

// EffectiveGuardCategory is a guard's own declared Category, "" when unset.
func EffectiveGuardCategory(g Guard) string {
	return g.Category
}

// LayerResult is one proof's computed effective layer/category, plus
// whether the guards requiring it disagreed on layer.
type LayerResult struct {
	Layer    string
	Category string
	// Conflict is true when more than one distinct effective layer was
	// found among the guards requiring this proof. The earliest layer in
	// LayerOrder still wins deterministically; Conflict only flags that a
	// human should look, via ConflictDetail.
	Conflict       bool
	ConflictDetail string
}

// requiringGuards returns every guard in ctx that lists proofID in its
// Requires.Proofs, in declared order.
func requiringGuards(ctx Context, proofID string) []Guard {
	var out []Guard
	for _, g := range ctx.Guards {
		for _, want := range g.Requires.Proofs {
			if want == proofID {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// nonCrossCuttingRequiringGuards is requiringGuards filtered to drop any
// guard whose own effective layer is LayerCrossCutting. A cross-cutting
// guard spans two or more layers by definition and must never propagate
// ITS layer onto a proof it requires; a proof required only by cross-
// cutting guard(s) falls through exactly as if no guard required it at
// all (proof keyword match, else unfiled).
func nonCrossCuttingRequiringGuards(ctx Context, proofID string) []Guard {
	all := requiringGuards(ctx, proofID)
	out := make([]Guard, 0, len(all))
	for _, g := range all {
		if EffectiveGuardLayer(g) != LayerCrossCutting {
			out = append(out, g)
		}
	}
	return out
}

// EffectiveProofLayer computes a proof's effective layer per the taxonomy
// spec's proof-first precedence: the proof's own Layer if set; else a
// keyword match on the proof's own id + drill artifact path + evidence
// basename (KeywordLayer — the same fixed rule table `classify` proposes
// from, so a proof's own domain vocabulary always wins over an incidental
// guard grouping); else the layer of the guard(s) that require it
// (LayerCrossCutting guards excluded — see nonCrossCuttingRequiringGuards),
// earliest-in-vocabulary-order winning on disagreement (with a one-line
// conflict note); else LayerUnfiled. Because a real keyword match returns
// early, a proof with its own classification never reaches the guard
// tie-break at all, so it never carries a stale "layer conflict" note
// either. Category is computed the same way, using the SAME winning guard
// (the one whose layer won the tie-break) as the source when the proof
// declares no category of its own.
func EffectiveProofLayer(ctx Context, p Proof) LayerResult {
	guards := nonCrossCuttingRequiringGuards(ctx, p.ID)
	// Category falls back to the requiring guard's category whenever the
	// proof declares none of its own — independent of which precedence
	// step below decides the LAYER, so a proof whose own keyword match
	// wins the layer still inherits its category from the guard that
	// requires it (e.g. ssh-key-recovery keyword-matches identity-secrets
	// on its own, but still picks up the "ssh-keys" category its guard
	// declared).
	category := p.Category
	if category == "" && len(guards) > 0 {
		category = EffectiveGuardCategory(guards[bestRequiringGuardIndex(guards)])
	}

	if p.Layer != "" {
		return LayerResult{Layer: p.Layer, Category: category}
	}
	if layer, _, matched := KeywordLayer(ProofKeywordSearchText(ctx, p)); matched {
		return LayerResult{Layer: layer, Category: category}
	}
	if len(guards) == 0 {
		return LayerResult{Layer: LayerUnfiled, Category: category}
	}

	cands := make([]layerCandidate, len(guards))
	for i, g := range guards {
		cands[i] = layerCandidate{guardID: g.ID, layer: EffectiveGuardLayer(g)}
	}

	best := 0
	distinct := map[string]bool{cands[0].layer: true}
	for i := 1; i < len(cands); i++ {
		distinct[cands[i].layer] = true
		if LayerRank(cands[i].layer) < LayerRank(cands[best].layer) {
			best = i
		}
	}

	res := LayerResult{Layer: cands[best].layer, Category: category}
	if len(distinct) > 1 {
		res.Conflict = true
		res.ConflictDetail = conflictDetail(cands, best)
	}
	return res
}

// layerCandidate is one guard's contribution to a proof's effective-layer
// tie-break: which guard, and what layer it resolved to.
type layerCandidate struct {
	guardID string
	layer   string
}

func conflictDetail(cands []layerCandidate, best int) string {
	msg := fmt.Sprintf("layer conflict: guard %s (%s) wins", cands[best].guardID, cands[best].layer)
	for i, c := range cands {
		if i == best {
			continue
		}
		msg += fmt.Sprintf(" over %s (%s)", c.guardID, c.layer)
	}
	return msg
}

// mergeScope overlays override onto base, field by field: any non-empty
// override field replaces the base's, an empty one keeps the base's. Tags
// are replaced wholesale when override declares any (an override that wants
// to ADD one tag while keeping the rest is not a case this schema supports —
// scope is a small set of free-form organizational labels, not a list to
// diff).
func mergeScope(base, override Scope) Scope {
	out := base
	if override.Environment != "" {
		out.Environment = override.Environment
	}
	if override.System != "" {
		out.System = override.System
	}
	if override.Host != "" {
		out.Host = override.Host
	}
	if override.Owner != "" {
		out.Owner = override.Owner
	}
	if len(override.Tags) > 0 {
		out.Tags = override.Tags
	}
	return out
}

// EffectiveGuardScope merges a context file's default Scope with one
// guard's own overrides, field by field.
func EffectiveGuardScope(ctx Context, g Guard) Scope {
	return mergeScope(ctx.Scope, g.Scope)
}

// bestRequiringGuardIndex picks the same "winning" guard EffectiveProofLayer
// would pick among guards requiring one proof: the one whose effective layer
// ranks earliest in LayerOrder. Scope inheritance reuses this tie-break so a
// proof's effective scope and effective layer/category trace back to the
// same guard when more than one guard requires it.
func bestRequiringGuardIndex(guards []Guard) int {
	best := 0
	for i := 1; i < len(guards); i++ {
		if LayerRank(EffectiveGuardLayer(guards[i])) < LayerRank(EffectiveGuardLayer(guards[best])) {
			best = i
		}
	}
	return best
}

// EffectiveProofScope computes a proof's effective scope (section F): the
// declaring context file's default Scope, overridden field by field by the
// requiring guard's own scope (the same winning guard EffectiveProofLayer
// picks when more than one guard requires this proof — see
// bestRequiringGuardIndex) when this proof is required by any guard, then
// overridden field by field by the proof's own Scope. This mirrors layer/
// category inheritance (guard -> required proof) rather than stopping at the
// context-file default, so a guard that declares environment/system for the
// resource it protects extends that placement to the proof it requires.
func EffectiveProofScope(ctx Context, p Proof) Scope {
	base := ctx.Scope
	if guards := requiringGuards(ctx, p.ID); len(guards) > 0 {
		base = EffectiveGuardScope(ctx, guards[bestRequiringGuardIndex(guards)])
	}
	return mergeScope(base, p.Scope)
}

// environmentOrder is the fixed criticality order named known environment
// names sort by — prod first (highest blast radius if wrong), unset last
// among known names. An unset Environment ("") sorts as the empty string
// entry here, immediately after "lab" and before any unrecognized name.
var environmentOrder = []string{"prod", "staging", "dev", "lab", ""}

// EnvironmentRank ranks an environment name by fixed criticality for known
// names (prod > staging > dev > lab > unset); an unrecognized name ranks
// after every known one, alphabetically among themselves (EnvironmentLess
// handles the alphabetical tiebreak — this function alone is not enough to
// sort two unknown names against each other).
func EnvironmentRank(env string) int {
	for i, e := range environmentOrder {
		if e == env {
			return i
		}
	}
	return len(environmentOrder) // every unknown name ranks here
}

// EnvironmentLess orders two environment names by the effective-ordering
// rule: fixed criticality for known names, then alphabetical among unknown
// names.
func EnvironmentLess(a, b string) bool {
	ra, rb := EnvironmentRank(a), EnvironmentRank(b)
	if ra != rb {
		return ra < rb
	}
	if ra < len(environmentOrder) {
		return false // both are the same known name
	}
	return a < b
}
