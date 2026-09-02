// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package policy

import (
	"fmt"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// Finding is a policy-layer merge finding: a later layer tried to loosen or
// remove a guard an earlier layer declared, and the attempt was ignored
// (docs/SCHEMA.md §Layered policy, tighten-only). Verdict is always "warn" —
// a loosening attempt does not block the run it is discovered during, it
// flags the policy file that needs an owner's attention.
type Finding struct {
	ID      string // "policy/loosened"
	GuardID string
	File    string
	Verdict string // "warn"
}

// String renders the finding in the form the spec names: "policy/loosened
// <id> in <file>".
func (f Finding) String() string {
	return fmt.Sprintf("%s %s in %s", f.ID, f.GuardID, f.File)
}

// Merge loads and merges every path into one Context, same union semantics
// as contextspec.LoadAll for facts/proofs/drills (a duplicate id across
// files is an error naming both), but guard-by-guard tighten-only for
// guards: a file later in paths may add a new guard id, or replace an
// earlier layer's guard with one that only ever gets stricter — higher
// enforcement, more required proofs/facts, a lower (or newly added)
// max-proof-age bound, more matched paths. A later file's guard that would
// loosen any of those dimensions is NOT applied — the earlier (stricter)
// guard is kept — and is instead reported as a Finding, so an org's
// fleet-wide floor (docs/ENTERPRISE.md) cannot be silently narrowed by a
// per-host file.
//
// paths is a flat, priority-ascending list — earlier entries are lower
// priority ("org"), later ones higher ("host"); internal/discovery's
// PolicyDirs/LayeredConfigFiles establishes that order for the real
// discovery pipeline. A single path is Load(paths[0]) with no merge step,
// matching contextspec.LoadAll's own single-path behavior.
func Merge(paths []string) (contextspec.Context, []Finding, error) {
	if len(paths) == 0 {
		return contextspec.Context{}, nil, fmt.Errorf("policy: Merge requires at least one path")
	}
	if len(paths) == 1 {
		ctx, err := contextspec.Load(paths[0])
		return ctx, nil, err
	}

	m := newMergeState()
	for _, path := range paths {
		ctx, err := contextspec.Load(path)
		if err != nil {
			return contextspec.Context{}, nil, err
		}
		if err := m.checkVersion(path, ctx.Version); err != nil {
			return contextspec.Context{}, nil, err
		}
		m.mergeGuards(path, ctx)
		if err := m.mergeRest(path, ctx); err != nil {
			return contextspec.Context{}, nil, err
		}
	}

	merged := contextspec.Context{
		Version: m.version,
		Guards:  m.guards,
		Facts:   m.facts,
		Proofs:  m.proofs,
		Drills:  m.drills,
		Origin:  joinOrigins(paths),
	}
	return merged, m.findings, nil
}

// mergeState is Merge's accumulator across files, split out so Merge itself
// stays a short, readable ladder of steps rather than one long function
// (the gocyclo cap this codebase enforces).
type mergeState struct {
	haveVersion bool
	version     int
	firstPath   string

	guards    []contextspec.Guard
	guardIdx  map[string]int
	guardFile map[string]string

	facts   []contextspec.Fact
	factAt  map[string]string
	proofs  []contextspec.Proof
	proofAt map[string]string
	drills  []contextspec.Drill
	drillAt map[string]string

	findings []Finding
}

func newMergeState() *mergeState {
	return &mergeState{
		guardIdx:  map[string]int{},
		guardFile: map[string]string{},
		factAt:    map[string]string{},
		proofAt:   map[string]string{},
		drillAt:   map[string]string{},
	}
}

func (m *mergeState) checkVersion(path string, version int) error {
	if !m.haveVersion {
		m.haveVersion, m.version, m.firstPath = true, version, path
		return nil
	}
	if version != m.version {
		return fmt.Errorf("policy: version mismatch: %s is version %d, %s is version %d",
			m.firstPath, m.version, path, version)
	}
	return nil
}

// mergeGuards folds one file's guards into the accumulator, tighten-only
// per id (see Merge's doc comment). Each guard's Scope is resolved to its
// EffectiveGuardScope before merging — the same point contextspec.LoadAll
// bakes a file's default Scope into its items, since the merged Context's
// own Scope is left zero (there is no longer one file to default from).
func (m *mergeState) mergeGuards(path string, ctx contextspec.Context) {
	for _, g := range ctx.Guards {
		g.Scope = contextspec.EffectiveGuardScope(ctx, g)
		idx, exists := m.guardIdx[g.ID]
		if !exists {
			m.guardIdx[g.ID] = len(m.guards)
			m.guardFile[g.ID] = path
			m.guards = append(m.guards, g)
			continue
		}
		existing := m.guards[idx]
		if tightens(existing, g) {
			m.guards[idx] = g
			m.guardFile[g.ID] = path
			continue
		}
		m.findings = append(m.findings, Finding{ID: "policy/loosened", GuardID: g.ID, File: path, Verdict: "warn"})
	}
}

// mergeRest folds one file's facts/proofs/drills into the accumulator by
// plain union — a duplicate id across files is an error naming both,
// mirroring contextspec.LoadAll exactly: these are not policy guards, so
// tighten-only has no meaning for them, and a silently-collapsing duplicate
// would hide the same kind of drift LoadAll's own union guards against.
func (m *mergeState) mergeRest(path string, ctx contextspec.Context) error {
	for i := range ctx.Proofs {
		ctx.Proofs[i].Scope = contextspec.EffectiveProofScope(ctx, ctx.Proofs[i])
	}
	if err := mergeUnique("fact", path, ctx.Facts, m.factAt, func(f contextspec.Fact) string { return f.ID }, &m.facts); err != nil {
		return err
	}
	if err := mergeUnique("proof", path, ctx.Proofs, m.proofAt, func(p contextspec.Proof) string { return p.ID }, &m.proofs); err != nil {
		return err
	}
	if err := mergeUnique("drill", path, ctx.Drills, m.drillAt, func(d contextspec.Drill) string { return d.Proof }, &m.drills); err != nil {
		return err
	}
	return nil
}

// mergeUnique appends items into *out, recording each id's source path in
// at so a later duplicate names both the file it was first seen in and the
// one it collided with — contextspec.LoadAll's own mergeByID, duplicated
// here because that helper is unexported and facts/proofs/drills need
// exactly its semantics, unlike guards.
func mergeUnique[T any](kind, path string, items []T, at map[string]string, idOf func(T) string, out *[]T) error {
	for _, item := range items {
		id := idOf(item)
		if prev, dup := at[id]; dup {
			return fmt.Errorf("policy: duplicate %s id %q in %s and %s", kind, id, prev, path)
		}
		at[id] = path
		*out = append(*out, item)
	}
	return nil
}

func joinOrigins(paths []string) string {
	out := paths[0]
	for _, p := range paths[1:] {
		out += ", " + p
	}
	return out
}

// tightens reports whether candidate is a legal tighten-or-equal evolution
// of existing (same guard id, a later layer): every dimension the spec
// names — enforcement, required proofs/facts, max proof age, matched paths
// — only ever gets stricter or stays the same, never weaker.
func tightens(existing, candidate contextspec.Guard) bool {
	if enforcementRank(candidate.Enforcement) < enforcementRank(existing.Enforcement) {
		return false
	}
	if !supersetStrings(candidate.Requires.Proofs, existing.Requires.Proofs) {
		return false
	}
	if !supersetStrings(candidate.Requires.Facts, existing.Requires.Facts) {
		return false
	}
	if !ageTightensOrEqual(existing.MaxProofAgeHours, candidate.MaxProofAgeHours) {
		return false
	}
	return supersetStrings(candidate.Match.Paths, existing.Match.Paths)
}

// enforcementRank orders Enforcement by strictness: warn is weaker than
// block. An unrecognized value ranks as warn (the weakest defined level) —
// contextspec's own validation already rejects anything else at parse
// time, so this only matters for a zero-value Enforcement.
func enforcementRank(e contextspec.Enforcement) int {
	if e == contextspec.EnforcementBlock {
		return 1
	}
	return 0
}

// ageTightensOrEqual reports whether candidateHours is at least as strict a
// freshness bound as existingHours (0 = unbounded, contextspec's own
// convention). Unbounded to unbounded, or unbounded to any positive bound,
// tightens; a positive bound loosens if the candidate raises it or drops it
// back to unbounded.
func ageTightensOrEqual(existingHours, candidateHours int) bool {
	if existingHours == 0 {
		return true
	}
	if candidateHours == 0 {
		return false
	}
	return candidateHours <= existingHours
}

// supersetStrings reports whether candidate contains every element of
// existing — the "only ever adds" shape tighten-only allows for a guard's
// required proofs/facts and matched paths.
func supersetStrings(candidate, existing []string) bool {
	have := make(map[string]bool, len(candidate))
	for _, s := range candidate {
		have[s] = true
	}
	for _, s := range existing {
		if !have[s] {
			return false
		}
	}
	return true
}
