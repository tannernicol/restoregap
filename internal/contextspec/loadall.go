package contextspec

import (
	"fmt"
	"strings"
)

// LoadAll loads and merges multiple context documents into one, by union:
// every path's Guards/Facts/Proofs/Drills are appended together. This is
// what lets a real deployment split declarations across several files (one
// per drill, since each drill's proof-writing timer owns and rewrites its
// own file) while preflight/status still see the whole machine.
//
// A single path behaves exactly like Load(paths[0]) — same Context, same
// Origin — so callers that go from one context to many see no change in the
// one-path case.
//
// An id (guard id, fact id, proof id, or drill proof name) declared in more
// than one file is an error naming both files, never a silent last-wins
// merge: two different declarations quietly collapsing under one id would
// hide exactly the kind of drift (a stale copy-pasted proof block, two
// timers racing to own the same drill) a multi-file split is supposed to
// tolerate, not paper over.
func LoadAll(paths []string) (Context, error) {
	if len(paths) == 0 {
		return Context{}, fmt.Errorf("contextspec: LoadAll requires at least one path")
	}
	if len(paths) == 1 {
		return Load(paths[0])
	}

	var merged Context
	guardAt := map[string]string{}
	factAt := map[string]string{}
	proofAt := map[string]string{}
	drillAt := map[string]string{}
	origins := make([]string, 0, len(paths))

	for _, p := range paths {
		ctx, err := Load(p)
		if err != nil {
			return Context{}, err
		}
		if len(origins) == 0 {
			merged.Version = ctx.Version
		} else if ctx.Version != merged.Version {
			return Context{}, fmt.Errorf("contextspec: version mismatch: %s is version %d, %s is version %d",
				origins[0], merged.Version, p, ctx.Version)
		}

		// Resolve each guard/proof's scope against ITS OWN file's scope:
		// default before merging: once every file's entries share one
		// Context, there is no longer a single file-level default to fall
		// back to (merged.Scope is deliberately left zero), so the merge
		// point is the last place a per-file default can still apply.
		// mergeScope is idempotent against a zero base, so this is a no-op
		// for entries that already declare every field themselves.
		for i := range ctx.Guards {
			ctx.Guards[i].Scope = mergeScope(ctx.Scope, ctx.Guards[i].Scope)
		}
		for i := range ctx.Proofs {
			ctx.Proofs[i].Scope = mergeScope(ctx.Scope, ctx.Proofs[i].Scope)
		}

		if err := mergeByID("guard", p, ctx.Guards, guardAt, func(g Guard) string { return g.ID }, &merged.Guards); err != nil {
			return Context{}, err
		}
		if err := mergeByID("fact", p, ctx.Facts, factAt, func(f Fact) string { return f.ID }, &merged.Facts); err != nil {
			return Context{}, err
		}
		if err := mergeByID("proof", p, ctx.Proofs, proofAt, func(pr Proof) string { return pr.ID }, &merged.Proofs); err != nil {
			return Context{}, err
		}
		if err := mergeByID("drill", p, ctx.Drills, drillAt, func(d Drill) string { return d.Proof }, &merged.Drills); err != nil {
			return Context{}, err
		}
		origins = append(origins, p)
	}

	merged.Origin = strings.Join(origins, ", ")
	return merged, nil
}

// mergeByID appends items into *out, recording each id's source path in at
// so a later duplicate names both the file it was first seen in and the one
// it collided with. Deliberately not built on collectUnique (parse.go):
// that helper's errors name a within-file index, but a cross-file duplicate
// is only useful to a human when it names the two files involved.
func mergeByID[T any](kind, path string, items []T, at map[string]string, idOf func(T) string, out *[]T) error {
	for _, item := range items {
		id := idOf(item)
		if prev, dup := at[id]; dup {
			return fmt.Errorf("contextspec: duplicate %s id %q in %s and %s", kind, id, prev, path)
		}
		at[id] = path
		*out = append(*out, item)
	}
	return nil
}
