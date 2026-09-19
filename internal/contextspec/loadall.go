package contextspec

import (
	"fmt"
	"strings"
)

// LoadedLayer is one parsed context file with per-file defaults applied to
// its guards and proofs. It is the shared seam for callers that need both the
// merged union and per-file provenance.
type LoadedLayer struct {
	Path    string
	Context Context
}

// LoadedLayers contains the strict union shared by LoadAll and policy.Merge.
// Guards remain per-layer because LoadAll rejects duplicate guard IDs while
// policy.Merge applies its separate tighten-only guard overlay.
type LoadedLayers struct {
	Version int
	Origin  string
	Layers  []LoadedLayer
	Facts   []Fact
	Proofs  []Proof
	Drills  []Drill
}

// LoadLayers parses paths, checks their common version, resolves each file's
// scope defaults, and strictly unions facts, proofs, and drills by ID. Guard
// policy is intentionally left to the caller.
func LoadLayers(paths []string) (LoadedLayers, error) {
	if len(paths) == 0 {
		return LoadedLayers{}, fmt.Errorf("contextspec: LoadLayers requires at least one path")
	}
	loaded := LoadedLayers{Layers: make([]LoadedLayer, 0, len(paths))}
	factAt := map[string]string{}
	proofAt := map[string]string{}
	drillAt := map[string]string{}
	for _, path := range paths {
		ctx, err := Load(path)
		if err != nil {
			return LoadedLayers{}, err
		}
		if len(loaded.Layers) == 0 {
			loaded.Version = ctx.Version
		} else if ctx.Version != loaded.Version {
			return LoadedLayers{}, fmt.Errorf("contextspec: version mismatch: %s is version %d, %s is version %d",
				loaded.Layers[0].Path, loaded.Version, path, ctx.Version)
		}
		for i := range ctx.Guards {
			ctx.Guards[i].Scope = mergeScope(ctx.Scope, ctx.Guards[i].Scope)
		}
		for i := range ctx.Proofs {
			ctx.Proofs[i].Scope = mergeScope(ctx.Scope, ctx.Proofs[i].Scope)
		}
		loaded.Layers = append(loaded.Layers, LoadedLayer{Path: path, Context: ctx})
		if err := mergeByID("fact", path, ctx.Facts, factAt, func(f Fact) string { return f.ID }, &loaded.Facts); err != nil {
			return LoadedLayers{}, err
		}
		if err := mergeByID("proof", path, ctx.Proofs, proofAt, func(p Proof) string { return p.ID }, &loaded.Proofs); err != nil {
			return LoadedLayers{}, err
		}
		if err := mergeByID("drill", path, ctx.Drills, drillAt, func(d Drill) string { return d.Proof }, &loaded.Drills); err != nil {
			return LoadedLayers{}, err
		}
	}
	loaded.Origin = strings.Join(paths, ", ")
	return loaded, nil
}

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

	layers, err := LoadLayers(paths)
	if err != nil {
		return Context{}, err
	}
	var merged Context
	merged.Version, merged.Origin = layers.Version, layers.Origin
	merged.Facts, merged.Proofs, merged.Drills = layers.Facts, layers.Proofs, layers.Drills
	guardAt := map[string]string{}
	for _, layer := range layers.Layers {
		if err := mergeByID("guard", layer.Path, layer.Context.Guards, guardAt, func(g Guard) string { return g.ID }, &merged.Guards); err != nil {
			return Context{}, err
		}
	}
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
