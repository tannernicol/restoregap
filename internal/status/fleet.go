// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package status also owns fleet aggregation (docs/SCHEMA.md §Offline fleet
// merge): combining several hosts' verified bundles into one view, using
// the exact same proof-state/layer/category classification (getProofs,
// buildInventory, Classify) a single host's own `status` command uses, so
// a fleet row and a single-host row are never computed two different ways.
package status

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tannernicol/restoregap/internal/bundle"
	"github.com/tannernicol/restoregap/internal/contextspec"
)

// Tar-free file names `bundle merge`/`status --fleet` read and write inside
// the merge output directory.
const (
	fleetJSONName = "fleet.json"
	fleetHTMLName = "fleet.html"
)

// FleetBundleInfo is one merged-in bundle's identity, for fleet.json's
// "bundles" list and fleet.html's per-host summary.
type FleetBundleInfo struct {
	Path        string    `json:"path"`
	Host        string    `json:"host"`
	HostID      string    `json:"host_id"`
	Epoch       string    `json:"epoch"`
	GeneratedAt time.Time `json:"generated_at"`
}

// FleetProof is one proof/gap's full merged view: scope, host, epoch,
// layer, category, and state — everything status --fleet's tree and
// fleet.html's rows need, and everything fleet.json exports.
type FleetProof struct {
	Proof        string            `json:"proof"`
	Layer        string            `json:"layer"`
	Category     string            `json:"category"`
	State        string            `json:"state"`
	Level        string            `json:"level"`
	Why          string            `json:"why"`
	Host         string            `json:"host"`
	Epoch        string            `json:"epoch"`
	Scope        contextspec.Scope `json:"scope"`
	Artifact     string            `json:"artifact"`
	ContextFile  string            `json:"context_file"`
	SourceBundle string            `json:"source_bundle"`
	GeneratedAt  time.Time         `json:"generated_at"`
}

// MergeKey is the (guard/proof id, environment, system, host) identity
// bundle merge keys on (docs/SCHEMA.md §Offline fleet merge) — the same
// four-field shape ScopeRow.MergeKey already established for a two-host
// merge, with Host taken from the fleet row's own resolved Host (bundle
// identity when the proof declares no scope.host of its own) rather than
// scope.Host alone, so a proof that never got an explicit host stamp still
// keys uniquely per bundle instead of colliding across hosts.
func (r FleetProof) MergeKey() string {
	return fmt.Sprintf("%s\x1f%s\x1f%s\x1f%s", r.Proof, r.Scope.Environment, r.Scope.System, r.Host)
}

// FleetConflict names one merge-key collision and which bundle's row won.
type FleetConflict struct {
	Key           string `json:"key"`
	KeptBundle    string `json:"kept_bundle"`
	DroppedBundle string `json:"dropped_bundle"`
	Reason        string `json:"reason"`
}

// Fleet is fleet.json's decoded shape.
type Fleet struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Bundles     []FleetBundleInfo `json:"bundles"`
	Proofs      []FleetProof      `json:"proofs"`
	Conflicts   []FleetConflict   `json:"conflicts"`
}

// MergeBundles verifies and loads every bundle path (bundle.LoadVerified —
// a bundle that fails verification aborts the whole merge rather than
// silently ingesting partial/untrusted data), classifies each bundle's own
// proofs exactly as a single-host `status` would, and merges them keyed by
// FleetProof.MergeKey: later Manifest.GeneratedAt wins per key, and every
// collision is recorded in Conflicts (never silently dropped).
func MergeBundles(paths []string) (Fleet, error) {
	if len(paths) == 0 {
		return Fleet{}, fmt.Errorf("bundle merge: at least one bundle is required")
	}
	fleet := Fleet{GeneratedAt: time.Now().UTC()}
	byKey := map[string]FleetProof{}

	for _, p := range paths {
		manifest, ctx, err := bundle.LoadVerified(p)
		if err != nil {
			return Fleet{}, fmt.Errorf("bundle merge: %w", err)
		}
		fleet.Bundles = append(fleet.Bundles, FleetBundleInfo{
			Path: p, Host: manifest.Host.Name, HostID: manifest.Host.ID,
			Epoch: manifest.Epoch, GeneratedAt: manifest.GeneratedAt,
		})
		for _, row := range fleetRowsForBundle(ctx, manifest, p) {
			mergeFleetRow(byKey, &fleet.Conflicts, row)
		}
	}

	fleet.Proofs = sortedFleetProofs(byKey)
	sort.Slice(fleet.Conflicts, func(i, j int) bool { return fleet.Conflicts[i].Key < fleet.Conflicts[j].Key })
	return fleet, nil
}

// WriteFleet writes fleet's fleet.json (machine-readable, every merged
// proof) and fleet.html (the self-contained dark dashboard) into dir,
// creating it if needed — `bundle merge`'s own output step. Returns both
// written paths so the caller can report them.
func WriteFleet(fleet Fleet, dir string) (jsonPath, htmlPath string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("bundle merge: %w", err)
	}
	raw, err := json.MarshalIndent(fleet, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("bundle merge: encode fleet.json: %w", err)
	}
	jsonPath = filepath.Join(dir, fleetJSONName)
	if err := os.WriteFile(jsonPath, raw, 0o644); err != nil {
		return "", "", fmt.Errorf("bundle merge: %w", err)
	}
	html, err := fleet.RenderHTML()
	if err != nil {
		return "", "", err
	}
	htmlPath = filepath.Join(dir, fleetHTMLName)
	if err := os.WriteFile(htmlPath, html, 0o644); err != nil {
		return "", "", fmt.Errorf("bundle merge: %w", err)
	}
	return jsonPath, htmlPath, nil
}

// LoadFleet reads back the fleet.json a prior `bundle merge` wrote to dir —
// `status --fleet <dir>`'s input, so the terminal tree and fleet.html are
// always rendered from the exact same merged data.
func LoadFleet(dir string) (Fleet, error) {
	raw, err := os.ReadFile(filepath.Join(dir, fleetJSONName))
	if err != nil {
		return Fleet{}, fmt.Errorf("status --fleet: %w", err)
	}
	var fleet Fleet
	if err := json.Unmarshal(raw, &fleet); err != nil {
		return Fleet{}, fmt.Errorf("status --fleet: %s: %w", filepath.Join(dir, fleetJSONName), err)
	}
	return fleet, nil
}

// mergeFleetRow applies the later-generated_at-wins rule for one row,
// appending a Conflict whenever a key collides — win or lose, a collision
// is always reported, never silently absorbed.
func mergeFleetRow(byKey map[string]FleetProof, conflicts *[]FleetConflict, row FleetProof) {
	key := row.MergeKey()
	existing, present := byKey[key]
	if !present {
		byKey[key] = row
		return
	}
	if row.GeneratedAt.After(existing.GeneratedAt) {
		*conflicts = append(*conflicts, FleetConflict{Key: key, KeptBundle: row.SourceBundle, DroppedBundle: existing.SourceBundle, Reason: "later generated_at wins"})
		byKey[key] = row
		return
	}
	*conflicts = append(*conflicts, FleetConflict{Key: key, KeptBundle: existing.SourceBundle, DroppedBundle: row.SourceBundle, Reason: "later generated_at wins"})
}

func sortedFleetProofs(byKey map[string]FleetProof) []FleetProof {
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]FleetProof, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}

// fleetRowsForBundle builds one FleetProof per declared proof in ctx, using
// the SAME classification pipeline single-host `status` uses (getProofs ->
// buildInventory -> Classify), evaluated as of the bundle's own
// GeneratedAt/Epoch — a bundle is a snapshot, so its proofs' freshness is
// judged against the moment it was taken, not the moment it is merged.
func fleetRowsForBundle(ctx contextspec.Context, manifest bundle.Manifest, bundlePath string) []FleetProof {
	now := manifest.GeneratedAt
	epoch := manifest.Epoch

	var verdict string
	var expiringSoon int
	proofStates := getProofs(ctx, now, epoch, &verdict, &expiringSoon)
	stateByProof := make(map[string]ProofState, len(proofStates))
	for _, p := range proofStates {
		stateByProof[p.ID] = p
	}

	sources := &sourceFiles{drills: map[string]string{}, proofs: map[string]string{}}
	for _, p := range ctx.Proofs {
		sources.proofs[p.ID] = bundlePath
	}
	for _, d := range ctx.Drills {
		sources.drills[d.Proof] = bundlePath
	}
	inventory := buildInventory(ctx, sources, now, epoch)

	proofEpoch := make(map[string]string, len(ctx.Proofs))
	for _, p := range ctx.Proofs {
		if p.Epoch != "" {
			proofEpoch[p.ID] = p.Epoch
		}
	}

	rows := make([]FleetProof, 0, len(inventory))
	for _, row := range inventory {
		ps, hasState := stateByProof[row.Proof]
		c := Classify(ctx, row.Proof, row, ps, hasState)
		host := c.Scope.Host
		if host == "" {
			host = manifest.Host.Name
		}
		rowEpoch := epoch
		if e, ok := proofEpoch[row.Proof]; ok {
			rowEpoch = e
		}
		rows = append(rows, FleetProof{
			Proof: row.Proof, Layer: c.Layer, Category: c.Category, State: c.State,
			Level: row.Level, Why: row.ProofAge, Host: host, Epoch: rowEpoch,
			Scope: c.Scope, Artifact: c.Artifact, ContextFile: c.ContextFile,
			SourceBundle: bundlePath, GeneratedAt: manifest.GeneratedAt,
		})
	}
	return rows
}
