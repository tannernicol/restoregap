// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package migrate upgrades a context file to the schema version this
// restoregap binary understands (docs/SCHEMA.md §Versioning policy): a
// chain of self-contained per-version transforms (currently one hop, v1 ->
// v2 == contextspec.CurrentVersion), a `.bak.<UTC>` of the original bytes
// written before the first byte of the real file changes, and a --dry-run
// mode that performs every read/transform step but writes nothing.
//
// v1 is section 5's name for "no version field, or version: 1" — the
// pre-Go-rewrite Python schema docs/ARCHITECTURE.md §5 describes as
// change_guards / update_guards / command_guards / assurance_contracts /
// lifeline_artifacts collapsing into one unified `guards:` list. No v1
// fixture or the original Python source ships in this repo to check the
// transform field-for-field against, so upgradeV1ToV2 is a best-effort
// reconstruction from that doc's own description — flagged here for an
// owner's review rather than presented as verified.
package migrate

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// Result summarizes one File call.
type Result struct {
	Path        string
	FromVersion int
	ToVersion   int
	// Changed is true when the document actually needed upgrading. False
	// means it was already at contextspec.CurrentVersion — File is a no-op,
	// nothing is read back out, no backup is written even outside --dry-run.
	Changed bool
	DryRun  bool
	// BackupPath is where the pre-upgrade bytes were copied. Empty when
	// DryRun (nothing is written) or when Changed is false.
	BackupPath string
}

// step is one version's upgrade: transform a decoded document from its
// declared version to the next one. Registered in steps, keyed by the
// version it upgrades FROM.
type step func(map[string]any) map[string]any

var steps = map[int]step{
	1: upgradeV1ToV2,
}

// File upgrades path in place, version by version, until it reaches
// contextspec.CurrentVersion. A document already at CurrentVersion is left
// untouched (Result.Changed == false). A document declaring a version newer
// than CurrentVersion is refused with *contextspec.UnsupportedVersionError
// — migrate does not know how to go backwards, and refusing early here
// matches the same refusal every other command already gives (docs/
// SCHEMA.md §Versioning policy).
func File(path string, dryRun bool) (Result, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return Result{}, fmt.Errorf("migrate: %s: %w", path, err)
	}

	version := contextspec.PeekVersion(original)
	if version > contextspec.CurrentVersion {
		return Result{}, &contextspec.UnsupportedVersionError{Got: version}
	}
	if version == 0 {
		version = 1 // undeclared version is the oldest schema this chain knows
	}
	res := Result{Path: path, FromVersion: version, ToVersion: version, DryRun: dryRun}
	if version == contextspec.CurrentVersion {
		return res, nil
	}

	var doc map[string]any
	if err := yaml.Unmarshal(original, &doc); err != nil {
		return Result{}, fmt.Errorf("migrate: %s: invalid YAML: %w", path, err)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	for v := version; v < contextspec.CurrentVersion; v++ {
		up, ok := steps[v]
		if !ok {
			return Result{}, fmt.Errorf("migrate: %s: no upgrade step registered from version %d to %d", path, v, v+1)
		}
		doc = up(doc)
	}
	res.ToVersion = contextspec.CurrentVersion
	res.Changed = true

	out, err := yaml.Marshal(doc)
	if err != nil {
		return Result{}, fmt.Errorf("migrate: %s: encoding upgraded document: %w", path, err)
	}
	if dryRun {
		return res, nil
	}

	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode()
	}
	backup := path + ".bak." + time.Now().UTC().Format("20060102T150405Z")
	if err := os.WriteFile(backup, original, mode); err != nil {
		return Result{}, fmt.Errorf("migrate: %s: writing backup %s: %w", path, backup, err)
	}
	res.BackupPath = backup
	if err := os.WriteFile(path, out, mode); err != nil {
		return Result{}, fmt.Errorf("migrate: %s: writing upgraded document: %w", path, err)
	}
	return res, nil
}

// legacyGuardLists maps a v1 top-level key to the v2 guard `kind` its
// entries default to (an entry's own `kind:`, if it declares one, wins —
// see upgradeLegacyGuard). This is the one assumption this package's own
// doc comment flags: docs/ARCHITECTURE.md §5 names these five Python-era
// lists as the ones that collapse into `guards:`, but does not spell out
// their per-field shape.
var legacyGuardLists = map[string]string{
	"change_guards":       string(contextspec.GuardKindGuard),
	"update_guards":       string(contextspec.GuardKindGuard),
	"command_guards":      string(contextspec.GuardKindGuard),
	"assurance_contracts": string(contextspec.GuardKindGuard),
	"lifeline_artifacts":  string(contextspec.GuardKindLifeline),
}

// legacyMatchFields are the v1 flat matcher fields upgradeLegacyGuard nests
// under the v2 `match:` block, unchanged in name (docs/ARCHITECTURE.md §5's
// sketch keeps every matcher field name identical, only the nesting moved).
var legacyMatchFields = []string{"paths", "commands", "packages", "actions", "actors", "context_windows"}

// upgradeV1ToV2 folds every legacy guard-shaped list into one `guards:`
// list, nests each entry's flat matcher/requirement fields, and stamps the
// document version 2. facts/proofs/drills pass through unchanged — v1 and
// v2 declare them "unchanged in spirit" (docs/ARCHITECTURE.md §5).
func upgradeV1ToV2(doc map[string]any) map[string]any {
	guards, _ := doc["guards"].([]any)
	for key, kind := range legacyGuardLists {
		items, _ := doc[key].([]any)
		for _, raw := range items {
			if entry, ok := raw.(map[string]any); ok {
				guards = append(guards, upgradeLegacyGuard(entry, kind))
			}
		}
		delete(doc, key)
	}
	if len(guards) > 0 {
		doc["guards"] = guards
	}
	doc["version"] = contextspec.CurrentVersion
	return doc
}

// upgradeLegacyGuard nests one v1 flat guard entry's matcher fields under
// `match:` and its flat requirement fields under `requires:`, and fills in
// `kind` from defaultKind unless the entry already declares its own.
func upgradeLegacyGuard(entry map[string]any, defaultKind string) map[string]any {
	match := map[string]any{}
	for _, f := range legacyMatchFields {
		if v, ok := entry[f]; ok {
			match[f] = v
			delete(entry, f)
		}
	}
	if len(match) > 0 {
		entry["match"] = match
	}

	requires := map[string]any{}
	if v, ok := entry["requires_proofs"]; ok {
		requires["proofs"] = v
		delete(entry, "requires_proofs")
	}
	if v, ok := entry["requires_facts"]; ok {
		requires["facts"] = v
		delete(entry, "requires_facts")
	}
	if len(requires) > 0 {
		entry["requires"] = requires
	}

	if kind, ok := entry["kind"].(string); !ok || kind == "" {
		entry["kind"] = defaultKind
	}
	return entry
}
