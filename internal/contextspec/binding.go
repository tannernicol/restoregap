// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package contextspec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// NormalizeDependencies returns a copy with duplicate entries removed and
// each explicit dependency list sorted. Dependency order is not semantic, so
// this keeps recipe and captured-dependency comparisons stable.
func NormalizeDependencies(in Dependencies) Dependencies {
	return Dependencies{
		Paths:    normalizedStrings(in.Paths),
		Commands: normalizedStrings(in.Commands),
		Packages: normalizedStrings(in.Packages),
	}
}

func normalizedStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, value := range in {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// DependenciesEqual compares normalized explicit recovery dependencies.
func DependenciesEqual(a, b Dependencies) bool {
	na, nb := NormalizeDependencies(a), NormalizeDependencies(b)
	return string(canonicalJSON(na)) == string(canonicalJSON(nb))
}

// RecipeDigest is the stable digest of every declared input that changes what
// a full drill proves: artifact/source/recovery and pin commands, typed
// checks, budgets, and explicit recovery dependencies. It does not inspect
// target systems or infer dependencies.
func RecipeDigest(drill Drill) string {
	recipe := struct {
		Artifact       string       `json:"artifact"`
		RecoverySource string       `json:"recovery_source"`
		Recover        string       `json:"recover"`
		PinCheck       string       `json:"pin_check"`
		Validate       []DrillCheck `json:"validate"`
		Budgets        DrillBudgets `json:"budgets"`
		Dependencies   Dependencies `json:"dependencies"`
	}{
		Artifact: drill.Artifact, RecoverySource: drill.RecoverySource,
		Recover: drill.Recover, PinCheck: drill.PinCheck,
		Validate: drill.Validate, Budgets: drill.Budgets,
		Dependencies: NormalizeDependencies(drill.Dependencies),
	}
	return digest(canonicalJSON(recipe))
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		// All inputs here are closed typed values and therefore marshalable. A
		// panic is preferable to silently issuing an unbound proof if that
		// invariant is ever broken by a future type change.
		panic(err)
	}
	return data
}
