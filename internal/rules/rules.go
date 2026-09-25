// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package rules matches normalized change intents against a contextspec
// guard set and turns the result into engine.Findings. It is the "guard
// matching" and "zero-config lifeline rule" component named in
// docs/ARCHITECTURE.md §Module layout: engine.Decide and the Verdict/
// RiskClass/ProofStatus vocabulary stay in internal/engine as pure
// primitives; rules is where those primitives get applied to a real
// (Context, ChangeIntent) pair, including all proof/fact freshness lookups
// via contextspec's proofcheck component. rules performs no I/O — Context
// and ChangeIntent are already loaded by the caller.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/engine"
	"github.com/tannernicol/restoregap/internal/globmatch"
	"github.com/tannernicol/restoregap/internal/intent"
)

// Rule is a typed matcher: given one change intent and the active context,
// it reports every guard match with a typed result (no string-keyed
// attribute bags). GuardRule is the only Rule in phase 1 — the unified guard
// model (docs/ARCHITECTURE.md §5) means one generic matcher replaces
// Python's five separate guard/contract rule types; zero-config safety
// comes from evaluating GuardRule against contextspec.Default() rather than
// from a second, special-cased rule (see Evaluate).
type Rule interface {
	Match(ci intent.ChangeIntent, ctx contextspec.Context) []MatchResult
}

// MatchResult is one guard that matched a change intent, before proof
// checking or verdict computation.
type MatchResult struct {
	GuardID          string
	Kind             contextspec.GuardKind
	Resource         string
	Actions          []string
	Requires         contextspec.Requirement
	Enforcement      contextspec.Enforcement
	MaxProofAgeHours int
	RequireVerified  bool
	RequireBound     bool
}

// GuardRule matches a change intent against every declared guard using the
// AND-across-categories / OR-within-category semantics documented on
// contextspec.Matcher.
type GuardRule struct{}

// EvaluateOptions controls optional strictness for the pure evaluator.
// RequireCoverage is opt-in so existing hooks retain their established
// matching and exit behavior.
type EvaluateOptions struct {
	// PathAliases supplies resolved local alternatives without filesystem I/O.
	// Only matching uses these; proof verification uses original declarations.
	PathAliases     map[string]string
	RequireCoverage bool
}

// Match reports which of the context's guards apply to the change intent.
func (GuardRule) Match(ci intent.ChangeIntent, ctx contextspec.Context) []MatchResult {
	var results []MatchResult
	for _, g := range ctx.Guards {
		ok, resource := guardMatches(g, ci)
		if !ok {
			continue
		}
		results = append(results, MatchResult{
			GuardID:          g.ID,
			Kind:             g.Kind,
			Resource:         resource,
			Actions:          []string{string(ci.Action)},
			Requires:         g.Requires,
			Enforcement:      g.Enforcement,
			MaxProofAgeHours: g.MaxProofAgeHours,
			RequireVerified:  g.RequireVerified,
			RequireBound:     g.RequireBound,
		})
	}
	return results
}

// guardMatches applies every populated matcher category on g (ANDed) and
// returns the resource string best describing what matched, for display.
// dimension is one matcher category evaluated by guardMatches. present says
// whether the guard constrains this dimension at all; match evaluates it and
// returns the concrete thing that matched (used to name the resource).
type dimension struct {
	present bool
	match   func() (string, bool)
}

// guardMatches reports whether a guard applies to a change intent.
//
// Populated matcher categories are ANDed: every dimension the guard constrains
// must match, and any single failure disqualifies the guard outright. An empty
// category means "not constrained by this dimension" and is skipped. The
// returned resource is the first concrete value that matched, which is what
// findings are labelled with; it falls back to the intent's primary resource
// when the guard matched only on non-naming dimensions such as actions.
func guardMatches(g contextspec.Guard, ci intent.ChangeIntent) (matched bool, resource string) {
	m := g.Match
	dims := []dimension{
		{len(m.Paths) > 0, func() (string, bool) {
			return matchGuardPaths(m.Paths, ci)
		}},
		{len(m.Commands) > 0, func() (string, bool) {
			if ci.Command == "" || !globmatch.MatchCommandAny(m.Commands, ci.Command) {
				return "", false
			}
			return ci.Command, true
		}},
		{len(m.Packages) > 0, func() (string, bool) {
			return firstMatch(m.Packages, ci.Packages, globmatch.MatchAny)
		}},
		{len(m.Actions) > 0, func() (string, bool) {
			return "", containsString(m.Actions, string(ci.Action))
		}},
		{len(m.Actors) > 0, func() (string, bool) {
			return "", ci.Actor != "" && globmatch.MatchAny(m.Actors, ci.Actor)
		}},
		{len(m.ContextWindows) > 0, func() (string, bool) {
			return "", containsString(m.ContextWindows, ci.ContextWindow)
		}},
	}

	for _, d := range dims {
		if !d.present {
			continue
		}
		got, ok := d.match()
		if !ok {
			return false, ""
		}
		matched = true
		if resource == "" {
			resource = got
		}
	}

	if resource == "" {
		resource = primaryResource(ci)
	}
	return matched, resource
}

// matchGuardPaths reports whether any guard path matches the intent. Beyond
// the ordinary glob match (the intent names the guarded path, or a glob that
// covers it), a destructive-subtree action (delete_file, move_file) also
// matches a guard whose declared path lies BENEATH an intent path: deleting
// or moving a directory destroys everything under it, so a guard on
// /home/user/.ssh/id_ed25519 must fire on an intent to delete /home/user/.ssh
// even though that file is never named. The returned resource spells out why,
// so the finding explains a directory delete it refused.
func matchGuardPaths(guardPaths []string, ci intent.ChangeIntent) (string, bool) {
	intentPaths := ci.MatchPaths()
	if res, ok := firstMatch(guardPaths, intentPaths, globmatch.MatchPathAny); ok {
		return res, true
	}
	if !intent.DestroysSubtree(ci.Action) {
		return "", false
	}
	for _, ip := range intentPaths {
		for _, gp := range guardPaths {
			if globmatch.IsAncestor(ip, gp) {
				return fmt.Sprintf("%s contains guarded path %s", ip, gp), true
			}
		}
	}
	return "", false
}

// firstMatch returns the first candidate matching any pattern via the given
// "any" matcher function.
func firstMatch(patterns, candidates []string, anyFn func([]string, string) bool) (string, bool) {
	for _, c := range candidates {
		if anyFn(patterns, c) {
			return c, true
		}
	}
	return "", false
}

func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

func primaryResource(ci intent.ChangeIntent) string {
	if len(ci.Paths) > 0 {
		return ci.Paths[0]
	}
	if ci.Command != "" {
		return ci.Command
	}
	if len(ci.Packages) > 0 {
		return ci.Packages[0]
	}
	return ci.Actor
}

// Evaluate is the phase-1 rule registry: it runs every Rule against ctx and
// turns each match into a decided engine.Finding via engine.Decide, applying
// proof/fact freshness through contextspec. now is injected so callers can
// pin evaluation time (--as-of / tests) instead of using wall-clock time.
func Evaluate(intents []intent.ChangeIntent, ctx contextspec.Context, now time.Time) []engine.Finding {
	return EvaluateWithOptions(intents, ctx, now, EvaluateOptions{})
}

// EvaluateWithOptions evaluates intents using the existing guard semantics
// and, when RequireCoverage is set, checks every addressed resource in each
// intent independently. A match for one path never covers another path; the
// same rule applies to target paths, packages, and commands.
func EvaluateWithOptions(intents []intent.ChangeIntent, ctx contextspec.Context, now time.Time, options EvaluateOptions) []engine.Finding {
	var findings []engine.Finding
	matchCtx := matchingContext(ctx, options.PathAliases)
	dependencyConflicts := recoveryDependencyConflicts(matchCtx, intents)
	for _, ci := range intents {
		matches := GuardRule{}.Match(ci, matchCtx)
		for _, m := range matches {
			findings = append(findings, decide(m, ctx, now, dependencyConflicts))
		}
		// The advisory heuristic layer only speaks when no declared guard
		// covered this intent: declared context tightens reporting, never
		// silences it (a guard that matched already said something better).
		if len(matches) == 0 && (!options.RequireCoverage || strictIntentClassifiable(ci)) {
			for _, m := range (HeuristicRule{}).Match(ci, ctx) {
				findings = append(findings, heuristicFinding(m))
			}
		}
		if options.RequireCoverage {
			findings = append(findings, strictCoverageFindings(ci, matchCtx)...)
		}
	}
	return findings
}

type coverageKind string

const (
	coveragePath    coverageKind = "path"
	coveragePackage coverageKind = "package"
	coverageCommand coverageKind = "command"
)

type addressedResource struct {
	kind coverageKind
	name string
}

func strictCoverageFindings(ci intent.ChangeIntent, ctx contextspec.Context) []engine.Finding {
	resources := addressedResources(ci)
	var findings []engine.Finding
	if !strictIntentClassifiable(ci) {
		findings = append(findings, coverageFinding(ci, "intent", "intent is empty or has an unknown action; strict coverage cannot classify it"))
	}
	for _, resource := range resources {
		covered := false
		for _, guard := range ctx.Guards {
			if guardCoversResource(guard, ci, resource) {
				covered = true
				break
			}
		}
		if !covered {
			findings = append(findings, coverageFinding(ci, resource.name,
				fmt.Sprintf("strict coverage: no declared guard applies to %s %q for action %q", resource.kind, resource.name, ci.Action)))
		}
	}
	return findings
}

func strictIntentClassifiable(ci intent.ChangeIntent) bool {
	if !hasNonBlank(ci.AllPaths()) && !hasNonBlank(ci.Packages) && !nonBlank(ci.Command) {
		return false
	}
	switch ci.Action {
	case intent.ActionDeleteFile, intent.ActionModifyFile, intent.ActionMoveFile:
		return hasNonBlank(ci.AllPaths())
	case intent.ActionPackageUpdate, intent.ActionInstallPkg, intent.ActionRemovePkg:
		return hasNonBlank(ci.Packages)
	case intent.ActionRunCommand:
		return nonBlank(ci.Command)
	case intent.ActionSystemUpdate:
		return true
	default:
		return false
	}
}

func addressedResources(ci intent.ChangeIntent) []addressedResource {
	var out []addressedResource
	seen := make(map[string]bool)
	for _, path := range ci.AllPaths() {
		key := string(coveragePath) + "\x00" + path
		if nonBlank(path) && !seen[key] {
			seen[key] = true
			out = append(out, addressedResource{kind: coveragePath, name: path})
		}
	}
	for _, pkg := range ci.Packages {
		key := string(coveragePackage) + "\x00" + pkg
		if nonBlank(pkg) && !seen[key] {
			seen[key] = true
			out = append(out, addressedResource{kind: coveragePackage, name: pkg})
		}
	}
	if nonBlank(ci.Command) {
		out = append(out, addressedResource{kind: coverageCommand, name: ci.Command})
	}
	return out
}

func guardCoversResource(g contextspec.Guard, ci intent.ChangeIntent, resource addressedResource) bool {
	// A guard is applicable to a resource when it explicitly constrains that
	// resource dimension, or when it has no path/package/command dimensions at
	// all. Other populated resource dimensions remain ANDed context for the
	// isolated resource value.
	if !resourceDimensionApplicable(g.Match, resource.kind) {
		return false
	}
	// Coverage is explicit for the proposed path itself. The ordinary matcher
	// also accepts a descendant guard for a destructive parent delete so that
	// the child proof still fires; that implicit subtree match cannot certify
	// the parent resource's own coverage.
	if !pathResourceCovered(g.Match, resource) {
		return false
	}
	isolated := isolateResource(ci, resource)
	matched, _ := guardMatches(g, isolated)
	return matched
}

func resourceDimensionApplicable(m contextspec.Matcher, kind coverageKind) bool {
	if len(m.Paths) == 0 && len(m.Packages) == 0 && len(m.Commands) == 0 {
		return true
	}
	switch kind {
	case coveragePath:
		return len(m.Paths) > 0
	case coveragePackage:
		return len(m.Packages) > 0
	case coverageCommand:
		return len(m.Commands) > 0
	default:
		return false
	}
}

func pathResourceCovered(m contextspec.Matcher, resource addressedResource) bool {
	return resource.kind != coveragePath || len(m.Paths) == 0 || globmatch.MatchPathAny(m.Paths, resource.name)
}

func isolateResource(ci intent.ChangeIntent, resource addressedResource) intent.ChangeIntent {
	isolated := ci
	switch resource.kind {
	case coveragePath:
		isolated.Paths = []string{resource.name}
		isolated.TargetPaths = nil
	case coveragePackage:
		isolated.Packages = []string{resource.name}
	case coverageCommand:
		isolated.Command = resource.name
	}
	return isolated
}

func nonBlank(value string) bool {
	return strings.TrimSpace(value) != ""
}

func hasNonBlank(values []string) bool {
	for _, value := range values {
		if nonBlank(value) {
			return true
		}
	}
	return false
}

func coverageFinding(ci intent.ChangeIntent, resource, detail string) engine.Finding {
	sum := sha256.Sum256([]byte("coverage|" + string(ci.Action) + "|" + resource))
	return engine.Finding{
		ID:               "coverage_" + hex.EncodeToString(sum[:])[:24],
		GuardID:          "coverage",
		Kind:             "coverage",
		Resource:         resource,
		Actions:          []string{string(ci.Action)},
		RiskClass:        engine.RiskCannotProveSafe,
		ProofStatus:      engine.ProofUnknown,
		Verdict:          engine.VerdictBlock,
		Title:            "Restore Gap strict coverage could not classify every addressed resource.",
		Proof:            detail,
		RequiredNextStep: fmt.Sprintf("Declare or review a guard that explicitly covers %q for proposed action %q, then review the resulting coverage change.", resource, ci.Action),
	}
}
