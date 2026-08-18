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
}

// GuardRule matches a change intent against every declared guard using the
// AND-across-categories / OR-within-category semantics documented on
// contextspec.Matcher.
type GuardRule struct{}

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
			return firstMatch(m.Paths, ci.AllPaths(), globmatch.MatchPathAny)
		}},
		{len(m.Commands) > 0, func() (string, bool) {
			if ci.Command == "" || !globmatch.MatchAny(m.Commands, ci.Command) {
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
	var findings []engine.Finding
	for _, ci := range intents {
		matches := GuardRule{}.Match(ci, ctx)
		for _, m := range matches {
			findings = append(findings, decide(m, ctx, now))
		}
		// The advisory heuristic layer only speaks when no declared guard
		// covered this intent: declared context tightens reporting, never
		// silences it (a guard that matched already said something better).
		if len(matches) == 0 {
			for _, m := range (HeuristicRule{}).Match(ci, ctx) {
				findings = append(findings, heuristicFinding(m))
			}
		}
	}
	return findings
}
