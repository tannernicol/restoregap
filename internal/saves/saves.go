// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package saves reconstructs, from the ledger, the times a gate actually
// changed an outcome.
//
// The ledger records every evaluation, and a gate that runs on a timer produces
// thousands of them. Counting raw blocks would answer "how noisy is this?" —
// not "did it ever save me?". So evaluations are coalesced per (guard,
// resource) into episodes, and each episode is classified by how it ENDED:
//
//	SAVE          blocked, then later passed — the gap was closed rather than
//	              bypassed. This is the only outcome that demonstrates value.
//	ACCEPTED RISK blocked, then overridden — the owner chose to proceed. Worth
//	              counting honestly and separately; a tool that hid these would
//	              be marking its own homework.
//	OPEN BLOCK    blocked and never resolved either way.
//
// Repeated identical checks never inflate the count: one gap re-detected fifty
// times is one episode, not fifty saves.
package saves

import (
	"sort"
	"time"

	"github.com/tannernicol/restoregap/internal/ledger"
)

// Outcome classifies how an episode ended.
type Outcome string

// The Outcome values.
const (
	OutcomeSave         Outcome = "save"
	OutcomeAcceptedRisk Outcome = "accepted-risk"
	OutcomeOpenBlock    Outcome = "open-block"
)

// Episode is one (guard, resource) story across the ledger window.
type Episode struct {
	GuardID     string
	Resource    string
	Outcome     Outcome
	FirstBlock  time.Time
	LastBlock   time.Time
	ResolvedAt  time.Time // pass or override time, zero when still open
	Evaluations int
	RiskClass   string
	ProofStatus string
	ApprovedBy  string // set for accepted risk
	Reason      string // set for accepted risk
}

// Report is the aggregate view.
type Report struct {
	Episodes       []Episode
	Saves          int
	AcceptedRisks  int
	OpenBlocks     int
	RawEvaluations int
	RawBlocks      int
	WindowStart    time.Time
	WindowEnd      time.Time
}

type key struct{ guard, resource string }

// Build analyses ledger entries into a Report. Entries are assumed to be in
// ledger order; they are sorted by time defensively so a concatenated or
// out-of-order file still analyses correctly.
// builder accumulates episodes while walking the ledger in time order.
type builder struct {
	rep Report
	acc map[key]*Episode
	// byFinding maps a finding id to its episode, so an override — which
	// references only a finding id — can be attributed back to its
	// guard/resource.
	byFinding map[string]*Episode
}

// episodeFor returns the episode for one guard/resource pair, creating it on
// first sight.
func (b *builder) episodeFor(guardID, resource string) *Episode {
	k := key{guardID, resource}
	ep, ok := b.acc[k]
	if !ok {
		ep = &Episode{GuardID: guardID, Resource: resource}
		b.acc[k] = ep
	}
	return ep
}

// applyFinding folds one finding into its episode.
func (b *builder) applyFinding(f ledger.FindingRecord, at time.Time) {
	// One evaluation is one FINDING, not one decision entry: a single
	// preflight evaluates many guards, and counting entries would understate
	// the work while overstating quiet runs.
	b.rep.RawEvaluations++
	ep := b.episodeFor(f.GuardID, f.Resource)
	ep.Evaluations++
	b.byFinding[f.FindingID] = ep

	if f.Verdict == "block" {
		b.rep.RawBlocks++
		if ep.FirstBlock.IsZero() {
			ep.FirstBlock = at
		}
		ep.LastBlock = at
		ep.RiskClass = f.RiskClass
		ep.ProofStatus = f.ProofStatus
		// A block after a resolution reopens the episode: the gap came back
		// and is open again until something closes it.
		ep.Outcome = OutcomeOpenBlock
		ep.ResolvedAt = time.Time{}
		return
	}

	// Anything that is not a block ends the blocking state — pass outright, or
	// warn (the guard still matches but no longer stops the change). Both mean
	// the gap that was blocking got closed. It only counts as a save if this
	// episode had actually been blocked: a guard that never blocked saved
	// nothing.
	if !ep.FirstBlock.IsZero() && ep.Outcome == OutcomeOpenBlock {
		ep.Outcome = OutcomeSave
		ep.ResolvedAt = at
	}
}

// applyOverride attributes an accepted risk to the episode that was blocked.
func (b *builder) applyOverride(o *ledger.OverridePayload, at time.Time) {
	ep, ok := b.byFinding[o.FindingID]
	if !ok || ep.FirstBlock.IsZero() {
		return
	}
	ep.Outcome = OutcomeAcceptedRisk
	ep.ResolvedAt = at
	ep.ApprovedBy = o.ApprovedBy
	ep.Reason = o.Reason
}

// finish materialises the accumulated episodes into the report, dropping any
// guard that never actually blocked.
func (b *builder) finish() Report {
	for _, ep := range b.acc {
		if ep.FirstBlock.IsZero() {
			continue // never blocked: not an episode worth reporting
		}
		b.rep.Episodes = append(b.rep.Episodes, *ep)
		switch ep.Outcome {
		case OutcomeSave:
			b.rep.Saves++
		case OutcomeAcceptedRisk:
			b.rep.AcceptedRisks++
		default:
			b.rep.OpenBlocks++
		}
	}
	sort.SliceStable(b.rep.Episodes, func(i, j int) bool {
		if b.rep.Episodes[i].Outcome != b.rep.Episodes[j].Outcome {
			return b.rep.Episodes[i].Outcome < b.rep.Episodes[j].Outcome
		}
		return b.rep.Episodes[i].LastBlock.After(b.rep.Episodes[j].LastBlock)
	})
	return b.rep
}

// Build folds a ledger into the saves report.
func Build(entries []ledger.Entry) Report {
	sorted := make([]ledger.Entry, len(entries))
	copy(sorted, entries)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].CreatedAt.Before(sorted[j].CreatedAt) })

	b := &builder{acc: map[key]*Episode{}, byFinding: map[string]*Episode{}}
	for _, e := range sorted {
		if b.rep.WindowStart.IsZero() || e.CreatedAt.Before(b.rep.WindowStart) {
			b.rep.WindowStart = e.CreatedAt
		}
		if e.CreatedAt.After(b.rep.WindowEnd) {
			b.rep.WindowEnd = e.CreatedAt
		}

		switch e.EntryType {
		case ledger.EntryDecision:
			if e.Payload.Decision == nil {
				continue
			}
			for _, f := range e.Payload.Decision.Findings {
				b.applyFinding(f, e.CreatedAt)
			}
		case ledger.EntryOverride:
			if e.Payload.Override == nil {
				continue
			}
			b.applyOverride(e.Payload.Override, e.CreatedAt)
		}
	}
	return b.finish()
}
