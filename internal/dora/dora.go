// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package dora computes recovery's four keys from the ledger.
//
// The DORA four keys measure how a team ships. The same four questions, asked
// of recovery instead of delivery, are the numbers that say whether a recovery
// posture is real: how often is it actually exercised, how long does a restore
// take, how often does an exercise fail, and how long does a broken lifeline
// stay broken. They are computed from the ledger the gate already writes —
// measured from the gate, never self-reported by the thing being measured.
//
// Every metric here is a PROXY and says so:
//
//   - DrillFrequency  — verified drill entries per day over the window. The
//     delivery analogue is deployment frequency; a recovery you never
//     rehearse is a claim, not a capability.
//   - TimeToRestore   — median RTO of the drills that actually restored
//     something (RTOMs > 0). The analogue is lead time: how long from
//     "we need it" to "we have it".
//   - DrillFailureRate — failed drills / all drills. The analogue is change
//     failure rate.
//   - LifelineMTTR    — median seconds from a lifeline going bad (a blocking
//     decision or a failed drill naming it) to the next good signal for the
//     SAME id. The analogue is time to restore service; here it measures how
//     long a known-broken lifeline is tolerated.
//
// A window with no data reports zero counts and nil medians rather than a
// misleading 0s — "we have not measured this" and "this takes no time" are
// different answers.
package dora

import (
	"sort"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/ledger"
)

// Metrics is the computed window.
type Metrics struct {
	WindowDays int
	From       time.Time
	To         time.Time

	Drills       int
	DrillsFailed int
	// DrillFrequency is verified drills per day.
	DrillFrequency float64
	// DrillFailureRate is in [0,1]; nil when no drills ran.
	DrillFailureRate *float64
	// TimeToRestore is the median restore duration; nil when nothing restored.
	TimeToRestore *time.Duration
	// LifelineMTTR is the median broken→good gap; nil when nothing broke, or
	// when everything that broke is still broken (which Unrecovered reports).
	LifelineMTTR *time.Duration
	// Unrecovered names lifelines that went bad in the window and have no
	// later good signal — deliberately separate from the median, because an
	// unrecovered lifeline must not quietly improve the average.
	Unrecovered []string
}

// Compute reduces entries to the four keys over the trailing window ending at
// now. Entries outside the window are still read for the MTTR search, so a
// recovery that lands just after the window is not counted as unrecovered.
func Compute(entries []ledger.Entry, window time.Duration, now time.Time) Metrics {
	from := now.Add(-window)
	m := Metrics{WindowDays: int(window.Hours() / 24), From: from, To: now}

	var restores []time.Duration
	for _, e := range entries {
		if e.EntryType != ledger.EntryDrill || e.Payload.Drill == nil || !inWindow(e.CreatedAt, from, now) {
			continue
		}
		d := e.Payload.Drill
		m.Drills++
		if !d.Verified {
			m.DrillsFailed++
		}
		// Only a real drill restores something. A pin_check re-verifies a
		// recorded pin and finishes in milliseconds; averaging those into
		// "time to restore" would report a recovery posture nobody has.
		if d.Verified && d.Mode != "pin_check" && d.RTOMs > 0 {
			restores = append(restores, time.Duration(d.RTOMs)*time.Millisecond)
		}
	}
	if days := window.Hours() / 24; days > 0 {
		m.DrillFrequency = float64(m.Drills) / days
	}
	if m.Drills > 0 {
		rate := float64(m.DrillsFailed) / float64(m.Drills)
		m.DrillFailureRate = &rate
	}
	if len(restores) > 0 {
		med := medianDuration(restores)
		m.TimeToRestore = &med
	}

	mttr, unrecovered := lifelineMTTR(entries, from, now)
	m.LifelineMTTR, m.Unrecovered = mttr, unrecovered
	return m
}

// allGuardsRecovered is the pseudo-id a passing decision emits: it clears
// every guard currently counted as broken (see collectSignals).
const allGuardsRecovered = "\x00all-guards"

// signal is one good/bad observation about a lifeline at a point in time.
type signal struct {
	when time.Time
	id   string
	good bool
}

// lifelineMTTR pairs each bad signal with the next good one for the same
// lifeline. Signals are read over the whole ledger, but only gaps that START
// inside the window are counted.
func lifelineMTTR(entries []ledger.Entry, from, to time.Time) (*time.Duration, []string) {
	signals := collectSignals(entries)
	sort.Slice(signals, func(i, j int) bool { return signals[i].when.Before(signals[j].when) })

	var gaps []time.Duration
	unrecoveredSet := map[string]bool{}
	broken := map[string]time.Time{} // id -> when it went bad (first bad since last good)

	for _, s := range signals {
		if !s.good {
			if _, already := broken[s.id]; !already {
				broken[s.id] = s.when
			}
			continue
		}
		if s.id == allGuardsRecovered {
			for id, start := range broken {
				if !strings.HasPrefix(id, "guard:") {
					continue
				}
				delete(broken, id)
				if inWindow(start, from, to) {
					gaps = append(gaps, s.when.Sub(start))
				}
			}
			continue
		}
		start, wasBroken := broken[s.id]
		if !wasBroken {
			continue
		}
		delete(broken, s.id)
		if inWindow(start, from, to) {
			gaps = append(gaps, s.when.Sub(start))
		}
	}
	for id, start := range broken {
		if inWindow(start, from, to) {
			unrecoveredSet[id] = true
		}
	}
	unrecovered := make([]string, 0, len(unrecoveredSet))
	for id := range unrecoveredSet {
		unrecovered = append(unrecovered, displayID(id))
	}
	sort.Strings(unrecovered)

	if len(gaps) == 0 {
		return nil, unrecovered
	}
	med := medianDuration(gaps)
	return &med, unrecovered
}

// collectSignals reads both sources of lifeline health: drill entries (a drill
// is the strongest signal — it either restored or it did not) and blocking
// decisions (a guard refused, naming the finding it refused for).
//
// Proof ids and guard ids are DIFFERENT namespaces, so they are prefixed here.
// Without that, a passing drill for proof "x" would silently "recover" a
// blocking guard also called "x", and the MTTR would measure a coincidence.
func collectSignals(entries []ledger.Entry) []signal {
	var out []signal
	for _, e := range entries {
		switch {
		case e.EntryType == ledger.EntryDrill && e.Payload.Drill != nil:
			out = append(out, signal{when: e.CreatedAt, id: "proof:" + e.Payload.Drill.ProofID, good: e.Payload.Drill.Verified})
		case e.EntryType == ledger.EntryDecision && e.Payload.Decision != nil:
			d := e.Payload.Decision
			// A broken gate says nothing about the lifeline — it says the
			// gate could not look. Counting it as a lifeline failure would
			// blame the wrong thing (gauntlet-v2 lesson: cannot-run != failed).
			if d.GateState == "broken" {
				continue
			}
			for _, f := range d.Findings {
				if f.GuardID == "" {
					continue
				}
				out = append(out, signal{when: e.CreatedAt, id: "guard:" + f.GuardID, good: d.Verdict == "pass"})
			}
			// A PASSING decision names no findings at all, so a guard that
			// blocked once could never clear and every such guard looked
			// "still broken" forever — "not re-evaluated" wearing the costume
			// of "broken". A pass means nothing blocked, so it is a good
			// signal for every guard currently counted as bad.
			if d.Verdict == "pass" {
				out = append(out, signal{when: e.CreatedAt, id: allGuardsRecovered, good: true})
			}
		}
	}
	return out
}

// displayID turns the internal namespaced id back into something a human
// reads: "proof:x" -> "x (proof)". The namespace is kept — which kind of
// declaration is still broken is part of the answer.
func displayID(id string) string {
	if kind, name, ok := strings.Cut(id, ":"); ok {
		return name + " (" + kind + ")"
	}
	return id
}

func inWindow(t, from, to time.Time) bool {
	return !t.Before(from) && !t.After(to)
}

func medianDuration(values []time.Duration) time.Duration {
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	n := len(values)
	if n%2 == 1 {
		return values[n/2]
	}
	return (values[n/2-1] + values[n/2]) / 2
}
