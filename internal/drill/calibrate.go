// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package drill

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/ledger"
)

// DefaultMinRuns is how many verified drill runs a proof needs before
// Calibrate proposes a budget for it at all — the drill --calibrate
// --min-runs default. A budget derived from fewer samples is a guess
// wearing a measurement's clothes.
const DefaultMinRuns = 3

// DefaultMargin is the safety multiplier Calibrate applies to the observed
// RTO p95 — the drill --calibrate --margin default.
const DefaultMargin = 4.0

// rtoFloor is the absolute minimum a proposed RTO budget is ever allowed to
// be, regardless of how fast a drill runs: a sub-second drill multiplied by
// even a generous margin can still land under a second, which would flake
// on any contended disk.
const rtoFloor = 30 * time.Second

// rpoFloor is the absolute amount added on top of the RPO p95 (rather than
// multiplied) — RPO is a property of the backup schedule, not of drill
// duration, so its floor is a flat buffer, not a scaled one.
const rpoFloor = 6 * time.Hour

// rpoMargin is the multiplier Calibrate applies to the observed RPO p95.
const rpoMargin = 1.5

// CalibrateOptions configures Calibrate.
type CalibrateOptions struct {
	// MinRuns is the minimum number of verified runs a drill needs (for RTO,
	// and independently for RPO) before a budget is proposed at all.
	// <= 0 defaults to DefaultMinRuns.
	MinRuns int
	// Margin is the safety multiplier applied to the observed RTO p95.
	// <= 0 defaults to DefaultMargin.
	Margin float64
}

func (o CalibrateOptions) resolved() CalibrateOptions {
	if o.MinRuns <= 0 {
		o.MinRuns = DefaultMinRuns
	}
	if o.Margin <= 0 {
		o.Margin = DefaultMargin
	}
	return o
}

// CalibrateResult is one drill's calibration outcome.
type CalibrateResult struct {
	Proof string

	// Skip is non-empty when this drill has too few verified runs for a
	// budget proposal — every field below is zero-valued in that case.
	Skip string

	RunCount int

	DeclaredRTO    time.Duration // 0 means no rto budget is currently declared
	ObservedRTOP95 time.Duration
	ProposedRTO    time.Duration
	// RTODegenerate is true when fewer than 20 samples were available, so
	// p95 (nearest-rank) equals the max sample — correct and intended, not
	// a bug, but worth surfacing.
	RTODegenerate bool

	// HasRPO is true when at least MinRuns runs measured rpo_ms, so an RPO
	// proposal was possible. RPO fields below are zero-valued otherwise.
	HasRPO         bool
	DeclaredRPO    time.Duration
	ObservedRPOP95 time.Duration
	ProposedRPO    time.Duration

	// Warnings are budget-sanity findings against the DECLARED budget
	// (headroom too loose to ever fail, or too tight to avoid flaking),
	// printed even without --apply.
	Warnings []string
}

// Calibrate derives proposed RTO/RPO budgets for every declared drill from
// its verified telemetry in entries (ledger entries of type "drill" with
// mode "drill" and verified true, matched by proof_id). It never reads a
// ledger itself — entries is read once by the caller via the existing
// ledger.ReadAll path, so there is exactly one ledger parser in this
// program.
func Calibrate(drills []contextspec.Drill, entries []ledger.Entry, opts CalibrateOptions) []CalibrateResult {
	opts = opts.resolved()
	rtoByProof, rpoByProof := collectCalibrateSamples(entries)

	results := make([]CalibrateResult, 0, len(drills))
	for _, d := range drills {
		results = append(results, calibrateOne(d, rtoByProof[d.Proof], rpoByProof[d.Proof], opts))
	}
	return results
}

func collectCalibrateSamples(entries []ledger.Entry) (rto, rpo map[string][]int64) {
	rto = map[string][]int64{}
	rpo = map[string][]int64{}
	for _, e := range entries {
		if e.EntryType != ledger.EntryDrill || e.Payload.Drill == nil {
			continue
		}
		p := e.Payload.Drill
		if p.Mode != "drill" || !p.Verified {
			continue
		}
		rto[p.ProofID] = append(rto[p.ProofID], p.RTOMs)
		if p.RPOMs != nil {
			rpo[p.ProofID] = append(rpo[p.ProofID], *p.RPOMs)
		}
	}
	return rto, rpo
}

func calibrateOne(d contextspec.Drill, rtoSamplesMs, rpoSamplesMs []int64, opts CalibrateOptions) CalibrateResult {
	if len(rtoSamplesMs) < opts.MinRuns {
		return CalibrateResult{
			Proof: d.Proof,
			Skip: fmt.Sprintf("only %d verified run(s), need %d — a budget from one sample is a guess wearing a measurement's clothes.",
				len(rtoSamplesMs), opts.MinRuns),
		}
	}

	p95ms := percentile95(rtoSamplesMs)
	p95d := time.Duration(p95ms) * time.Millisecond
	proposedRTO := roundUpFriendlyRTO(maxDuration(scaleDuration(p95d, opts.Margin), rtoFloor))

	res := CalibrateResult{
		Proof:          d.Proof,
		RunCount:       len(rtoSamplesMs),
		DeclaredRTO:    d.Budgets.RTO,
		ObservedRTOP95: p95d,
		ProposedRTO:    proposedRTO,
		RTODegenerate:  len(rtoSamplesMs) < 20,
		Warnings:       headroomWarnings(d.Budgets.RTO, p95d),
	}

	if len(rpoSamplesMs) >= opts.MinRuns {
		rpo95ms := percentile95(rpoSamplesMs)
		rpo95d := time.Duration(rpo95ms) * time.Millisecond
		proposedRPO := roundUpToHour(maxDuration(scaleDuration(rpo95d, rpoMargin), rpo95d+rpoFloor))
		res.HasRPO = true
		res.DeclaredRPO = d.Budgets.RPO
		res.ObservedRPOP95 = rpo95d
		res.ProposedRPO = proposedRPO
	}

	return res
}

// headroomWarnings sanity-checks a currently-declared RTO budget against
// what was actually observed — the finding drill --lint can't make because
// it never touches ledger telemetry, so it lives here instead, printed even
// without --apply.
func headroomWarnings(declared, p95 time.Duration) []string {
	if declared <= 0 || p95 <= 0 {
		return nil
	}
	ratio := float64(declared) / float64(p95)
	switch {
	case ratio > 10:
		return []string{fmt.Sprintf("budget %s is %.0fx the worst observed run — it cannot fail", declared, ratio)}
	case ratio < 1.5:
		return []string{fmt.Sprintf("budget %s is only %.1fx observed p95 — expect flakes", declared, ratio)}
	}
	return nil
}

// percentile95 returns the p95 of samples by the nearest-rank method:
// rank = ceil(0.95 * n), 1-indexed. With fewer than 20 samples this always
// lands on the last (largest) element — p95 degenerating to max is correct
// and intended for a small sample, not a bug.
func percentile95(samples []int64) int64 {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]int64{}, samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	n := len(sorted)
	rank := int(math.Ceil(0.95 * float64(n)))
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

func scaleDuration(d time.Duration, factor float64) time.Duration {
	return time.Duration(float64(d) * factor)
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// roundUpFriendlyRTO rounds d up to "something a human would write": the
// next whole 30s below 5 minutes, the next whole minute at or above it.
func roundUpFriendlyRTO(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	step := 30 * time.Second
	if d > 5*time.Minute {
		step = time.Minute
	}
	if rem := d % step; rem != 0 {
		d += step - rem
	}
	return d
}

// roundUpToHour rounds d up to the next whole hour.
func roundUpToHour(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	if rem := d % time.Hour; rem != 0 {
		d += time.Hour - rem
	}
	return d
}

// FormatCalibratedRTO renders a Calibrate-proposed RTO duration the way it
// is both shown to the operator and written into budgets.rto — one
// formatter for both, so what's printed and what's applied can never drift
// apart. Values below 5 minutes read as whole seconds ("90s"); at or above
// it, whole minutes ("6m") — the same "friendly duration" grain
// roundUpFriendlyRTO already rounded to, rather than Go's default
// h/m/s-per-component rendering.
func FormatCalibratedRTO(d time.Duration) string {
	if d < 5*time.Minute {
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
	return fmt.Sprintf("%dm", int(d/time.Minute))
}

// FormatCalibratedRPO renders a Calibrate-proposed RPO duration as whole
// hours ("6h") — the grain roundUpToHour already rounded to. Shared by the
// CLI's printed proposal and the value written into budgets.rpo.
func FormatCalibratedRPO(d time.Duration) string {
	return fmt.Sprintf("%dh", int(d/time.Hour))
}
