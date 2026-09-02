// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package ledger

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/engine"
)

// DefaultOverrideExpiry is deliberately short: an override records an
// exception to a recovery gate, not a permanent policy decision.
const DefaultOverrideExpiry = 30 * 24 * time.Hour

// MaxOverrideExpiry prevents a dated override from becoming an amnesty with a
// date-shaped disguise. Longer exceptions need an explicit re-approval.
const MaxOverrideExpiry = 90 * 24 * time.Hour

// LegacyOverrideGrace is the migration path for entries written before
// expires_at was mandatory. Those historical entries remain readable for a
// bounded window from their own CreatedAt, then stop applying.
const LegacyOverrideGrace = 30 * 24 * time.Hour

// OverrideState is one currently active ledger override, reduced to the
// operational fields status and preflight need. ExpiresAt is always present:
// legacy no-expiry entries receive their derived migration-grace deadline.
type OverrideState struct {
	EntryID        string
	FindingID      string
	ApprovedBy     string
	Reason         string
	ExpiresAt      time.Time
	LegacyNoExpiry bool
}

// NewOverridePayload validates and constructs a new override payload. New
// entries always receive expires_at; only old on-disk entries may omit it.
func NewOverridePayload(findingID, approvedBy, reason string, expiresIn time.Duration, now time.Time) (*OverridePayload, error) {
	if strings.TrimSpace(findingID) == "" {
		return nil, fmt.Errorf("override: finding id is required")
	}
	if strings.TrimSpace(approvedBy) == "" {
		return nil, fmt.Errorf("override: approved by is required")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, fmt.Errorf("override: --reason is required")
	}
	if expiresIn == 0 {
		expiresIn = DefaultOverrideExpiry
	}
	if expiresIn < 0 {
		return nil, fmt.Errorf("override: --expires-in must be positive")
	}
	if expiresIn > MaxOverrideExpiry {
		return nil, fmt.Errorf("override: --expires-in exceeds the maximum 90 days")
	}
	expiresAt := now.UTC().Add(expiresIn)
	return &OverridePayload{
		FindingID: findingID, ApprovedBy: approvedBy, Reason: reason, ExpiresAt: &expiresAt,
	}, nil
}

// ActiveOverrides scans entries for override records that are still active
// as of now and returns them as engine.Overrides ready for
// engine.ApplyOverrides. An old no-expires_at entry is allowed only through
// LegacyOverrideGrace from its CreatedAt; this preserves read compatibility
// without perpetuating a permanent exception. Later active overrides for the
// same finding id win (matching how ledger.Append only ever appends — history
// is never deleted, but the most recent decision governs).
func ActiveOverrides(entries []Entry, now time.Time) []engine.Override {
	states := ActiveOverrideStates(entries, now)
	overrides := make([]engine.Override, 0, len(states))
	for _, s := range states {
		overrides = append(overrides, engine.Override{
			FindingID: s.FindingID, ApprovedBy: s.ApprovedBy, Reason: s.Reason,
		})
	}
	return overrides
}

// ActiveOverrideStates returns one active override per finding, sorted by
// ledger entry id for stable status/report output. Legacy no-expiry entries
// carry their derived migration deadline in ExpiresAt.
func ActiveOverrideStates(entries []Entry, now time.Time) []OverrideState {
	byFinding := make(map[string]OverrideState)
	for _, e := range entries {
		if e.EntryType != EntryOverride || e.Payload.Override == nil {
			continue
		}
		o := e.Payload.Override
		expiresAt, legacy := overrideExpiry(e, now)
		if !now.Before(expiresAt) {
			continue
		}
		byFinding[o.FindingID] = OverrideState{
			EntryID: e.ID, FindingID: o.FindingID, ApprovedBy: o.ApprovedBy,
			Reason: o.Reason, ExpiresAt: expiresAt, LegacyNoExpiry: legacy,
		}
	}
	states := make([]OverrideState, 0, len(byFinding))
	for _, state := range byFinding {
		states = append(states, state)
	}
	sort.Slice(states, func(i, j int) bool { return states[i].EntryID < states[j].EntryID })
	return states
}

// overrideExpiry returns the effective expiry for an override. The legacy
// branch documents the one-way migration: a missing expires_at is accepted on
// read because old binaries wrote it, but only until CreatedAt+30 days.
func overrideExpiry(e Entry, _ time.Time) (time.Time, bool) {
	if e.Payload.Override.ExpiresAt != nil {
		return e.Payload.Override.ExpiresAt.UTC(), false
	}
	return e.CreatedAt.UTC().Add(LegacyOverrideGrace), true
}
