package ledger

import (
	"time"

	"github.com/tannernicol/restoregap/internal/engine"
)

// ActiveOverrides scans entries for override records that are still active
// as of now (no expires_at, or expires_at in the future) and returns them as
// engine.Overrides ready for engine.ApplyOverrides. Later overrides for the
// same finding id win (matching how ledger.Append only ever appends —
// history is never deleted, but the most recent decision governs).
func ActiveOverrides(entries []Entry, now time.Time) []engine.Override {
	byFinding := map[string]engine.Override{}
	for _, e := range entries {
		if e.EntryType != EntryOverride || e.Payload.Override == nil {
			continue
		}
		o := e.Payload.Override
		if o.ExpiresAt != nil && now.After(*o.ExpiresAt) {
			continue
		}
		byFinding[o.FindingID] = engine.Override{
			FindingID:  o.FindingID,
			ApprovedBy: o.ApprovedBy,
			Reason:     o.Reason,
		}
	}
	overrides := make([]engine.Override, 0, len(byFinding))
	for _, o := range byFinding {
		overrides = append(overrides, o)
	}
	return overrides
}
