// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package ledger

import (
	"fmt"
	"time"
)

// Anchor appends an owner-approved chain_anchor entry vouching for entryID:
// one historical entry whose stored hash no longer matches its content and
// cannot be repaired in place (see ChainAnchorPayload). now and ulid make
// construction deterministic for tests; production callers should use
// AnchorNow. It refuses to write when:
//   - entryID does not exist in the ledger;
//   - the entry already verifies (recomputed hash matches its stored hash —
//     there is nothing to anchor);
//   - an anchor for entryID has already been appended (anchors are
//     append-only history, never replaced).
//
// It never rewrites an existing line — like Append, it only ever appends.
func Anchor(path, entryID, reason, approvedBy, actor string, now time.Time, ulid string) (Entry, error) {
	if reason == "" {
		return Entry{}, fmt.Errorf("ledger: anchor: --reason is required")
	}
	if approvedBy == "" {
		return Entry{}, fmt.Errorf("ledger: anchor: --approved-by is required")
	}

	entries, err := ReadAll(path)
	if err != nil {
		return Entry{}, err
	}

	var target *Entry
	for i := range entries {
		if entries[i].ID == entryID {
			target = &entries[i]
			break
		}
	}
	if target == nil {
		return Entry{}, fmt.Errorf("ledger: anchor: entry %q not found", entryID)
	}
	for _, e := range entries {
		if e.EntryType == EntryChainAnchor && e.Payload.ChainAnchor != nil && e.Payload.ChainAnchor.EntryID == entryID {
			return Entry{}, fmt.Errorf("ledger: anchor: entry %q already has a chain anchor (%s) — refusing to write a second one", entryID, e.ID)
		}
	}

	recomputed, err := hashEntry(*target)
	if err != nil {
		return Entry{}, fmt.Errorf("ledger: anchor: cannot recompute hash for %q: %w", entryID, err)
	}
	if recomputed == target.Hash {
		return Entry{}, fmt.Errorf("ledger: anchor: entry %q already verifies — nothing to anchor", entryID)
	}

	payload := Payload{ChainAnchor: &ChainAnchorPayload{
		EntryID:        entryID,
		StoredHash:     target.Hash,
		RecomputedHash: recomputed,
		Reason:         reason,
		ApprovedBy:     approvedBy,
	}}
	return Append(path, EntryChainAnchor, actor, payload, now, ulid)
}

// AnchorNow is Anchor with production time/id sources (matching AppendNow).
func AnchorNow(path, entryID, reason, approvedBy, actor string) (Entry, error) {
	id, err := NewID()
	if err != nil {
		return Entry{}, err
	}
	return Anchor(path, entryID, reason, approvedBy, actor, time.Now().UTC(), id)
}
