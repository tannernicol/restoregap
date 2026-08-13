package ledger

import "fmt"

// VerifyResult is the outcome of walking a ledger's hash chain.
type VerifyResult struct {
	OK         bool
	EntryCount int
	LastHash   string
	// FailedAt is the 1-based index of the first entry that failed
	// verification, or 0 if OK.
	FailedAt int
	Reason   string
	// AnchoredAnomalies holds the entry ids of every entry whose stored
	// hash mismatched its recomputed hash but was accepted because a valid
	// chain_anchor entry vouches for it. An OK result with a non-empty
	// AnchoredAnomalies is not byte-for-byte pristine — it is a chain whose
	// known, owner-approved deviations were called out rather than
	// silently accepted or left permanently broken.
	AnchoredAnomalies []string
}

// chainAnchor pairs an anchor's payload with the anchor entry's own 1-based
// position in the file — needed to enforce that an anchor can only vouch for
// an entry earlier in the file than itself (an anchor is appended after the
// fact, by construction).
type chainAnchor struct {
	payload *ChainAnchorPayload
	atIndex int
}

// scanChainAnchors pre-scans entries for chain_anchor payloads, keyed by the
// entry id they vouch for. A malformed/adversarial ledger could carry more
// than one anchor for the same id; the last one in file order wins, matching
// how the rest of this package treats "later entries govern" (e.g.
// ActiveOverrides).
func scanChainAnchors(entries []Entry) map[string]chainAnchor {
	anchors := make(map[string]chainAnchor)
	for i, e := range entries {
		if e.EntryType != EntryChainAnchor || e.Payload.ChainAnchor == nil {
			continue
		}
		anchors[e.Payload.ChainAnchor.EntryID] = chainAnchor{payload: e.Payload.ChainAnchor, atIndex: i + 1}
	}
	return anchors
}

// Verify walks path's entries in order and checks that each entry's Prev
// matches the previous entry's Hash (or GenesisHash for the first entry)
// and that each entry's Hash matches its own recomputed canonical hash. It
// stops at the first break in the chain — everything after a corrupted
// entry is unverifiable by definition.
func Verify(path string) (VerifyResult, error) {
	entries, err := ReadAll(path)
	if err != nil {
		return VerifyResult{}, err
	}
	return VerifyEntries(entries), nil
}

// VerifyEntries is Verify's pure core, usable directly by tests and by
// callers that already hold entries in memory.
func VerifyEntries(entries []Entry) VerifyResult {
	anchors := scanChainAnchors(entries)
	var anchoredAnomalies []string
	prev := GenesisHash
	for i, e := range entries {
		n := i + 1
		// Prev-linkage is checked unconditionally, for every entry
		// including chain_anchor entries themselves — an anchor vouches
		// for one earlier entry's hash, never for its own place in the
		// chain, and never for a break anywhere else.
		if e.Prev != prev {
			return VerifyResult{OK: false, EntryCount: len(entries), FailedAt: n,
				Reason: fmt.Sprintf("entry %d (%s): prev %q does not match preceding entry's hash %q", n, e.ID, e.Prev, prev)}
		}
		claimed := e.Hash
		recomputed, err := hashEntry(e)
		if err != nil {
			return VerifyResult{OK: false, EntryCount: len(entries), FailedAt: n,
				Reason: fmt.Sprintf("entry %d (%s): cannot recompute hash: %v", n, e.ID, err)}
		}
		if claimed != recomputed {
			anchor, anchored := anchors[e.ID]
			// An anchor can only be honored for a mismatch it was written
			// to describe: it must name this exact entry, its StoredHash
			// must equal what's actually claimed on disk, and it must sit
			// later in the file (an anchor is appended after the fact).
			if !anchored || anchor.payload.StoredHash != claimed || anchor.atIndex <= n {
				return VerifyResult{OK: false, EntryCount: len(entries), FailedAt: n,
					Reason: fmt.Sprintf("entry %d (%s): hash %q does not match recomputed hash %q — entry was modified after writing", n, e.ID, claimed, recomputed)}
			}
			anchoredAnomalies = append(anchoredAnomalies, e.ID)
		}
		prev = claimed
	}
	return VerifyResult{OK: true, EntryCount: len(entries), LastHash: prev, AnchoredAnomalies: anchoredAnomalies}
}
