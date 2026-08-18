// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package ledger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"
)

// GenesisHash is the `prev` value of the first entry in a chain.
const GenesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000"

// Append builds a new Entry for (entryType, actor, payload), chains it onto
// the last entry currently in path (or GenesisHash if path is empty/absent),
// and appends it to path under an exclusive flock so concurrent restoregap
// processes never interleave writes. now and idSource make entry
// construction deterministic for tests; production callers should pass
// time.Now().UTC() and crypto/rand.Reader (or use AppendNow).
func Append(path string, entryType EntryType, actor string, payload Payload, now time.Time, ulid string) (Entry, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return Entry{}, fmt.Errorf("ledger: cannot open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return Entry{}, fmt.Errorf("ledger: cannot lock %s: %w", path, err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	prev, err := lastHashLocked(f)
	if err != nil {
		return Entry{}, err
	}

	entry := Entry{
		Schema:    SchemaVersion,
		ID:        ulid,
		CreatedAt: now,
		EntryType: entryType,
		Actor:     actor,
		Payload:   payload,
		Prev:      prev,
	}
	hash, err := hashEntry(entry)
	if err != nil {
		return Entry{}, err
	}
	entry.Hash = hash

	line, err := json.Marshal(entry)
	if err != nil {
		return Entry{}, fmt.Errorf("ledger: cannot marshal entry: %w", err)
	}
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return Entry{}, fmt.Errorf("ledger: cannot write to %s: %w", path, err)
	}
	return entry, nil
}

// AppendNow is Append with production time/id sources.
func AppendNow(path string, entryType EntryType, actor string, payload Payload) (Entry, error) {
	id, err := NewID()
	if err != nil {
		return Entry{}, err
	}
	return Append(path, entryType, actor, payload, time.Now().UTC(), id)
}

// lastHashLocked reads path (already open and locked by the caller) and
// returns the hash of its last well-formed entry, or GenesisHash if the
// file is empty. It does not validate the chain — that's Verify's job.
func lastHashLocked(f *os.File) (string, error) {
	if _, err := f.Seek(0, 0); err != nil {
		return "", fmt.Errorf("ledger: seek: %w", err)
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	last := GenesisHash
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return "", fmt.Errorf("ledger: corrupt entry, cannot append: %w", err)
		}
		last = e.Hash
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("ledger: read %s: %w", f.Name(), err)
	}
	if _, err := f.Seek(0, 2); err != nil {
		return "", fmt.Errorf("ledger: seek: %w", err)
	}
	return last, nil
}

// ReadAll returns every entry in path, in file order. A missing file
// returns an empty, non-error result (an unstarted ledger).
func ReadAll(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("ledger: cannot read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("ledger: %s: malformed entry: %w", path, err)
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ledger: read %s: %w", path, err)
	}
	return entries, nil
}
