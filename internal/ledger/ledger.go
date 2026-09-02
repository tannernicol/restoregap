// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package ledger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// GenesisHash is the `prev` value of the first entry in a chain.
const GenesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000"

// syncFile is the fsync seam Append calls on every write. It is a
// package-level var (not a parameter or an AppendOption) so it can be
// substituted in tests without touching real disks, while every call site
// still shares one non-optional enforcement point — see Append's doc
// comment for why this is not a flag.
var syncFile = func(f *os.File) error { return f.Sync() }

// syncDir is the best-effort fsync seam for the ledger's containing
// directory, called only right after Append creates a brand-new ledger
// file. A directory entry (the fact that the file exists at all) is its own
// piece of durable state, distinct from the file's contents, and on most
// filesystems it needs its own fsync to survive a crash. Errors are
// swallowed by the caller (never here) — see Append for why.
var syncDir = func(dirPath string) error {
	d, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// appendConfig collects the optional stamps an Append may carry, so the
// Append call shape stays closed (variadic options rather than a growing
// positional parameter list). There is no durability flag here: fsync is
// mandatory (see Append), never an opt-in.
type appendConfig struct {
	host   *HostRecord
	epoch  string
	policy *PolicyRecord
}

// AppendOption customizes one Append with the portability stamps (host,
// epoch, policy — docs/SCHEMA.md) the entry carries.
type AppendOption func(*appendConfig)

// WithHost stamps the entry with the machine identity that wrote it.
func WithHost(h HostRecord) AppendOption {
	return func(c *appendConfig) { c.host = &h }
}

// WithEpoch stamps the entry with the epoch id it was written under.
func WithEpoch(e string) AppendOption {
	return func(c *appendConfig) { c.epoch = e }
}

// WithPolicy stamps the entry with the policy revision (and its context
// files) the decision was made under.
func WithPolicy(p PolicyRecord) AppendOption {
	return func(c *appendConfig) { c.policy = &p }
}

// Append builds a new Entry for (entryType, actor, payload), chains it onto
// the last entry currently in path (or GenesisHash if path is empty/absent),
// and appends it to path. Concurrency contract: the ledger file is opened
// O_APPEND, an exclusive flock is held on <path>.lock around the whole
// read-last-hash + write critical section, and each entry is one single
// write() call — so N concurrent writers (timers, agents, hooks on one box)
// produce a valid chain, never interleaved bytes. now and idSource make
// entry construction deterministic for tests; production callers should pass
// time.Now().UTC() and crypto/rand.Reader (or use AppendNow).
//
// Durability: every entry is fsynced to disk before the flock is released,
// with no option to skip it. This ledger is the audit trail of a tool whose
// entire pitch is "you can prove your recovery works" — a verdict that
// isn't actually on disk did not happen, and a power cut between write()
// and the next drill is exactly the failure this tool exists to catch
// elsewhere. The cost is irrelevant at this volume: a handful of entries
// per hour, not a hot path. When Append creates a brand-new ledger file,
// its containing directory is also fsynced (best-effort — see syncDir), so
// the file's very existence survives a crash on a fresh ledger too.
func Append(path string, entryType EntryType, actor string, payload Payload, now time.Time, ulid string, opts ...AppendOption) (Entry, error) {
	cfg := appendConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	// Recorded before the ledger file is opened (which may create it with
	// O_CREATE) so we know, after a successful write, whether this Append
	// just brought the file into existence and therefore needs its
	// directory entry fsynced too.
	isFreshLedger := false
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		isFreshLedger = true
	}

	// The lock lives in a sibling file, not on the ledger fd itself: locking
	// the ledger requires opening it read-write even for readers, and — more
	// importantly — the lock must be held across the read-modify-append
	// window by a stable handle that nobody rotates or replaces.
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return Entry{}, fmt.Errorf("ledger: cannot open %s.lock: %w", path, err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return Entry{}, fmt.Errorf("ledger: cannot lock %s.lock: %w", path, err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return Entry{}, fmt.Errorf("ledger: cannot open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

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
		Host:      cfg.host,
		Epoch:     cfg.epoch,
		Policy:    cfg.policy,
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
	// One write() per entry — with O_APPEND this is the unit the kernel
	// keeps atomic; a marshalled-then-partial write would interleave under
	// contention even while holding the lock against well-behaved writers.
	if _, err := f.Write(line); err != nil {
		return Entry{}, fmt.Errorf("ledger: cannot write to %s: %w", path, err)
	}
	// Fsync before the deferred flock unlock runs (below the return, in LIFO
	// order): a reader that acquires the lock next must never observe an
	// entry that isn't durable yet. Unlike syncDir below, a failure here is
	// NOT swallowed — if the entry's own bytes cannot be guaranteed on disk,
	// Append must say so rather than silently returning a "success" that a
	// crash could erase.
	if err := syncFile(f); err != nil {
		return Entry{}, fmt.Errorf("ledger: cannot fsync %s: %w", path, err)
	}
	if isFreshLedger {
		// Best-effort: a platform that cannot open a directory for syncing
		// (or any other failure here) must not fail an otherwise-durable
		// append. The file's contents are already safely fsynced above;
		// this only hardens the rarer case of a crash losing the directory
		// entry that makes the file discoverable at all.
		_ = syncDir(filepath.Dir(path))
	}
	return entry, nil
}

// AppendNow is Append with production time/id sources.
func AppendNow(path string, entryType EntryType, actor string, payload Payload, opts ...AppendOption) (Entry, error) {
	id, err := NewID()
	if err != nil {
		return Entry{}, err
	}
	return Append(path, entryType, actor, payload, time.Now().UTC(), id, opts...)
}

// Stamp returns the standard portability options for the given identity and
// policy record — the one-liner every stamping caller shares, so a future
// stamp field is added in exactly one place.
func Stamp(host *HostRecord, epoch string, policy *PolicyRecord) []AppendOption {
	opts := make([]AppendOption, 0, 3)
	if host != nil {
		opts = append(opts, WithHost(*host))
	}
	if epoch != "" {
		opts = append(opts, WithEpoch(epoch))
	}
	if policy != nil {
		opts = append(opts, WithPolicy(*policy))
	}
	return opts
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
