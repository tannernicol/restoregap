// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package store is the persistence layer of Restore Gap Cloud: one SQLite
// database plus the bundle archives on disk, as docs/CLOUD.md promises.
//
// Secrets (API tokens, share links, login links, session cookies) are
// returned in plaintext exactly once at creation and stored only as SHA-256,
// so a stolen database file or backup cannot be replayed against the service.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver; pure Go, no cgo
)

var (
	// ErrNotFound covers missing rows and also secrets that exist but are no
	// longer usable (revoked, expired, consumed), so callers cannot leak which.
	ErrNotFound = errors.New("store: not found")
	// ErrKeyMismatch is a host presenting a signing key other than the pinned one.
	ErrKeyMismatch = errors.New("store: host public key does not match pinned key")
	// ErrConflict is a uniqueness violation (e.g. a duplicate membership).
	ErrConflict = errors.New("store: conflict")
)

// timeLayout is RFC3339Nano with the fraction zero-padded to a fixed width.
// Plain RFC3339Nano trims trailing zeros, which makes the text sort wrongly
// ("…05.5Z" < "…05Z" lexically); every ORDER BY and comparison in this
// package relies on the stored text sorting chronologically. The result still
// parses with time.RFC3339Nano.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

// Store is the cloud database and bundle archive directory.
type Store struct {
	db      *sql.DB
	dataDir string
	now     func() time.Time
}

// Open creates dataDir if needed, opens dataDir/cloud.db and migrates it.
func Open(dataDir string) (*Store, error) {
	if dataDir == "" {
		return nil, errors.New("store: empty data directory")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("store: resolve data dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(abs, "bundles"), 0o700); err != nil {
		return nil, fmt.Errorf("store: create data dir: %w", err)
	}
	dbPath := filepath.Join(abs, "cloud.db")
	// Create the file 0600 ourselves: SQLite would otherwise use the umask,
	// and the WAL/SHM siblings inherit the main file's mode.
	f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: create database file: %w", err)
	}
	_ = f.Close()

	// _pragma entries apply to every connection the pool opens, which is the
	// only reliable way to get foreign_keys (it is per-connection) everywhere.
	dsn := "file:" + dbPath +
		"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}
	// One connection serializes writers inside this process. SQLite has one
	// writer anyway, and a deferred read-then-write transaction on a second
	// connection can fail with SQLITE_BUSY immediately (busy_timeout does not
	// apply to a lock upgrade). The cost is that nothing may issue a query on
	// s.db while holding open rows or a transaction; the code below never does.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, dataDir: abs, now: func() time.Time { return time.Now().UTC() }}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close checkpoints and closes the database.
func (s *Store) Close() error { return s.db.Close() }

// DataDir is the absolute data directory.
func (s *Store) DataDir() string { return s.dataDir }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("store: schema_version: %w", err)
	}
	var cur int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&cur)
	if err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	if cur > len(migrations) {
		return fmt.Errorf("store: database schema v%d is newer than this binary (v%d)", cur, len(migrations))
	}
	for v := cur + 1; v <= len(migrations); v++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: migrate v%d: %w", v, err)
		}
		if _, err := tx.ExecContext(ctx, migrations[v-1]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: migrate v%d: %w", v, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, v); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: migrate v%d: %w", v, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: migrate v%d: %w", v, err)
		}
	}
	return nil
}

// ---- helpers ----

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("store: random id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// newSecret returns 32 random bytes as base64url, with an optional prefix.
func newSecret(prefix string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("store: random secret: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func hashSecret(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func fmtTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func fmtTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return fmtTime(*t)
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("store: bad stored time %q: %w", s, err)
	}
	return t.UTC(), nil
}

func parseTimePtr(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid {
		return nil, nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// scanner is satisfied by *sql.Row and *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

func mapNoRows(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func limitArg(limit int) int {
	if limit <= 0 {
		return -1 // SQLite: negative LIMIT means no limit
	}
	return limit
}

func requireRows(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
