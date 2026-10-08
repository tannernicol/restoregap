// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Bundle is the stored record of one pushed archive. The archive bytes live on
// disk (BundlePath); the row holds what the dashboard and verification need.
type Bundle struct {
	ID, WorkspaceID, HostRowID    string
	GeneratedAt, ReceivedAt       time.Time
	Epoch, PolicyRevision         string
	PublicKeyHex, SignatureHex    string
	Guards, Proofs, LedgerEntries int
	SizeBytes                     int64
	SHA256                        string
}

// ProofRow is one proof's declared state inside one bundle: the unit of
// history and of regression detection.
type ProofRow struct {
	BundleID, WorkspaceID, HostRowID, Proof, Layer, Category, State, Level, Why string
	Host, Epoch, Environment, System, Artifact                                  string
	GeneratedAt                                                                 time.Time
}

const bundleCols = `id, workspace_id, host_row_id, generated_at, received_at, epoch, policy_revision,
	public_key_hex, signature_hex, guards, proofs, ledger_entries, size_bytes, sha256`

// bundleOrder is the one definition of "newest": generation time, then
// arrival, then id as a stable tiebreak. Latest, Previous, List and Prune all
// use it so they can never disagree about which bundle is current.
const bundleOrder = `generated_at DESC, received_at DESC, id DESC`

func scanBundle(sc scanner) (Bundle, error) {
	var b Bundle
	var gen, rec string
	if err := sc.Scan(&b.ID, &b.WorkspaceID, &b.HostRowID, &gen, &rec, &b.Epoch, &b.PolicyRevision,
		&b.PublicKeyHex, &b.SignatureHex, &b.Guards, &b.Proofs, &b.LedgerEntries, &b.SizeBytes, &b.SHA256); err != nil {
		return Bundle{}, err
	}
	var err error
	if b.GeneratedAt, err = parseTime(gen); err != nil {
		return Bundle{}, err
	}
	b.ReceivedAt, err = parseTime(rec)
	return b, err
}

func queryBundles(s *Store, q string, args ...any) ([]Bundle, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Bundle
	for rows.Next() {
		b, err := scanBundle(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// BundlePath is where a bundle's archive lives. IDs are store-generated hex,
// so the path cannot be steered outside the data directory.
func (s *Store) BundlePath(b Bundle) string {
	return filepath.Join(s.dataDir, "bundles", b.WorkspaceID, b.ID+".tgz")
}

// SaveBundle persists an archive and its proof rows. The store assigns the
// bundle id and, as the authority on what it holds, overwrites SizeBytes and
// SHA256 from the archive bytes. ReceivedAt defaults to now. The file is
// written (0600, temp + rename) before the transaction so a committed row
// always has its archive; if the insert fails the file is removed.
func (s *Store) SaveBundle(b Bundle, archive []byte, proofs []ProofRow) (Bundle, error) {
	if b.WorkspaceID == "" || b.HostRowID == "" {
		return Bundle{}, errors.New("store: bundle needs workspace and host")
	}
	id, err := newID()
	if err != nil {
		return Bundle{}, err
	}
	b.ID = id
	if b.ReceivedAt.IsZero() {
		b.ReceivedAt = s.now()
	}
	sum := sha256.Sum256(archive)
	b.SHA256 = hex.EncodeToString(sum[:])
	b.SizeBytes = int64(len(archive))

	path := s.BundlePath(b)
	if err := writeFileAtomic(path, archive); err != nil {
		return Bundle{}, fmt.Errorf("store: write bundle: %w", err)
	}
	if err := s.insertBundle(b, proofs); err != nil {
		_ = os.Remove(path)
		return Bundle{}, err
	}
	return b, nil
}

func (s *Store) insertBundle(b Bundle, proofs []ProofRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// The FK only proves the host exists; this proves it is this workspace's,
	// so a bad caller cannot attach a bundle across tenants.
	var one int
	if err := tx.QueryRow(`SELECT 1 FROM hosts WHERE id = ? AND workspace_id = ?`,
		b.HostRowID, b.WorkspaceID).Scan(&one); err != nil {
		return mapNoRows(err)
	}
	if _, err := tx.Exec(`INSERT INTO bundles (`+bundleCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		b.ID, b.WorkspaceID, b.HostRowID, fmtTime(b.GeneratedAt), fmtTime(b.ReceivedAt), b.Epoch,
		b.PolicyRevision, b.PublicKeyHex, b.SignatureHex, b.Guards, b.Proofs, b.LedgerEntries,
		b.SizeBytes, b.SHA256); err != nil {
		return fmt.Errorf("store: insert bundle: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO proof_rows (bundle_id, workspace_id, host_row_id, proof, layer,
		category, state, level, why, host, epoch, environment, system, artifact, generated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, p := range proofs {
		gen := p.GeneratedAt
		if gen.IsZero() {
			gen = b.GeneratedAt
		}
		// Identity columns always come from the bundle: a ProofRow must not be
		// able to land under another bundle, host or workspace.
		if _, err := stmt.Exec(b.ID, b.WorkspaceID, b.HostRowID, p.Proof, p.Layer, p.Category, p.State,
			p.Level, p.Why, p.Host, p.Epoch, p.Environment, p.System, p.Artifact, fmtTime(gen)); err != nil {
			return fmt.Errorf("store: insert proof %q: %w", p.Proof, err)
		}
	}
	return tx.Commit()
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".incoming-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { _ = f.Close(); _ = os.Remove(tmp) }
	if err := f.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return err
	}
	// Sync before rename: otherwise a crash can leave a renamed, empty file.
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// GetBundle returns a bundle row within a workspace.
func (s *Store) GetBundle(workspaceID, id string) (Bundle, error) {
	b, err := scanBundle(s.db.QueryRow(`SELECT `+bundleCols+` FROM bundles WHERE workspace_id = ? AND id = ?`,
		workspaceID, id))
	return b, mapNoRows(err)
}

// ReadBundle returns the archive bytes. It goes through the row first so only
// ids that exist in the workspace ever reach the filesystem.
func (s *Store) ReadBundle(workspaceID, id string) ([]byte, error) {
	b, err := s.GetBundle(workspaceID, id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.BundlePath(b))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return data, err
}

// ListBundles returns bundles newest first; hostRowID "" means all hosts and
// limit <= 0 means no limit.
func (s *Store) ListBundles(workspaceID, hostRowID string, limit int) ([]Bundle, error) {
	q := `SELECT ` + bundleCols + ` FROM bundles WHERE workspace_id = ?`
	args := []any{workspaceID}
	if hostRowID != "" {
		q += ` AND host_row_id = ?`
		args = append(args, hostRowID)
	}
	q += ` ORDER BY ` + bundleOrder + ` LIMIT ?`
	args = append(args, limitArg(limit))
	return queryBundles(s, q, args...)
}

// LatestBundlePerHost returns each host's newest bundle: the fleet view.
func (s *Store) LatestBundlePerHost(workspaceID string) ([]Bundle, error) {
	return queryBundles(s, `SELECT `+bundleCols+` FROM (
		SELECT *, ROW_NUMBER() OVER (PARTITION BY host_row_id ORDER BY `+bundleOrder+`) AS rn
		FROM bundles WHERE workspace_id = ?) WHERE rn = 1 ORDER BY host_row_id`, workspaceID)
}

// PreviousBundle is the host's newest bundle generated strictly before the
// given time; regression detection diffs a new bundle against it.
func (s *Store) PreviousBundle(workspaceID, hostRowID string, before time.Time) (Bundle, bool, error) {
	b, err := scanBundle(s.db.QueryRow(`SELECT `+bundleCols+` FROM bundles
		WHERE workspace_id = ? AND host_row_id = ? AND generated_at < ?
		ORDER BY `+bundleOrder+` LIMIT 1`, workspaceID, hostRowID, fmtTime(before)))
	if errors.Is(err, sql.ErrNoRows) {
		return Bundle{}, false, nil
	}
	if err != nil {
		return Bundle{}, false, err
	}
	return b, true, nil
}

const proofCols = `bundle_id, workspace_id, host_row_id, proof, layer, category, state, level, why,
	host, epoch, environment, system, artifact, generated_at`

func queryProofs(s *Store, q string, args ...any) ([]ProofRow, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProofRow
	for rows.Next() {
		var p ProofRow
		var gen string
		if err := rows.Scan(&p.BundleID, &p.WorkspaceID, &p.HostRowID, &p.Proof, &p.Layer, &p.Category,
			&p.State, &p.Level, &p.Why, &p.Host, &p.Epoch, &p.Environment, &p.System, &p.Artifact, &gen); err != nil {
			return nil, err
		}
		if p.GeneratedAt, err = parseTime(gen); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProofsForBundle returns a bundle's proof rows ordered by proof name.
func (s *Store) ProofsForBundle(workspaceID, bundleID string) ([]ProofRow, error) {
	return queryProofs(s, `SELECT `+proofCols+` FROM proof_rows WHERE workspace_id = ? AND bundle_id = ?
		ORDER BY proof`, workspaceID, bundleID)
}

// ProofHistory is one proof on one host across bundles, newest first.
func (s *Store) ProofHistory(workspaceID, hostRowID, proof string, limit int) ([]ProofRow, error) {
	return queryProofs(s, `SELECT `+proofCols+` FROM proof_rows
		WHERE workspace_id = ? AND host_row_id = ? AND proof = ?
		ORDER BY generated_at DESC, bundle_id DESC LIMIT ?`, workspaceID, hostRowID, proof, limitArg(limit))
}

// PruneBundles enforces retention: it deletes bundles generated before the
// cutoff, with their proof rows and archives, except each host's newest
// bundle so a quiet host never loses its last evidence. Rows go in one
// transaction; files are removed after commit, so a crash leaves orphan
// files at worst, never rows pointing at missing archives.
func (s *Store) PruneBundles(workspaceID string, olderThan time.Time) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.Query(`SELECT id FROM (
		SELECT id, generated_at, ROW_NUMBER() OVER (PARTITION BY host_row_id ORDER BY `+bundleOrder+`) AS rn
		FROM bundles WHERE workspace_id = ?) WHERE rn > 1 AND generated_at < ?`,
		workspaceID, fmtTime(olderThan))
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	for _, id := range ids {
		// proof_rows go via ON DELETE CASCADE.
		if _, err := tx.Exec(`DELETE FROM bundles WHERE id = ? AND workspace_id = ?`, id, workspaceID); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	for _, id := range ids {
		if err := os.Remove(s.BundlePath(Bundle{ID: id, WorkspaceID: workspaceID})); err != nil && !errors.Is(err, os.ErrNotExist) {
			return len(ids), fmt.Errorf("store: remove pruned archive %s: %w", id, err)
		}
	}
	return len(ids), nil
}
