// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Host is a machine that pushes bundles. ID is the store's row id; HostID is
// the id the bundle itself declares. The signing key is pinned on first sight.
type Host struct {
	ID, WorkspaceID, HostID, Name, Epoch, PublicKeyHex string
	ExpectedEvery                                      time.Duration // 0: no cadence, never lapses
	FirstSeenAt, LastSeenAt                            time.Time
	LapsedAt                                           *time.Time
}

const hostCols = `id, workspace_id, host_id, name, epoch, public_key_hex, expected_every_ns,
	first_seen_at, last_seen_at, lapsed_at`

func scanHost(sc scanner) (Host, error) {
	var h Host
	var every int64
	var first, last string
	var lapsed sql.NullString
	if err := sc.Scan(&h.ID, &h.WorkspaceID, &h.HostID, &h.Name, &h.Epoch, &h.PublicKeyHex,
		&every, &first, &last, &lapsed); err != nil {
		return Host{}, err
	}
	h.ExpectedEvery = time.Duration(every)
	var err error
	if h.FirstSeenAt, err = parseTime(first); err != nil {
		return Host{}, err
	}
	if h.LastSeenAt, err = parseTime(last); err != nil {
		return Host{}, err
	}
	h.LapsedAt, err = parseTimePtr(lapsed)
	return h, err
}

// UpsertHostOnBundle records a bundle arriving from hostID. The first bundle
// pins pubkey (trust on first use); a later one with a different key returns
// ErrKeyMismatch and changes nothing. A successful sight clears LapsedAt; a
// caller that needs to emit "recovered" must read the host (GetHostByHostID)
// before calling.
func (s *Store) UpsertHostOnBundle(workspaceID, hostID, name, epoch, pubkey string, seenAt time.Time) (Host, error) {
	if hostID == "" || pubkey == "" {
		return Host{}, errors.New("store: host id and public key required")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Host{}, err
	}
	defer func() { _ = tx.Rollback() }()

	h, err := scanHost(tx.QueryRow(`SELECT `+hostCols+` FROM hosts WHERE workspace_id = ? AND host_id = ?`,
		workspaceID, hostID))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		id, idErr := newID()
		if idErr != nil {
			return Host{}, idErr
		}
		if _, err := tx.Exec(`INSERT INTO hosts (id, workspace_id, host_id, name, epoch, public_key_hex,
			first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			id, workspaceID, hostID, name, epoch, pubkey, fmtTime(seenAt), fmtTime(seenAt)); err != nil {
			return Host{}, fmt.Errorf("store: insert host: %w", err)
		}
		h, err = scanHost(tx.QueryRow(`SELECT `+hostCols+` FROM hosts WHERE id = ?`, id))
		if err != nil {
			return Host{}, err
		}
	case err != nil:
		return Host{}, err
	default:
		if h.PublicKeyHex != pubkey {
			return Host{}, ErrKeyMismatch
		}
		// max() so a late-arriving older bundle cannot move last-seen backwards
		// and make a healthy host look lapsed.
		if _, err := tx.Exec(`UPDATE hosts SET name = ?, epoch = ?, last_seen_at = max(last_seen_at, ?),
			lapsed_at = NULL WHERE id = ?`, name, epoch, fmtTime(seenAt), h.ID); err != nil {
			return Host{}, err
		}
		h, err = scanHost(tx.QueryRow(`SELECT `+hostCols+` FROM hosts WHERE id = ?`, h.ID))
		if err != nil {
			return Host{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Host{}, err
	}
	return h, nil
}

// GetHost returns a host by row id within a workspace.
func (s *Store) GetHost(workspaceID, id string) (Host, error) {
	h, err := scanHost(s.db.QueryRow(`SELECT `+hostCols+` FROM hosts WHERE workspace_id = ? AND id = ?`,
		workspaceID, id))
	return h, mapNoRows(err)
}

// GetHostByHostID returns a host by the id its bundles declare. A handler
// needs it to tell a new host (host-limit check) from a known one.
func (s *Store) GetHostByHostID(workspaceID, hostID string) (Host, error) {
	h, err := scanHost(s.db.QueryRow(`SELECT `+hostCols+` FROM hosts WHERE workspace_id = ? AND host_id = ?`,
		workspaceID, hostID))
	return h, mapNoRows(err)
}

// ListHosts returns a workspace's hosts ordered by name.
func (s *Store) ListHosts(workspaceID string) ([]Host, error) {
	rows, err := s.db.Query(`SELECT `+hostCols+` FROM hosts WHERE workspace_id = ? ORDER BY name, host_id`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// CountHosts is the number of hosts in a workspace, for plan limits.
func (s *Store) CountHosts(workspaceID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE workspace_id = ?`, workspaceID).Scan(&n)
	return n, err
}

// SetHostExpectedEvery sets the cadence; zero turns lapse monitoring off.
func (s *Store) SetHostExpectedEvery(id string, d time.Duration) error {
	if d < 0 {
		return errors.New("store: negative cadence")
	}
	return requireRows(s.db.Exec(`UPDATE hosts SET expected_every_ns = ? WHERE id = ?`, int64(d), id))
}

// SetHostPublicKey is the owner's key rotation: it replaces the pinned key.
func (s *Store) SetHostPublicKey(id, pubkeyHex string) error {
	if pubkeyHex == "" {
		return errors.New("store: public key required")
	}
	return requireRows(s.db.Exec(`UPDATE hosts SET public_key_hex = ? WHERE id = ?`, pubkeyHex, id))
}

// MarkHostLapsed records that the host went silent at the given time.
func (s *Store) MarkHostLapsed(id string, at time.Time) error {
	return requireRows(s.db.Exec(`UPDATE hosts SET lapsed_at = ? WHERE id = ?`, fmtTime(at), id))
}
