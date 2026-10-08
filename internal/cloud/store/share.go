// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ShareLink is a revocable read-only URL secret. Scope is "fleet" or
// "host:<hostRowID>". Token is populated only by CreateShareLink (as the
// plaintext); the database keeps just its SHA-256.
type ShareLink struct {
	ID, WorkspaceID, Token, Scope string
	CreatedAt                     time.Time
	ExpiresAt, RevokedAt          *time.Time
}

const shareCols = `id, workspace_id, scope, created_at, expires_at, revoked_at`

func scanShare(sc scanner) (ShareLink, error) {
	var l ShareLink
	var created string
	var exp, rev sql.NullString
	if err := sc.Scan(&l.ID, &l.WorkspaceID, &l.Scope, &created, &exp, &rev); err != nil {
		return ShareLink{}, err
	}
	var err error
	if l.CreatedAt, err = parseTime(created); err != nil {
		return ShareLink{}, err
	}
	if l.ExpiresAt, err = parseTimePtr(exp); err != nil {
		return ShareLink{}, err
	}
	l.RevokedAt, err = parseTimePtr(rev)
	return l, err
}

// CreateShareLink mints a link. The plaintext is returned once.
func (s *Store) CreateShareLink(workspaceID, scope string, expires *time.Time) (ShareLink, string, error) {
	if scope != "fleet" && !(strings.HasPrefix(scope, "host:") && len(scope) > len("host:")) {
		return ShareLink{}, "", fmt.Errorf("store: invalid share scope %q", scope)
	}
	plain, err := newSecret("")
	if err != nil {
		return ShareLink{}, "", err
	}
	id, err := newID()
	if err != nil {
		return ShareLink{}, "", err
	}
	now := s.now()
	if _, err := s.db.Exec(`INSERT INTO share_links (id, workspace_id, token_hash, scope, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, id, workspaceID, hashSecret(plain), scope, fmtTime(now), fmtTimePtr(expires)); err != nil {
		return ShareLink{}, "", fmt.Errorf("store: create share link: %w", err)
	}
	l, err := scanShare(s.db.QueryRow(`SELECT `+shareCols+` FROM share_links WHERE id = ?`, id))
	if err != nil {
		return ShareLink{}, "", err
	}
	l.Token = plain
	return l, plain, nil
}

// LookupShareLink resolves a link secret. Unknown, revoked and expired links
// are all ErrNotFound.
func (s *Store) LookupShareLink(plaintext string) (ShareLink, Workspace, error) {
	now := fmtTime(s.now())
	l, err := scanShare(s.db.QueryRow(`SELECT `+shareCols+` FROM share_links
		WHERE token_hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
		hashSecret(plaintext), now))
	if err != nil {
		return ShareLink{}, Workspace{}, mapNoRows(err)
	}
	ws, err := s.GetWorkspace(l.WorkspaceID)
	if err != nil {
		return ShareLink{}, Workspace{}, err
	}
	return l, ws, nil
}

// ListShareLinks returns a workspace's links, newest first, revoked included.
func (s *Store) ListShareLinks(workspaceID string) ([]ShareLink, error) {
	rows, err := s.db.Query(`SELECT `+shareCols+` FROM share_links WHERE workspace_id = ?
		ORDER BY created_at DESC, id DESC`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ShareLink
	for rows.Next() {
		l, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// RevokeShareLink disables a link in the given workspace. Revoking an already
// revoked link succeeds.
func (s *Store) RevokeShareLink(workspaceID, id string) error {
	var one int
	if err := s.db.QueryRow(`SELECT 1 FROM share_links WHERE workspace_id = ? AND id = ?`,
		workspaceID, id).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	_, err := s.db.Exec(`UPDATE share_links SET revoked_at = ? WHERE workspace_id = ? AND id = ? AND revoked_at IS NULL`,
		fmtTime(s.now()), workspaceID, id)
	return err
}

// Stats is the dashboard summary.
type Stats struct {
	Hosts, Bundles, Alerts int
	LastBundleAt           *time.Time
}

// WorkspaceStats counts a workspace's hosts, bundles and alerts and reports
// when it last received a bundle.
func (s *Store) WorkspaceStats(workspaceID string) (Stats, error) {
	var st Stats
	var last sql.NullString
	err := s.db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM hosts WHERE workspace_id = ?1),
		(SELECT COUNT(*) FROM bundles WHERE workspace_id = ?1),
		(SELECT COUNT(*) FROM alerts WHERE workspace_id = ?1),
		(SELECT MAX(received_at) FROM bundles WHERE workspace_id = ?1)`, workspaceID).
		Scan(&st.Hosts, &st.Bundles, &st.Alerts, &last)
	if err != nil {
		return Stats{}, err
	}
	st.LastBundleAt, err = parseTimePtr(last)
	return st, err
}
