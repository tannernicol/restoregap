// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package store

import (
	"database/sql"
	"fmt"
	"time"
)

// APIToken is a push token. The plaintext exists only in the CreateToken
// return value; Prefix is the first 8 characters, for display.
type APIToken struct {
	ID, WorkspaceID, Name, Prefix string
	CreatedAt                     time.Time
	LastUsedAt, RevokedAt         *time.Time
}

const tokCols = `id, workspace_id, name, prefix, created_at, last_used_at, revoked_at`

func scanToken(sc scanner) (APIToken, error) {
	var t APIToken
	var created string
	var used, revoked sql.NullString
	if err := sc.Scan(&t.ID, &t.WorkspaceID, &t.Name, &t.Prefix, &created, &used, &revoked); err != nil {
		return APIToken{}, err
	}
	var err error
	if t.CreatedAt, err = parseTime(created); err != nil {
		return APIToken{}, err
	}
	if t.LastUsedAt, err = parseTimePtr(used); err != nil {
		return APIToken{}, err
	}
	t.RevokedAt, err = parseTimePtr(revoked)
	return t, err
}

// CreateToken mints "rgp_" + 32 random bytes (base64url) for a workspace.
func (s *Store) CreateToken(workspaceID, name string) (APIToken, string, error) {
	plain, err := newSecret("rgp_")
	if err != nil {
		return APIToken{}, "", err
	}
	id, err := newID()
	if err != nil {
		return APIToken{}, "", err
	}
	now := s.now()
	if _, err := s.db.Exec(`INSERT INTO api_tokens (id, workspace_id, name, prefix, token_hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, id, workspaceID, name, plain[:8], hashSecret(plain), fmtTime(now)); err != nil {
		return APIToken{}, "", fmt.Errorf("store: create token: %w", err)
	}
	tok, err := scanToken(s.db.QueryRow(`SELECT `+tokCols+` FROM api_tokens WHERE id = ?`, id))
	if err != nil {
		return APIToken{}, "", err
	}
	return tok, plain, nil
}

// LookupToken authenticates a push token and bumps LastUsedAt. Unknown and
// revoked tokens are indistinguishable (ErrNotFound).
func (s *Store) LookupToken(plaintext string) (APIToken, Workspace, error) {
	now := s.now()
	row := s.db.QueryRow(`UPDATE api_tokens SET last_used_at = ?
		WHERE token_hash = ? AND revoked_at IS NULL RETURNING `+tokCols, fmtTime(now), hashSecret(plaintext))
	tok, err := scanToken(row)
	if err != nil {
		return APIToken{}, Workspace{}, mapNoRows(err)
	}
	ws, err := s.GetWorkspace(tok.WorkspaceID)
	if err != nil {
		return APIToken{}, Workspace{}, err
	}
	return tok, ws, nil
}

// RevokeToken disables a token in the given workspace. Scoping the lookup by
// workspace means a handler holding only a user-supplied id can never revoke
// another tenant's token. Revoking an already revoked token succeeds.
func (s *Store) RevokeToken(workspaceID, id string) error {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM api_tokens WHERE workspace_id = ? AND id = ?`,
		workspaceID, id).Scan(&one)
	if err != nil {
		return mapNoRows(err)
	}
	_, err = s.db.Exec(`UPDATE api_tokens SET revoked_at = ? WHERE workspace_id = ? AND id = ? AND revoked_at IS NULL`,
		fmtTime(s.now()), workspaceID, id)
	return err
}

// ListTokens returns a workspace's tokens, newest first, revoked included.
func (s *Store) ListTokens(workspaceID string) ([]APIToken, error) {
	rows, err := s.db.Query(`SELECT `+tokCols+` FROM api_tokens WHERE workspace_id = ?
		ORDER BY created_at DESC, id DESC`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
