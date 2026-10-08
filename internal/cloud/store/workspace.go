// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Workspace is the tenant: hosts, tokens, alerts and billing hang off it.
type Workspace struct {
	ID, Name             string
	Plan                 string // solo | team | fleet | unlimited
	BillingStatus        string // trialing | active | past_due | canceled | unlimited
	StripeCustomerID     string
	StripeSubscriptionID string
	TrialEndsAt          *time.Time
	NotifyEmail          string
	NotifyWebhookURL     string
	NotifyWebhookSecret  string
	CreatedAt            time.Time
}

// User is a person who logs in by magic link. Email is stored lowercase.
type User struct {
	ID, Email string
	CreatedAt time.Time
}

// Membership ties a user to a workspace. Role is "owner" or "member".
type Membership struct {
	WorkspaceID, UserID, Role string
}

// Session is a logged-in browser session scoped to one workspace.
type Session struct {
	ID, UserID, WorkspaceID string
	ExpiresAt               time.Time
}

var (
	validPlans    = map[string]bool{"solo": true, "team": true, "fleet": true, "unlimited": true}
	validStatuses = map[string]bool{"trialing": true, "active": true, "past_due": true, "canceled": true, "unlimited": true}
	validRoles    = map[string]bool{"owner": true, "member": true}
)

func checkPlanStatus(plan, status string) error {
	if !validPlans[plan] {
		return fmt.Errorf("store: invalid plan %q", plan)
	}
	if !validStatuses[status] {
		return fmt.Errorf("store: invalid billing status %q", status)
	}
	return nil
}

const wsCols = `id, name, plan, billing_status, stripe_customer_id, stripe_subscription_id,
	trial_ends_at, notify_email, notify_webhook_url, notify_webhook_secret, created_at`

func scanWorkspace(sc scanner) (Workspace, error) {
	var w Workspace
	var trial sql.NullString
	var created string
	err := sc.Scan(&w.ID, &w.Name, &w.Plan, &w.BillingStatus, &w.StripeCustomerID,
		&w.StripeSubscriptionID, &trial, &w.NotifyEmail, &w.NotifyWebhookURL,
		&w.NotifyWebhookSecret, &created)
	if err != nil {
		return Workspace{}, err
	}
	if w.TrialEndsAt, err = parseTimePtr(trial); err != nil {
		return Workspace{}, err
	}
	if w.CreatedAt, err = parseTime(created); err != nil {
		return Workspace{}, err
	}
	return w, nil
}

// CreateWorkspace inserts a workspace and, when ownerUserID is non-empty, an
// owner membership in the same transaction. An empty owner is allowed so the
// admin CLI can create a workspace before anyone has logged in.
func (s *Store) CreateWorkspace(name, plan, status string, trialEnds *time.Time, ownerUserID string) (Workspace, error) {
	if strings.TrimSpace(name) == "" {
		return Workspace{}, errors.New("store: workspace name required")
	}
	if err := checkPlanStatus(plan, status); err != nil {
		return Workspace{}, err
	}
	id, err := newID()
	if err != nil {
		return Workspace{}, err
	}
	now := s.now()
	tx, err := s.db.Begin()
	if err != nil {
		return Workspace{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO workspaces (id, name, plan, billing_status, trial_ends_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, id, name, plan, status, fmtTimePtr(trialEnds), fmtTime(now)); err != nil {
		return Workspace{}, fmt.Errorf("store: create workspace: %w", err)
	}
	if ownerUserID != "" {
		if _, err := tx.Exec(`INSERT INTO memberships (workspace_id, user_id, role) VALUES (?, ?, 'owner')`,
			id, ownerUserID); err != nil {
			return Workspace{}, fmt.Errorf("store: create owner membership: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Workspace{}, err
	}
	return s.GetWorkspace(id)
}

// GetWorkspace returns one workspace by id.
func (s *Store) GetWorkspace(id string) (Workspace, error) {
	w, err := scanWorkspace(s.db.QueryRow(`SELECT `+wsCols+` FROM workspaces WHERE id = ?`, id))
	return w, mapNoRows(err)
}

// WorkspaceByStripeCustomer resolves a Stripe webhook to its workspace.
func (s *Store) WorkspaceByStripeCustomer(customerID string) (Workspace, error) {
	if customerID == "" {
		return Workspace{}, ErrNotFound // '' means "no customer yet" in the table
	}
	w, err := scanWorkspace(s.db.QueryRow(`SELECT `+wsCols+` FROM workspaces WHERE stripe_customer_id = ?`, customerID))
	return w, mapNoRows(err)
}

// ListWorkspaces returns every workspace, oldest first.
func (s *Store) ListWorkspaces() ([]Workspace, error) {
	return s.queryWorkspaces(`SELECT ` + wsCols + ` FROM workspaces ORDER BY created_at, id`)
}

// WorkspacesForUser returns the workspaces a user belongs to, oldest first.
func (s *Store) WorkspacesForUser(userID string) ([]Workspace, error) {
	return s.queryWorkspaces(`SELECT `+wsCols+` FROM workspaces
		WHERE id IN (SELECT workspace_id FROM memberships WHERE user_id = ?)
		ORDER BY created_at, id`, userID)
}

func (s *Store) queryWorkspaces(q string, args ...any) ([]Workspace, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Workspace
	for rows.Next() {
		w, err := scanWorkspace(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// UpdateWorkspaceBilling overwrites plan, status and the Stripe ids. Empty ids
// are stored as empty (no customer / no subscription).
func (s *Store) UpdateWorkspaceBilling(id, plan, status, customerID, subID string, trialEnds *time.Time) error {
	if err := checkPlanStatus(plan, status); err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE workspaces SET plan = ?, billing_status = ?, stripe_customer_id = ?,
		stripe_subscription_id = ?, trial_ends_at = ? WHERE id = ?`,
		plan, status, customerID, subID, fmtTimePtr(trialEnds), id)
	if err != nil && isUnique(err) {
		return fmt.Errorf("%w: stripe customer already attached to another workspace", ErrConflict)
	}
	return requireRows(res, err)
}

// UpdateWorkspaceNotify sets where alerts are delivered.
func (s *Store) UpdateWorkspaceNotify(id, email, webhookURL, webhookSecret string) error {
	return requireRows(s.db.Exec(`UPDATE workspaces SET notify_email = ?, notify_webhook_url = ?,
		notify_webhook_secret = ? WHERE id = ?`, email, webhookURL, webhookSecret, id))
}

// ---- users and memberships ----

func normalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

// GetUser returns a user by id.
func (s *Store) GetUser(id string) (User, error) {
	return scanUser(s.db.QueryRow(`SELECT id, email, created_at FROM users WHERE id = ?`, id))
}

// UserByEmail returns a user by (case-insensitive) email.
func (s *Store) UserByEmail(email string) (User, error) {
	return scanUser(s.db.QueryRow(`SELECT id, email, created_at FROM users WHERE email = ?`, normalizeEmail(email)))
}

func scanUser(sc scanner) (User, error) {
	var u User
	var created string
	if err := sc.Scan(&u.ID, &u.Email, &created); err != nil {
		return User{}, mapNoRows(err)
	}
	var err error
	u.CreatedAt, err = parseTime(created)
	return u, err
}

// AddMembership grants a user a role in a workspace; ErrConflict if present.
func (s *Store) AddMembership(workspaceID, userID, role string) error {
	if !validRoles[role] {
		return fmt.Errorf("store: invalid role %q", role)
	}
	_, err := s.db.Exec(`INSERT INTO memberships (workspace_id, user_id, role) VALUES (?, ?, ?)`,
		workspaceID, userID, role)
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// GetMembership returns a user's role in a workspace, or ErrNotFound.
func (s *Store) GetMembership(workspaceID, userID string) (Membership, error) {
	var m Membership
	err := s.db.QueryRow(`SELECT workspace_id, user_id, role FROM memberships
		WHERE workspace_id = ? AND user_id = ?`, workspaceID, userID).Scan(&m.WorkspaceID, &m.UserID, &m.Role)
	return m, mapNoRows(err)
}

// ---- magic-link login and sessions ----

// CreateLoginToken mints a single-use magic-link secret for an email.
func (s *Store) CreateLoginToken(email string, ttl time.Duration) (string, error) {
	email = normalizeEmail(email)
	if email == "" || !strings.Contains(email, "@") {
		return "", errors.New("store: invalid email")
	}
	plain, err := newSecret("")
	if err != nil {
		return "", err
	}
	now := s.now()
	if _, err := s.db.Exec(`INSERT INTO login_tokens (token_hash, email, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		hashSecret(plain), email, fmtTime(now), fmtTime(now.Add(ttl))); err != nil {
		return "", fmt.Errorf("store: create login token: %w", err)
	}
	return plain, nil
}

// ConsumeLoginToken burns the secret and returns its user, creating the user
// on first login. Use and user creation share a transaction so a failed
// user insert does not leave the link burned.
func (s *Store) ConsumeLoginToken(plaintext string, now time.Time) (User, error) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback() }()

	// The conditional UPDATE is the single-use gate: two racing consumers
	// cannot both match used_at IS NULL.
	var email string
	err = tx.QueryRow(`UPDATE login_tokens SET used_at = ?
		WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? RETURNING email`,
		fmtTime(now), hashSecret(plaintext), fmtTime(now)).Scan(&email)
	if err != nil {
		return User{}, mapNoRows(err)
	}
	u, err := scanUser(tx.QueryRow(`SELECT id, email, created_at FROM users WHERE email = ?`, email))
	if errors.Is(err, ErrNotFound) {
		id, idErr := newID()
		if idErr != nil {
			return User{}, idErr
		}
		if _, err := tx.Exec(`INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)`,
			id, email, fmtTime(now)); err != nil {
			return User{}, fmt.Errorf("store: create user: %w", err)
		}
		u, err = scanUser(tx.QueryRow(`SELECT id, email, created_at FROM users WHERE id = ?`, id))
	}
	if err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return u, nil
}

// CreateSession mints a session secret for a user in a workspace.
func (s *Store) CreateSession(userID, workspaceID string, ttl time.Duration) (string, error) {
	plain, err := newSecret("")
	if err != nil {
		return "", err
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	now := s.now()
	if _, err := s.db.Exec(`INSERT INTO sessions (id, token_hash, user_id, workspace_id, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, id, hashSecret(plain), userID, workspaceID, fmtTime(now), fmtTime(now.Add(ttl))); err != nil {
		return "", fmt.Errorf("store: create session: %w", err)
	}
	return plain, nil
}

// LookupSession resolves a session secret; expired sessions are ErrNotFound.
func (s *Store) LookupSession(plaintext string, now time.Time) (Session, error) {
	var ss Session
	var exp string
	err := s.db.QueryRow(`SELECT id, user_id, workspace_id, expires_at FROM sessions
		WHERE token_hash = ? AND expires_at > ?`, hashSecret(plaintext), fmtTime(now)).
		Scan(&ss.ID, &ss.UserID, &ss.WorkspaceID, &exp)
	if err != nil {
		return Session{}, mapNoRows(err)
	}
	ss.ExpiresAt, err = parseTime(exp)
	return ss, err
}

// DeleteSession logs a session out. Unknown sessions are not an error.
func (s *Store) DeleteSession(plaintext string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, hashSecret(plaintext))
	return err
}
