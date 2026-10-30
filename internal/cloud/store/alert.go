// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Alert kinds, per docs/CLOUD.md "Monitoring".
const (
	AlertLapsed         = "lapsed"
	AlertRecovered      = "recovered"
	AlertProofRegressed = "proof_regressed"
)

// Alert is a recorded fact about a host: it went silent, came back, or a
// proof's declared state regressed.
type Alert struct {
	ID, WorkspaceID, HostRowID, Kind, Message string
	CreatedAt                                 time.Time
	DeliveredAt                               *time.Time
	DeliveryError                             string
}

const alertCols = `id, workspace_id, host_row_id, kind, message, created_at, delivered_at, delivery_error`

func queryAlerts(s *Store, q string, args ...any) ([]Alert, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var created string
		var delivered sql.NullString
		if err := rows.Scan(&a.ID, &a.WorkspaceID, &a.HostRowID, &a.Kind, &a.Message, &created,
			&delivered, &a.DeliveryError); err != nil {
			return nil, err
		}
		if a.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		if a.DeliveredAt, err = parseTimePtr(delivered); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CreateAlert records an alert, undelivered. Kind must be one of the
// Alert* constants.
func (s *Store) CreateAlert(workspaceID, hostRowID, kind, message string) (Alert, error) {
	switch kind {
	case AlertLapsed, AlertRecovered, AlertProofRegressed:
	default:
		return Alert{}, fmt.Errorf("store: invalid alert kind %q", kind)
	}
	id, err := newID()
	if err != nil {
		return Alert{}, err
	}
	now := s.now()
	if _, err := s.db.Exec(`INSERT INTO alerts (id, workspace_id, host_row_id, kind, message, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, id, workspaceID, hostRowID, kind, message, fmtTime(now)); err != nil {
		return Alert{}, fmt.Errorf("store: create alert: %w", err)
	}
	return Alert{ID: id, WorkspaceID: workspaceID, HostRowID: hostRowID, Kind: kind, Message: message, CreatedAt: now}, nil
}

// ListAlerts returns a workspace's alerts, newest first.
func (s *Store) ListAlerts(workspaceID string, limit int) ([]Alert, error) {
	return queryAlerts(s, `SELECT `+alertCols+` FROM alerts WHERE workspace_id = ?
		ORDER BY created_at DESC, id DESC LIMIT ?`, workspaceID, limitArg(limit))
}

// UndeliveredAlerts returns alerts not yet processed by the notifier, across
// all workspaces, oldest first.
func (s *Store) UndeliveredAlerts(limit int) ([]Alert, error) {
	return queryAlerts(s, `SELECT `+alertCols+` FROM alerts WHERE delivered_at IS NULL
		ORDER BY created_at, id LIMIT ?`, limitArg(limit))
}

// MarkAlertDelivered records that the notifier has dealt with an alert. A
// non-empty errText is kept as DeliveryError but the alert still leaves the
// undelivered queue: otherwise one permanently broken webhook would sit at the
// head of the oldest-first queue and starve every later alert.
func (s *Store) MarkAlertDelivered(id string, at time.Time, errText string) error {
	return requireRows(s.db.Exec(`UPDATE alerts SET delivered_at = ?, delivery_error = ? WHERE id = ?`,
		fmtTime(at), errText, id))
}
