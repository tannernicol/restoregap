// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package report

import "encoding/json"

// JSON renders r as indented, stable-key JSON (struct field order == JSON
// key order, matching the schema documented in docs/ARCHITECTURE.md).
func (r Report) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
