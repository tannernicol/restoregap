// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import "testing"

func TestDrillRejectsNonPositiveTimeout(t *testing.T) {
	cmd := newDrillCmd()
	cmd.SetArgs([]string{"--timeout", "0s"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected non-positive timeout to be rejected")
	}
}
