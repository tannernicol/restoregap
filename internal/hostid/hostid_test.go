// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package hostid

import (
	"regexp"
	"testing"
)

func TestHostIDEpochShapes(t *testing.T) {
	id := hostID("0123456789abcdef0123456789abcdef", "somehost")
	if len(id) != 16 {
		t.Fatalf("host id must be 16 hex chars, got %q", id)
	}
	if !isHex(id) {
		t.Fatalf("host id must be hex, got %q", id)
	}
	ep := epochID("0123456789abcdef0123456789abcdef", "1111-2222")
	if len(ep) != 12 {
		t.Fatalf("epoch must be 12 hex chars, got %q", ep)
	}
	if !isHex(ep) {
		t.Fatalf("epoch must be hex, got %q", ep)
	}
}

func TestEpochChangesWithFilesystem(t *testing.T) {
	mid := "0123456789abcdef0123456789abcdef"
	if epochID(mid, "uuid-a") == epochID(mid, "uuid-b") {
		t.Fatal("a reinstall (new root fs UUID) must start a new epoch")
	}
	first := epochID(mid, "uuid-a")
	second := epochID(mid, "uuid-a")
	if first != second {
		t.Fatal("epoch must be deterministic for the same machine id + fs UUID")
	}
}

func TestHostIDFallbackDiffersFromMachineID(t *testing.T) {
	// Same machine-id and hostname, but a different machine-id must yield a
	// different host id — the id exists to tell hosts apart.
	if hostID("aaa", "h") == hostID("bbb", "h") {
		t.Fatal("different machine ids must produce different host ids")
	}
}

func TestOverride(t *testing.T) {
	Override = &Identity{HostName: "testhost", HostID: "0123456789abcdef", Epoch: "0123456789ab"}
	defer func() { Override = nil }()
	got := Current()
	if got != *Override {
		t.Fatalf("Current must honor Override, got %+v", got)
	}
	if s := got.String(); !regexp.MustCompile(`^host testhost \(0123456789abcdef\) · epoch 0123456789ab$`).MatchString(s) {
		t.Fatalf("unexpected String form: %q", s)
	}
}

func TestCurrentOnThisMachine(t *testing.T) {
	id := Current()
	if id.HostID == "" || len(id.HostID) != 16 {
		t.Fatalf("current host id must resolve to 16 hex chars, got %q", id.HostID)
	}
	if id.Epoch == "" || len(id.Epoch) != 12 {
		t.Fatalf("current epoch must resolve to 12 hex chars, got %q", id.Epoch)
	}
	if id.HostName == "" {
		t.Fatal("current host name must not be empty")
	}
}

func isHex(s string) bool {
	for _, c := range s {
		digit := c >= '0' && c <= '9'
		hexLetter := c >= 'a' && c <= 'f'
		if !digit && !hexLetter {
			return false
		}
	}
	return true
}
