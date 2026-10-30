// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package ledger

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestNewULIDAllZeroVector(t *testing.T) {
	zero := bytes.NewReader(make([]byte, 10))
	id, err := NewULID(time.UnixMilli(0), zero)
	if err != nil {
		t.Fatalf("NewULID: %v", err)
	}
	want := strings.Repeat("0", 26)
	if id != want {
		t.Errorf("all-zero ULID = %q, want %q", id, want)
	}
}

func TestNewULIDLengthAndCharset(t *testing.T) {
	id, err := NewULID(time.Now(), rand.Reader)
	if err != nil {
		t.Fatalf("NewULID: %v", err)
	}
	if len(id) != 26 {
		t.Fatalf("len = %d, want 26", len(id))
	}
	for _, c := range id {
		if !strings.ContainsRune(crockfordAlphabet, c) {
			t.Errorf("character %q not in Crockford alphabet", c)
		}
	}
}

func TestULIDRoundTripsTimestamp(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	id, err := NewULID(now, rand.Reader)
	if err != nil {
		t.Fatalf("NewULID: %v", err)
	}
	decoded, err := DecodeTime(id)
	if err != nil {
		t.Fatalf("DecodeTime: %v", err)
	}
	if !decoded.Equal(now) {
		t.Errorf("decoded time = %s, want %s", decoded, now)
	}
}

func TestULIDMonotonicAcrossMilliseconds(t *testing.T) {
	// Same (zero) random tail both times isolates the timestamp's effect on
	// lexicographic ordering.
	t1 := time.UnixMilli(1000)
	t2 := time.UnixMilli(1001)
	id1, err := NewULID(t1, bytes.NewReader(make([]byte, 10)))
	if err != nil {
		t.Fatalf("NewULID: %v", err)
	}
	id2, err := NewULID(t2, bytes.NewReader(make([]byte, 10)))
	if err != nil {
		t.Fatalf("NewULID: %v", err)
	}
	if id1 >= id2 {
		t.Errorf("id1=%s should sort before id2=%s (later timestamp)", id1, id2)
	}
}

func TestNewULIDNegativeTimestampRejected(t *testing.T) {
	_, err := NewULID(time.UnixMilli(-1), rand.Reader)
	if err == nil {
		t.Fatal("expected error for negative timestamp")
	}
}
