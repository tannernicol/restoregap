// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package ledger

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"time"
)

// crockfordAlphabet is Crockford's base32 alphabet (excludes I, L, O, U to
// avoid transcription ambiguity), used by ULID.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID generates a ULID for t: a 48-bit millisecond timestamp followed by
// 80 bits read from rnd, encoded as 26 Crockford base32 characters. Callers
// pass crypto/rand.Reader in production and a seeded reader in tests for
// determinism.
func NewULID(t time.Time, rnd io.Reader) (string, error) {
	var data [16]byte
	msSigned := t.UnixMilli()
	if msSigned < 0 {
		return "", fmt.Errorf("ledger: ULID timestamp must not be negative")
	}
	ms := uint64(msSigned)
	data[0] = byte(ms >> 40)
	data[1] = byte(ms >> 32)
	data[2] = byte(ms >> 24)
	data[3] = byte(ms >> 16)
	data[4] = byte(ms >> 8)
	data[5] = byte(ms)
	if _, err := io.ReadFull(rnd, data[6:]); err != nil {
		return "", fmt.Errorf("ledger: ULID entropy: %w", err)
	}
	return encodeCrockford(data[:]), nil
}

// NewID is NewULID using the system CSPRNG and the current time.
func NewID() (string, error) {
	return NewULID(time.Now().UTC(), rand.Reader)
}

// encodeCrockford packs 128 bits (16 bytes, MSB-first) into 26 Crockford
// base32 characters, 5 bits at a time. The final group reads 2 bits past
// the end of data, which read as zero.
func encodeCrockford(data []byte) string {
	const bitsPerChar = 5
	numChars := (len(data)*8 + bitsPerChar - 1) / bitsPerChar
	var sb strings.Builder
	sb.Grow(numChars)
	for i := 0; i < numChars; i++ {
		sb.WriteByte(crockfordAlphabet[readBits(data, i*bitsPerChar, bitsPerChar)])
	}
	return sb.String()
}

// decodeCrockford is the inverse of encodeCrockford, used only by tests to
// round-trip and by DecodeTime to recover a ULID's embedded timestamp.
func decodeCrockford(s string) ([]byte, error) {
	rev := make(map[byte]byte, len(crockfordAlphabet))
	for i := 0; i < len(crockfordAlphabet); i++ {
		rev[crockfordAlphabet[i]] = byte(i)
	}
	out := make([]byte, 16)
	for i, ch := range []byte(s) {
		v, ok := rev[ch]
		if !ok {
			return nil, fmt.Errorf("ledger: invalid ULID character %q", ch)
		}
		writeBits(out, i*5, 5, v)
	}
	return out, nil
}

func readBits(data []byte, bitPos, nBits int) byte {
	var v uint16
	for b := 0; b < nBits; b++ {
		bit := bitPos + b
		byteIdx := bit / 8
		var bitVal uint16
		if byteIdx < len(data) {
			shift := 7 - uint(bit%8)
			bitVal = uint16((data[byteIdx] >> shift) & 1)
		}
		v = (v << 1) | bitVal
	}
	return byte(v)
}

func writeBits(data []byte, bitPos, nBits int, value byte) {
	for b := 0; b < nBits; b++ {
		bit := bitPos + (nBits - 1 - b)
		byteIdx := bit / 8
		if byteIdx >= len(data) {
			continue
		}
		shift := 7 - uint(bit%8)
		if (value>>b)&1 == 1 {
			data[byteIdx] |= 1 << shift
		}
	}
}

// DecodeTime recovers the millisecond timestamp embedded in a ULID.
func DecodeTime(id string) (time.Time, error) {
	if len(id) != 26 {
		return time.Time{}, fmt.Errorf("ledger: ULID must be 26 characters, got %d", len(id))
	}
	data, err := decodeCrockford(id)
	if err != nil {
		return time.Time{}, err
	}
	ms := uint64(data[0])<<40 | uint64(data[1])<<32 | uint64(data[2])<<24 |
		uint64(data[3])<<16 | uint64(data[4])<<8 | uint64(data[5])
	return time.UnixMilli(int64(ms)).UTC(), nil
}
