// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Restore Gap contributors

package shellintent

import (
	"net/netip"
	"strings"
)

// maxSpellings bounds the alternative prefixes one wrapper may carry. Nested
// ssh hosts multiply their spellings, and a line built to multiply them must
// fail the parse rather than make it exponential.
const maxSpellings = 16

// hostSpellings returns an ssh destination host as typed, followed by every
// other spelling ssh could resolve the same text to. Coverage and guards are
// globs over command text, so `ssh 192.0.521 x`, `ssh NAS x` and
// `ssh 192.0.2.9 x` must each be checked in the form a policy names.
//
// It is pure and offline: it never runs ssh -G, reads ssh_config or asks DNS,
// so an ssh_config alias is still only its own name. A hostname is lowercased
// and loses a trailing dot. An IPv6 literal loses its brackets and zone and is
// written in the compressed form ssh -G prints. A numeric IPv4 spelling becomes
// a dotted quad; where the C libraries read one differently, every reading is
// returned (see inetAton and dottedDecimal).
func hostSpellings(host string) []string {
	out := []string{host}
	add := func(s string) {
		for _, have := range out {
			if have == s {
				return
			}
		}
		out = append(out, s)
	}
	h := host
	if len(h) > 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	if strings.Contains(h, ":") {
		addr, _, _ := strings.Cut(h, "%")
		if ip, err := netip.ParseAddr(addr); err == nil {
			add(ip.String())
		} else {
			add(strings.ToLower(h))
		}
		return out
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	readings := 0
	for _, read := range []func(string) (string, bool){inetAton, dottedDecimal} {
		if ip, ok := read(h); ok {
			add(ip)
			readings++
		}
	}
	if readings == 0 && h != "" {
		add(h)
	}
	return out
}

// inetAton reads s the way inet_aton(3), and getaddrinfo(3) through it, do:
// one to four dot-separated parts, each decimal, octal (leading 0) or hex
// (leading 0x), where the last part fills the remaining bytes, so 192.0.521
// and 3221225993 are 192.0.2.9. macOS lets each part wrap at 64 bits and a
// lone part at 32 bits (7516193289 is 192.0.2.9 there); glibc rejects those
// values instead, so reading them as macOS does only ever adds a spelling.
func inetAton(s string) (string, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return "", false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		v, ok := atonPart(p)
		if !ok {
			return "", false
		}
		vals[i] = v
	}
	last := len(vals) - 1
	if last == 0 {
		return dottedQuad(uint32(vals[0])), true
	}
	var addr uint32
	for i, v := range vals[:last] {
		if v > 0xff {
			return "", false
		}
		addr |= uint32(v) << (24 - 8*i)
	}
	if vals[last] > 0xffffffff>>(8*last) {
		return "", false
	}
	return dottedQuad(addr | uint32(vals[last])), true
}

// atonPart parses one inet_aton part. The value wraps at 64 bits, as macOS
// accumulates it; "0x" with no digits and an 8 or 9 after a leading 0 are
// invalid everywhere.
func atonPart(p string) (uint64, bool) {
	base, digits := uint64(10), p
	switch {
	case len(p) > 1 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'):
		base, digits = 16, p[2:]
	case len(p) > 1 && p[0] == '0':
		base, digits = 8, p[1:]
	}
	if digits == "" {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(digits); i++ {
		d, ok := digitValue(digits[i])
		if !ok || d >= base {
			return 0, false
		}
		v = v*base + d
	}
	return v, true
}

func digitValue(c byte) (uint64, bool) {
	switch {
	case c >= '0' && c <= '9':
		return uint64(c - '0'), true
	case c >= 'a' && c <= 'f':
		return uint64(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return uint64(c-'A') + 10, true
	}
	return 0, false
}

// dottedDecimal reads exactly four decimal parts of up to 255, leading zeros
// allowed and still decimal. macOS getaddrinfo(3) tries this before inet_aton,
// so there 192.0.02.010 is 192.0.2.10, where inet_aton reads 192.0.2.8,
// and 192.0.002.009, which inet_aton rejects, is 192.0.2.9.
func dottedDecimal(s string) (string, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return "", false
	}
	var addr uint32
	for _, p := range parts {
		if p == "" {
			return "", false
		}
		v := 0
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return "", false
			}
			if v = v*10 + int(p[i]-'0'); v > 0xff {
				return "", false
			}
		}
		addr = addr<<8 | uint32(v)
	}
	return dottedQuad(addr), true
}

func dottedQuad(addr uint32) string {
	return netip.AddrFrom4([4]byte{byte(addr >> 24), byte(addr >> 16), byte(addr >> 8), byte(addr)}).String()
}
