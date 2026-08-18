// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package globmatch

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"nvidia*", "nvidia-driver", true},
		{"nvidia*", "mesa", false},
		{"openclaw*", "openclaw update", true},
		{"agent/*", "agent/claude", true},
		{"agent/*", "human/tanner", false},
		{"*", "anything", true},
		{"", "", true},
		{"", "x", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.name); got != c.want {
			t.Errorf("Match(%q,%q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"~/.ssh/id_*", "~/.ssh/id_ed25519", true},
		{"~/.ssh/id_*", "~/.ssh/known_hosts", false},
		{"recovery-usb/**", "recovery-usb/bundle/kit.tar", true},
		{"recovery-usb/**", "recovery-usb", true},
		{"**/authorized_keys", "~/.ssh/authorized_keys", true},
		{"**/authorized_keys", "authorized_keys", true},
		{"runbooks/**", "src/runbooks/x", false},
		{"Caddyfile", "Caddyfile", true},
		{"Caddyfile", "sub/Caddyfile", false},
		{"**/Caddyfile", "sub/Caddyfile", true},
	}
	for _, c := range cases {
		if got := MatchPath(c.pattern, c.name); got != c.want {
			t.Errorf("MatchPath(%q,%q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestMatchAnyEmptyPatternsMatchesNothing(t *testing.T) {
	if MatchAny(nil, "anything") {
		t.Error("MatchAny(nil, ...) should be false — no patterns means matcher not in use")
	}
	if MatchPathAny(nil, "anything") {
		t.Error("MatchPathAny(nil, ...) should be false")
	}
}

func TestMatchPathExpandsHome(t *testing.T) {
	oldHome := homeDir
	homeDir = "/home/user"
	defer func() { homeDir = oldHome }()
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"~/.ssh/id_ed25519", "/home/user/.ssh/id_ed25519", true},
		{"/home/user/.ssh/id_ed25519", "~/.ssh/id_ed25519", true},
		{"~/.ssh/id_*", "/home/user/.ssh/id_rsa", true},
		{"~/.openclaw/credentials/**", "/home/user/.openclaw/credentials/t/creds.json", true},
		{"~/.ssh/id_ed25519", "/home/other/.ssh/id_ed25519", false},
	}
	for _, c := range cases {
		if got := MatchPath(c.pattern, c.name); got != c.want {
			t.Errorf("MatchPath(%q,%q)=%v want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestIsAncestor(t *testing.T) {
	cases := []struct {
		intentPath, guardPattern string
		want                     bool
	}{
		// parent / grandparent of a guarded file
		{"/home/user/.ssh", "/home/user/.ssh/id_ed25519", true},
		{"/home/user", "/home/user/.ssh/id_ed25519", true},
		// the guarded path itself is not a *proper* ancestor (exact match is
		// MatchPath's job, not IsAncestor's)
		{"/home/user/.ssh/id_ed25519", "/home/user/.ssh/id_ed25519", false},
		// prefix must end at a path boundary
		{"/home/user/.ss", "/home/user/.ssh/id_ed25519", false},
		// sibling
		{"/home/user/.config", "/home/user/.ssh/id_ed25519", false},
		// home expansion + a trailing slash / "." segment on either side
		{"~/.ssh", "/home/user/.ssh/id_ed25519", false}, // different home unless HOME=/home/user; boundary/normalize case below
		{"/home/user/.ssh/", "/home/user/.ssh/id_ed25519", true},
		{"/home/user/./.ssh", "/home/user/.ssh/id_ed25519", true},
		// guard glob: ancestor matches the glob's literal prefix
		{"/home/user", "/home/user/.ssh/*", true},
		{"/home/user/.ssh", "/home/user/.ssh/*", true},
		{"/home/user/.config", "/home/user/.ssh/*", false},
		{"/home/user/backups", "/home/user/**", false}, // below the prefix — MatchPath handles this, not IsAncestor
		{"/home/user", "/home/user/**", true},          // at the prefix, wildcard reaches below
		// empty intent path never an ancestor
		{"", "/home/user/.ssh/id_ed25519", false},
	}
	for _, c := range cases {
		if got := IsAncestor(c.intentPath, c.guardPattern); got != c.want {
			t.Errorf("IsAncestor(%q,%q) = %v, want %v", c.intentPath, c.guardPattern, got, c.want)
		}
	}
}
