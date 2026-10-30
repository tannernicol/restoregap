// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package globmatch

import "testing"

// A command guard must not be evadable by spelling the same invocation
// differently. path.Match's "* does not cross /" rule made every command guard
// bypassable with an absolute path, which is exactly the form systemd units and
// PATH-less contexts are obliged to use.
func TestMatchCommandIgnoresPathSeparators(t *testing.T) {
	for _, tc := range []struct {
		pattern, command string
		want             bool
	}{
		{"*caddy*", "caddy reload", true},
		{"*caddy*", "/usr/bin/caddy reload", true},
		{"*caddy*", "sudo /usr/bin/caddy reload", true},
		{"*caddy*", "/usr/local/bin/caddy --config x", true},
		{"*firewall-cmd*", "/usr/bin/firewall-cmd --reload", true},
		{"*tailscale*", "/usr/bin/tailscale set --advertise-exit-node", true},
		// Applied over the HTTP API, so no binary-name glob would ever see it.
		{"*tailscale*", "curl -X POST https://api.tailscale.com/api/v2/tailnet/-/acl", true},

		// Must still not match unrelated commands: widening the separator rule
		// must not turn every guard into a catch-all.
		{"*caddy*", "systemctl restart nginx", false},
		{"*tailscale*", "rm -rf /tmp/x", false},
		{"*caddy*", "", false},
	} {
		if got := MatchCommand(tc.pattern, tc.command); got != tc.want {
			t.Errorf("MatchCommand(%q, %q) = %v, want %v", tc.pattern, tc.command, got, tc.want)
		}
	}
}

// Paths and actors keep path.Match semantics: "/" stays a real separator there,
// so this fix must not leak into them.
func TestMatchStillTreatsSlashAsSeparator(t *testing.T) {
	if Match("*.tmp", "a/b.tmp") {
		t.Error("Match must not let * cross /; paths and actors depend on that")
	}
	if !Match("agent/*", "agent/claude") {
		t.Error("actor globs must still match across an explicit separator")
	}
}

func TestMatchCommandAny(t *testing.T) {
	pats := []string{"*firewall-cmd*", "*tailscale*", "*caddy*"}
	if !MatchCommandAny(pats, "/usr/bin/caddy reload") {
		t.Error("MatchCommandAny missed an absolute-path invocation")
	}
	if MatchCommandAny(pats, "echo hello") {
		t.Error("MatchCommandAny matched an unrelated command")
	}
	if MatchCommandAny(nil, "caddy reload") {
		t.Error("an empty pattern list must match nothing")
	}
}
