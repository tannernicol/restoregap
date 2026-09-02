// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"strings"
	"testing"
)

// statusFilterFixture spans two layers, two environments, two systems, two
// owners, and a tag — enough to exercise every --layer/--state/--env/
// --system/--owner/--tag axis from one context file.
const statusFilterFixture = `version: 2
scope:
  environment: prod
  system: money
guards:
  - id: ssh-guard
    kind: lifeline
    match: {paths: ["~/.ssh/id_ed25519"]}
    layer: identity-secrets
    scope: {owner: tanner, tags: [cold-metal]}
    requires: {proofs: [ssh-key-recovery]}
  - id: git-guard
    kind: guard
    match: {paths: ["/repo/**"]}
    layer: git-code
    scope: {environment: lab, system: obsidian, owner: someone-else}
    requires: {proofs: [git-estate-recovery]}
proofs:
  - id: ssh-key-recovery
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
  - id: git-estate-recovery
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
`

func runStatus(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newStatusCmd()
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// TestStatusLayerFlagNarrowsTree: --layer prints only that layer's proofs,
// unfiltered status prints both layers' — the flag filters, it never
// replaces the section with something else.
func TestStatusLayerFlagNarrowsTree(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", statusFilterFixture)

	out, err := runStatus(t, "--context", ctxPath, "--layer", "identity-secrets")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	if !strings.Contains(out, "ssh-key-recovery") {
		t.Errorf("expected the identity-secrets proof, got:\n%s", out)
	}
	if strings.Contains(out, "git-estate-recovery") {
		t.Errorf("--layer identity-secrets must not show a git-code proof, got:\n%s", out)
	}

	full, err := runStatus(t, "--context", ctxPath)
	if err != nil {
		t.Fatalf("Execute (unfiltered): %v (%s)", err, full)
	}
	if !strings.Contains(full, "ssh-key-recovery") || !strings.Contains(full, "git-estate-recovery") {
		t.Errorf("unfiltered status must show both proofs, got:\n%s", full)
	}
}

// TestStatusStateFlagNarrowsTree: --state keeps only proofs in that state.
// Both fixture proofs are unreviewed attestations, so --state unreviewed
// shows them and --state restored shows none of the tree at all.
func TestStatusStateFlagNarrowsTree(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", statusFilterFixture)

	out, err := runStatus(t, "--context", ctxPath, "--state", "unreviewed")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	if !strings.Contains(out, "ssh-key-recovery") {
		t.Errorf("expected the unreviewed proof, got:\n%s", out)
	}

	restored, err := runStatus(t, "--context", ctxPath, "--state", "restored")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, restored)
	}
	if strings.Contains(restored, "Recovery taxonomy") {
		t.Errorf("--state restored must leave an empty (omitted) tree, got:\n%s", restored)
	}
}

// TestStatusStateFlagAcceptsEveryStateName exercises `status --state <x>`
// for every valid state name (the taxonomy spec's refined vocabulary) plus
// the "attention" meta-value, against a fixture that has at least one
// matching proof for each — printing nothing for a valid name (other than
// the deliberately-empty ones this fixture has none of) is a bug.
func TestStatusStateFlagAcceptsEveryStateName(t *testing.T) {
	const fixture = `version: 2
guards:
  - id: restored-guard
    kind: guard
    match: {paths: ["/data/restored"]}
    requires: {proofs: [restored-proof]}
  - id: observed-guard
    kind: guard
    match: {paths: ["/data/observed"]}
    requires: {proofs: [observed-proof]}
  - id: accepted-guard
    kind: guard
    match: {paths: ["/data/accepted"]}
    requires: {proofs: [accepted-proof]}
  - id: unreviewed-guard
    kind: guard
    match: {paths: ["/data/unreviewed"]}
    requires: {proofs: [unreviewed-proof]}
  - id: disputed-guard
    kind: guard
    match: {paths: ["/data/disputed"]}
    requires: {proofs: [disputed-proof]}
  - id: expired-guard
    kind: guard
    match: {paths: ["/data/expired"]}
    requires: {proofs: [expired-proof]}
  - id: unreachable-guard
    kind: guard
    match: {paths: ["/data/unreachable"]}
    requires: {proofs: [unreachable-proof]}
  - id: lapsed-guard
    kind: guard
    match: {paths: ["/data/lapsed"]}
    requires: {proofs: [lapsed-proof]}
proofs:
  - id: restored-proof
    status: validated
    observed_at: "2026-08-20T00:00:00Z"
    verified: true
  - id: observed-proof
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
    expires_at: "2099-01-01T00:00:00Z"
  - id: accepted-proof
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
    accepted: {by: owner/tanner, at: "2026-08-20T00:00:00Z", reason: cannot drill, review_by: "2099-01-01T00:00:00Z"}
  - id: unreviewed-proof
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
  - id: disputed-proof
    status: disputed
    observed_at: "2026-08-20T00:00:00Z"
  - id: expired-proof
    status: observed
    observed_at: "2020-01-01T00:00:00Z"
    expires_at: "2020-01-02T00:00:00Z"
  - id: unreachable-proof
    status: unreachable
    observed_at: "2026-08-20T00:00:00Z"
  - id: lapsed-proof
    status: observed
    observed_at: "2020-01-01T00:00:00Z"
    accepted: {by: owner/tanner, at: "2020-01-01T00:00:00Z", reason: cannot drill, review_by: "2020-02-01T00:00:00Z"}
`
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", fixture)
	cases := map[string]string{
		"restored":    "restored-proof",
		"observed":    "observed-proof",
		"accepted":    "accepted-proof",
		"unreviewed":  "unreviewed-proof",
		"disputed":    "disputed-proof",
		"expired":     "expired-proof",
		"unreachable": "unreachable-proof",
		"lapsed":      "lapsed-proof",
	}
	for state, want := range cases {
		out, err := runStatus(t, "--context", ctxPath, "--state", state)
		if err != nil {
			t.Fatalf("--state %s: Execute: %v (%s)", state, err, out)
		}
		if !strings.Contains(out, want) {
			t.Errorf("--state %s printed nothing for a valid name — expected %s, got:\n%s", state, want, out)
		}
	}

	// The "attention" meta-value must match all four attention states at once.
	out, err := runStatus(t, "--context", ctxPath, "--state", "attention")
	if err != nil {
		t.Fatalf("--state attention: Execute: %v (%s)", err, out)
	}
	for _, want := range []string{"disputed-proof", "expired-proof", "unreachable-proof", "lapsed-proof"} {
		if !strings.Contains(out, want) {
			t.Errorf("--state attention missing %s, got:\n%s", want, out)
		}
	}
	for _, notWant := range []string{"restored-proof", "observed-proof", "accepted-proof", "unreviewed-proof"} {
		if strings.Contains(out, notWant) {
			t.Errorf("--state attention must not match %s, got:\n%s", notWant, out)
		}
	}
}

// TestStatusScopeFlagsNarrowTree: --env/--system/--owner/--tag filter on the
// scope axes the same way --layer filters on the layer axis.
func TestStatusScopeFlagsNarrowTree(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", statusFilterFixture)

	cases := []struct {
		flag, value, want, notWant string
	}{
		{"--env", "prod", "ssh-key-recovery", "git-estate-recovery"},
		{"--env", "lab", "git-estate-recovery", "ssh-key-recovery"},
		{"--system", "obsidian", "git-estate-recovery", "ssh-key-recovery"},
		{"--owner", "tanner", "ssh-key-recovery", "git-estate-recovery"},
		{"--tag", "cold-metal", "ssh-key-recovery", "git-estate-recovery"},
	}
	for _, c := range cases {
		out, err := runStatus(t, "--context", ctxPath, c.flag, c.value)
		if err != nil {
			t.Fatalf("Execute %s %s: %v (%s)", c.flag, c.value, err, out)
		}
		if !strings.Contains(out, c.want) {
			t.Errorf("%s %s: expected %s, got:\n%s", c.flag, c.value, c.want, out)
		}
		if strings.Contains(out, c.notWant) {
			t.Errorf("%s %s: must not show %s, got:\n%s", c.flag, c.value, c.notWant, out)
		}
	}
}

// TestStatusFiltersAreTextOnly: --layer with --format json (or html) is
// refused with an explanation — json always emits everything for a
// downstream merge, html filters client-side via its chips.
func TestStatusFiltersAreTextOnly(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", statusFilterFixture)
	for _, format := range []string{"json", "html"} {
		out, err := runStatus(t, "--context", ctxPath, "--layer", "identity-secrets", "--format", format)
		if err == nil {
			t.Errorf("--layer with --format %s must error, got:\n%s", format, out)
		}
		if err == nil || !strings.Contains(err.Error(), "text-only") {
			t.Errorf("expected the text-only explanation for --format %s, got: %v (%s)", format, err, out)
		}
	}
}

// TestStatusJSONEmitsFullScope: --format json prints every proof with its
// effective layer/category/state/scope — the multi-host merge document
// (taxonomy spec section F).
func TestStatusJSONEmitsFullScope(t *testing.T) {
	ctxPath := writeFile(t, t.TempDir(), "restoregap.yml", statusFilterFixture)

	out, err := runStatus(t, "--context", ctxPath, "--format", "json")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	for _, want := range []string{
		`"id": "ssh-key-recovery"`,
		`"layer": "identity-secrets"`,
		`"environment": "prod"`,
		`"system": "money"`,
		`"owner": "tanner"`,
		`"id": "git-estate-recovery"`,
		`"environment": "lab"`,
		`"state": "unreviewed"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status --format json missing %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"context_file": ""`) {
		t.Errorf("status --format json must fill context_file for every proof (both fixture proofs are declared in ctxPath), got:\n%s", out)
	}
	if !strings.Contains(out, `"context_file": "`+ctxPath+`"`) {
		t.Errorf("status --format json context_file must name the declaring file (%s), got:\n%s", ctxPath, out)
	}
}
