// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package contextspec

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const minimalGuardYAML = `version: 2
guards:
  - id: portable-recovery-kit
    kind: lifeline
    match:
      paths: ["recovery-usb/**", "runbooks/**"]
    requires:
      proofs: [kit-restore-drill]
    enforcement: block
    max_proof_age_hours: 24
proofs:
  - id: kit-restore-drill
    status: validated
    observed_at: "2026-05-14T00:00:00Z"
`

func TestParseValid(t *testing.T) {
	ctx, err := Parse(strings.NewReader(minimalGuardYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(ctx.Guards) != 1 {
		t.Fatalf("got %d guards, want 1", len(ctx.Guards))
	}
	g := ctx.Guards[0]
	if g.ID != "portable-recovery-kit" || g.Kind != GuardKindLifeline || g.Enforcement != EnforcementBlock {
		t.Errorf("unexpected guard: %+v", g)
	}
	if g.MaxProofAgeHours != 24 {
		t.Errorf("MaxProofAgeHours = %d, want 24", g.MaxProofAgeHours)
	}
	if len(ctx.Proofs) != 1 || ctx.Proofs[0].ID != "kit-restore-drill" {
		t.Errorf("unexpected proofs: %+v", ctx.Proofs)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"wrong version", "version: 1\nguards: []\n"},
		{"missing version", "guards: []\n"},
		{"empty document", ""},
		{"guard missing id", "version: 2\nguards:\n  - kind: lifeline\n    match: {paths: [x]}\n"},
		{"guard bad kind", "version: 2\nguards:\n  - id: x\n    kind: bogus\n    match: {paths: [x]}\n"},
		{"guard empty match", "version: 2\nguards:\n  - id: x\n    kind: lifeline\n    match: {}\n"},
		{"guard bad enforcement", "version: 2\nguards:\n  - id: x\n    kind: guard\n    match: {paths: [x]}\n    enforcement: maybe\n"},
		{"duplicate guard id", "version: 2\nguards:\n  - id: x\n    kind: guard\n    match: {paths: [a]}\n  - id: x\n    kind: guard\n    match: {paths: [b]}\n"},
		{"proof missing observed_at", "version: 2\nproofs:\n  - id: p1\n    status: validated\n"},
		{"proof bad status", "version: 2\nproofs:\n  - id: p1\n    status: nonsense\n    observed_at: \"2026-05-14T00:00:00Z\"\n"},
		{"fact missing statement", "version: 2\nfacts:\n  - id: f1\n"},
		{"unknown top-level key", "version: 2\nbogus_key: true\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(c.yaml)); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}

// taxonomyYAML declares layer:/category:/scope: on both a guard and a proof,
// plus a file-level scope: default — the taxonomy spec section A/F schema
// additions parse.go must accept.
const taxonomyYAML = `version: 2
scope:
  environment: prod
  system: money
  owner: tanner
guards:
  - id: restic-guard
    kind: lifeline
    match:
      paths: ["/data/money/**"]
    requires:
      proofs: [restic-proof]
    enforcement: block
    layer: backups-offsite
    category: restic
    scope:
      system: money-db
proofs:
  - id: restic-proof
    status: validated
    observed_at: "2026-05-14T00:00:00Z"
    layer: identity-secrets
    category: ssh-keys
    scope:
      host: host-nas
      tags: ["kit"]
`

// TestParseTaxonomyFields is the schema-side half of the taxonomy spec
// (section A): layer:/category: on both guards and proofs, plus scope: at
// the file, guard, and proof level, must all land in the typed Guard/Proof/
// Context structs untouched.
func TestParseTaxonomyFields(t *testing.T) {
	ctx, err := Parse(strings.NewReader(taxonomyYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ctx.Scope.Environment != "prod" || ctx.Scope.System != "money" || ctx.Scope.Owner != "tanner" {
		t.Errorf("file-level Scope = %+v, want environment=prod system=money owner=tanner", ctx.Scope)
	}
	if len(ctx.Guards) != 1 {
		t.Fatalf("got %d guards, want 1", len(ctx.Guards))
	}
	g := ctx.Guards[0]
	if g.Layer != LayerBackupsOffsite || g.Category != "restic" {
		t.Errorf("guard Layer/Category = %q/%q, want %q/%q", g.Layer, g.Category, LayerBackupsOffsite, "restic")
	}
	if g.Scope.System != "money-db" {
		t.Errorf("guard Scope.System = %q, want its own override %q", g.Scope.System, "money-db")
	}
	if len(ctx.Proofs) != 1 {
		t.Fatalf("got %d proofs, want 1", len(ctx.Proofs))
	}
	p := ctx.Proofs[0]
	if p.Layer != LayerIdentitySecrets || p.Category != "ssh-keys" {
		t.Errorf("proof Layer/Category = %q/%q, want %q/%q", p.Layer, p.Category, LayerIdentitySecrets, "ssh-keys")
	}
	if p.Scope.Host != "host-nas" || len(p.Scope.Tags) != 1 || p.Scope.Tags[0] != "kit" {
		t.Errorf("proof Scope = %+v, want host=host-nas tags=[kit]", p.Scope)
	}
}

// TestParseBadLayerIsAnError: layer: must be one of the fixed vocabulary —
// an unrecognized value is a parse error, on both guards and proofs, and
// LayerUnfiled itself (computed-only, never declarable) is also rejected.
func TestParseBadLayerIsAnError(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"guard bad layer", "version: 2\nguards:\n  - id: x\n    kind: guard\n    match: {paths: [a]}\n    layer: bogus\n"},
		{"guard layer unfiled", "version: 2\nguards:\n  - id: x\n    kind: guard\n    match: {paths: [a]}\n    layer: unfiled\n"},
		{"proof bad layer", "version: 2\nproofs:\n  - id: p1\n    status: validated\n    observed_at: \"2026-05-14T00:00:00Z\"\n    layer: bogus\n"},
		{"proof layer unfiled", "version: 2\nproofs:\n  - id: p1\n    status: validated\n    observed_at: \"2026-05-14T00:00:00Z\"\n    layer: unfiled\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(c.yaml)); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/restoregap.yml"); err == nil {
		t.Fatal("expected error loading a nonexistent file")
	}
}

const drillV2YAML = `version: 2
drills:
  - proof: money-db-recovery
    artifact: /path/live/money.db
    recovery_source: /path/backups/money-restic
    recover: ./recover-money.sh
    pin_check: restic -r "$RG_RECOVERY_SOURCE" snapshots "$PIN_ID" >/dev/null
    budgets: { rto: 5m, rpo: 26h }
    validate:
      - type: sqlite
        integrity: true
        tables: { transactions: ">= 12000", accounts: ">= 9" }
        freshness: { table: transactions, column: date }
      - type: command
        run: ./extra-invariant.sh
`

// TestParseDrillValidateAndBudgets is the schema-side half of drill v2: the
// validate/budgets/pin_check block from the spec's own example must parse
// into exactly the typed shape the drill engine expects.
func TestParseDrillValidateAndBudgets(t *testing.T) {
	ctx, err := Parse(strings.NewReader(drillV2YAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(ctx.Drills) != 1 {
		t.Fatalf("got %d drills, want 1", len(ctx.Drills))
	}
	d := ctx.Drills[0]
	if d.PinCheck == "" {
		t.Error("pin_check did not parse")
	}
	if d.Budgets.RTO != 5*time.Minute || d.Budgets.RPO != 26*time.Hour {
		t.Errorf("budgets = %+v, want rto=5m rpo=26h", d.Budgets)
	}
	if len(d.Validate) != 2 {
		t.Fatalf("got %d validate entries, want 2", len(d.Validate))
	}
	sq := d.Validate[0]
	if sq.Type != "sqlite" || !sq.Integrity {
		t.Errorf("unexpected sqlite check: %+v", sq)
	}
	if sq.Tables["transactions"] != ">= 12000" || sq.Tables["accounts"] != ">= 9" {
		t.Errorf("unexpected tables constraint: %+v", sq.Tables)
	}
	if sq.Freshness == nil || sq.Freshness.Table != "transactions" || sq.Freshness.Column != "date" {
		t.Errorf("unexpected freshness: %+v", sq.Freshness)
	}
	cmd := d.Validate[1]
	if cmd.Type != "command" || cmd.Run != "./extra-invariant.sh" {
		t.Errorf("unexpected command check: %+v", cmd)
	}
}

const drillServeYAML = `version: 2
drills:
  - proof: money-db-recovery
    artifact: /path/live/money.db
    recover: ./recover-money.sh
    validate:
      - type: serve
        run: /usr/local/bin/app -addr 127.0.0.1:$RG_PORT -db "$RG_TARGET"
        ready_timeout: 45s
        probes:
          - type: http
            path: /api/summary
            expect_status: 200
            expect_body: net_worth
          - type: command
            run: echo ok
`

// TestParseDrillServeCheck: the serve check's schema (Run reused from
// command, ready_timeout, probes) round-trips into typed form, including
// probe defaults (expect_status defaults to 200).
func TestParseDrillServeCheck(t *testing.T) {
	ctx, err := Parse(strings.NewReader(drillServeYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := ctx.Drills[0].Validate[0]
	if c.Type != "serve" {
		t.Fatalf("Type = %q, want serve", c.Type)
	}
	if c.Run == "" {
		t.Error("serve run command did not parse")
	}
	if c.ReadyTimeout != 45*time.Second {
		t.Errorf("ReadyTimeout = %s, want 45s", c.ReadyTimeout)
	}
	if len(c.Probes) != 2 {
		t.Fatalf("got %d probes, want 2", len(c.Probes))
	}
	http := c.Probes[0]
	if http.Type != "http" || http.Path != "/api/summary" || http.ExpectStatus != 200 || http.ExpectBody != "net_worth" {
		t.Errorf("unexpected http probe: %+v", http)
	}
	cmd := c.Probes[1]
	if cmd.Type != "command" || cmd.Run != "echo ok" {
		t.Errorf("unexpected command probe: %+v", cmd)
	}
}

// TestParseDrillServeDefaultReadyTimeout: ready_timeout defaults to 30s when
// not declared.
func TestParseDrillServeDefaultReadyTimeout(t *testing.T) {
	yaml := `version: 2
drills:
  - proof: p
    artifact: a
    recover: r
    validate:
      - type: serve
        run: x
        probes: [{type: http, path: /}]
`
	ctx, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := ctx.Drills[0].Validate[0].ReadyTimeout; got != DefaultServeReadyTimeout {
		t.Errorf("ReadyTimeout = %s, want default %s", got, DefaultServeReadyTimeout)
	}
}

// TestParseDrillServeHTTPProbeDefaultStatus: expect_status defaults to 200.
func TestParseDrillServeHTTPProbeDefaultStatus(t *testing.T) {
	yaml := `version: 2
drills:
  - proof: p
    artifact: a
    recover: r
    validate:
      - type: serve
        run: x
        probes: [{type: http, path: /health}]
`
	ctx, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := ctx.Drills[0].Validate[0].Probes[0].ExpectStatus; got != 200 {
		t.Errorf("ExpectStatus = %d, want default 200", got)
	}
}

const drillKeyFingerprintYAML = `version: 2
drills:
  - proof: ssh-keys-recovery
    artifact: /home/user/.ssh
    recover: r
    validate:
      - type: key_fingerprint
        keys: ssh
        expect_from: /home/user/.ssh
        min_keys: 2
      - type: key_fingerprint
        keys: gpg
        expect: ["502bef184cd7b4d34431a3905a25a42584fa5759"]
`

// TestParseDrillKeyFingerprintCheck: the key_fingerprint schema (keys,
// expect_from, expect, min_keys) round-trips into typed form, and an
// explicit expect: fingerprint is NOT case-mangled by parsing itself (any
// normalization is the engine's job, not parse's — see
// normalizeFingerprint).
func TestParseDrillKeyFingerprintCheck(t *testing.T) {
	ctx, err := Parse(strings.NewReader(drillKeyFingerprintYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(ctx.Drills[0].Validate) != 2 {
		t.Fatalf("got %d validate entries, want 2", len(ctx.Drills[0].Validate))
	}

	ssh := ctx.Drills[0].Validate[0]
	if ssh.Type != "key_fingerprint" || ssh.Keys != "ssh" {
		t.Fatalf("unexpected ssh check: %+v", ssh)
	}
	if ssh.ExpectFrom != "/home/user/.ssh" {
		t.Errorf("ExpectFrom = %q, want /home/user/.ssh", ssh.ExpectFrom)
	}
	if ssh.MinKeys != 2 {
		t.Errorf("MinKeys = %d, want 2", ssh.MinKeys)
	}

	gpg := ctx.Drills[0].Validate[1]
	if gpg.Type != "key_fingerprint" || gpg.Keys != "gpg" {
		t.Fatalf("unexpected gpg check: %+v", gpg)
	}
	if len(gpg.Expect) != 1 || gpg.Expect[0] != "502bef184cd7b4d34431a3905a25a42584fa5759" {
		t.Errorf("Expect = %+v, want the declared fingerprint unchanged (parse does not normalize)", gpg.Expect)
	}
}

// TestParseDrillKeyFingerprintDefaultMinKeys: min_keys defaults to 1 when
// omitted entirely (DefaultKeyFingerprintMinKeys), distinct from an
// explicit min_keys: 0.
func TestParseDrillKeyFingerprintDefaultMinKeys(t *testing.T) {
	yaml := `version: 2
drills:
  - proof: p
    artifact: a
    recover: r
    validate:
      - type: key_fingerprint
        keys: ssh
        expect_from: /home/user/.ssh
`
	ctx, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := ctx.Drills[0].Validate[0].MinKeys; got != DefaultKeyFingerprintMinKeys {
		t.Errorf("MinKeys = %d, want default %d", got, DefaultKeyFingerprintMinKeys)
	}
}

// TestParseDrillKeyFingerprintExplicitZeroMinKeys: min_keys: 0 is a
// legitimate, distinct declaration from omitting the field — it survives
// parsing as exactly 0, not silently promoted to the default.
func TestParseDrillKeyFingerprintExplicitZeroMinKeys(t *testing.T) {
	yaml := `version: 2
drills:
  - proof: p
    artifact: a
    recover: r
    validate:
      - type: key_fingerprint
        keys: ssh
        expect_from: /home/user/.ssh
        min_keys: 0
`
	ctx, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := ctx.Drills[0].Validate[0].MinKeys; got != 0 {
		t.Errorf("MinKeys = %d, want 0 (explicit, not defaulted)", got)
	}
}

// TestDrillWithNoValidateBlockIsBackwardCompatible pins the empty-Validate
// shape: an old drills: entry with none of the v2 fields must still parse,
// with Validate/Budgets/PinCheck at their zero values so the engine falls
// back to the pre-v2 byte_identical behavior.
func TestDrillWithNoValidateBlockIsBackwardCompatible(t *testing.T) {
	yaml := `version: 2
drills:
  - proof: old-style
    artifact: /path/live/thing
    recover: ./recover.sh
`
	ctx, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	d := ctx.Drills[0]
	if len(d.Validate) != 0 {
		t.Errorf("Validate = %+v, want empty", d.Validate)
	}
	if d.Budgets != (DrillBudgets{}) {
		t.Errorf("Budgets = %+v, want zero value", d.Budgets)
	}
	if d.PinCheck != "" {
		t.Errorf("PinCheck = %q, want empty", d.PinCheck)
	}
}

func TestParseDrillErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"bad rto duration", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    budgets: {rto: not-a-duration}\n"},
		{"bad rpo duration", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    budgets: {rpo: not-a-duration}\n"},
		{"unknown check type", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    validate: [{type: bogus}]\n"},
		{"freshness missing column", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    validate: [{type: sqlite, freshness: {table: t}}]\n"},
		{"serve with no probes", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    validate: [{type: serve, run: x}]\n"},
		{"serve with empty probes list", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    validate: [{type: serve, run: x, probes: []}]\n"},
		{"serve bad ready_timeout", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    validate: [{type: serve, run: x, ready_timeout: not-a-duration, probes: [{type: http, path: /x}]}]\n"},
		{"serve probe unknown type", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    validate: [{type: serve, run: x, probes: [{type: bogus}]}]\n"},
		{"serve http probe missing path", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    validate: [{type: serve, run: x, probes: [{type: http}]}]\n"},
		{"serve command probe missing run", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    validate: [{type: serve, run: x, probes: [{type: command}]}]\n"},
		{"key_fingerprint bad keys value", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    validate: [{type: key_fingerprint, keys: rsa2048}]\n"},
		{"key_fingerprint missing keys", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    validate: [{type: key_fingerprint}]\n"},
		{"key_fingerprint negative min_keys", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    validate: [{type: key_fingerprint, keys: ssh, min_keys: -1}]\n"},
		{"key_fingerprint asserts nothing (min_keys 0, no expect*)", "version: 2\ndrills:\n  - proof: p\n    artifact: a\n    recover: r\n    validate: [{type: key_fingerprint, keys: ssh, min_keys: 0}]\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(c.yaml)); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}

// TestParseProofMeasurements: a proof's measurements: block (the shape drill
// v2 writes back) must round-trip into typed Measurements, and a proof with
// none must leave it nil so drill and non-drill proofs stay distinguishable.
func TestParseProofMeasurements(t *testing.T) {
	yaml := `version: 2
proofs:
  - id: money-db-recovery
    status: validated
    observed_at: "2026-05-14T00:00:00Z"
    measurements:
      rto_seconds: 4.21
      rpo_seconds: 11532.0
      checks: [{type: sqlite, pass: true, detail: "integrity ok"}]
`
	ctx, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	m := ctx.Proofs[0].Measurements
	if m == nil {
		t.Fatal("Measurements is nil")
	}
	if m.RTOSeconds != 4.21 {
		t.Errorf("RTOSeconds = %v, want 4.21", m.RTOSeconds)
	}
	if m.RPOSeconds == nil || *m.RPOSeconds != 11532.0 {
		t.Errorf("RPOSeconds = %v, want 11532.0", m.RPOSeconds)
	}
	if len(m.Checks) != 1 || m.Checks[0].Type != "sqlite" || !m.Checks[0].Pass || m.Checks[0].Detail != "integrity ok" {
		t.Errorf("unexpected checks: %+v", m.Checks)
	}

	yamlNoMeasurements := `version: 2
proofs:
  - id: p
    status: observed
    observed_at: "2026-05-14T00:00:00Z"
`
	ctx2, err := Parse(strings.NewReader(yamlNoMeasurements))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ctx2.Proofs[0].Measurements != nil {
		t.Errorf("Measurements = %+v, want nil for a proof with no measurements: block", ctx2.Proofs[0].Measurements)
	}
}

// TestParseProofStatusUnreachableAndLegacyDisputed: the new `unreachable`
// status must parse, and a file written by an older binary — one that only
// ever wrote observed/validated/stale/disputed — must keep parsing and keep
// behaving exactly as before (disputed checks as contradicted, both collapse
// to LevelDeclared). Back-compat is the whole point: a schema addition must
// not strand every existing context file.
func TestParseProofStatusUnreachableAndLegacyDisputed(t *testing.T) {
	yaml := `version: 2
proofs:
  - id: nas-backed
    status: unreachable
    observed_at: "2026-08-18T00:00:00Z"
  - id: legacy-disputed
    status: disputed
    observed_at: "2026-08-18T00:00:00Z"
`
	ctx, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(ctx.Proofs) != 2 {
		t.Fatalf("got %d proofs, want 2", len(ctx.Proofs))
	}
	if ctx.Proofs[0].Status != ProofRecordUnreachable {
		t.Errorf("nas-backed status = %s, want unreachable", ctx.Proofs[0].Status)
	}
	if ctx.Proofs[1].Status != ProofRecordDisputed {
		t.Errorf("legacy-disputed status = %s, want disputed", ctx.Proofs[1].Status)
	}

	now := t3339("2026-08-18T12:00:00Z")
	if got := ctx.CheckProof("nas-backed", 0, false, now); got.State != StateUnreachable {
		t.Errorf("unreachable proof checks as %s, want unreachable", got.State)
	}
	if got := ctx.CheckProof("legacy-disputed", 0, false, now); got.State != StateContradicted {
		t.Errorf("legacy disputed proof checks as %s, want contradicted (unchanged behavior)", got.State)
	}
	level, reason := LevelOf(ctx.Proofs[0], now)
	if level != LevelDeclared || reason != "unreachable" {
		t.Errorf("LevelOf(unreachable) = %s/%q, want declared/\"unreachable\"", level, reason)
	}
	level, reason = LevelOf(ctx.Proofs[1], now)
	if level != LevelDeclared || reason != "disputed" {
		t.Errorf("LevelOf(disputed) = %s/%q, want declared/\"disputed\" (unchanged behavior)", level, reason)
	}
}

func TestParseRefusesNewerVersionWithUnsupportedVersionError(t *testing.T) {
	_, err := Parse(strings.NewReader("version: 3\nsome_future_field: true\n"))
	if err == nil {
		t.Fatal("expected an error for a version newer than CurrentVersion")
	}
	var uv *UnsupportedVersionError
	if !errors.As(err, &uv) {
		t.Fatalf("expected *UnsupportedVersionError, got %T: %v", err, err)
	}
	if uv.Got != 3 {
		t.Errorf("Got = %d, want 3", uv.Got)
	}
	if !strings.Contains(err.Error(), "upgrade restoregap") {
		t.Errorf("expected a one-line upgrade message, got %q", err.Error())
	}
}

func TestParseNewerVersionRefusedEvenWithoutUnknownFields(t *testing.T) {
	// A future version that happens to reuse every current field name would,
	// pre-peekVersion, sail through strict decode and only fail on the
	// generic "version must be 2" check further down — still an error, but
	// this asserts the newer-version case specifically routes through
	// UnsupportedVersionError, not the older/wrong-version message.
	_, err := Parse(strings.NewReader("version: 2026\nguards: []\n"))
	var uv *UnsupportedVersionError
	if !errors.As(err, &uv) {
		t.Fatalf("expected *UnsupportedVersionError, got %T: %v", err, err)
	}
}
