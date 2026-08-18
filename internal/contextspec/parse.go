// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package contextspec

import (
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// rawContext mirrors the v2 YAML wire shape (docs/ARCHITECTURE.md §5).
type rawContext struct {
	Version int        `yaml:"version"`
	Guards  []rawGuard `yaml:"guards"`
	Facts   []rawFact  `yaml:"facts"`
	Proofs  []rawProof `yaml:"proofs"`
	Drills  []rawDrill `yaml:"drills"`
}

type rawDrill struct {
	Proof          string          `yaml:"proof"`
	Artifact       string          `yaml:"artifact"`
	Recover        string          `yaml:"recover"`
	RecoverySource string          `yaml:"recovery_source"`
	Validate       []rawDrillCheck `yaml:"validate"`
	Budgets        rawDrillBudgets `yaml:"budgets"`
	PinCheck       string          `yaml:"pin_check"`
}

type rawDrillFreshness struct {
	Table  string `yaml:"table"`
	Column string `yaml:"column"`
}

type rawDrillProbe struct {
	Type         string `yaml:"type"`
	Path         string `yaml:"path"`
	ExpectStatus int    `yaml:"expect_status"`
	ExpectBody   string `yaml:"expect_body"`
	Run          string `yaml:"run"`
}

type rawDrillCheck struct {
	Type      string             `yaml:"type"`
	Integrity bool               `yaml:"integrity"`
	Tables    map[string]string  `yaml:"tables"`
	Freshness *rawDrillFreshness `yaml:"freshness"`
	Refs      string             `yaml:"refs"`
	Files     string             `yaml:"files"`
	MustExist []string           `yaml:"must_exist"`
	Run       string             `yaml:"run"`

	// serve
	ReadyTimeout string          `yaml:"ready_timeout"`
	Probes       []rawDrillProbe `yaml:"probes"`

	// key_fingerprint
	Keys       string   `yaml:"keys"`
	ExpectFrom string   `yaml:"expect_from"`
	Expect     []string `yaml:"expect"`
	// MinKeys is a pointer so an explicitly-declared `min_keys: 0` is
	// distinguishable from the field being omitted entirely — see
	// DefaultKeyFingerprintMinKeys.
	MinKeys *int `yaml:"min_keys"`
}

type rawDrillBudgets struct {
	RTO string `yaml:"rto"`
	RPO string `yaml:"rpo"`
}

type rawMatch struct {
	Paths          []string `yaml:"paths"`
	Commands       []string `yaml:"commands"`
	Packages       []string `yaml:"packages"`
	Actions        []string `yaml:"actions"`
	Actors         []string `yaml:"actors"`
	ContextWindows []string `yaml:"context_windows"`
}

type rawRequires struct {
	Proofs []string `yaml:"proofs"`
	Facts  []string `yaml:"facts"`
}

type rawGuard struct {
	ID               string      `yaml:"id"`
	Kind             string      `yaml:"kind"`
	Match            rawMatch    `yaml:"match"`
	RequiredFor      []string    `yaml:"required_for"`
	Requires         rawRequires `yaml:"requires"`
	Enforcement      string      `yaml:"enforcement"`
	MaxProofAgeHours int         `yaml:"max_proof_age_hours"`
	RecoveryCopy     string      `yaml:"recovery_copy"`
	AlternatePaths   []string    `yaml:"alternate_paths"`
	RequireVerified  bool        `yaml:"require_verified"`
}

type rawFact struct {
	ID         string `yaml:"id"`
	Statement  string `yaml:"statement"`
	Provenance string `yaml:"provenance"`
	ExpiresAt  string `yaml:"expires_at"`
	MaxAgeDays *int   `yaml:"max_age_days"`
}

type rawSignature struct {
	PublicKey string `yaml:"public_key"`
	Signature string `yaml:"signature"`
}

type rawProof struct {
	ID           string           `yaml:"id"`
	Status       string           `yaml:"status"`
	ObservedAt   string           `yaml:"observed_at"`
	ExpiresAt    string           `yaml:"expires_at"`
	SHA256       string           `yaml:"sha256"`
	EvidenceURL  string           `yaml:"evidence_url"`
	Signature    *rawSignature    `yaml:"signature"`
	Verified     bool             `yaml:"verified"`
	Command      string           `yaml:"command"`
	Measurements *rawMeasurements `yaml:"measurements"`
}

type rawCheckOutcome struct {
	Type   string `yaml:"type"`
	Pass   bool   `yaml:"pass"`
	Detail string `yaml:"detail"`
}

type rawMeasurements struct {
	RTOSeconds float64           `yaml:"rto_seconds"`
	RPOSeconds *float64          `yaml:"rpo_seconds"`
	Checks     []rawCheckOutcome `yaml:"checks"`
}

// Load reads and validates a v2 context document from path.
func Load(path string) (Context, error) {
	f, err := os.Open(path)
	if err != nil {
		return Context{}, fmt.Errorf("contextspec: cannot read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	ctx, err := Parse(f)
	if err != nil {
		return Context{}, fmt.Errorf("contextspec: %s: %w", path, err)
	}
	ctx.Origin = path
	return ctx, nil
}

// Parse decodes and validates a v2 context document.
func Parse(r io.Reader) (Context, error) {
	var raw rawContext
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		if err == io.EOF {
			return Context{}, fmt.Errorf("context: empty document, must declare version: 2")
		}
		return Context{}, fmt.Errorf("context: invalid YAML: %w", err)
	}
	return fromRaw(raw)
}

// collectUnique converts each raw entry of one document section and enforces
// id uniqueness within it. Errors carry the section name and index so a bad
// entry is locatable in the source document rather than merely described.
func collectUnique[R, T any](section string, in []R, conv func(R) (T, error), idOf func(T) string) ([]T, error) {
	seen := map[string]bool{}
	out := make([]T, 0, len(in))
	for i, r := range in {
		v, err := conv(r)
		if err != nil {
			return nil, fmt.Errorf("context: %s[%d]: %w", section, i, err)
		}
		id := idOf(v)
		if seen[id] {
			return nil, fmt.Errorf("context: %s[%d]: duplicate id %q", section, i, id)
		}
		seen[id] = true
		out = append(out, v)
	}
	return out, nil
}

// collectDrills is separate from collectUnique: drills are keyed by the proof
// they exercise rather than by an id of their own, and their errors name that
// proof because that is what a human recognises them by.
func collectDrills(in []rawDrill) ([]Drill, error) {
	seen := map[string]bool{}
	out := make([]Drill, 0, len(in))
	for i, rd := range in {
		d, err := fromRawDrill(rd)
		if err != nil {
			return nil, fmt.Errorf("context: drills[%d]: %w", i, err)
		}
		if seen[d.Proof] {
			return nil, fmt.Errorf("context: drills[%d]: duplicate proof %q", i, d.Proof)
		}
		seen[d.Proof] = true
		out = append(out, d)
	}
	return out, nil
}

// fromRawDrill converts one drill's raw YAML shape to its typed form,
// parsing budget durations and validating each validate[] entry's check
// type against the closed set the engine knows how to run.
func fromRawDrill(rd rawDrill) (Drill, error) {
	if rd.Proof == "" {
		return Drill{}, fmt.Errorf("proof is required")
	}
	if rd.Artifact == "" || rd.Recover == "" {
		return Drill{}, fmt.Errorf("%s: artifact and recover are required", rd.Proof)
	}
	checks := make([]DrillCheck, 0, len(rd.Validate))
	for i, rc := range rd.Validate {
		c, err := fromRawDrillCheck(rc)
		if err != nil {
			return Drill{}, fmt.Errorf("%s: validate[%d]: %w", rd.Proof, i, err)
		}
		checks = append(checks, c)
	}
	budgets, err := fromRawDrillBudgets(rd.Budgets)
	if err != nil {
		return Drill{}, fmt.Errorf("%s: %w", rd.Proof, err)
	}
	return Drill{
		Proof:          rd.Proof,
		Artifact:       rd.Artifact,
		Recover:        rd.Recover,
		RecoverySource: rd.RecoverySource,
		Validate:       checks,
		Budgets:        budgets,
		PinCheck:       rd.PinCheck,
	}, nil
}

// drillCheckTypes is the closed set of validate[].type values the drill
// engine implements. Kept here (not just in internal/drill) so a bad type is
// a parse-time error, matching how Guard.Kind and Enforcement fail fast
// rather than surfacing as a confusing runtime failure mid-drill.
var drillCheckTypes = map[string]bool{
	"byte_identical":  true,
	"sqlite":          true,
	"git":             true,
	"file_tree":       true,
	"command":         true,
	"serve":           true,
	"key_fingerprint": true,
}

// DefaultServeReadyTimeout is how long a serve check waits for its first
// probe to pass when ready_timeout is not declared.
const DefaultServeReadyTimeout = 30 * time.Second

// DefaultKeyFingerprintMinKeys is how many keys a key_fingerprint check
// requires in the recovered set when min_keys: is not declared at all.
const DefaultKeyFingerprintMinKeys = 1

func fromRawDrillCheck(rc rawDrillCheck) (DrillCheck, error) {
	if !drillCheckTypes[rc.Type] {
		return DrillCheck{}, fmt.Errorf("type must be byte_identical/sqlite/git/file_tree/command/serve/key_fingerprint, got %q", rc.Type)
	}
	var fresh *DrillFreshness
	if rc.Freshness != nil {
		if rc.Freshness.Table == "" || rc.Freshness.Column == "" {
			return DrillCheck{}, fmt.Errorf("freshness requires both table and column")
		}
		fresh = &DrillFreshness{Table: rc.Freshness.Table, Column: rc.Freshness.Column}
	}
	readyTimeout, probes, err := fromRawServeFields(rc)
	if err != nil {
		return DrillCheck{}, err
	}
	keys, expectFrom, expect, minKeys, err := fromRawKeyFingerprintFields(rc)
	if err != nil {
		return DrillCheck{}, err
	}
	return DrillCheck{
		Type:      rc.Type,
		Integrity: rc.Integrity,
		Tables:    rc.Tables,
		Freshness: fresh,
		Refs:      rc.Refs,
		Files:     rc.Files,
		MustExist: rc.MustExist,
		Run:       rc.Run,

		ReadyTimeout: readyTimeout,
		Probes:       probes,

		Keys:       keys,
		ExpectFrom: expectFrom,
		Expect:     expect,
		MinKeys:    minKeys,
	}, nil
}

// fromRawKeyFingerprintFields validates and converts the key_fingerprint-
// only fields. It is a no-op (zero values, no error) for every other check
// type, matching fromRawServeFields' pattern. keys must be ssh or gpg;
// min_keys (once defaulted) must not be negative; and the check must
// declare at least one real assertion — expect_from, expect, or a positive
// min_keys — because a key_fingerprint check with none of those would pass
// on any recovered set at all, including an empty one, which is exactly the
// false comfort this check type exists to prevent.
func fromRawKeyFingerprintFields(rc rawDrillCheck) (string, string, []string, int, error) {
	if rc.Type != "key_fingerprint" {
		return "", "", nil, 0, nil
	}
	if rc.Keys != "ssh" && rc.Keys != "gpg" {
		return "", "", nil, 0, fmt.Errorf("key_fingerprint: keys must be ssh or gpg, got %q", rc.Keys)
	}
	minKeys := DefaultKeyFingerprintMinKeys
	if rc.MinKeys != nil {
		if *rc.MinKeys < 0 {
			return "", "", nil, 0, fmt.Errorf("key_fingerprint: min_keys must not be negative")
		}
		minKeys = *rc.MinKeys
	}
	if rc.ExpectFrom == "" && len(rc.Expect) == 0 && minKeys == 0 {
		return "", "", nil, 0, fmt.Errorf("key_fingerprint: declares no assertion — set expect_from, expect, or a positive min_keys")
	}
	return rc.Keys, rc.ExpectFrom, rc.Expect, minKeys, nil
}

// fromRawServeFields validates and converts the serve-only fields. It is a
// no-op (zero values, no error) for every other check type — ready_timeout/
// probes declared on a non-serve check are simply ignored rather than
// rejected, matching how e.g. a sqlite check's freshness: is meaningless but
// harmless on a git check.
func fromRawServeFields(rc rawDrillCheck) (time.Duration, []DrillProbe, error) {
	if rc.Type != "serve" {
		return 0, nil, nil
	}
	readyTimeout := DefaultServeReadyTimeout
	if rc.ReadyTimeout != "" {
		d, err := time.ParseDuration(rc.ReadyTimeout)
		if err != nil {
			return 0, nil, fmt.Errorf("serve: ready_timeout: %w", err)
		}
		readyTimeout = d
	}
	if len(rc.Probes) == 0 {
		return 0, nil, fmt.Errorf("serve: at least one probe is required")
	}
	probes := make([]DrillProbe, 0, len(rc.Probes))
	for i, rp := range rc.Probes {
		p, err := fromRawDrillProbe(rp)
		if err != nil {
			return 0, nil, fmt.Errorf("serve: probes[%d]: %w", i, err)
		}
		probes = append(probes, p)
	}
	return readyTimeout, probes, nil
}

func fromRawDrillProbe(rp rawDrillProbe) (DrillProbe, error) {
	switch rp.Type {
	case "http":
		if rp.Path == "" {
			return DrillProbe{}, fmt.Errorf("http probe requires path")
		}
		status := rp.ExpectStatus
		if status == 0 {
			status = 200
		}
		return DrillProbe{Type: "http", Path: rp.Path, ExpectStatus: status, ExpectBody: rp.ExpectBody}, nil
	case "command":
		if rp.Run == "" {
			return DrillProbe{}, fmt.Errorf("command probe requires run")
		}
		return DrillProbe{Type: "command", Run: rp.Run}, nil
	default:
		return DrillProbe{}, fmt.Errorf("type must be http or command, got %q", rp.Type)
	}
}

func fromRawDrillBudgets(rb rawDrillBudgets) (DrillBudgets, error) {
	var budgets DrillBudgets
	if rb.RTO != "" {
		d, err := time.ParseDuration(rb.RTO)
		if err != nil {
			return DrillBudgets{}, fmt.Errorf("budgets.rto: %w", err)
		}
		budgets.RTO = d
	}
	if rb.RPO != "" {
		d, err := time.ParseDuration(rb.RPO)
		if err != nil {
			return DrillBudgets{}, fmt.Errorf("budgets.rpo: %w", err)
		}
		budgets.RPO = d
	}
	return budgets, nil
}

func fromRaw(raw rawContext) (Context, error) {
	if raw.Version != 2 {
		return Context{}, fmt.Errorf("context: version must be 2, got %d", raw.Version)
	}

	guards, err := collectUnique("guards", raw.Guards, fromRawGuard, func(g Guard) string { return g.ID })
	if err != nil {
		return Context{}, err
	}
	facts, err := collectUnique("facts", raw.Facts, fromRawFact, func(f Fact) string { return f.ID })
	if err != nil {
		return Context{}, err
	}
	proofs, err := collectUnique("proofs", raw.Proofs, fromRawProof, func(p Proof) string { return p.ID })
	if err != nil {
		return Context{}, err
	}
	drills, err := collectDrills(raw.Drills)
	if err != nil {
		return Context{}, err
	}

	return Context{Version: raw.Version, Guards: guards, Facts: facts, Proofs: proofs, Drills: drills}, nil
}

func fromRawGuard(g rawGuard) (Guard, error) {
	if g.ID == "" {
		return Guard{}, fmt.Errorf("missing id")
	}
	var kind GuardKind
	switch g.Kind {
	case "lifeline":
		kind = GuardKindLifeline
	case "guard", "":
		kind = GuardKindGuard
	default:
		return Guard{}, fmt.Errorf("%s: kind must be lifeline or guard, got %q", g.ID, g.Kind)
	}
	match := Matcher{
		Paths:          g.Match.Paths,
		Commands:       g.Match.Commands,
		Packages:       g.Match.Packages,
		Actions:        g.Match.Actions,
		Actors:         g.Match.Actors,
		ContextWindows: g.Match.ContextWindows,
	}
	if match.Empty() {
		return Guard{}, fmt.Errorf("%s: match must declare at least one of paths/commands/packages/actions/actors/context_windows", g.ID)
	}
	var enforcement Enforcement
	switch g.Enforcement {
	case "block", "":
		enforcement = EnforcementBlock
	case "warn":
		enforcement = EnforcementWarn
	default:
		return Guard{}, fmt.Errorf("%s: enforcement must be block or warn, got %q", g.ID, g.Enforcement)
	}
	if g.MaxProofAgeHours < 0 {
		return Guard{}, fmt.Errorf("%s: max_proof_age_hours must not be negative", g.ID)
	}
	return Guard{
		ID:               g.ID,
		Kind:             kind,
		Match:            match,
		RequiredFor:      g.RequiredFor,
		Requires:         Requirement{Proofs: g.Requires.Proofs, Facts: g.Requires.Facts},
		Enforcement:      enforcement,
		MaxProofAgeHours: g.MaxProofAgeHours,
		RecoveryCopy:     g.RecoveryCopy,
		AlternatePaths:   g.AlternatePaths,
		RequireVerified:  g.RequireVerified,
	}, nil
}

func fromRawFact(rf rawFact) (Fact, error) {
	if rf.ID == "" {
		return Fact{}, fmt.Errorf("missing id")
	}
	if rf.Statement == "" {
		return Fact{}, fmt.Errorf("%s: statement is required", rf.ID)
	}
	var expires *time.Time
	if rf.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, rf.ExpiresAt)
		if err != nil {
			return Fact{}, fmt.Errorf("%s: expires_at must be RFC3339: %w", rf.ID, err)
		}
		expires = &t
	}
	return Fact{ID: rf.ID, Statement: rf.Statement, Provenance: rf.Provenance, ExpiresAt: expires, MaxAgeDays: rf.MaxAgeDays}, nil
}

func fromRawProof(rp rawProof) (Proof, error) {
	if rp.ID == "" {
		return Proof{}, fmt.Errorf("missing id")
	}
	var status ProofRecordStatus
	switch rp.Status {
	case "observed":
		status = ProofRecordObserved
	case "validated":
		status = ProofRecordValidated
	case "stale":
		status = ProofRecordStale
	case "disputed":
		status = ProofRecordDisputed
	default:
		return Proof{}, fmt.Errorf("%s: status must be observed/validated/stale/disputed, got %q", rp.ID, rp.Status)
	}
	if rp.ObservedAt == "" {
		return Proof{}, fmt.Errorf("%s: observed_at is required", rp.ID)
	}
	observed, err := time.Parse(time.RFC3339, rp.ObservedAt)
	if err != nil {
		return Proof{}, fmt.Errorf("%s: observed_at must be RFC3339: %w", rp.ID, err)
	}
	var expires *time.Time
	if rp.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, rp.ExpiresAt)
		if err != nil {
			return Proof{}, fmt.Errorf("%s: expires_at must be RFC3339: %w", rp.ID, err)
		}
		expires = &t
	}
	var sig *Signature
	if rp.Signature != nil {
		if rp.Signature.PublicKey == "" || rp.Signature.Signature == "" {
			return Proof{}, fmt.Errorf("%s: signature requires both public_key and signature", rp.ID)
		}
		sig = &Signature{PublicKeyHex: rp.Signature.PublicKey, SignatureHex: rp.Signature.Signature}
	}
	return Proof{
		ID:           rp.ID,
		Status:       status,
		ObservedAt:   &observed,
		ExpiresAt:    expires,
		SHA256:       rp.SHA256,
		EvidenceURL:  rp.EvidenceURL,
		Signature:    sig,
		Verified:     rp.Verified,
		Command:      rp.Command,
		Measurements: fromRawMeasurements(rp.Measurements),
	}, nil
}

// fromRawMeasurements converts an optional measurements: block. A nil input
// (the field was absent) yields a nil result, distinguishing "not a drill
// proof" from a proof that measured nothing.
func fromRawMeasurements(rm *rawMeasurements) *Measurements {
	if rm == nil {
		return nil
	}
	checks := make([]CheckOutcome, 0, len(rm.Checks))
	for _, rc := range rm.Checks {
		checks = append(checks, CheckOutcome(rc))
	}
	return &Measurements{RTOSeconds: rm.RTOSeconds, RPOSeconds: rm.RPOSeconds, Checks: checks}
}
