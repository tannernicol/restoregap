// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package contextspec

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ParseSigningKeySeed decodes a hex Ed25519 seed into a signer — the one
// place this decode happens, shared by `restoregap drill --signing-key` and
// `restoregap bundle export --signing-key` (docs/SCHEMA.md §Portable signed
// bundle: "reuse the existing proof-signing key material"), so the two
// commands can never drift on what counts as a valid key. An empty seed
// yields a nil signer and no error — callers that treat "no key" as "leave
// it unsigned" rely on that.
func ParseSigningKeySeed(hexSeed string) (ed25519.PrivateKey, error) {
	if hexSeed == "" {
		return nil, nil
	}
	seed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf("--signing-key must be hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("--signing-key must be a %d-byte hex seed, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ProofState is the outcome of checking one required proof or fact against
// the declared evidence. This is the single vocabulary every freshness and
// signature check in contextspec reports through — no other package
// re-derives proof state.
type ProofState string

// The ProofState values a proof check can report.
const (
	StatePresent      ProofState = "present"
	StateMissing      ProofState = "missing"
	StateStale        ProofState = "stale"
	StateContradicted ProofState = "contradicted"
	// StateUnreachable is the proof-record status "unreachable" as a check
	// result: the recovery source could not be reached when the drill ran, so
	// nothing was proven. It sits in the same severity tier as contradicted —
	// it never satisfies a guard and never satisfies require_verified — but it
	// keeps its own name so a finding can say "could not try" instead of
	// "tried and failed".
	StateUnreachable ProofState = "unreachable"
)

// CheckResult is the outcome of validating one required proof or fact ID.
type CheckResult struct {
	State  ProofState
	Detail string
}

// EvaluateProof derives the intrinsic state of one proof record. Intrinsic
// state covers the record's own terminal outcome, signature, and expiry. A
// guard's require_verified and max_proof_age_hours constraints are deliberately
// applied by CheckProof after this result: they are requirements of the
// consumer, not claims made by the proof record itself.
func EvaluateProof(proof Proof, now time.Time) CheckResult {
	if proof.Status == ProofRecordUnreachable {
		return CheckResult{State: StateUnreachable, Detail: fmt.Sprintf(
			"proof %q is unreachable: the recovery source was not reachable when the drill last ran, so nothing was proven "+
				"(no data loss is implied); re-run the drill once the source is reachable", proof.ID)}
	}
	if proof.Status == ProofRecordDisputed {
		return CheckResult{State: StateContradicted, Detail: fmt.Sprintf("proof %q is disputed: the recovery ran and did not verify; investigate the copy", proof.ID)}
	}
	if proof.Signature != nil {
		ok, err := verifySignature(proof)
		if err != nil {
			return CheckResult{State: StateContradicted, Detail: fmt.Sprintf("proof %q signature invalid: %v", proof.ID, err)}
		}
		if !ok {
			return CheckResult{State: StateContradicted, Detail: fmt.Sprintf("proof %q signature does not verify", proof.ID)}
		}
	}
	if proof.ExpiresAt != nil && now.After(*proof.ExpiresAt) {
		return CheckResult{State: StateStale, Detail: fmt.Sprintf("proof %q expired at %s", proof.ID, proof.ExpiresAt.Format(time.RFC3339))}
	}
	if proof.Status == ProofRecordStale {
		return CheckResult{State: StateStale, Detail: fmt.Sprintf("proof %q is marked stale", proof.ID)}
	}
	return CheckResult{State: StatePresent, Detail: fmt.Sprintf("proof %q is %s and fresh", proof.ID, proof.Status)}
}

// CheckProof validates a required proof by id against the context's
// declared proofs: existence, status, signature (if declared), and
// freshness against both the guard's max_proof_age_hours and the proof's
// own expires_at. now is injected so preflight can pin evaluation time via
// --as-of.
func (c Context) CheckProof(id string, maxProofAgeHours int, requireVerified bool, now time.Time) CheckResult {
	return c.CheckProofWithBinding(id, maxProofAgeHours, requireVerified, false, now)
}

// CheckProofWithBinding is CheckProof with the opt-in requirement that the
// proof is bound to the currently declared recovery recipe and dependencies.
// CheckProof remains the compatibility wrapper for callers that do not opt in.
func (c Context) CheckProofWithBinding(id string, maxProofAgeHours int, requireVerified, requireBound bool, now time.Time) CheckResult {
	proof, ok := c.proofByID(id)
	if !ok {
		return CheckResult{State: StateMissing, Detail: fmt.Sprintf("proof %q is not declared", id)}
	}
	result := EvaluateProof(proof, now)
	if result.State != StatePresent {
		return result
	}
	bound, bindingFailure := c.validateProofBinding(proof, id, requireBound)
	if bindingFailure != nil {
		return *bindingFailure
	}
	if result = applyProofRequirements(result, proof, id, requireVerified, maxProofAgeHours, now); result.State != StatePresent {
		return result
	}
	return withProofAssurance(result, proof, bound)
}

func (c Context) validateProofBinding(proof Proof, id string, requireBound bool) (bool, *CheckResult) {
	bound := proof.RecipeDigest != "" || proof.Dependencies != nil
	if !bound {
		if requireBound {
			result := CheckResult{State: StateMissing, Detail: fmt.Sprintf("proof %q is legacy evidence without a recovery binding; run `restoregap drill`", id)}
			return false, &result
		}
		return false, nil
	}
	if proof.RecipeDigest == "" || proof.Dependencies == nil {
		result := CheckResult{State: StateContradicted, Detail: fmt.Sprintf("proof %q has an incomplete recovery binding", id)}
		return true, &result
	}
	drill, found := c.drillByProof(id)
	if !found {
		result := CheckResult{State: StateContradicted, Detail: fmt.Sprintf("proof %q has a binding but no declared drill", id)}
		return true, &result
	}
	if want := RecipeDigest(drill); proof.RecipeDigest != want {
		result := CheckResult{State: StateContradicted, Detail: fmt.Sprintf("proof %q recipe binding does not match the declared drill", id)}
		return true, &result
	}
	if !DependenciesEqual(*proof.Dependencies, drill.Dependencies) {
		result := CheckResult{State: StateContradicted, Detail: fmt.Sprintf("proof %q recovery dependencies do not match the declared drill", id)}
		return true, &result
	}
	return true, nil
}

func applyProofRequirements(result CheckResult, proof Proof, id string, requireVerified bool, maxProofAgeHours int, now time.Time) CheckResult {
	// A guard that demands verification is saying an attestation is not enough:
	// only a drill that reconstructed the artifact and compared the bytes
	// counts. Treat an unverified proof as absent rather than merely weak, so
	// the guard blocks instead of passing on a lesser claim than it asked for.
	if requireVerified && !proof.Verified {
		return CheckResult{
			State: StateMissing,
			Detail: fmt.Sprintf("proof %q is %s but not verified; this guard requires a drill-produced proof "+
				"(run `restoregap drill`)", id, proof.Status),
		}
	}
	if maxProofAgeHours > 0 && proof.ObservedAt != nil {
		age := now.Sub(*proof.ObservedAt)
		if age > time.Duration(maxProofAgeHours)*time.Hour {
			return CheckResult{State: StateStale, Detail: fmt.Sprintf("proof %q observed %s ago, exceeds max_proof_age_hours=%d", id, age.Round(time.Hour), maxProofAgeHours)}
		}
	}
	return result
}

func withProofAssurance(result CheckResult, proof Proof, bound bool) CheckResult {
	if bound {
		result.Detail += "; recipe-bound"
	} else {
		result.Detail += "; legacy unbound evidence"
		switch {
		case proof.Signature == nil:
			result.Detail += "; unsigned"
		case proof.Signature.Version == 0:
			result.Detail += "; legacy signature covers limited fields"
		default:
			result.Detail += "; v2 signature without recipe binding"
		}
	}
	return result
}

func (c Context) drillByProof(id string) (Drill, bool) {
	for _, drill := range c.Drills {
		if drill.Proof == id {
			return drill, true
		}
	}
	return Drill{}, false
}

// CheckFact validates a required fact by id: existence and freshness
// against expires_at / max_age_days.
func (c Context) CheckFact(id string, now time.Time) CheckResult {
	fact, ok := c.factByID(id)
	if !ok {
		return CheckResult{State: StateMissing, Detail: fmt.Sprintf("fact %q is not declared", id)}
	}
	if fact.ExpiresAt != nil && now.After(*fact.ExpiresAt) {
		return CheckResult{State: StateStale, Detail: fmt.Sprintf("fact %q expired at %s", id, fact.ExpiresAt.Format(time.RFC3339))}
	}
	return CheckResult{State: StatePresent, Detail: fmt.Sprintf("fact %q: %s", id, fact.Statement)}
}

func (c Context) proofByID(id string) (Proof, bool) {
	for _, p := range c.Proofs {
		if p.ID == id {
			return p, true
		}
	}
	return Proof{}, false
}

func (c Context) factByID(id string) (Fact, bool) {
	for _, f := range c.Facts {
		if f.ID == id {
			return f, true
		}
	}
	return Fact{}, false
}

// verifySignature checks an Ed25519 signature over the proof's canonical
// signed content, built by SignedMessage.
func verifySignature(p Proof) (bool, error) {
	pub, err := hex.DecodeString(p.Signature.PublicKeyHex)
	if err != nil {
		return false, fmt.Errorf("public_key is not valid hex: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return false, fmt.Errorf("public_key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	sig, err := hex.DecodeString(p.Signature.SignatureHex)
	if err != nil {
		return false, fmt.Errorf("signature is not valid hex: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	observedAt := ""
	if p.ObservedAt != nil {
		observedAt = p.ObservedAt.Format(time.RFC3339)
	}
	var message []byte
	switch p.Signature.Version {
	case 0:
		if p.RecipeDigest != "" || p.Dependencies != nil {
			return false, fmt.Errorf("legacy signature does not cover recovery binding fields")
		}
		message = []byte(SignedMessage(p.ID, string(p.Status), observedAt, p.SHA256, p.Measurements))
	case 2:
		structured, err := SignedMessageV2(p)
		if err != nil {
			return false, err
		}
		message = []byte(structured)
	default:
		return false, fmt.Errorf("unsupported signature version %d", p.Signature.Version)
	}
	return ed25519.Verify(pub, message, sig), nil
}

// VerifyProofSignature checks a proof signature independently of the proof's
// status, expiry, or other intrinsic health. A proof without a signature is
// not signed and returns false without an error.
func VerifyProofSignature(p Proof) (bool, error) {
	if p.Signature == nil {
		return false, nil
	}
	return verifySignature(p)
}

type signedMeasurementsV2 struct {
	RTOSeconds float64         `json:"rto_seconds"`
	RPOSeconds *float64        `json:"rpo_seconds"`
	Checks     []signedCheckV2 `json:"checks"`
}

type signedCheckV2 struct {
	Type   string `json:"type"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

type signedProofV2 struct {
	Domain       string                `json:"domain"`
	Version      int                   `json:"version"`
	ID           string                `json:"id"`
	Status       ProofRecordStatus     `json:"status"`
	ObservedAt   string                `json:"observed_at"`
	ExpiresAt    *string               `json:"expires_at,omitempty"`
	Verified     bool                  `json:"verified"`
	SHA256       string                `json:"sha256"`
	Command      string                `json:"command"`
	Measurements *signedMeasurementsV2 `json:"measurements,omitempty"`
	RecipeDigest string                `json:"recipe_digest"`
	Dependencies *Dependencies         `json:"dependencies"`
	Host         *ProofHost            `json:"host,omitempty"`
	Epoch        string                `json:"epoch,omitempty"`
}

// SignedMessageV2 builds the domain/version-prefixed structured message for
// new proof signatures. It covers every decision-bearing proof field and the
// explicit recovery binding, plus host/epoch when the proof claims stamped
// origin. Scope defaults are intentionally excluded because they are resolved
// by the declaring context file rather than by the drill producer.
func SignedMessageV2(p Proof) (string, error) {
	observedAt := ""
	if p.ObservedAt != nil {
		observedAt = p.ObservedAt.Format(time.RFC3339Nano)
	}
	var expiresAt *string
	if p.ExpiresAt != nil {
		value := p.ExpiresAt.Format(time.RFC3339Nano)
		expiresAt = &value
	}
	var measurements *signedMeasurementsV2
	if p.Measurements != nil {
		checks := make([]signedCheckV2, 0, len(p.Measurements.Checks))
		for _, check := range p.Measurements.Checks {
			checks = append(checks, signedCheckV2(check))
		}
		measurements = &signedMeasurementsV2{RTOSeconds: p.Measurements.RTOSeconds, RPOSeconds: p.Measurements.RPOSeconds, Checks: checks}
	}
	var dependencies *Dependencies
	if p.Dependencies != nil {
		value := NormalizeDependencies(*p.Dependencies)
		dependencies = &value
	}
	message := signedProofV2{
		Domain: "restoregap/proof", Version: 2, ID: p.ID, Status: p.Status,
		ObservedAt: observedAt, ExpiresAt: expiresAt, Verified: p.Verified,
		SHA256: p.SHA256, Command: p.Command, Measurements: measurements,
		RecipeDigest: p.RecipeDigest, Dependencies: dependencies,
		Host: p.Host, Epoch: p.Epoch,
	}
	data, err := json.Marshal(message)
	if err != nil {
		return "", fmt.Errorf("canonical v2 proof encoding: %w", err)
	}
	return "restoregap-proof-v2\x00" + string(data), nil
}

// SignProofV2 creates a version-2 signature over the typed proof fields.
func SignProofV2(private ed25519.PrivateKey, proof Proof) (*Signature, error) {
	message, err := SignedMessageV2(proof)
	if err != nil {
		return nil, err
	}
	return &Signature{
		Version:      2,
		PublicKeyHex: hex.EncodeToString(private.Public().(ed25519.PublicKey)),
		SignatureHex: hex.EncodeToString(ed25519.Sign(private, []byte(message))),
	}, nil
}

// SignedMessage builds the canonical message a proof's Ed25519 signature
// covers: "<id>|<status>|<observed_at>|<sha256>", with "|m=<digest>"
// appended when measurements is non-nil. This is the ONE place that decides
// what a signature covers — recordDrillProofs (sign side) and
// verifySignature (verify side) both call it, so they cannot drift apart.
//
// A proof recorded before drill v2 has no measurements and signs exactly the
// pre-v2 message, so every signature made before this change keeps
// verifying unchanged.
func SignedMessage(id, status, observedAt, sha256Hex string, measurements *Measurements) string {
	msg := id + "|" + status + "|" + observedAt + "|" + sha256Hex
	if measurements != nil {
		msg += "|m=" + MeasurementDigest(*measurements)
	}
	return msg
}

// MeasurementDigest is the deterministic digest over one proof's recorded
// measurements that participates in SignedMessage. Detail strings are
// excluded on purpose: rewording a check's human-readable detail must never
// invalidate a signature that only ever claimed the numbers and pass/fail
// bits, or a cosmetic edit would look identical to a forged measurement.
func MeasurementDigest(m Measurements) string {
	var b strings.Builder
	fmt.Fprintf(&b, "rto=%.3f|rpo=", m.RTOSeconds)
	if m.RPOSeconds != nil {
		fmt.Fprintf(&b, "%.3f", *m.RPOSeconds)
	} else {
		b.WriteString("-")
	}
	for _, c := range m.Checks {
		fmt.Fprintf(&b, "|%s:%v", c.Type, c.Pass)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
