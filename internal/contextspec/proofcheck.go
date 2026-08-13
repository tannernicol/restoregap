package contextspec

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

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
)

// CheckResult is the outcome of validating one required proof or fact ID.
type CheckResult struct {
	State  ProofState
	Detail string
}

// CheckProof validates a required proof by id against the context's
// declared proofs: existence, status, signature (if declared), and
// freshness against both the guard's max_proof_age_hours and the proof's
// own expires_at. now is injected so preflight can pin evaluation time via
// --as-of.
func (c Context) CheckProof(id string, maxProofAgeHours int, requireVerified bool, now time.Time) CheckResult {
	proof, ok := c.proofByID(id)
	if !ok {
		return CheckResult{State: StateMissing, Detail: fmt.Sprintf("proof %q is not declared", id)}
	}
	if proof.Status == ProofRecordDisputed {
		return CheckResult{State: StateContradicted, Detail: fmt.Sprintf("proof %q is disputed", id)}
	}
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
	if proof.Signature != nil {
		ok, err := verifySignature(proof)
		if err != nil {
			return CheckResult{State: StateContradicted, Detail: fmt.Sprintf("proof %q signature invalid: %v", id, err)}
		}
		if !ok {
			return CheckResult{State: StateContradicted, Detail: fmt.Sprintf("proof %q signature does not verify", id)}
		}
	}
	if proof.ExpiresAt != nil && now.After(*proof.ExpiresAt) {
		return CheckResult{State: StateStale, Detail: fmt.Sprintf("proof %q expired at %s", id, proof.ExpiresAt.Format(time.RFC3339))}
	}
	if maxProofAgeHours > 0 && proof.ObservedAt != nil {
		age := now.Sub(*proof.ObservedAt)
		if age > time.Duration(maxProofAgeHours)*time.Hour {
			return CheckResult{State: StateStale, Detail: fmt.Sprintf("proof %q observed %s ago, exceeds max_proof_age_hours=%d", id, age.Round(time.Hour), maxProofAgeHours)}
		}
	}
	if proof.Status == ProofRecordStale {
		return CheckResult{State: StateStale, Detail: fmt.Sprintf("proof %q is marked stale", id)}
	}
	return CheckResult{State: StatePresent, Detail: fmt.Sprintf("proof %q is %s and fresh", id, proof.Status)}
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
	message := []byte(SignedMessage(p.ID, string(p.Status), observedAt, p.SHA256, p.Measurements))
	return ed25519.Verify(pub, message, sig), nil
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
