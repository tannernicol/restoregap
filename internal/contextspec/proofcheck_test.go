// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package contextspec

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func t3339(s string) time.Time {
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return tm
}

func TestCheckProof(t *testing.T) {
	now := t3339("2026-05-14T12:00:00Z")
	observed := t3339("2026-05-14T00:00:00Z") // 12h before now
	ctx := Context{
		Proofs: []Proof{
			{ID: "fresh", Status: ProofRecordValidated, ObservedAt: &observed},
			{ID: "disputed", Status: ProofRecordDisputed, ObservedAt: &observed},
			{ID: "marked-stale", Status: ProofRecordStale, ObservedAt: &observed},
			{ID: "unreachable", Status: ProofRecordUnreachable, ObservedAt: &observed},
		},
	}
	cases := []struct {
		name             string
		id               string
		maxProofAgeHours int
		want             ProofState
	}{
		{"missing proof", "nope", 0, StateMissing},
		{"fresh, no max age bound", "fresh", 0, StatePresent},
		{"fresh, within max age", "fresh", 24, StatePresent},
		{"fresh, exceeds max age", "fresh", 1, StateStale},
		{"disputed", "disputed", 0, StateContradicted},
		{"marked stale", "marked-stale", 0, StateStale},
		{"unreachable", "unreachable", 0, StateUnreachable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ctx.CheckProof(c.id, c.maxProofAgeHours, false, now)
			if got.State != c.want {
				t.Errorf("CheckProof(%q, %d) = %s (%s), want %s", c.id, c.maxProofAgeHours, got.State, got.Detail, c.want)
			}
		})
	}
}

// TestCheckProofUnreachableNeverSatisfies: an unreachable proof means "the
// recovery source could not be reached, nothing was proven" — the NAS-asleep
// shape. It must never satisfy a guard, and never satisfy require_verified
// (which accepts only a drill-produced verified proof). Its detail must also
// read differently from a disputed proof's: reachability remediation, not
// "investigate the copy", and no implication of data loss.
func TestCheckProofUnreachableNeverSatisfies(t *testing.T) {
	now := time.Now()
	observedAt := now.Add(-time.Hour)
	ctx := Context{Proofs: []Proof{
		{ID: "nas-sleeping", Status: ProofRecordUnreachable, ObservedAt: &observedAt},
		{ID: "corrupt-copy", Status: ProofRecordDisputed, ObservedAt: &observedAt},
	}}

	got := ctx.CheckProof("nas-sleeping", 0, false, now)
	if got.State != StateUnreachable {
		t.Fatalf("unreachable proof state = %s (%s), want unreachable", got.State, got.Detail)
	}
	if got := ctx.CheckProof("nas-sleeping", 0, true, now); got.State == StatePresent {
		t.Fatal("an unreachable proof must never satisfy require_verified")
	}
	if !strings.Contains(got.Detail, "not reachable") || !strings.Contains(got.Detail, "re-run the drill") {
		t.Errorf("unreachable detail should carry reachability remediation, got %q", got.Detail)
	}
	if strings.Contains(got.Detail, "investigate the copy") {
		t.Errorf("unreachable detail must not imply the copy is bad, got %q", got.Detail)
	}

	disputed := ctx.CheckProof("corrupt-copy", 0, false, now)
	if disputed.State != StateContradicted {
		t.Fatalf("disputed proof state = %s, want contradicted (unchanged)", disputed.State)
	}
	if !strings.Contains(disputed.Detail, "investigate the copy") {
		t.Errorf("disputed detail should carry investigate-the-copy remediation, got %q", disputed.Detail)
	}
	if disputed.Detail == got.Detail {
		t.Error("unreachable and disputed must render different detail text")
	}
}

func TestCheckProofExpired(t *testing.T) {
	now := t3339("2026-05-14T12:00:00Z")
	observed := t3339("2026-05-14T00:00:00Z")
	expired := t3339("2026-05-14T06:00:00Z")
	ctx := Context{Proofs: []Proof{{ID: "p", Status: ProofRecordValidated, ObservedAt: &observed, ExpiresAt: &expired}}}
	got := ctx.CheckProof("p", 0, false, now)
	if got.State != StateStale {
		t.Errorf("got %s, want stale", got.State)
	}
}

func TestCheckFact(t *testing.T) {
	now := t3339("2026-05-14T12:00:00Z")
	future := t3339("2026-05-15T00:00:00Z")
	past := t3339("2026-05-14T00:00:00Z")
	ctx := Context{Facts: []Fact{
		{ID: "current", Statement: "still true", ExpiresAt: &future},
		{ID: "expired", Statement: "was true", ExpiresAt: &past},
	}}
	if got := ctx.CheckFact("missing", now); got.State != StateMissing {
		t.Errorf("missing fact: got %s", got.State)
	}
	if got := ctx.CheckFact("current", now); got.State != StatePresent {
		t.Errorf("current fact: got %s", got.State)
	}
	if got := ctx.CheckFact("expired", now); got.State != StateStale {
		t.Errorf("expired fact: got %s", got.State)
	}
}

func TestCheckProofSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	observed := t3339("2026-05-14T00:00:00Z")
	sha := "sha256:deadbeef"
	message := []byte("signed-proof|validated|" + observed.Format(time.RFC3339) + "|" + sha)
	sig := ed25519.Sign(priv, message)

	valid := Proof{
		ID: "signed-proof", Status: ProofRecordValidated, ObservedAt: &observed, SHA256: sha,
		Signature: &Signature{PublicKeyHex: hex.EncodeToString(pub), SignatureHex: hex.EncodeToString(sig)},
	}
	tamperedBytes := append([]byte(nil), sig...)
	tamperedBytes[len(tamperedBytes)-1] ^= 0xFF // guaranteed to differ, unlike overwriting with a fixed byte
	tampered := valid
	tamperedSig := *valid.Signature
	tamperedSig.SignatureHex = hex.EncodeToString(tamperedBytes)
	tampered.Signature = &tamperedSig

	now := t3339("2026-05-14T12:00:00Z")
	ctx := Context{Proofs: []Proof{valid}}
	if got := ctx.CheckProof("signed-proof", 0, false, now); got.State != StatePresent {
		t.Errorf("valid signature: got %s (%s)", got.State, got.Detail)
	}
	ctx = Context{Proofs: []Proof{tampered}}
	if got := ctx.CheckProof("signed-proof", 0, false, now); got.State != StateContradicted {
		t.Errorf("tampered signature: got %s, want contradicted", got.State)
	}
}

// TestCheckProofRequireVerified: require_verified exists to distinguish "someone
// attested" from "a recovery was reconstructed and the bytes matched". An
// observed proof must NOT satisfy a guard that asked for the stronger claim,
// otherwise the guard silently accepts less evidence than it demanded.
func TestCheckProofRequireVerified(t *testing.T) {
	now := time.Now()
	observedAt := now.Add(-time.Hour)
	ctx := Context{Proofs: []Proof{
		{ID: "attested", Status: ProofRecordObserved, ObservedAt: &observedAt},
		{ID: "drilled", Status: ProofRecordValidated, ObservedAt: &observedAt, Verified: true},
	}}

	if got := ctx.CheckProof("attested", 0, false, now); got.State != StatePresent {
		t.Errorf("unverified proof should satisfy a guard that does not require verification, got %s", got.State)
	}
	got := ctx.CheckProof("attested", 0, true, now)
	if got.State != StateMissing {
		t.Errorf("unverified proof must not satisfy require_verified; want missing, got %s", got.State)
	}
	if !strings.Contains(got.Detail, "drill") {
		t.Errorf("detail should point at how to produce a verified proof, got %q", got.Detail)
	}
	if got := ctx.CheckProof("drilled", 0, true, now); got.State != StatePresent {
		t.Errorf("drill-produced proof must satisfy require_verified, got %s (%s)", got.State, got.Detail)
	}
}

// TestSignedMessageOldShapeUnchanged: a proof signed before drill v2 (no
// measurements) must sign and verify over exactly the pre-v2 message, so
// every proof signed before this change keeps verifying without re-signing.
func TestSignedMessageOldShapeUnchanged(t *testing.T) {
	got := SignedMessage("p1", "validated", "2026-08-04T00:00:00Z", "sha256:abc", nil)
	want := "p1|validated|2026-08-04T00:00:00Z|sha256:abc"
	if got != want {
		t.Errorf("SignedMessage(no measurements) = %q, want %q", got, want)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	observed := t3339("2026-08-04T00:00:00Z")
	sig := ed25519.Sign(priv, []byte(want))
	proof := Proof{
		ID: "p1", Status: ProofRecordValidated, ObservedAt: &observed, SHA256: "sha256:abc",
		Signature: &Signature{PublicKeyHex: hex.EncodeToString(pub), SignatureHex: hex.EncodeToString(sig)},
	}
	ctx := Context{Proofs: []Proof{proof}}
	if got := ctx.CheckProof("p1", 0, false, observed); got.State != StatePresent {
		t.Errorf("old-shape signed proof must still verify, got %s (%s)", got.State, got.Detail)
	}
}

// TestSignedMessageWithMeasurementsRoundtrips: a proof signed with
// measurements verifies when the measurements are carried through unchanged,
// and a tampered rto_seconds (the signer's claim about how fast the recovery
// was) invalidates the signature — the whole point of folding the digest in.
func TestSignedMessageWithMeasurementsRoundtrips(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rpo := 11532.0
	measurements := &Measurements{
		RTOSeconds: 4.21,
		RPOSeconds: &rpo,
		Checks: []CheckOutcome{
			{Type: "sqlite", Pass: true, Detail: "integrity ok"},
			{Type: "command", Pass: true, Detail: "extra invariant ok"},
		},
	}
	observed := t3339("2026-08-04T00:00:00Z")
	msg := SignedMessage("money-db-recovery", "validated", observed.Format(time.RFC3339), "sha256:abc", measurements)
	sig := ed25519.Sign(priv, []byte(msg))

	proof := Proof{
		ID: "money-db-recovery", Status: ProofRecordValidated, ObservedAt: &observed, SHA256: "sha256:abc",
		Measurements: measurements,
		Signature:    &Signature{PublicKeyHex: hex.EncodeToString(pub), SignatureHex: hex.EncodeToString(sig)},
	}
	ctx := Context{Proofs: []Proof{proof}}
	if got := ctx.CheckProof("money-db-recovery", 0, false, observed); got.State != StatePresent {
		t.Fatalf("measurement-carrying signature must verify, got %s (%s)", got.State, got.Detail)
	}

	// Tamper with rto_seconds after signing, exactly as a hand-edited YAML
	// file would: the signature must no longer verify.
	tampered := proof
	tamperedMeasurements := *measurements
	tamperedMeasurements.RTOSeconds = 0.01
	tampered.Measurements = &tamperedMeasurements
	ctx = Context{Proofs: []Proof{tampered}}
	if got := ctx.CheckProof("money-db-recovery", 0, false, observed); got.State != StateContradicted {
		t.Errorf("tampered rto_seconds must fail verification, got %s (%s)", got.State, got.Detail)
	}
}

// TestMeasurementDigestExcludesDetail: rewording a check's Detail (cosmetic,
// human-readable text) must not change the digest — only the numbers and
// pass/fail bits are signed claims.
func TestMeasurementDigestExcludesDetail(t *testing.T) {
	a := Measurements{RTOSeconds: 1, Checks: []CheckOutcome{{Type: "sqlite", Pass: true, Detail: "integrity ok"}}}
	b := Measurements{RTOSeconds: 1, Checks: []CheckOutcome{{Type: "sqlite", Pass: true, Detail: "totally different wording"}}}
	if MeasurementDigest(a) != MeasurementDigest(b) {
		t.Error("digest must not change when only Detail changes")
	}
	c := Measurements{RTOSeconds: 1, Checks: []CheckOutcome{{Type: "sqlite", Pass: false, Detail: "integrity ok"}}}
	if MeasurementDigest(a) == MeasurementDigest(c) {
		t.Error("digest must change when Pass changes")
	}
}
