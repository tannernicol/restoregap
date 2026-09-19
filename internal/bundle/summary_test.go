// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package bundle

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/ledger"
)

func summaryExpectedKey(t *testing.T, seed string) string {
	t.Helper()
	private, err := contextspec.ParseSigningKeySeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(private.Public().(ed25519.PublicKey))
}

func summaryLedger(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "ledger.jsonl")
	if _, err := ledger.AppendNow(path, ledger.EntryDecision, "sentinel-ledger-actor", ledger.Payload{
		Decision: &ledger.DecisionPayload{Verdict: "pass", Actor: "sentinel-actor"},
	}); err != nil {
		t.Fatal(err)
	}
	return path
}

func summaryContext(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "restoregap.yml")
	body := `version: 2
guards:
  - id: sentinel-guard
    kind: lifeline
    match: {paths: ["/sentinel/path"]}
    requires: {proofs: [sentinel-proof-id]}
drills:
  - proof: sentinel-proof-id
    artifact: /sentinel/artifact
    recovery_source: /sentinel/source
    recover: "sentinel recovery command"
    dependencies:
      paths: ["/sentinel/dependency"]
      commands: ["sentinel dependency command"]
proofs:
  - id: sentinel-proof-id
    status: validated
    observed_at: "2026-09-19T00:00:00Z"
    expires_at: "2026-10-19T00:00:00Z"
    verified: true
    command: "sentinel verifier command"
    measurements:
      rto_seconds: 1.25
      checks:
        - {type: sqlite, pass: true, detail: "sentinel check detail"}
    evidence_url: "https://sentinel.example/raw"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExportSummaryIsFixedFieldAndOpaque(t *testing.T) {
	dir := t.TempDir()
	ctxPath := summaryContext(t, dir)
	ledgerPath := summaryLedger(t, dir)
	seed := testSigningKey(t)
	out := filepath.Join(dir, "summary.json")
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	if _, err := ExportSummary(SummaryExportRequest{
		ContextPaths: []string{ctxPath}, LedgerPath: ledgerPath, SigningKey: seed,
		Out: out, AsOf: now, Now: now, Label: "Orders database recovery",
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, sentinel := range []string{
		"sentinel-proof-id", "sentinel-guard", "sentinel/path", "sentinel/artifact",
		"sentinel recovery command", "sentinel verifier command", "sentinel.example",
		"sentinel check detail", "sentinel-ledger-actor",
	} {
		if strings.Contains(string(raw), sentinel) {
			t.Fatalf("summary leaked sentinel %q: %s", sentinel, raw)
		}
	}
	verified, err := VerifySummary(out, summaryExpectedKey(t, seed))
	if err != nil {
		t.Fatal(err)
	}
	if !verified.OK {
		t.Fatalf("summary should verify: %s", verified.Reason)
	}
	if verified.Summary.Label != "Orders database recovery" || verified.Summary.Ledger.Count != 1 {
		t.Fatalf("unexpected summary metadata: %+v", verified.Summary)
	}
	if strings.Join(verified.Summary.Limitations, ",") != "declared_scope_only,producer_claims_only,not_execution_receipt" {
		t.Fatalf("unexpected fixed limitations: %+v", verified.Summary.Limitations)
	}
	if len(verified.Summary.Proofs) != 1 {
		t.Fatalf("proof count = %d, want 1", len(verified.Summary.Proofs))
	}
	proof := verified.Summary.Proofs[0]
	if proof.Outcome != "pass" || !proof.Verified || proof.Method != "drill" || proof.Assurance != "unbound_legacy" {
		t.Fatalf("unexpected proof summary: %+v", proof)
	}
	if proof.Measurements == nil || len(proof.Measurements.Checks) != 1 || proof.Measurements.Checks[0].Type != "sqlite" || !proof.Measurements.Checks[0].Pass {
		t.Fatalf("unexpected safe measurements: %+v", proof.Measurements)
	}
}

func TestSummaryInvalidSignatureDoesNotLookGreen(t *testing.T) {
	dir := t.TempDir()
	ctxPath := filepath.Join(dir, "restoregap.yml")
	body := `version: 2
proofs:
  - id: signed-proof
    status: validated
    observed_at: "2026-09-19T00:00:00Z"
    verified: true
    signature:
      version: 2
      public_key: "0000000000000000000000000000000000000000000000000000000000000000"
      signature: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
`
	if err := os.WriteFile(ctxPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	seed := testSigningKey(t)
	path, err := ExportSummary(SummaryExportRequest{ContextPaths: []string{ctxPath}, LedgerPath: summaryLedger(t, dir), SigningKey: seed, Out: filepath.Join(dir, "summary.json")})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySummary(path, summaryExpectedKey(t, seed))
	if err != nil || !verified.OK {
		t.Fatalf("summary signature should be its own valid envelope: %v %+v", err, verified)
	}
	if len(verified.Summary.Proofs) != 1 || verified.Summary.Proofs[0].Outcome != "disputed" || verified.Summary.Proofs[0].Verified {
		t.Fatalf("invalid proof signature must not look green: %+v", verified.Summary.Proofs)
	}
	if verified.Summary.Proofs[0].Method != "drill" || verified.Summary.Proofs[0].Assurance != "invalid_signature" {
		t.Fatalf("invalid signature must preserve recorded drill method and assurance: %+v", verified.Summary.Proofs[0])
	}
}

func TestSummaryAssuranceChecksSignatureIndependentOfHealth(t *testing.T) {
	observed := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	proof := contextspec.Proof{
		ID: "proof-signature-name", Status: contextspec.ProofRecordDisputed,
		ObservedAt: &observed,
		Signature:  &contextspec.Signature{PublicKeyHex: hex.EncodeToString(public)},
	}
	message := contextspec.SignedMessage(proof.ID, string(proof.Status), observed.Format(time.RFC3339), proof.SHA256, proof.Measurements)
	proof.Signature.SignatureHex = hex.EncodeToString(ed25519.Sign(private, []byte(message)))
	if got := summaryAssurance(proof); got == "invalid_signature" {
		t.Fatalf("valid signature on disputed proof was mislabeled: %s", got)
	}
	proof.Signature.SignatureHex = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	if got := summaryAssurance(proof); got != "invalid_signature" {
		t.Fatalf("tampered terminal proof was not labeled invalid_signature: %s", got)
	}
}

func TestSummaryScopeIsOpaqueAndExpiryPreservesRecordedMethod(t *testing.T) {
	dir := t.TempDir()
	ctxPath := filepath.Join(dir, "restoregap.yml")
	if err := os.WriteFile(ctxPath, []byte(`version: 2
proofs:
  - id: prod-proof
    status: validated
    observed_at: "2026-08-01T00:00:00Z"
    expires_at: "2026-09-01T00:00:00Z"
    verified: true
    scope: {environment: customer-prod-sentinel}
  - id: dev-proof
    status: validated
    observed_at: "2026-08-01T00:00:00Z"
    verified: true
    scope: {environment: customer-dev-sentinel}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	seed := testSigningKey(t)
	out := filepath.Join(dir, "summary.json")
	asOf := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	if _, err := ExportSummary(SummaryExportRequest{
		ContextPaths: []string{ctxPath}, LedgerPath: summaryLedger(t, dir), SigningKey: seed,
		Out: out, AsOf: asOf, Scope: ScopeFilter{Environment: "customer-prod-sentinel"},
	}); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySummary(out, summaryExpectedKey(t, seed))
	if err != nil || !verified.OK {
		t.Fatalf("scoped summary should verify: %v %+v", err, verified)
	}
	if verified.Summary.ScopeSelection != "filtered" || verified.Summary.ScopeEnvironmentDigest != opaqueDigest("customer-prod-sentinel") || len(verified.Summary.Proofs) != 1 {
		t.Fatalf("scope selection should be opaque and filtered: %+v", verified.Summary)
	}
	if strings.Contains(string(mustRead(t, out)), "customer-prod-sentinel") {
		t.Fatal("summary leaked the selected scope identifier")
	}
	proof := verified.Summary.Proofs[0]
	if proof.Outcome != "expired" || proof.Verified || proof.Method != "drill" {
		t.Fatalf("expired drill must retain method while losing current verification: %+v", proof)
	}
}

func TestValidateSummaryRejectsSemanticDuplicates(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	base := SummaryPayload{
		SchemaVersion: SummarySchemaVersion, GeneratedAt: now, AsOf: now,
		Limitations: summaryLimitations(), ScopeSelection: "all",
		Ledger: SummaryLedger{Integrity: "valid"},
	}
	proof := SummaryProof{ProofDigest: opaqueDigest("p"), Outcome: "pass", Assurance: "unbound_legacy", Verified: true, Method: "drill"}
	base.Proofs = []SummaryProof{proof, proof}
	if err := validateSummaryPayload(base); err == nil || !strings.Contains(err.Error(), "duplicate proof_digest") {
		t.Fatalf("duplicate proof digests must be rejected: %v", err)
	}
	base.Proofs = []SummaryProof{{ProofDigest: opaqueDigest("p"), Outcome: "pass", Assurance: "unbound_legacy", Verified: false, Method: "attestation"}}
	if err := validateSummaryPayload(base); err == nil || !strings.Contains(err.Error(), "must be verified") {
		t.Fatalf("pass without verification must be rejected: %v", err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifySummaryRejectsTamperUnknownVersionAndWrongKey(t *testing.T) {
	dir := t.TempDir()
	ctxPath := summaryContext(t, dir)
	seed := testSigningKey(t)
	out := filepath.Join(dir, "summary.json")
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	if _, err := ExportSummary(SummaryExportRequest{ContextPaths: []string{ctxPath}, LedgerPath: summaryLedger(t, dir), SigningKey: seed, Out: out, AsOf: now, Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportSummary(SummaryExportRequest{ContextPaths: []string{ctxPath}, LedgerPath: summaryLedger(t, dir), SigningKey: seed, Out: out, AsOf: now, Now: now}); err == nil || !strings.Contains(err.Error(), "creating") {
		t.Fatalf("summary export must refuse replacing an existing output: %v", err)
	}
	wrong := testSigningKey(t)
	badKey, err := VerifySummary(out, summaryExpectedKey(t, wrong))
	if err != nil || badKey.OK || !strings.Contains(badKey.Reason, "expected public key") {
		t.Fatalf("wrong expected key must fail: %v %+v", err, badKey)
	}
	original, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(original, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["schema_version"] = float64(99)
	changed, _ := json.Marshal(envelope)
	if err := os.WriteFile(out, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	unknownVersion, err := VerifySummary(out, summaryExpectedKey(t, seed))
	if err != nil || unknownVersion.OK || !strings.Contains(unknownVersion.Reason, "unsupported summary schema") {
		t.Fatalf("unknown schema must fail validation: %v %+v", err, unknownVersion)
	}
	envelope["schema_version"] = float64(SummarySchemaVersion)
	envelope["unexpected"] = "reject this"
	changed, _ = json.Marshal(envelope)
	if err := os.WriteFile(out, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySummary(out, summaryExpectedKey(t, seed)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field must be rejected: %v", err)
	}
	duplicate := strings.Replace(string(original), `"schema_version": 1,`, `"schema_version": 1, "schema_version": 1,`, 1)
	if err := os.WriteFile(out, []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySummary(out, summaryExpectedKey(t, seed)); err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
		t.Fatalf("duplicate fields must be rejected: %v", err)
	}
	if err := os.WriteFile(out, original, 0o600); err != nil {
		t.Fatal(err)
	}
	var tampered map[string]any
	if err := json.Unmarshal(original, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered["label"] = "tampered"
	changed, _ = json.Marshal(tampered)
	if err := os.WriteFile(out, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	tamper, err := VerifySummary(out, summaryExpectedKey(t, seed))
	if err != nil || tamper.OK || !strings.Contains(tamper.Reason, "signature does not verify") {
		t.Fatalf("tamper must fail signature: %v %+v", err, tamper)
	}
}

func TestExportSummaryRefusesMissingOrBrokenLedger(t *testing.T) {
	dir := t.TempDir()
	ctxPath := summaryContext(t, dir)
	seed := testSigningKey(t)
	missing := filepath.Join(dir, "missing.jsonl")
	if _, err := ExportSummary(SummaryExportRequest{ContextPaths: []string{ctxPath}, LedgerPath: missing, SigningKey: seed, Out: filepath.Join(dir, "missing.json")}); err == nil || !strings.Contains(err.Error(), "missing or unreadable") {
		t.Fatalf("missing requested ledger must error: %v", err)
	}
	broken := filepath.Join(dir, "broken.jsonl")
	if err := os.WriteFile(broken, []byte("not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportSummary(SummaryExportRequest{ContextPaths: []string{ctxPath}, LedgerPath: broken, SigningKey: seed, Out: filepath.Join(dir, "broken.json")}); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("broken requested ledger must error: %v", err)
	}
}

func TestFullBundleExpectedKeyIsOptionalButIndependentWhenGiven(t *testing.T) {
	dir := t.TempDir()
	ctxPath := writeCtx(t, dir, "restoregap.yml", "version: 2\nguards: []\n")
	seed := testSigningKey(t)
	out := filepath.Join(dir, "full.tgz")
	if _, err := Export(ExportRequest{ContextPaths: []string{ctxPath}, SigningKey: seed, Out: out}); err != nil {
		t.Fatal(err)
	}
	if result, err := VerifyWithExpectedKey(out, summaryExpectedKey(t, seed)); err != nil || !result.OK {
		t.Fatalf("full bundle with matching expected key should verify: %v %+v", err, result)
	}
	if result, err := VerifyWithExpectedKey(out, summaryExpectedKey(t, testSigningKey(t))); err != nil || result.OK {
		t.Fatalf("full bundle with wrong expected key should fail: %v %+v", err, result)
	}
}
