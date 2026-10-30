// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package bundle

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/ledger"
	"github.com/tannernicol/restoregap/internal/policy"
)

// SummarySchemaVersion is independent of the full tar.gz bundle format. The
// summary is a deliberately smaller, fixed-shape handoff surface.
const SummarySchemaVersion = 1

const (
	summaryDomain        = "restoregap:evidence-summary:v1\x00"
	maxSummaryBytes      = 1 << 20
	maxSummaryProofs     = 4096
	maxSummaryChecks     = 64
	maxSummaryLedger     = maxSummaryProofs * 16
	maxSummaryLedgerLine = 1 << 20
	maxSummaryStringLen  = 256
)

// SummaryExportRequest is the input to the offline JSON evidence summary.
// It deliberately has no receiver, upload, or raw-file output option.
type SummaryExportRequest struct {
	ContextPaths []string
	LedgerPath   string
	SigningKey   string
	Out          string
	Scope        ScopeFilter
	Label        string
	AsOf         time.Time
	// Now is a test seam for GeneratedAt. A zero value uses the current UTC
	// time; AsOf defaults to the generated time when it is also zero.
	Now time.Time
}

// SummaryPayload is the signed, allowlisted evidence content. ProofDigest is
// sha256(proof ID), so an independent reviewer can map records without the
// summary itself carrying user-controlled identifiers.
type SummaryPayload struct {
	SchemaVersion          int            `json:"schema_version"`
	GeneratedAt            time.Time      `json:"generated_at"`
	AsOf                   time.Time      `json:"as_of"`
	Label                  string         `json:"label,omitempty"`
	Limitations            []string       `json:"limitations"`
	ScopeSelection         string         `json:"scope_selection"`
	ScopeEnvironmentDigest string         `json:"scope_environment_digest,omitempty"`
	ScopeSystemDigest      string         `json:"scope_system_digest,omitempty"`
	ScopeHostDigest        string         `json:"scope_host_digest,omitempty"`
	Proofs                 []SummaryProof `json:"proofs"`
	PolicyDigest           string         `json:"policy_digest,omitempty"`
	Ledger                 SummaryLedger  `json:"ledger"`
}

// SummaryProof is the fixed proof-level handoff vocabulary. Empty optional
// fields are omitted; there is no free-form detail field.
type SummaryProof struct {
	ProofDigest      string               `json:"proof_digest"`
	Outcome          string               `json:"outcome"`
	Assurance        string               `json:"assurance"`
	Verified         bool                 `json:"verified"`
	Method           string               `json:"method"`
	ObservedAt       *time.Time           `json:"observed_at,omitempty"`
	ExpiresAt        *time.Time           `json:"expires_at,omitempty"`
	RecipeDigest     string               `json:"recipe_digest,omitempty"`
	DependencyDigest string               `json:"dependency_digest,omitempty"`
	Measurements     *SummaryMeasurements `json:"measurements,omitempty"`
}

// SummaryMeasurements retains only finite numeric measurements and a bounded
// allowlist of check type/pass pairs. Human-readable check detail is excluded.
type SummaryMeasurements struct {
	RTOSeconds float64        `json:"rto_seconds"`
	RPOSeconds *float64       `json:"rpo_seconds,omitempty"`
	Checks     []SummaryCheck `json:"checks,omitempty"`
}

// SummaryCheck is one allowlisted finite measurement check without producer detail.
type SummaryCheck struct {
	Type string `json:"type"`
	Pass bool   `json:"pass"`
}

// SummaryLedger carries integrity facts only, never ledger entries or actors.
type SummaryLedger struct {
	Integrity     string `json:"integrity"` // valid | anchored
	Count         int    `json:"count"`
	TailDigest    string `json:"tail_digest,omitempty"`
	AnchoredCount int    `json:"anchored_count"`
}

// SummarySignature is outside the signed payload. The expected public key is
// supplied independently by the verifier; the key embedded here is metadata
// used only to check that the signer is the explicitly trusted key.
type SummarySignature struct {
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type summaryEnvelope struct {
	SummaryPayload
	Signature SummarySignature `json:"signature"`
}

// SummaryVerifyResult reports summary verification without returning any
// partially trusted result as successful.
type SummaryVerifyResult struct {
	OK      bool
	Summary SummaryPayload
	Reason  string
}

// ExportSummary builds and signs a bounded, offline JSON summary from the
// merged and validated context plus a fully verified requested ledger.
func ExportSummary(req SummaryExportRequest) (string, error) {
	signer, err := summarySigner(req.SigningKey)
	if err != nil {
		return "", err
	}
	ctx, policyDigest, ledgerSummary, err := loadSummaryInputs(req)
	if err != nil {
		return "", err
	}
	generated, asOf := summaryTimes(req)
	proofs, err := buildSummaryProofs(ctx, asOf, req.Scope)
	if err != nil {
		return "", err
	}
	payload := SummaryPayload{
		SchemaVersion:          SummarySchemaVersion,
		GeneratedAt:            generated,
		AsOf:                   asOf,
		Label:                  req.Label,
		Limitations:            summaryLimitations(),
		ScopeSelection:         summaryScopeSelection(req.Scope),
		ScopeEnvironmentDigest: summaryScopeDigest(req.Scope.Environment),
		ScopeSystemDigest:      summaryScopeDigest(req.Scope.System),
		ScopeHostDigest:        summaryScopeDigest(req.Scope.Host),
		Proofs:                 proofs,
		PolicyDigest:           policyDigest,
		Ledger:                 ledgerSummary,
	}
	return writeSignedSummary(payload, signer, req.Out)
}

func summarySigner(key string) (ed25519.PrivateKey, error) {
	signer, err := contextspec.ParseSigningKeySeed(key)
	if err != nil {
		return nil, fmt.Errorf("bundle summary export: %w", err)
	}
	if signer == nil {
		return nil, fmt.Errorf("bundle summary export: --signing-key is required")
	}
	return signer, nil
}

func loadSummaryInputs(req SummaryExportRequest) (contextspec.Context, string, SummaryLedger, error) {
	if len(req.ContextPaths) == 0 {
		return contextspec.Context{}, "", SummaryLedger{}, fmt.Errorf("bundle summary export: no context file found")
	}
	if strings.TrimSpace(req.LedgerPath) == "" {
		return contextspec.Context{}, "", SummaryLedger{}, fmt.Errorf("bundle summary export: --ledger is required and must name an existing ledger")
	}
	ctx, _, err := policy.Merge(req.ContextPaths)
	if err != nil {
		return contextspec.Context{}, "", SummaryLedger{}, fmt.Errorf("bundle summary export: merging context: %w", err)
	}
	policyDigest, _, err := policy.Revision(req.ContextPaths)
	if err != nil {
		return contextspec.Context{}, "", SummaryLedger{}, fmt.Errorf("bundle summary export: policy digest: %w", err)
	}
	ledgerSummary, err := readSummaryLedger(req.LedgerPath)
	if err != nil {
		return contextspec.Context{}, "", SummaryLedger{}, fmt.Errorf("bundle summary export: %w", err)
	}
	return ctx, policyDigest, ledgerSummary, nil
}

func summaryTimes(req SummaryExportRequest) (time.Time, time.Time) {
	generated := req.Now
	if generated.IsZero() {
		generated = time.Now().UTC()
	} else {
		generated = generated.UTC()
	}
	asOf := req.AsOf
	if asOf.IsZero() {
		asOf = generated
	} else {
		asOf = asOf.UTC()
	}
	return generated, asOf
}

func buildSummaryProofs(ctx contextspec.Context, asOf time.Time, scope ScopeFilter) ([]SummaryProof, error) {
	proofs := scopedProofs(ctx, scope)
	if len(proofs) > maxSummaryProofs {
		return nil, fmt.Errorf("bundle summary export: proof count %d exceeds limit %d", len(proofs), maxSummaryProofs)
	}
	summaryProofs := make([]SummaryProof, 0, len(proofs))
	for _, proof := range proofs {
		sp, err := makeSummaryProof(ctx, proof, asOf)
		if err != nil {
			return nil, fmt.Errorf("bundle summary export: proof summary: %w", err)
		}
		summaryProofs = append(summaryProofs, sp)
	}
	return summaryProofs, nil
}

func writeSignedSummary(payload SummaryPayload, signer ed25519.PrivateKey, requestedOut string) (string, error) {
	if err := validateSummaryPayload(payload); err != nil {
		return "", fmt.Errorf("bundle summary export: %w", err)
	}
	signed, err := summarySigningBytes(payload)
	if err != nil {
		return "", fmt.Errorf("bundle summary export: encoding payload: %w", err)
	}
	envelope := summaryEnvelope{SummaryPayload: payload, Signature: SummarySignature{
		PublicKey: hex.EncodeToString(signer.Public().(ed25519.PublicKey)),
		Signature: hex.EncodeToString(ed25519.Sign(signer, signed)),
	}}
	raw, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return "", fmt.Errorf("bundle summary export: encoding envelope: %w", err)
	}
	if len(raw)+1 > maxSummaryBytes {
		return "", fmt.Errorf("bundle summary export: summary exceeds %d-byte limit", maxSummaryBytes)
	}
	out := requestedOut
	if out == "" {
		out = "restoregap-summary-" + payload.GeneratedAt.Format("20060102T150405Z") + ".json"
	}
	if err := writeNewSummaryFile(out, append(raw, '\n')); err != nil {
		return "", fmt.Errorf("bundle summary export: %w", err)
	}
	return out, nil
}

func writeNewSummaryFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("syncing %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", path, err)
	}
	return nil
}

// VerifySummary requires an independently supplied expected public key. The
// public key embedded in the envelope is not trusted merely because it is
// present in the artifact.
func VerifySummary(path, expectedKey string) (SummaryVerifyResult, error) {
	if strings.TrimSpace(expectedKey) == "" {
		return SummaryVerifyResult{}, fmt.Errorf("bundle summary verify: --expected-key is required")
	}
	raw, err := readBoundedSummary(path)
	if err != nil {
		return SummaryVerifyResult{}, fmt.Errorf("bundle summary verify: %w", err)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return SummaryVerifyResult{}, fmt.Errorf("bundle summary verify: %w", err)
	}
	var envelope summaryEnvelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&envelope); err != nil {
		return SummaryVerifyResult{}, fmt.Errorf("bundle summary verify: invalid JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return SummaryVerifyResult{}, fmt.Errorf("bundle summary verify: trailing JSON data")
	}
	if err := validateSummaryPayload(envelope.SummaryPayload); err != nil {
		return SummaryVerifyResult{Summary: envelope.SummaryPayload, Reason: err.Error()}, nil
	}
	pub, err := parseExpectedPublicKey(expectedKey)
	if err != nil {
		return SummaryVerifyResult{}, fmt.Errorf("bundle summary verify: %w", err)
	}
	declaredPub, err := hex.DecodeString(envelope.Signature.PublicKey)
	if err != nil || len(declaredPub) != ed25519.PublicKeySize {
		return SummaryVerifyResult{Summary: envelope.SummaryPayload, Reason: "summary public key is not a valid Ed25519 key"}, nil
	}
	if !bytes.Equal(pub, declaredPub) {
		return SummaryVerifyResult{Summary: envelope.SummaryPayload, Reason: "summary signer does not match the expected public key"}, nil
	}
	sig, err := hex.DecodeString(envelope.Signature.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return SummaryVerifyResult{Summary: envelope.SummaryPayload, Reason: "summary signature is not a valid Ed25519 signature"}, nil
	}
	signed, err := summarySigningBytes(envelope.SummaryPayload)
	if err != nil {
		return SummaryVerifyResult{}, fmt.Errorf("bundle summary verify: encoding payload: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), signed, sig) {
		return SummaryVerifyResult{Summary: envelope.SummaryPayload, Reason: "summary signature does not verify"}, nil
	}
	return SummaryVerifyResult{OK: true, Summary: envelope.SummaryPayload}, nil
}

func makeSummaryProof(ctx contextspec.Context, proof contextspec.Proof, asOf time.Time) (SummaryProof, error) {
	result := ctx.CheckProof(proof.ID, 0, false, asOf)
	verified := proof.Verified && result.State == contextspec.StatePresent
	outcome := "observed"
	switch result.State {
	case contextspec.StatePresent:
		if verified {
			outcome = "pass"
		}
	case contextspec.StateStale:
		if proof.ExpiresAt != nil && asOf.After(*proof.ExpiresAt) {
			outcome = "expired"
		} else {
			outcome = "stale"
		}
	case contextspec.StateContradicted:
		outcome = "disputed"
	case contextspec.StateUnreachable:
		outcome = "unreachable"
	default:
		outcome = "unknown"
	}
	sp := SummaryProof{
		ProofDigest: opaqueDigest(proof.ID),
		Outcome:     outcome,
		Assurance:   summaryAssurance(proof),
		Verified:    verified,
		Method:      "attestation",
		ObservedAt:  proof.ObservedAt,
		ExpiresAt:   proof.ExpiresAt,
	}
	if proof.Verified {
		sp.Method = "drill"
	}
	if proof.Measurements != nil {
		measurements, err := makeSummaryMeasurements(*proof.Measurements)
		if err != nil {
			return SummaryProof{}, err
		}
		sp.Measurements = measurements
	}
	if proof.RecipeDigest != "" {
		sp.RecipeDigest = proof.RecipeDigest
	}
	if proof.Dependencies != nil {
		deps, err := json.Marshal(contextspec.NormalizeDependencies(*proof.Dependencies))
		if err != nil {
			return SummaryProof{}, fmt.Errorf("dependency digest: %w", err)
		}
		sp.DependencyDigest = opaqueDigest(string(deps))
	}
	return sp, nil
}

func summaryAssurance(proof contextspec.Proof) string {
	if proof.Signature != nil {
		valid, err := contextspec.VerifyProofSignature(proof)
		if err != nil || !valid {
			return "invalid_signature"
		}
	}
	bound := proof.RecipeDigest != "" || proof.Dependencies != nil
	complete := proof.RecipeDigest != "" && proof.Dependencies != nil
	signed := proof.Signature != nil
	if !bound {
		if signed && proof.Signature.Version == 2 {
			return "unbound_signed_v2"
		}
		if signed {
			return "unbound_signed_legacy"
		}
		return "unbound_legacy"
	}
	if !complete {
		return "binding_incomplete"
	}
	if signed && proof.Signature.Version == 2 {
		return "bound_signed_v2"
	}
	return "bound_unsigned"
}

func summaryScopeSelection(scope ScopeFilter) string {
	if scope.Environment == "" && scope.System == "" && scope.Host == "" {
		return "all"
	}
	return "filtered"
}

func summaryScopeDigest(value string) string {
	if value == "" {
		return ""
	}
	return opaqueDigest(value)
}

func makeSummaryMeasurements(m contextspec.Measurements) (*SummaryMeasurements, error) {
	if !finiteMeasurement(m.RTOSeconds) || m.RTOSeconds < 0 {
		return nil, fmt.Errorf("measurement rto_seconds must be finite and non-negative")
	}
	out := &SummaryMeasurements{RTOSeconds: m.RTOSeconds}
	if m.RPOSeconds != nil {
		if !finiteMeasurement(*m.RPOSeconds) || *m.RPOSeconds < 0 {
			return nil, fmt.Errorf("measurement rpo_seconds must be finite and non-negative")
		}
		value := *m.RPOSeconds
		out.RPOSeconds = &value
	}
	if len(m.Checks) > maxSummaryChecks {
		return nil, fmt.Errorf("measurement check count %d exceeds limit %d", len(m.Checks), maxSummaryChecks)
	}
	out.Checks = make([]SummaryCheck, 0, len(m.Checks))
	for _, check := range m.Checks {
		if !summaryCheckTypes[check.Type] {
			return nil, fmt.Errorf("measurement check type %q is not allowlisted", check.Type)
		}
		out.Checks = append(out.Checks, SummaryCheck{Type: check.Type, Pass: check.Pass})
	}
	return out, nil
}

var summaryCheckTypes = map[string]bool{
	"byte_identical":  true,
	"file_tree":       true,
	"command":         true,
	"sqlite":          true,
	"git":             true,
	"serve":           true,
	"key_fingerprint": true,
	"budget_rto":      true,
	"budget_rpo":      true,
}

func finiteMeasurement(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value <= 1e12
}

func opaqueDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func summarySigningBytes(payload SummaryPayload) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return append([]byte(summaryDomain), raw...), nil
}

func readSummaryLedger(path string) (SummaryLedger, error) {
	info, err := os.Stat(path)
	if err != nil {
		return SummaryLedger{}, fmt.Errorf("ledger %s is missing or unreadable: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return SummaryLedger{}, fmt.Errorf("ledger %s is not a regular file", path)
	}
	entries, err := readBoundedLedger(path)
	if err != nil {
		return SummaryLedger{}, fmt.Errorf("ledger %s is unreadable: %w", path, err)
	}
	for _, entry := range entries {
		if err := entry.Validate(); err != nil {
			return SummaryLedger{}, fmt.Errorf("ledger %s is invalid: %w", path, err)
		}
	}
	result := ledger.VerifyEntries(entries)
	if !result.OK {
		return SummaryLedger{}, fmt.Errorf("ledger %s failed integrity verification: %s", path, result.Reason)
	}
	integrity := "valid"
	if len(result.AnchoredAnomalies) > 0 {
		integrity = "anchored"
	}
	return SummaryLedger{
		Integrity:     integrity,
		Count:         result.EntryCount,
		TailDigest:    result.LastHash,
		AnchoredCount: len(result.AnchoredAnomalies),
	}, nil
}

func readBoundedLedger(path string) ([]ledger.Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxSummaryLedgerLine)
	entries := make([]ledger.Entry, 0)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if len(entries) == maxSummaryLedger {
			_ = file.Close()
			return nil, fmt.Errorf("ledger contains more than %d entries", maxSummaryLedger)
		}
		var entry ledger.Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			_ = file.Close()
			return nil, err
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return entries, nil
}

func validateSummaryPayload(payload SummaryPayload) error {
	if err := validateSummaryMetadata(payload); err != nil {
		return err
	}
	if err := validateSummaryLedger(payload.Ledger); err != nil {
		return err
	}
	return validateSummaryProofs(payload.Proofs)
}

func validateSummaryMetadata(payload SummaryPayload) error {
	if payload.SchemaVersion != SummarySchemaVersion {
		return fmt.Errorf("unsupported summary schema_version %d", payload.SchemaVersion)
	}
	if payload.GeneratedAt.IsZero() || payload.AsOf.IsZero() {
		return fmt.Errorf("summary generated_at and as_of are required")
	}
	if !equalStrings(payload.Limitations, summaryLimitations()) {
		return fmt.Errorf("summary limitations are missing or changed")
	}
	if err := validateSummaryScope(payload); err != nil {
		return err
	}
	if len(payload.Proofs) > maxSummaryProofs {
		return fmt.Errorf("summary proof count exceeds limit %d", maxSummaryProofs)
	}
	if len(payload.PolicyDigest) > maxSummaryStringLen {
		return fmt.Errorf("summary policy_digest exceeds length limit")
	}
	if err := validateSummaryLabel(payload.Label); err != nil {
		return err
	}
	return nil
}

func validateSummaryLedger(ledgerSummary SummaryLedger) error {
	if ledgerSummary.Integrity != "valid" && ledgerSummary.Integrity != "anchored" {
		return fmt.Errorf("summary ledger integrity is invalid")
	}
	if ledgerSummary.Count < 0 || ledgerSummary.Count > maxSummaryLedger {
		return fmt.Errorf("summary ledger count is out of bounds")
	}
	if ledgerSummary.AnchoredCount < 0 || ledgerSummary.AnchoredCount > ledgerSummary.Count {
		return fmt.Errorf("summary ledger anchored_count is out of bounds")
	}
	if ledgerSummary.TailDigest != "" && !validDigest(ledgerSummary.TailDigest) {
		return fmt.Errorf("summary ledger tail_digest is invalid")
	}
	return nil
}

func validateSummaryProofs(proofs []SummaryProof) error {
	seen := make(map[string]bool, len(proofs))
	for _, proof := range proofs {
		if err := validateSummaryProof(proof); err != nil {
			return err
		}
		if seen[proof.ProofDigest] {
			return fmt.Errorf("summary contains duplicate proof_digest %q", proof.ProofDigest)
		}
		seen[proof.ProofDigest] = true
	}
	return nil
}

func validateSummaryProof(proof SummaryProof) error {
	if !validDigest(proof.ProofDigest) {
		return fmt.Errorf("summary proof_digest is invalid")
	}
	if !summaryOutcomes[proof.Outcome] {
		return fmt.Errorf("summary proof outcome %q is not allowlisted", proof.Outcome)
	}
	if proof.Outcome == "pass" && !proof.Verified {
		return fmt.Errorf("summary pass proof must be verified")
	}
	if proof.Verified && proof.Outcome != "pass" {
		return fmt.Errorf("summary verified proof must have pass outcome")
	}
	if !summaryAssurances[proof.Assurance] {
		return fmt.Errorf("summary proof assurance %q is not allowlisted", proof.Assurance)
	}
	if proof.RecipeDigest != "" && !validDigest(proof.RecipeDigest) {
		return fmt.Errorf("summary recipe_digest is invalid")
	}
	if proof.DependencyDigest != "" && !validDigest(proof.DependencyDigest) {
		return fmt.Errorf("summary dependency_digest is invalid")
	}
	if proof.Method != "drill" && proof.Method != "attestation" {
		return fmt.Errorf("summary proof method %q is not allowlisted", proof.Method)
	}
	if proof.Measurements == nil {
		return nil
	}
	_, err := makeSummaryMeasurements(contextspec.Measurements{
		RTOSeconds: proof.Measurements.RTOSeconds,
		RPOSeconds: proof.Measurements.RPOSeconds,
		Checks:     summaryCheckOutcomes(proof.Measurements.Checks),
	})
	return err
}

func summaryCheckOutcomes(checks []SummaryCheck) []contextspec.CheckOutcome {
	out := make([]contextspec.CheckOutcome, 0, len(checks))
	for _, check := range checks {
		out = append(out, contextspec.CheckOutcome{Type: check.Type, Pass: check.Pass})
	}
	return out
}

func validateSummaryLabel(label string) error {
	if len(label) > 120 {
		return fmt.Errorf("summary label exceeds 120 bytes")
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return fmt.Errorf("summary label contains a control character")
		}
	}
	return nil
}

func validateSummaryScope(payload SummaryPayload) error {
	if payload.ScopeSelection != "all" && payload.ScopeSelection != "filtered" {
		return fmt.Errorf("summary scope_selection is invalid")
	}
	digests := []string{payload.ScopeEnvironmentDigest, payload.ScopeSystemDigest, payload.ScopeHostDigest}
	anyDigest := false
	for _, digest := range digests {
		if digest == "" {
			continue
		}
		anyDigest = true
		if !validDigest(digest) {
			return fmt.Errorf("summary scope digest is invalid")
		}
	}
	if payload.ScopeSelection == "all" && anyDigest {
		return fmt.Errorf("summary all-scope selection cannot carry scope digests")
	}
	if payload.ScopeSelection == "filtered" && !anyDigest {
		return fmt.Errorf("summary filtered scope must name an opaque selector digest")
	}
	return nil
}

var summaryOutcomes = map[string]bool{
	"pass":        true,
	"observed":    true,
	"expired":     true,
	"stale":       true,
	"disputed":    true,
	"unreachable": true,
	"unknown":     true,
}

var summaryAssurances = map[string]bool{
	"unbound_legacy":        true,
	"unbound_signed_legacy": true,
	"unbound_signed_v2":     true,
	"binding_incomplete":    true,
	"bound_unsigned":        true,
	"bound_signed_v2":       true,
	"invalid_signature":     true,
}

func summaryLimitations() []string {
	return []string{"declared_scope_only", "producer_claims_only", "not_execution_receipt"}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func readBoundedSummary(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("summary %s is not a regular file", path)
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxSummaryBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("reading %s: %w", path, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("closing %s: %w", path, closeErr)
	}
	if len(raw) > maxSummaryBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, maxSummaryBytes)
	}
	return raw, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON data")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch delim := token.(type) {
	case json.Delim:
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				keyString, ok := key.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				if seen[keyString] {
					return fmt.Errorf("duplicate JSON field %q", keyString)
				}
				seen[keyString] = true
				if err := consumeJSONValue(decoder); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := consumeJSONValue(decoder); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
	default:
		return nil
	}
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func parseExpectedPublicKey(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("--expected-key must be a %d-byte Ed25519 public key in hex", ed25519.PublicKeySize)
	}
	return decoded, nil
}
