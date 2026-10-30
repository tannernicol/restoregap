// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

func writeEvidenceContext(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "restoregap.yml")
	const doc = `version: 2
proofs:
  - id: p
    status: observed
    observed_at: "2026-08-01T00:00:00Z"
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExportRequestedUnreadableLedgerReturnsError(t *testing.T) {
	dir := t.TempDir()
	contextPath := writeEvidenceContext(t, dir)
	ledgerPath := filepath.Join(dir, "ledger-dir")
	if err := os.Mkdir(ledgerPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Export(ExportRequest{ContextPath: contextPath, LedgerPath: ledgerPath, AsOf: "2026-08-02T00:00:00Z"}); err == nil {
		t.Fatal("requested unreadable ledger must fail export")
	} else if !strings.Contains(err.Error(), "cannot verify requested ledger") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExportRequestedMissingLedgerReturnsError(t *testing.T) {
	dir := t.TempDir()
	contextPath := writeEvidenceContext(t, dir)
	_, err := Export(ExportRequest{
		ContextPath: contextPath,
		LedgerPath:  filepath.Join(dir, "missing-ledger.jsonl"),
		AsOf:        "2026-08-02T00:00:00Z",
	})
	if err == nil || !strings.Contains(err.Error(), "cannot verify requested ledger") {
		t.Fatalf("missing requested ledger error = %v", err)
	}
}

func TestExportInvalidSignatureIsWarn(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "signed.yml")
	doc := `version: 2
proofs:
  - id: signed
    status: validated
    observed_at: "2026-08-01T00:00:00Z"
    signature:
      public_key: "` + hex.EncodeToString(pub) + `"
      signature: "` + hex.EncodeToString(ed25519.Sign(priv, []byte("wrong message"))) + `"
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := Export(ExportRequest{ContextPath: path, AsOf: "2026-08-02T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "contradicted") || !strings.Contains(text, "WARN") {
		t.Fatalf("invalid signature export must be warned and visible, got:\n%s", text)
	}
}

func TestIngestClearsGeneratedProofAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restoregap.yml")
	fixture := strings.Join([]string{
		"version: 2",
		"proofs:",
		"  - id: p",
		"    status: validated",
		"    observed_at: \"2026-09-18T00:00:00Z\"",
		"    expires_at: \"2026-09-20T00:00:00Z\"",
		"    sha256: sha256:old",
		"    verified: true",
		"    command: \"restore old\"",
		"    evidence_url: https://old.example/proof",
		"    signature: {public_key: old-key, signature: old-signature}",
		"    measurements: {rto_seconds: 1, rpo_seconds: 2, checks: [{type: sqlite, pass: true, detail: ok}]}",
		"    layer: data-apps",
		"    category: database",
		"    scope: {environment: prod, host: nas}",
		"guards: []",
		"facts: []",
		"drills: []",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Ingest(IngestRequest{ContextPath: path, ProofID: "p"}); err != nil {
		t.Fatal(err)
	}
	ctx, err := contextspec.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p := ctx.Proofs[0]
	if p.Status != contextspec.ProofRecordObserved || p.Verified || p.SHA256 != "" || p.ExpiresAt != nil || p.Signature != nil || p.Measurements != nil {
		t.Fatalf("manual ingest retained generated authority: %+v", p)
	}
	if p.Command != "" || p.EvidenceURL != "" {
		t.Fatalf("manual ingest retained old producer fields: %+v", p)
	}
	if p.Layer != "data-apps" || p.Category != "database" || p.Scope.Environment != "prod" || p.Scope.Host != "nas" {
		t.Fatalf("manual ingest dropped declarative metadata: %+v", p)
	}
}

func TestBuildProofHashesFullVerifierOutputWhenCaptureIsBounded(t *testing.T) {
	proof, _, err := buildProofContext(context.Background(), IngestRequest{
		ProofID: "p", Command: "head -c 100000 /dev/zero", Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	all := make([]byte, 100000)
	digest := sha256.Sum256(all)
	want := "sha256:" + hex.EncodeToString(digest[:])
	if got := proof["sha256"]; got != want {
		t.Fatalf("sha256 = %v, want %s", got, want)
	}
}
