// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package evidence records recovery proofs and exports framework-scoped
// evidence packets — the money surface: restore drills become artifacts an
// underwriter or auditor can accept.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/ledger"
	"github.com/tannernicol/restoregap/internal/report"
)

// IngestRequest records/refreshes one proof in a v2 context file.
type IngestRequest struct {
	ContextPath string
	ProofID     string
	Command     string // optional verifier command; its output is hashed
	EvidenceURL string
	ExpiresIn   time.Duration // 0 = no expiry
	Validated   bool          // true => status validated, else observed
	LedgerPath  string        // optional: also record an acknowledgement entry
	Actor       string
}

// loadContextDoc reads a context file and requires the v2 schema.
func loadContextDoc(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("evidence ingest: %w", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("evidence ingest: parse context: %w", err)
	}
	if v, _ := doc["version"].(int); v != 2 {
		return nil, fmt.Errorf("evidence ingest: context is not v2 (declare `version: 2`; `restoregap context init` writes a v2 starter)")
	}
	return doc, nil
}

// buildProof assembles the proof map, running the verifier command when one
// is declared. The returned summary line feeds the ledger acknowledgement.
func buildProof(req IngestRequest) (map[string]any, string, error) {
	now := time.Now().UTC()
	proof := map[string]any{
		"id":          req.ProofID,
		"status":      map[bool]string{true: "validated", false: "observed"}[req.Validated],
		"observed_at": now.Format(time.RFC3339),
	}
	summaryDetail := "manual attestation (no verifier command)"
	if req.Command != "" {
		out, err := exec.Command("sh", "-c", req.Command).CombinedOutput()
		if err != nil {
			return nil, "", fmt.Errorf("evidence ingest: verifier command failed (proof NOT recorded): %w — output: %s", err, firstLine(out))
		}
		sum := sha256.Sum256(out)
		proof["sha256"] = "sha256:" + hex.EncodeToString(sum[:])
		proof["command"] = req.Command
		summaryDetail = fmt.Sprintf("verifier ran clean; output hash %s…", proof["sha256"].(string)[:23])
	}
	if req.EvidenceURL != "" {
		proof["evidence_url"] = req.EvidenceURL
	}
	if req.ExpiresIn > 0 {
		proof["expires_at"] = now.Add(req.ExpiresIn).Format(time.RFC3339)
	}
	return proof, summaryDetail, nil
}

// Ingest runs the optional verifier command, hashes its output, and upserts
// the proof into the context file's proofs list. The context file is
// re-marshaled (comments are not preserved — the migration header documents
// this); it is re-validated through contextspec.Parse before writing.
func Ingest(req IngestRequest) (string, error) {
	if req.ProofID == "" {
		return "", fmt.Errorf("evidence ingest: --proof is required")
	}
	if req.ContextPath == "" {
		return "", fmt.Errorf("evidence ingest: --context is required — run `restoregap context init` first, or pass --context")
	}
	doc, err := loadContextDoc(req.ContextPath)
	if err != nil {
		return "", err
	}

	proof, summaryDetail, err := buildProof(req)
	if err != nil {
		return "", err
	}

	proofs, _ := doc["proofs"].([]any)
	replaced := false
	for i, p := range proofs {
		if pm, ok := p.(map[string]any); ok && pm["id"] == req.ProofID {
			proofs[i] = proof
			replaced = true
		}
	}
	if !replaced {
		proofs = append(proofs, proof)
	}
	doc["proofs"] = proofs

	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", err
	}
	if _, err := contextspec.Parse(strings.NewReader(string(out))); err != nil {
		return "", fmt.Errorf("evidence ingest: updated context failed validation, not written: %w", err)
	}
	if err := os.WriteFile(req.ContextPath, out, 0o644); err != nil {
		return "", err
	}

	if req.LedgerPath != "" {
		actor := req.Actor
		if actor == "" {
			actor = "human/owner"
		}
		if _, err := ledger.AppendNow(req.LedgerPath, ledger.EntryAcknowledgement, actor, ledger.Payload{
			Acknowledgement: &ledger.AcknowledgementPayload{FindingID: req.ProofID, Note: "proof ingested: " + summaryDetail},
		}); err != nil {
			return "", fmt.Errorf("evidence ingest: proof written but ledger append failed: %w", err)
		}
	}
	return fmt.Sprintf("proof %q recorded (%s)", req.ProofID, summaryDetail), nil
}

// ExportRequest builds a framework-scoped evidence packet.
type ExportRequest struct {
	ContextPath string
	LedgerPath  string
	AsOf        string
}

// Export renders a self-contained HTML evidence packet: current posture, every
// declared proof with its freshness, and the integrity of the decision ledger.
//
// It deliberately does NOT map proofs onto compliance frameworks. That mapping
// was answering an auditor's question, which is a different product with a
// different buyer; carrying it here made the packet read as a GRC artifact
// rather than what it is — a straight answer to "can this be recovered, and
// what proved it".
func Export(req ExportRequest) ([]byte, error) {
	now := time.Now().UTC()
	if req.AsOf != "" {
		t, err := time.Parse(time.RFC3339, req.AsOf)
		if err != nil {
			return nil, fmt.Errorf("evidence export: --as-of must be RFC3339: %w", err)
		}
		now = t.UTC()
	}
	ctx, err := contextspec.Load(req.ContextPath)
	if err != nil {
		return nil, fmt.Errorf("evidence export: %w", err)
	}

	verdict := "pass"
	proofRows := []report.KVRow{}
	for _, p := range ctx.Proofs {
		state := "present"
		switch {
		case p.ExpiresAt != nil && p.ExpiresAt.Before(now):
			state, verdict = "EXPIRED", "warn"
		case p.Status == contextspec.ProofRecordStale, p.Status == contextspec.ProofRecordDisputed, p.Status == contextspec.ProofRecordUnreachable:
			state, verdict = string(p.Status), "warn"
		}
		detail := string(p.Status)
		if p.ObservedAt != nil {
			detail += " · observed " + p.ObservedAt.Format("2006-01-02")
		}
		if p.ExpiresAt != nil {
			detail += " · expires " + p.ExpiresAt.Format("2006-01-02")
		}
		if p.SHA256 != "" {
			detail += " · " + truncate(p.SHA256, 18) + "…"
		}
		proofRows = append(proofRows, report.KVRow{Key: p.ID + " (" + state + ")", Value: detail})
	}

	sections := []report.KVSection{
		{Title: "Scope", Rows: []report.KVRow{
			{Key: "Context", Value: ctx.Origin},
			{Key: "Generated", Value: now.Format(time.RFC3339)},
		}},
	}
	if len(proofRows) > 0 {
		sections = append(sections, report.KVSection{Title: "Proof inventory", Rows: proofRows})
	}
	if req.LedgerPath != "" {
		if res, err := ledger.Verify(req.LedgerPath); err == nil {
			state := fmt.Sprintf("%d entries · chain verified · last hash %s…", res.EntryCount, truncate(res.LastHash, 18))
			if !res.OK {
				state, verdict = fmt.Sprintf("CHAIN BROKEN at entry %d: %s", res.FailedAt, res.Reason), "block"
			}
			sections = append(sections, report.KVSection{Title: "Decision ledger", Rows: []report.KVRow{{Key: "Integrity", Value: state}}})
		}
	}

	summary := fmt.Sprintf("%d declared proof(s) · %s", len(proofRows), ctx.Origin)
	return report.StatusHTML(verdict, summary, sections)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	return s
}
