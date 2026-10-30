// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package evidence records recovery proofs and exports framework-scoped
// evidence packets — the money surface: restore drills become artifacts an
// underwriter or auditor can accept.
package evidence

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	commandrunner "github.com/tannernicol/restoregap/internal/command"
	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/ledger"
	"github.com/tannernicol/restoregap/internal/proofstore"
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
	Timeout     time.Duration // verifier runtime ceiling; 0 uses command.DefaultTimeout
}

func buildProofContext(ctx context.Context, req IngestRequest) (map[string]any, string, error) {
	now := time.Now().UTC()
	proof := map[string]any{
		"id":            req.ProofID,
		"status":        map[bool]string{true: "validated", false: "observed"}[req.Validated],
		"observed_at":   now.Format(time.RFC3339),
		"sha256":        nil,
		"command":       nil,
		"evidence_url":  nil,
		"expires_at":    nil,
		"verified":      nil,
		"measurements":  nil,
		"signature":     nil,
		"recipe_digest": nil,
		"dependencies":  nil,
	}
	summaryDetail := "manual attestation (no verifier command)"
	if req.Command != "" {
		timeout := req.Timeout
		if timeout <= 0 {
			timeout = commandrunner.DefaultTimeout
		}
		r := commandrunner.Shell(ctx, req.Command, commandrunner.Options{Timeout: timeout})
		if r.Err != nil {
			return nil, "", fmt.Errorf("evidence ingest: verifier command failed (proof NOT recorded): %w — output: %s", r.Err, firstLine(r.Output))
		}
		proof["sha256"] = "sha256:" + hex.EncodeToString(r.OutputDigest)
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
// the proof into the context file's proofs list through proofstore's locked,
// atomic persistence boundary.
func Ingest(req IngestRequest) (string, error) {
	return IngestContext(context.Background(), req)
}

// IngestContext is Ingest with caller cancellation propagated to the optional
// verifier command. A failed or canceled verifier is never persisted.
func IngestContext(ctx context.Context, req IngestRequest) (string, error) {
	if req.ProofID == "" {
		return "", fmt.Errorf("evidence ingest: --proof is required")
	}
	if req.ContextPath == "" {
		return "", fmt.Errorf("evidence ingest: --context is required — run `restoregap context init` first, or pass --context")
	}
	proof, summaryDetail, err := buildProofContext(ctx, req)
	if err != nil {
		return "", err
	}

	if err := proofstore.Upsert(req.ContextPath, []map[string]any{proof}); err != nil {
		return "", fmt.Errorf("evidence ingest: %w", err)
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

	proofRows, verdict := exportProofRows(ctx, now)

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
		res, err := verifyRequestedLedger(req.LedgerPath)
		if err != nil {
			return nil, err
		}
		state := fmt.Sprintf("%d entries · chain verified · last hash %s…", res.EntryCount, truncate(res.LastHash, 18))
		if !res.OK {
			state, verdict = fmt.Sprintf("CHAIN BROKEN at entry %d: %s", res.FailedAt, res.Reason), "block"
		}
		sections = append(sections, report.KVSection{Title: "Decision ledger", Rows: []report.KVRow{{Key: "Integrity", Value: state}}})
	}

	summary := fmt.Sprintf("%d declared proof(s) · %s", len(proofRows), ctx.Origin)
	return report.StatusHTML(verdict, summary, sections)
}

func exportProofRows(ctx contextspec.Context, now time.Time) ([]report.KVRow, string) {
	verdict := "pass"
	rows := make([]report.KVRow, 0, len(ctx.Proofs))
	for _, p := range ctx.Proofs {
		state := "present"
		checked := ctx.CheckProofWithBinding(p.ID, 0, false, false, now)
		switch checked.State {
		case contextspec.StateStale:
			state, verdict = "EXPIRED", "warn"
			if p.Status == contextspec.ProofRecordStale {
				state = string(p.Status)
			}
		case contextspec.StateContradicted:
			state, verdict = "contradicted", "warn"
		case contextspec.StateUnreachable:
			state, verdict = string(p.Status), "warn"
		}
		detail := string(p.Status)
		if checked.State != contextspec.StatePresent {
			detail = checked.Detail
		}
		if p.ObservedAt != nil {
			detail += " · observed " + p.ObservedAt.Format("2006-01-02")
		}
		if p.ExpiresAt != nil {
			detail += " · expires " + p.ExpiresAt.Format("2006-01-02")
		}
		if p.SHA256 != "" {
			detail += " · " + truncate(p.SHA256, 18) + "…"
		}
		rows = append(rows, report.KVRow{Key: p.ID + " (" + state + ")", Value: detail})
	}
	return rows, verdict
}

func verifyRequestedLedger(path string) (ledger.VerifyResult, error) {
	if _, err := os.Stat(path); err != nil {
		return ledger.VerifyResult{}, fmt.Errorf("evidence export: cannot verify requested ledger: %w", err)
	}
	res, err := ledger.Verify(path)
	if err != nil {
		return ledger.VerifyResult{}, fmt.Errorf("evidence export: cannot verify requested ledger: %w", err)
	}
	return res, nil
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
