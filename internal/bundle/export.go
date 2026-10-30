// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/globmatch"
	"github.com/tannernicol/restoregap/internal/hostid"
	"github.com/tannernicol/restoregap/internal/ledger"
	"github.com/tannernicol/restoregap/internal/policy"
)

// ExportRequest is `restoregap bundle export`'s full input.
type ExportRequest struct {
	ContextPaths []string
	LedgerPath   string
	// Since bounds the embedded ledger slice to entries created within this
	// window of now; zero means every entry.
	Since time.Duration
	// Environment/System/Host, when non-empty, narrow which proofs count
	// toward Counts.Proofs and Evidence — a scoped view of the SAME context
	// files, which are always embedded in full (docs/SCHEMA.md §Portable
	// signed bundle: they are the org/host policy source of truth, not a
	// per-scope artifact).
	Environment string
	System      string
	Host        string
	// SigningKey is a hex Ed25519 seed (contextspec.ParseSigningKeySeed) —
	// required: an unsigned bundle is not what this feature is for.
	SigningKey string
	// Out is the output tar.gz path; Export computes a default when empty.
	Out string
}

// Export builds a signed bundle per ExportRequest and writes it to
// req.Out (or a computed default), returning the path written.
func Export(req ExportRequest) (string, error) {
	signer, err := contextspec.ParseSigningKeySeed(req.SigningKey)
	if err != nil {
		return "", fmt.Errorf("bundle export: %w", err)
	}
	if signer == nil {
		return "", fmt.Errorf("bundle export: --signing-key is required — a bundle is only useful signed")
	}
	if len(req.ContextPaths) == 0 {
		return "", fmt.Errorf("bundle export: no context file found — pass --context or run `restoregap context init`")
	}

	ctx, contextFiles, err := loadContextFiles(req.ContextPaths)
	if err != nil {
		return "", fmt.Errorf("bundle export: %w", err)
	}
	scope := ScopeFilter{Environment: req.Environment, System: req.System, Host: req.Host}
	if req.Since > 0 {
		scope.Since = req.Since.String()
	}

	sliceEntries, ledgerFile, err := buildLedgerSlice(req.LedgerPath, req.Since)
	if err != nil {
		return "", fmt.Errorf("bundle export: %w", err)
	}

	proofs := scopedProofs(ctx, scope)
	evidence, excludedSecrets := buildEvidenceRefs(proofs)

	id := hostid.Current()
	policyRev, _, _ := policy.Revision(req.ContextPaths) // best-effort: absent on a hash failure, never fatal to export

	manifest := Manifest{
		FormatVersion:          FormatVersion,
		Host:                   HostInfo{Name: id.HostName, ID: id.HostID},
		Epoch:                  id.Epoch,
		PolicyRevision:         policyRev,
		GeneratedAt:            time.Now().UTC(),
		Scope:                  scope,
		Counts:                 Counts{Guards: len(ctx.Guards), Proofs: len(proofs), LedgerEntries: len(sliceEntries)},
		ContextFiles:           contextFiles,
		LedgerSlice:            ledgerFile,
		Evidence:               evidence,
		ExcludedSecretEvidence: excludedSecrets,
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("bundle export: encoding manifest: %w", err)
	}
	sig := Signature{
		PublicKeyHex: hex.EncodeToString(signer.Public().(ed25519.PublicKey)),
		SignatureHex: hex.EncodeToString(ed25519.Sign(signer, manifestBytes)),
	}
	sigBytes, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return "", fmt.Errorf("bundle export: encoding signature: %w", err)
	}

	out := req.Out
	if out == "" {
		out = fmt.Sprintf("restoregap-bundle-%s-%s.tgz", id.HostID, manifest.GeneratedAt.Format("20060102T150405Z"))
	}
	if err := writeTarGz(out, manifestBytes, sigBytes, req.ContextPaths, sliceEntries); err != nil {
		return "", fmt.Errorf("bundle export: %w", err)
	}
	return out, nil
}

// loadContextFiles reads every context path's raw bytes (embedded verbatim
// — a bundle carries the actual policy text, not a re-serialized merge) and
// also returns the tighten-only-merged Context (policy.Merge) for Counts
// and evidence resolution.
func loadContextFiles(paths []string) (contextspec.Context, []FileRef, error) {
	ctx, _, err := policy.Merge(paths)
	if err != nil {
		return contextspec.Context{}, nil, err
	}
	refs := make([]FileRef, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return contextspec.Context{}, nil, fmt.Errorf("reading %s: %w", p, err)
		}
		refs = append(refs, FileRef{Name: contextDirRel + tarSafeName(p), SHA256: sha256Hex(raw)})
	}
	return ctx, refs, nil
}

// tarSafeName renders a context path as a collision-resistant tar member
// basename: the plain basename when it is already unique is more readable,
// but two context paths sharing a basename (e.g. two drills' own
// restoregap.yml from different directories) are disambiguated by folding
// the full path into the name rather than silently overwriting one.
func tarSafeName(path string) string {
	return strings.ReplaceAll(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator), "__")
}

// scopedProofs is ctx.Proofs filtered by scope's non-empty fields via
// contextspec.EffectiveProofScope — the same effective-scope resolution
// status/classify already use, so a bundle's notion of "does this proof
// match this scope" never drifts from status --fleet's.
func scopedProofs(ctx contextspec.Context, scope ScopeFilter) []contextspec.Proof {
	if scope.Environment == "" && scope.System == "" && scope.Host == "" {
		return ctx.Proofs
	}
	var out []contextspec.Proof
	for _, p := range ctx.Proofs {
		s := contextspec.EffectiveProofScope(ctx, p)
		if scope.Environment != "" && s.Environment != scope.Environment {
			continue
		}
		if scope.System != "" && s.System != scope.System {
			continue
		}
		if scope.Host != "" && s.Host != scope.Host {
			continue
		}
		out = append(out, p)
	}
	return out
}

// buildEvidenceRefs resolves each proof's EvidenceURL to local-file
// metadata when it looks like one (not a URL) and the file exists,
// EXCLUDING — entirely, not just redacted — any path matching
// contextspec.SecretPathGlobs. excluded counts those exclusions.
func buildEvidenceRefs(proofs []contextspec.Proof) (refs []EvidenceRef, excluded int) {
	for _, p := range proofs {
		if p.EvidenceURL == "" || looksLikeURL(p.EvidenceURL) {
			continue
		}
		path := globmatch.ExpandHome(p.EvidenceURL)
		if globmatch.MatchPathAny(contextspec.SecretPathGlobs, path) {
			excluded++
			continue
		}
		ref := EvidenceRef{ProofID: p.ID, Path: p.EvidenceURL}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			ref.Exists = true
			ref.SizeBytes = info.Size()
			if raw, rerr := os.ReadFile(path); rerr == nil {
				ref.SHA256 = sha256Hex(raw)
			}
		}
		refs = append(refs, ref)
	}
	return refs, excluded
}

func looksLikeURL(s string) bool {
	return strings.Contains(s, "://")
}

// buildLedgerSlice reads the full ledger and keeps entries created within
// since of now (since == 0 keeps everything), returning the slice and its
// FileRef/LedgerSlice metadata. A missing or empty ledger yields an empty
// slice, not an error — a bundle from a host with no ledger yet is still a
// valid (if thin) bundle.
func buildLedgerSlice(ledgerPath string, since time.Duration) ([]ledger.Entry, LedgerSlice, error) {
	if ledgerPath == "" {
		return nil, LedgerSlice{Name: ledgerSliceRel, SHA256: sha256Hex(nil)}, nil
	}
	entries, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		return nil, LedgerSlice{}, err
	}
	if since > 0 {
		cutoff := time.Now().UTC().Add(-since)
		var kept []ledger.Entry
		for _, e := range entries {
			if !e.CreatedAt.Before(cutoff) {
				kept = append(kept, e)
			}
		}
		entries = kept
	}
	jsonl, err := ledgerJSONL(entries)
	if err != nil {
		return nil, LedgerSlice{}, err
	}
	info := LedgerSlice{Name: ledgerSliceRel, SHA256: sha256Hex(jsonl), EntryCount: len(entries)}
	if len(entries) > 0 {
		info.FirstPrev = entries[0].Prev
	}
	return entries, info, nil
}

func ledgerJSONL(entries []ledger.Entry) ([]byte, error) {
	var buf bytes.Buffer
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return nil, fmt.Errorf("encoding ledger entry %s: %w", e.ID, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// writeTarGz assembles the bundle's actual tar.gz bytes: manifest.json,
// manifest.sig, one context/<name> member per contextPaths entry (in the
// SAME order loadContextFiles built their FileRef digests, so member N
// matches manifest.ContextFiles[N]), and ledger/slice.jsonl.
func writeTarGz(out string, manifestBytes, sigBytes []byte, contextPaths []string, sliceEntries []ledger.Entry) error {
	members := map[string][]byte{manifestName: manifestBytes, signatureName: sigBytes}
	for _, p := range contextPaths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		members[contextDirRel+tarSafeName(p)] = raw
	}
	jsonl, err := ledgerJSONL(sliceEntries)
	if err != nil {
		return err
	}
	members[ledgerSliceRel] = jsonl
	return writeTarGzMembers(out, members)
}

// writeTarGzMembers is the actual tar.gz writer, taking every member's
// final bytes directly — writeTarGz builds that map from context paths and
// ledger entries; tests build it directly to simulate a tampered bundle
// without re-deriving a whole fixture by hand.
func writeTarGzMembers(out string, members map[string][]byte) error {
	f, err := os.Create(out) //nolint:gosec // fixed output path from CLI/tests, not attacker-controlled
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	now := time.Now()
	for name, data := range members {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: now}); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return f.Sync()
}
