// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package bundle

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/hostid"
	"github.com/tannernicol/restoregap/internal/ledger"
)

func testSigningKey(t *testing.T) string {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(seed)
}

func writeCtx(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func setTestHost(t *testing.T) {
	t.Helper()
	hostid.Override = &hostid.Identity{HostName: "test-host", HostID: "0123456789abcdef", Epoch: "0123456789ab"}
	t.Cleanup(func() { hostid.Override = nil })
}

const bundleFixture = `version: 2
guards:
  - id: g1
    kind: guard
    match: {paths: ["/data/**"]}
    requires: {proofs: [p1]}
proofs:
  - id: p1
    status: validated
    observed_at: "2026-08-01T00:00:00Z"
    evidence_url: "%s"
    scope: {environment: prod}
`

func TestExportVerifyRoundTrip(t *testing.T) {
	setTestHost(t)
	dir := t.TempDir()
	evidencePath := writeCtx(t, dir, "evidence.txt", "some evidence bytes")
	ctxPath := writeCtx(t, dir, "restoregap.yml", sprintfFixture(evidencePath))
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	if _, err := ledger.AppendNow(ledgerPath, ledger.EntryEpoch, "human/owner", ledger.Payload{Epoch: &ledger.EpochPayload{Label: "test"}}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.tgz")

	key := testSigningKey(t)
	path, err := Export(ExportRequest{
		ContextPaths: []string{ctxPath},
		LedgerPath:   ledgerPath,
		SigningKey:   key,
		Out:          out,
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if path != out {
		t.Errorf("Export returned %q, want %q", path, out)
	}

	res, err := Verify(out)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected OK, got reason: %s", res.Reason)
	}
	if res.Manifest.Host.Name != "test-host" || res.Manifest.Epoch != "0123456789ab" {
		t.Errorf("unexpected host/epoch in manifest: %+v", res.Manifest.Host)
	}
	if res.Manifest.Counts.Guards != 1 || res.Manifest.Counts.Proofs != 1 || res.Manifest.Counts.LedgerEntries != 1 {
		t.Errorf("unexpected counts: %+v", res.Manifest.Counts)
	}
	if len(res.Manifest.Evidence) != 1 || res.Manifest.Evidence[0].ProofID != "p1" || !res.Manifest.Evidence[0].Exists {
		t.Errorf("unexpected evidence: %+v", res.Manifest.Evidence)
	}

	inspected, err := Inspect(out)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if inspected.Host.ID != res.Manifest.Host.ID {
		t.Errorf("Inspect and Verify manifests disagree: %+v vs %+v", inspected, res.Manifest)
	}
}

func sprintfFixture(evidencePath string) string {
	return fixtureFormat(bundleFixture, evidencePath)
}

// fixtureFormat is fmt.Sprintf with exactly one %s — kept local and tiny so
// this test file does not need to reason about fmt verbs beyond the one it
// uses.
func fixtureFormat(tmpl, arg string) string {
	out := ""
	for i := 0; i < len(tmpl); i++ {
		if i+1 < len(tmpl) && tmpl[i] == '%' && tmpl[i+1] == 's' {
			out += arg
			i++
			continue
		}
		out += string(tmpl[i])
	}
	return out
}

func TestExportRequiresSigningKey(t *testing.T) {
	setTestHost(t)
	dir := t.TempDir()
	ctxPath := writeCtx(t, dir, "restoregap.yml", "version: 2\nguards: []\n")
	if _, err := Export(ExportRequest{ContextPaths: []string{ctxPath}, Out: filepath.Join(dir, "out.tgz")}); err == nil {
		t.Fatal("expected an error when --signing-key is empty")
	}
}

func TestVerifyDetectsTamperedContextFile(t *testing.T) {
	setTestHost(t)
	dir := t.TempDir()
	ctxPath := writeCtx(t, dir, "restoregap.yml", "version: 2\nguards: []\n")
	out := filepath.Join(dir, "out.tgz")
	if _, err := Export(ExportRequest{ContextPaths: []string{ctxPath}, SigningKey: testSigningKey(t), Out: out}); err != nil {
		t.Fatal(err)
	}

	tamperTarGzMember(t, out, contextDirRel+tarSafeName(ctxPath), []byte("version: 2\nguards: [tampered]\n"))

	res, err := Verify(out)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("expected verify to fail on a tampered context file")
	}
}

func TestVerifyDetectsTamperedManifest(t *testing.T) {
	setTestHost(t)
	dir := t.TempDir()
	ctxPath := writeCtx(t, dir, "restoregap.yml", "version: 2\nguards: []\n")
	out := filepath.Join(dir, "out.tgz")
	if _, err := Export(ExportRequest{ContextPaths: []string{ctxPath}, SigningKey: testSigningKey(t), Out: out}); err != nil {
		t.Fatal(err)
	}

	members, err := readTarGz(out)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), members[manifestName]...)
	tampered = append(tampered, ' ') // any byte change invalidates the signature
	tamperTarGzMember(t, out, manifestName, tampered)

	res, err := Verify(out)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("expected verify to fail on a tampered manifest (signature mismatch)")
	}
}

func TestVerifyDetectsBrokenLedgerSliceChain(t *testing.T) {
	setTestHost(t)
	dir := t.TempDir()
	ctxPath := writeCtx(t, dir, "restoregap.yml", "version: 2\nguards: []\n")
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	for i := 0; i < 3; i++ {
		if _, err := ledger.AppendNow(ledgerPath, ledger.EntryEpoch, "human/owner", ledger.Payload{Epoch: &ledger.EpochPayload{Label: "m"}}); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "out.tgz")
	if _, err := Export(ExportRequest{ContextPaths: []string{ctxPath}, LedgerPath: ledgerPath, SigningKey: testSigningKey(t), Out: out}); err != nil {
		t.Fatal(err)
	}

	members, err := readTarGz(out)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseLedgerJSONL(members[ledgerSliceRel])
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 ledger entries, got %d", len(entries))
	}
	entries[1].Actor = "someone-else" // changes entry[1]'s hash without updating entry[2].Prev
	tampered, err := ledgerJSONL(entries)
	if err != nil {
		t.Fatal(err)
	}
	tamperTarGzMember(t, out, ledgerSliceRel, tampered)

	res, err := Verify(out)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("expected verify to fail: the ledger slice digest no longer matches the manifest")
	}
}

func TestExportExcludesSecretStoreEvidence(t *testing.T) {
	setTestHost(t)
	dir := t.TempDir()
	secretDir := filepath.Join(dir, ".password-store")
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secretFile := writeCtx(t, secretDir, "site.gpg", "not a real secret, just test bytes")
	ctxPath := writeCtx(t, dir, "restoregap.yml", sprintfFixture(secretFile))
	out := filepath.Join(dir, "out.tgz")

	if _, err := Export(ExportRequest{ContextPaths: []string{ctxPath}, SigningKey: testSigningKey(t), Out: out}); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("expected OK, got: %s", res.Reason)
	}
	if len(res.Manifest.Evidence) != 0 {
		t.Errorf("expected zero evidence refs for a secret-store path, got %+v", res.Manifest.Evidence)
	}
	if res.Manifest.ExcludedSecretEvidence != 1 {
		t.Errorf("expected ExcludedSecretEvidence=1, got %d", res.Manifest.ExcludedSecretEvidence)
	}

	// The secret path itself must never appear anywhere in the bundle.
	members, err := readTarGz(out)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range members {
		if name == contextDirRel+tarSafeName(ctxPath) {
			continue // the context file legitimately names the evidence_url it declares
		}
		if bytesContain(data, []byte(".password-store")) {
			t.Errorf("bundle member %q must not mention the secret store path, got: %s", name, data)
		}
	}
}

func TestExportScopeFiltersProofs(t *testing.T) {
	setTestHost(t)
	dir := t.TempDir()
	ctxPath := writeCtx(t, dir, "restoregap.yml", `version: 2
proofs:
  - id: prod-p
    status: validated
    observed_at: "2026-08-01T00:00:00Z"
    scope: {environment: prod}
  - id: dev-p
    status: validated
    observed_at: "2026-08-01T00:00:00Z"
    scope: {environment: dev}
`)
	out := filepath.Join(dir, "out.tgz")
	if _, err := Export(ExportRequest{ContextPaths: []string{ctxPath}, Environment: "prod", SigningKey: testSigningKey(t), Out: out}); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifest.Counts.Proofs != 1 {
		t.Errorf("expected scope filter to narrow to 1 proof, got %d", res.Manifest.Counts.Proofs)
	}
	if res.Manifest.Scope.Environment != "prod" {
		t.Errorf("expected scope.environment=prod recorded, got %+v", res.Manifest.Scope)
	}
}

func TestExportSinceFiltersLedgerSlice(t *testing.T) {
	setTestHost(t)
	dir := t.TempDir()
	ctxPath := writeCtx(t, dir, "restoregap.yml", "version: 2\nguards: []\n")
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	old := time.Now().UTC().Add(-100 * 24 * time.Hour)
	id, err := ledger.NewID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Append(ledgerPath, ledger.EntryEpoch, "human/owner", ledger.Payload{Epoch: &ledger.EpochPayload{Label: "old"}}, old, id); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AppendNow(ledgerPath, ledger.EntryEpoch, "human/owner", ledger.Payload{Epoch: &ledger.EpochPayload{Label: "recent"}}); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "out.tgz")
	if _, err := Export(ExportRequest{ContextPaths: []string{ctxPath}, LedgerPath: ledgerPath, Since: 30 * 24 * time.Hour, SigningKey: testSigningKey(t), Out: out}); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifest.Counts.LedgerEntries != 1 {
		t.Errorf("expected --since 30d to keep only the recent entry, got %d entries", res.Manifest.Counts.LedgerEntries)
	}
}

// bytesContain is a tiny substring check kept local to avoid pulling in
// bytes.Contains just for test assertions elsewhere unused.
func bytesContain(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// tamperTarGzMember rewrites one named member's content in an existing
// tar.gz, keeping every other member byte-identical — used to simulate a
// one-byte-changed bundle without re-deriving a whole fixture by hand.
func tamperTarGzMember(t *testing.T, path, name string, newContent []byte) {
	t.Helper()
	members, err := readTarGz(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := members[name]; !ok {
		t.Fatalf("tamperTarGzMember: %q not found in %s", name, path)
	}
	members[name] = newContent
	if err := writeTarGzMembers(path, members); err != nil {
		t.Fatal(err)
	}
}
