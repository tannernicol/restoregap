// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tannernicol/restoregap/internal/hostid"
)

func runBundle(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newBundleCmd()
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func testMergeSigningKey(t *testing.T) string {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(seed)
}

// exportMergeFixtureBundle writes a one-proof context for hostName/env/
// system and exports a signed bundle for it, pinning hostid.Current() for
// the duration of the export via hostid.Override — the same seam
// internal/status's own fleet-merge tests use.
func exportMergeFixtureBundle(t *testing.T, dir, hostName, hostID, epoch, env, system, proofID string) string {
	t.Helper()
	hostid.Override = &hostid.Identity{HostName: hostName, HostID: hostID, Epoch: epoch}
	defer func() { hostid.Override = nil }()

	ctxPath := filepath.Join(dir, hostName+"-restoregap.yml")
	body := "version: 2\nproofs:\n  - id: " + proofID + "\n    status: validated\n    observed_at: \"2026-08-01T00:00:00Z\"\n" +
		"    scope: {environment: " + env + ", system: " + system + "}\n"
	if err := os.WriteFile(ctxPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, hostName+".tgz")
	outStr, err := runBundle(t, "export", "--context", ctxPath, "--signing-key", testMergeSigningKey(t), "--out", out)
	if err != nil {
		t.Fatalf("bundle export(%s): %v — %s", hostName, err, outStr)
	}
	return out
}

// TestBundleMergeWritesFleetFilesAndStatusFleetRendersThem exercises the
// full CLI path section 7 promises: `bundle merge` across bundles spanning
// two environments and three hosts writes fleet.json + fleet.html, and
// `status --fleet <dir>` renders the same tree in the terminal.
func TestBundleMergeWritesFleetFilesAndStatusFleetRendersThem(t *testing.T) {
	dir := t.TempDir()
	b1 := exportMergeFixtureBundle(t, dir, "host-a", "aaaaaaaaaaaaaaaa", "epocha00000", "prod", "web", "shared-proof")
	b2 := exportMergeFixtureBundle(t, dir, "host-b", "bbbbbbbbbbbbbbbb", "epochb00000", "prod", "db", "host-b-only")
	b3 := exportMergeFixtureBundle(t, dir, "host-c", "cccccccccccccccc", "epochc00000", "staging", "web", "shared-proof")

	outDir := filepath.Join(dir, "fleet-out")
	out, err := runBundle(t, "merge", b1, b2, b3, "--out", outDir)
	if err != nil {
		t.Fatalf("bundle merge: %v — %s", err, out)
	}
	if !strings.Contains(out, "merged 3 bundle(s), 3 proof(s)") {
		t.Errorf("unexpected merge summary: %q", out)
	}
	if _, err := os.Stat(filepath.Join(outDir, "fleet.json")); err != nil {
		t.Errorf("fleet.json not written: %v", err)
	}
	htmlPath := filepath.Join(outDir, "fleet.html")
	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("fleet.html not written: %v", err)
	}
	html := string(htmlBytes)
	for _, want := range []string{"host-a", "host-b", "host-c", "data-hostslug", "f-host-", "restoregap fleet"} {
		if !strings.Contains(html, want) {
			t.Errorf("fleet.html missing %q", want)
		}
	}

	statusOut, err := runStatus(t, "--fleet", outDir)
	if err != nil {
		t.Fatalf("status --fleet: %v — %s", err, statusOut)
	}
	for _, want := range []string{"host-a", "host-b", "host-c", "shared-proof", "host-b-only"} {
		if !strings.Contains(statusOut, want) {
			t.Errorf("status --fleet output missing %q:\n%s", want, statusOut)
		}
	}
}

// TestBundleMergeRefusesUnverifiableBundle mirrors the internal/status
// merge test at the CLI layer: a corrupt/non-bundle file must abort the
// whole merge, never silently produce a partial fleet.
func TestBundleMergeRefusesUnverifiableBundle(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "not-a-bundle.tgz")
	if err := os.WriteFile(fake, []byte("not a tar.gz"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := runBundle(t, "merge", fake, "--out", filepath.Join(dir, "out")); err == nil {
		t.Fatalf("expected bundle merge to refuse an unverifiable bundle, got: %s", out)
	}
}
