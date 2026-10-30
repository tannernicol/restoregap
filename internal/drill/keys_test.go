// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package drill

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// ---- test fixtures --------------------------------------------------------

// genSSHKeypair generates an ed25519 keypair at <dir>/<name> (and
// <name>.pub) and returns its SHA256 fingerprint (as ssh-keygen -lf reports
// it), so tests can assert against a known value without hand-parsing.
func genSSHKeypair(t *testing.T, dir, name string) string {
	t.Helper()
	priv := filepath.Join(dir, name)
	out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", priv, "-C", "test-fixture").CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -t ed25519: %v: %s", err, out)
	}
	fp, err := exec.Command("ssh-keygen", "-lf", priv).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -lf: %v: %s", err, fp)
	}
	fields := strings.Fields(string(fp))
	if len(fields) < 2 {
		t.Fatalf("unexpected ssh-keygen -lf output: %s", fp)
	}
	return fields[1]
}

// genGPGKeypair generates an ed25519 OpenPGP key in a throwaway GNUPGHOME
// (the "live keyring" the fixture is exported from — distinct from the
// collector's own isolated inspection homedir) and writes its public
// export to <dir>/<name>.asc, returning its fingerprint.
func genGPGKeypair(t *testing.T, dir, name string) string {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found on PATH")
	}
	genHome := newGPGFixtureHome(t)
	batch := filepath.Join(dir, name+".batch")
	email := name + "@example.invalid"
	script := "%no-protection\n" +
		"Key-Type: EDDSA\nKey-Curve: ed25519\n" +
		"Name-Real: Test Fixture\nName-Email: " + email + "\nExpire-Date: 0\n%commit\n"
	if err := os.WriteFile(batch, []byte(script), 0o644); err != nil {
		t.Fatalf("write batch: %v", err)
	}
	genEnv := append(os.Environ(), "GNUPGHOME="+genHome)

	gen := exec.Command("gpg", "--batch", "--generate-key", batch)
	gen.Env = genEnv
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("gpg --generate-key: %v: %s", err, out)
	}

	exportPath := filepath.Join(dir, name+".asc")
	exp := exec.Command("gpg", "--export", email)
	exp.Env = genEnv
	out, err := exp.Output()
	if err != nil {
		t.Fatalf("gpg --export: %v", err)
	}
	if err := os.WriteFile(exportPath, out, 0o644); err != nil {
		t.Fatalf("write export: %v", err)
	}

	showEnv := append(os.Environ(), "GNUPGHOME="+newGPGFixtureHome(t))
	show := exec.Command("gpg", "--show-keys", "--with-colons", exportPath)
	show.Env = showEnv
	fp, err := show.Output()
	if err != nil {
		t.Fatalf("gpg --show-keys: %v", err)
	}
	for _, line := range strings.Split(string(fp), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 10 && fields[0] == "fpr" {
			return strings.ToUpper(strings.TrimSpace(fields[9]))
		}
	}
	t.Fatalf("no fpr: record in gpg --show-keys output: %s", fp)
	return ""
}

// newGPGFixtureHome gives gpg-agent a short, unique homedir. macOS limits
// Unix-domain socket paths; t.TempDir includes the full test name and can
// make gpg-agent's socket path too long before key generation starts.
func newGPGFixtureHome(t *testing.T) string {
	t.Helper()
	home, err := os.MkdirTemp("", "rg-gpg-")
	if err != nil {
		t.Fatalf("create gpg fixture homedir: %v", err)
	}
	if err := os.Chmod(home, 0o700); err != nil {
		_ = os.RemoveAll(home)
		t.Fatalf("chmod gpg fixture homedir: %v", err)
	}
	t.Cleanup(func() {
		if gpgconf, err := exec.LookPath("gpgconf"); err == nil {
			kill := exec.Command(gpgconf, "--homedir", home, "--kill", "gpg-agent")
			kill.Env = append(os.Environ(), "GNUPGHOME="+home)
			_ = kill.Run()
		}
		_ = os.RemoveAll(home)
	})
	return home
}

// ---- collectors -----------------------------------------------------------

// TestCollectSSHFingerprints is intentionally NOT skippable on a missing
// ssh-keygen — it's required by the repo's own test environment (the git
// check's tests make the same assumption about git).
func TestCollectSSHFingerprintsFromKeypair(t *testing.T) {
	dir := t.TempDir()
	fp := genSSHKeypair(t, dir, "id_ed25519")

	set, err := collectSSHFingerprints(dir)
	if err != nil {
		t.Fatalf("collectSSHFingerprints: %v", err)
	}
	if len(set) != 1 || !set[fp] {
		t.Fatalf("set = %v, want exactly {%s}", set, fp)
	}
}

func TestCollectSSHFingerprintsDedupesPubAndPrivate(t *testing.T) {
	dir := t.TempDir()
	fp := genSSHKeypair(t, dir, "id_ed25519") // writes both id_ed25519 and id_ed25519.pub

	set, err := collectSSHFingerprints(dir)
	if err != nil {
		t.Fatalf("collectSSHFingerprints: %v", err)
	}
	if len(set) != 1 || !set[fp] {
		t.Fatalf("a private/public pair of the same key must count as ONE key, got %v", set)
	}
}

func TestCollectSSHFingerprintsIgnoresNonKeyFiles(t *testing.T) {
	dir := t.TempDir()
	fp := genSSHKeypair(t, dir, "id_ed25519")
	writeFile(t, dir, "README.md", "this is a recovery kit, not a key\n")
	writeFile(t, dir, "known_hosts.old", "stale known-hosts data\n")
	writeFile(t, dir, "config", "Host example\n  User git\n")

	set, err := collectSSHFingerprints(dir)
	if err != nil {
		t.Fatalf("collectSSHFingerprints: %v", err)
	}
	if len(set) != 1 || !set[fp] {
		t.Fatalf("non-key files must be silently ignored, got %v", set)
	}
}

func TestCollectSSHFingerprintsSingleFile(t *testing.T) {
	dir := t.TempDir()
	fp := genSSHKeypair(t, dir, "id_ed25519")

	set, err := collectSSHFingerprints(filepath.Join(dir, "id_ed25519.pub"))
	if err != nil {
		t.Fatalf("collectSSHFingerprints: %v", err)
	}
	if len(set) != 1 || !set[fp] {
		t.Fatalf("collecting from a single file should work the same as a directory, got %v", set)
	}
}

func TestCollectSSHFingerprintsMissingBinary(t *testing.T) {
	dir := t.TempDir()
	empty := t.TempDir()
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", empty); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	if _, err := collectSSHFingerprints(dir); err == nil || !strings.Contains(err.Error(), "ssh-keygen not found") {
		t.Fatalf("expected a clear missing-binary error, got %v", err)
	}
}

// TestCollectGPGFingerprintsFromExport builds a fixture via a real
// `gpg --export` into a throwaway GNUPGHOME, per the spec. Skippable ONLY
// if gpg is genuinely absent from PATH — unlike ssh-keygen, gpg is not
// assumed universally present.
func TestCollectGPGFingerprintsFromExport(t *testing.T) {
	dir := t.TempDir()
	fp := genGPGKeypair(t, dir, "primary")

	set, err := collectGPGFingerprints(dir)
	if err != nil {
		t.Fatalf("collectGPGFingerprints: %v", err)
	}
	if len(set) != 1 || !set[fp] {
		t.Fatalf("set = %v, want exactly {%s}", set, fp)
	}
}

func TestCollectGPGFingerprintsIgnoresNonKeyFiles(t *testing.T) {
	dir := t.TempDir()
	fp := genGPGKeypair(t, dir, "primary")
	writeFile(t, dir, "README.md", "not a key\n")

	set, err := collectGPGFingerprints(dir)
	if err != nil {
		t.Fatalf("collectGPGFingerprints: %v", err)
	}
	if len(set) != 1 || !set[fp] {
		t.Fatalf("non-key files must be silently ignored, got %v", set)
	}
}

func TestCollectGPGFingerprintsMissingBinary(t *testing.T) {
	dir := t.TempDir()
	empty := t.TempDir()
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", empty); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	if _, err := collectGPGFingerprints(dir); err == nil || !strings.Contains(err.Error(), "gpg not found") {
		t.Fatalf("expected a clear missing-binary error, got %v", err)
	}
}

// TestCollectGPGFingerprintsNeverTouchesRealHomedir proves the WALL-1-
// adjacent isolation claim directly: point HOME/GNUPGHOME at a directory
// that does not exist and confirm collectGPGFingerprints never creates it —
// every gpg invocation must go through its own throwaway --homedir.
func TestCollectGPGFingerprintsNeverTouchesRealHomedir(t *testing.T) {
	dir := t.TempDir()
	_ = genGPGKeypair(t, dir, "primary")

	fakeReal := filepath.Join(t.TempDir(), "should-never-be-created")
	oldHome := os.Getenv("GNUPGHOME")
	t.Cleanup(func() { _ = os.Setenv("GNUPGHOME", oldHome) })
	if err := os.Setenv("GNUPGHOME", fakeReal); err != nil {
		t.Fatalf("Setenv: %v", err)
	}

	if _, err := collectGPGFingerprints(dir); err != nil {
		t.Fatalf("collectGPGFingerprints: %v", err)
	}
	if _, err := os.Stat(fakeReal); !os.IsNotExist(err) {
		t.Fatalf("collectGPGFingerprints must never create/touch the operator's real GNUPGHOME, but %s now exists", fakeReal)
	}
}

// ---- check semantics -------------------------------------------------------

func TestRunKeyFingerprintExpectFromCovered(t *testing.T) {
	live := t.TempDir()
	genSSHKeypair(t, live, "id_ed25519")
	recovered := t.TempDir()
	genSSHKeypairCopy(t, live, "id_ed25519", recovered, "id_ed25519")

	c := contextspec.DrillCheck{Type: "key_fingerprint", Keys: "ssh", ExpectFrom: live, MinKeys: 1}
	res := runCheck(c, fixedEnv(recovered, recovered, time.Now()))
	if !res.outcome.Pass {
		t.Fatalf("expected pass, got %+v", res.outcome)
	}
	if !strings.Contains(res.outcome.Detail, "all 1 live fingerprints covered") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}
}

func TestRunKeyFingerprintExpectFromMissingKeyFails(t *testing.T) {
	live := t.TempDir()
	genSSHKeypair(t, live, "id_ed25519")          // present live
	missingFp := genSSHKeypair(t, live, "id_rsa") // will NOT be in the recovery copy
	recovered := t.TempDir()
	genSSHKeypairCopy(t, live, "id_ed25519", recovered, "id_ed25519") // only copy the first key

	c := contextspec.DrillCheck{Type: "key_fingerprint", Keys: "ssh", ExpectFrom: live, MinKeys: 1}
	res := runCheck(c, fixedEnv(recovered, recovered, time.Now()))
	if res.outcome.Pass {
		t.Fatal("a live key missing from the recovery copy must fail the check")
	}
	if !strings.Contains(res.outcome.Detail, "1 live fingerprint NOT in the recovery copy") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}
	if !strings.Contains(res.outcome.Detail, missingFp) {
		t.Errorf("detail should name the missing fingerprint, got %q", res.outcome.Detail)
	}
}

func TestRunKeyFingerprintExplicitExpectHitAndMiss(t *testing.T) {
	dir := t.TempDir()
	fp := genSSHKeypair(t, dir, "id_ed25519")

	hit := contextspec.DrillCheck{Type: "key_fingerprint", Keys: "ssh", Expect: []string{fp}}
	res := runCheck(hit, fixedEnv(dir, dir, time.Now()))
	if !res.outcome.Pass {
		t.Fatalf("expected pass, got %+v", res.outcome)
	}
	if !strings.Contains(res.outcome.Detail, "all 1 expected fingerprints present") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}

	miss := contextspec.DrillCheck{Type: "key_fingerprint", Keys: "ssh", Expect: []string{"SHA256:doesnotexist0000000000000000000000000"}}
	res = runCheck(miss, fixedEnv(dir, dir, time.Now()))
	if res.outcome.Pass {
		t.Fatal("an explicit expected fingerprint that is absent must fail")
	}
	if !strings.Contains(res.outcome.Detail, "1 expected fingerprint missing") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}
}

func TestRunKeyFingerprintMinKeysNotMet(t *testing.T) {
	dir := t.TempDir()
	genSSHKeypair(t, dir, "id_ed25519")

	c := contextspec.DrillCheck{Type: "key_fingerprint", Keys: "ssh", MinKeys: 5}
	res := runCheck(c, fixedEnv(dir, dir, time.Now()))
	if res.outcome.Pass {
		t.Fatal("min_keys not met must fail")
	}
	if !strings.Contains(res.outcome.Detail, "min_keys not met: found 1, need >= 5") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}
}

// TestRunKeyFingerprintZeroMinKeysMeansNoMinimum pins the deliberate
// asymmetry with ReadyTimeout: a DrillCheck built directly in Go (bypassing
// parse.go's YAML-only default-to-1) with MinKeys left at its Go zero value
// is treated as "no minimum enforced", not silently upgraded to 1. Here the
// recovered set is empty (an empty directory) and ExpectFrom points at the
// SAME empty directory, so the only thing that could fail this check is an
// engine-level re-defaulted min_keys — which must not happen.
func TestRunKeyFingerprintZeroMinKeysMeansNoMinimum(t *testing.T) {
	dir := t.TempDir() // no keys at all
	c := contextspec.DrillCheck{Type: "key_fingerprint", Keys: "ssh", ExpectFrom: dir}
	res := runCheck(c, fixedEnv(dir, dir, time.Now()))
	if !res.outcome.Pass {
		t.Fatalf("MinKeys left at zero value must mean 'no minimum enforced', got %+v", res.outcome)
	}
}

func TestRunKeyFingerprintUnknownKeysScheme(t *testing.T) {
	res := runCheck(contextspec.DrillCheck{Type: "key_fingerprint", Keys: "pgp-legacy-typo"}, fixedEnv(t.TempDir(), t.TempDir(), time.Now()))
	if res.outcome.Pass {
		t.Fatal("an unrecognized keys scheme must fail closed")
	}
	if !strings.Contains(res.outcome.Detail, "unknown keys scheme") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}
}

func TestRunKeyFingerprintGPGEndToEnd(t *testing.T) {
	live := t.TempDir()
	fp := genGPGKeypair(t, live, "primary")

	c := contextspec.DrillCheck{Type: "key_fingerprint", Keys: "gpg", Expect: []string{fp}, MinKeys: 1}
	res := runCheck(c, fixedEnv(live, live, time.Now()))
	if !res.outcome.Pass {
		t.Fatalf("expected pass, got %+v", res.outcome)
	}
}

// genSSHKeypairCopy copies a previously generated keypair's private+public
// files from src (under srcName) to dst (as dstName), simulating "the
// recovery copy contains this key" without regenerating it (which would
// produce a DIFFERENT fingerprint).
func genSSHKeypairCopy(t *testing.T, srcDir, srcName, dstDir, dstName string) {
	t.Helper()
	for _, suffix := range []string{"", ".pub"} {
		data, err := os.ReadFile(filepath.Join(srcDir, srcName+suffix))
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, dstName+suffix), data, 0o600); err != nil {
			t.Fatalf("write copy: %v", err)
		}
	}
}
