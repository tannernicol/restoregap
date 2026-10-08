// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tannernicol/restoregap/internal/bundle"
	"github.com/tannernicol/restoregap/internal/hostid"
)

const pushTestToken = "tok-SECRET-0123456789"

// pushFixedSeed is a fixed ed25519 seed (hex of 32 bytes) so archives are
// signed by a stable key.
func pushFixedSeed() string {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return hex.EncodeToString(seed)
}

// pushFixture writes a minimal context file and returns the context path, a
// (nonexistent) ledger path, and a real signed archive built with
// bundle.Export.
func pushFixture(t *testing.T) (ctxPath, ledgerPath, archive string) {
	t.Helper()
	hostid.Override = &hostid.Identity{HostName: "push-host", HostID: "0123456789abcdef", Epoch: "0123456789ab"}
	t.Cleanup(func() { hostid.Override = nil })
	dir := t.TempDir()
	ctxPath = filepath.Join(dir, "restoregap.yml")
	body := "version: 2\nproofs:\n  - id: p1\n    status: validated\n    observed_at: \"2026-08-01T00:00:00Z\"\n    scope: {environment: prod}\n"
	if err := os.WriteFile(ctxPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ledgerPath = filepath.Join(dir, "ledger.jsonl")
	archive = filepath.Join(dir, "host.tgz")
	if _, err := bundle.Export(bundle.ExportRequest{ContextPaths: []string{ctxPath}, LedgerPath: ledgerPath, SigningKey: pushFixedSeed(), Out: archive}); err != nil {
		t.Fatalf("bundle.Export: %v", err)
	}
	return ctxPath, ledgerPath, archive
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("error %v is not an ExitError", err)
	}
	return ee.Code
}

type pushCapture struct {
	method, path, auth, ctype, ua string
	body                          []byte
	hits                          atomic.Int32
}

func pushServer(t *testing.T, status int, resp string) (*httptest.Server, *pushCapture) {
	t.Helper()
	c := &pushCapture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		c.method, c.path = r.Method, r.URL.Path
		c.auth, c.ctype, c.ua = r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Header.Get("User-Agent")
		c.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func TestBundlePushExistingArchiveSuccess(t *testing.T) {
	_, _, archive := pushFixture(t)
	want, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	srv, c := pushServer(t, 201, `{"bundle_id":"b1","host":"push-host","host_id":"0123456789abcdef","generated_at":"2026-10-07T00:00:00Z","url":"https://cloud.example/hosts/0123"}`)
	t.Setenv(pushTokenEnv, "")
	out, err := runBundle(t, "push", "--to", srv.URL+"/", "--token", pushTestToken, archive)
	if err != nil {
		t.Fatalf("push: %v — %s", err, out)
	}
	if c.method != http.MethodPost || c.path != "/api/v1/bundles" {
		t.Errorf("request = %s %s", c.method, c.path)
	}
	if c.auth != "Bearer "+pushTestToken {
		t.Errorf("Authorization = %q", c.auth)
	}
	if c.ctype != "application/gzip" {
		t.Errorf("Content-Type = %q", c.ctype)
	}
	if c.ua != "restoregap/"+Version {
		t.Errorf("User-Agent = %q", c.ua)
	}
	if string(c.body) != string(want) {
		t.Errorf("body (%d bytes) differs from archive (%d bytes)", len(c.body), len(want))
	}
	wantOut := "pushed: push-host (0123456789abcdef) generated 2026-10-07T00:00:00Z → https://cloud.example/hosts/0123\n"
	if out != wantOut {
		t.Errorf("output = %q, want %q", out, wantOut)
	}
	if strings.Contains(out, pushTestToken) {
		t.Error("token leaked into output")
	}
}

func TestBundlePushBuildsArchiveFromExportFlags(t *testing.T) {
	ctxPath, ledgerPath, _ := pushFixture(t)
	srv, c := pushServer(t, 201, `{"host":"push-host","host_id":"0123456789abcdef","generated_at":"t","url":"u"}`)
	t.Setenv(pushTokenEnv, pushTestToken) // token via env, not flag
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	out, err := runBundle(t, "push", "--to", srv.URL, "--context", ctxPath, "--ledger", ledgerPath, "--signing-key", pushFixedSeed(), "--since", "30d")
	if err != nil {
		t.Fatalf("push: %v — %s", err, out)
	}
	if c.auth != "Bearer "+pushTestToken {
		t.Errorf("Authorization = %q", c.auth)
	}
	// The pushed body is a real, verifiable archive.
	got := filepath.Join(t.TempDir(), "got.tgz")
	if err := os.WriteFile(got, c.body, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := bundle.Verify(got)
	if err != nil || !res.OK {
		t.Fatalf("pushed archive does not verify: %v %+v", err, res)
	}
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 0 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestBundlePushRefusals(t *testing.T) {
	_, _, archive := pushFixture(t)
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{401, `{"error":"unknown or revoked token"}`, "push refused (401): unknown or revoked token\n"},
		{402, `{"error":"workspace is not active"}`, "push refused (402): workspace is not active\n"},
		{409, `{"error":"key mismatch for host"}`, "push refused (409): key mismatch for host\n"},
		{413, `{"error":"bundle too large"}`, "push refused (413): bundle too large\n"},
		{422, `{"error":"bundle failed verification: bad signature"}`, "push refused (422): bundle failed verification: bad signature\n"},
		{413, "plain text body\x1b[31m", "push refused (413): plain text body[31m\n"},
		{401, "", "push refused (401): Unauthorized\n"},
	} {
		srv, _ := pushServer(t, tc.status, tc.body)
		t.Setenv(pushTokenEnv, "")
		out, err := runBundle(t, "push", "--to", srv.URL, "--token", pushTestToken, archive)
		if code := exitCode(t, err); code != 1 {
			t.Errorf("status %d: exit = %d, want 1 (%v)", tc.status, code, err)
		}
		if out != tc.want {
			t.Errorf("status %d: output = %q, want %q", tc.status, out, tc.want)
		}
	}
}

func TestBundlePushOtherStatusExits2(t *testing.T) {
	_, _, archive := pushFixture(t)
	srv, _ := pushServer(t, 500, `{"error":"boom"}`)
	t.Setenv(pushTokenEnv, "")
	out, err := runBundle(t, "push", "--to", srv.URL, "--token", pushTestToken, archive)
	if code := exitCode(t, err); code != 2 {
		t.Fatalf("exit = %d, want 2 (%v)", code, err)
	}
	if !strings.Contains(err.Error(), "500") || strings.Contains(err.Error()+out, pushTestToken) {
		t.Errorf("bad error %q / output %q", err, out)
	}
}

func TestBundlePushNetworkErrorExits2(t *testing.T) {
	_, _, archive := pushFixture(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens any more
	t.Setenv(pushTokenEnv, "")
	out, err := runBundle(t, "push", "--to", url, "--token", pushTestToken, archive)
	if code := exitCode(t, err); code != 2 {
		t.Fatalf("exit = %d, want 2 (%v)", code, err)
	}
	if strings.Contains(err.Error()+out, pushTestToken) {
		t.Errorf("token leaked: %q / %q", err, out)
	}
}

func TestBundlePushDoesNotFollowRedirect(t *testing.T) {
	_, _, archive := pushFixture(t)
	target, tc := pushServer(t, 201, `{}`)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/elsewhere", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redir.Close)
	t.Setenv(pushTokenEnv, "")
	out, err := runBundle(t, "push", "--to", redir.URL, "--token", pushTestToken, archive)
	if code := exitCode(t, err); code != 2 {
		t.Fatalf("exit = %d, want 2 (%v)", code, err)
	}
	if tc.hits.Load() != 0 {
		t.Error("redirect target was contacted — token would have been re-sent")
	}
	if strings.Contains(err.Error()+out, pushTestToken) {
		t.Error("token leaked")
	}
}

func TestBundlePushUsageErrors(t *testing.T) {
	ctxPath, ledgerPath, archive := pushFixture(t)
	srv, c := pushServer(t, 201, `{}`)
	for _, tc := range []struct {
		name string
		env  string
		args []string
		want string
	}{
		{"http non-localhost", "", []string{"push", "--to", "http://example.com", "--token", pushTestToken, archive}, "refusing plain http://"},
		{"scheme", "", []string{"push", "--to", "ftp://example.com", "--token", pushTestToken, archive}, "https://"},
		{"credentials in url", "", []string{"push", "--to", "https://u:p@example.com", "--token", pushTestToken, archive}, "credentials"},
		{"missing to", "", []string{"push", "--token", pushTestToken, archive}, "--to is required"},
		{"missing token", "", []string{"push", "--to", srv.URL, archive}, "--token or " + pushTokenEnv},
		{"summary-only", "", []string{"push", "--to", srv.URL, "--token", pushTestToken, "--summary-only", archive}, "--summary-only is not supported"},
		{"no signing key", "", []string{"push", "--to", srv.URL, "--token", pushTestToken, "--context", ctxPath, "--ledger", ledgerPath}, "--signing-key is required"},
		{"flags with archive", "", []string{"push", "--to", srv.URL, "--token", pushTestToken, "--signing-key", pushFixedSeed(), archive}, "cannot be combined"},
		{"bad since", "", []string{"push", "--to", srv.URL, "--token", pushTestToken, "--context", ctxPath, "--ledger", ledgerPath, "--signing-key", pushFixedSeed(), "--since", "nope"}, "--since"},
		{"missing archive", "", []string{"push", "--to", srv.URL, "--token", pushTestToken, filepath.Join(t.TempDir(), "none.tgz")}, "read archive"},
	} {
		t.Setenv(pushTokenEnv, tc.env)
		out, err := runBundle(t, tc.args...)
		if code := exitCode(t, err); code != 2 {
			t.Errorf("%s: exit = %d, want 2 (%v)", tc.name, code, err)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q lacks %q", tc.name, err, tc.want)
		}
		if strings.Contains(err.Error()+out, pushTestToken) {
			t.Errorf("%s: token leaked", tc.name)
		}
	}
	if c.hits.Load() != 0 {
		t.Errorf("a usage error still reached the server (%d hits)", c.hits.Load())
	}
}

func TestBundlePushAllowsLoopbackAndInsecureHTTP(t *testing.T) {
	for _, tc := range []struct {
		to       string
		insecure bool
		ok       bool
	}{
		{"http://localhost:8080", false, true},
		{"http://127.0.0.1:8080", false, true},
		{"http://[::1]:8080", false, true},
		{"https://cloud.example.com", false, true},
		{"http://cloud.example.com", false, false},
		{"http://cloud.example.com", true, true},
	} {
		ep, err := pushEndpoint(tc.to, tc.insecure)
		if (err == nil) != tc.ok {
			t.Errorf("pushEndpoint(%q, %v) = %q, %v; want ok=%v", tc.to, tc.insecure, ep, err, tc.ok)
		}
		if err == nil && !strings.HasSuffix(ep, "/api/v1/bundles") {
			t.Errorf("endpoint %q", ep)
		}
	}
}

func TestBundleExportAndPushShareFlags(t *testing.T) {
	exp, push := newBundleExportCmd(), newBundlePushCmd()
	for _, name := range bundleExportFlagNames {
		a, b := exp.Flags().Lookup(name), push.Flags().Lookup(name)
		if a == nil || b == nil {
			t.Fatalf("flag --%s missing (export=%v push=%v)", name, a != nil, b != nil)
		}
		if a.Usage != b.Usage || a.DefValue != b.DefValue {
			t.Errorf("flag --%s differs between export and push", name)
		}
	}
}
