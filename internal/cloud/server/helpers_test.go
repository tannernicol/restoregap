// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/bundle"
	"github.com/tannernicol/restoregap/internal/cloud/billing"
	"github.com/tannernicol/restoregap/internal/cloud/store"
	"github.com/tannernicol/restoregap/internal/hostid"
)

// ---- time and logs ----

// clock is the server's injectable Now. It starts at the real time because the
// store stamps sessions and share links with its own clock, and bundles carry
// the time they were exported.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Now().UTC().Truncate(time.Second)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// ---- the test service ----

type testEnv struct {
	t     *testing.T
	st    *store.Store
	srv   *Server
	ts    *httptest.Server
	clock *clock
	logs  *syncBuf
	cfg   Config
}

// newEnv starts a real server on a loopback port over a temp store. mods
// adjust the Config before the server is built.
func newEnv(t *testing.T, mods ...func(*Config)) *testEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ts := httptest.NewUnstartedServer(nil)
	clk, logs := newClock(), &syncBuf{}
	cfg := Config{
		BaseURL: "http://" + ts.Listener.Addr().String(), DataDir: st.DataDir(),
		AllowSignup: true, TrialDays: 14,
		Plans: billing.Plans(func(k string) string {
			return "price_" + strings.ToLower(strings.TrimPrefix(k, "RESTOREGAP_CLOUD_PRICE_"))
		}),
		Now: clk.Now, Logger: slog.New(slog.NewTextHandler(logs, nil)),
	}
	for _, m := range mods {
		m(&cfg)
	}
	srv, err := New(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = srv.Handler()
	ts.Start()
	t.Cleanup(ts.Close)
	return &testEnv{t: t, st: st, srv: srv, ts: ts, clock: clk, logs: logs, cfg: cfg}
}

// browser is an HTTP client with a cookie jar that never follows redirects, so
// tests see each 303 for what it is.
func (e *testEnv) browser() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (e *testEnv) do(c *http.Client, method, path string, body io.Reader, hdr map[string]string) (*http.Response, string) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (e *testEnv) get(c *http.Client, path string) (*http.Response, string) {
	e.t.Helper()
	return e.do(c, http.MethodGet, path, nil, nil)
}

func (e *testEnv) postForm(c *http.Client, path string, form url.Values) (*http.Response, string) {
	e.t.Helper()
	return e.do(c, http.MethodPost, path, strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
}

// csrfOf reads the CSRF token from the browser's jar, the value forms embed.
func (e *testEnv) csrfOf(c *http.Client) string {
	e.t.Helper()
	u, _ := url.Parse(e.ts.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == csrfCookie {
			return ck.Value
		}
	}
	e.t.Fatal("no CSRF cookie in the jar")
	return ""
}

// post posts a form with the browser's CSRF token filled in.
func (e *testEnv) post(c *http.Client, path string, form url.Values) (*http.Response, string) {
	e.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf", e.csrfOf(c))
	return e.postForm(c, path, form)
}

var loginLinkRE = regexp.MustCompile(`login link: (http\S+/auth/[A-Za-z0-9_-]+)`)

// loginViaLink drives the real flow: POST /login, read the dev-mode link from
// the log, open it. It returns a signed-in browser.
func (e *testEnv) loginViaLink(email string) *http.Client {
	e.t.Helper()
	c, _ := e.loginResponse(email)
	return c
}

// loginResponse is loginViaLink that also returns the /auth response, for
// tests that look at the cookies it set.
func (e *testEnv) loginResponse(email string) (*http.Client, *http.Response) {
	e.t.Helper()
	c := e.browser()
	before := len(loginLinkRE.FindAllString(e.logs.String(), -1))
	resp, body := e.postForm(c, "/login", url.Values{"email": {email}})
	if resp.StatusCode != 200 || !strings.Contains(body, "If that address can sign in, a link is on its way") {
		e.t.Fatalf("POST /login = %d %q", resp.StatusCode, body)
	}
	all := loginLinkRE.FindAllStringSubmatch(e.logs.String(), -1)
	if len(all) != before+1 {
		e.t.Fatalf("expected one new login link in the log, got %d new\n%s", len(all)-before, e.logs.String())
	}
	u, err := url.Parse(all[len(all)-1][1])
	if err != nil {
		e.t.Fatal(err)
	}
	// A GET only shows the confirm page; the POST is what signs in.
	if resp, body := e.get(c, u.Path); resp.StatusCode != 200 || !strings.Contains(body, "Sign in to Restore Gap Cloud") {
		e.t.Fatalf("GET %s = %d", u.Path, resp.StatusCode)
	}
	resp, _ = e.postForm(c, u.Path, url.Values{})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/app" {
		e.t.Fatalf("GET %s = %d -> %q", u.Path, resp.StatusCode, resp.Header.Get("Location"))
	}
	return c, resp
}

// workspaceOf returns the one workspace belonging to email.
func (e *testEnv) workspaceOf(email string) store.Workspace {
	e.t.Helper()
	u, err := e.st.UserByEmail(email)
	if err != nil {
		e.t.Fatal(err)
	}
	wss, err := e.st.WorkspacesForUser(u.ID)
	if err != nil || len(wss) != 1 {
		e.t.Fatalf("workspaces for %s = %v, %v", email, wss, err)
	}
	return wss[0]
}

// newWorkspace makes a workspace directly (no login) and returns it with a push token.
func (e *testEnv) newWorkspace(name, plan, status string) (store.Workspace, string) {
	e.t.Helper()
	ws, err := e.st.CreateWorkspace(name, plan, status, nil, "")
	if err != nil {
		e.t.Fatal(err)
	}
	_, tok, err := e.st.CreateToken(ws.ID, "test")
	if err != nil {
		e.t.Fatal(err)
	}
	return ws, tok
}

// push sends an archive to the ingest endpoint.
func (e *testEnv) push(token string, archive []byte) (*http.Response, map[string]string) {
	e.t.Helper()
	resp, body := e.do(e.ts.Client(), http.MethodPost, "/api/v1/bundles", bytes.NewReader(archive),
		map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/gzip"})
	out := map[string]string{}
	_ = json.Unmarshal([]byte(body), &out)
	return resp, out
}

// ---- signed bundles ----

func newSeed(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func pubOf(seed string) string {
	b, _ := hex.DecodeString(seed)
	return hex.EncodeToString(ed25519.NewKeyFromSeed(b).Public().(ed25519.PublicKey))
}

type proofSpec struct {
	ID string
	// ObservedAt and ExpiresAt bound the evidence's freshness window; the
	// state a bundle reports for the proof is judged as of its GeneratedAt.
	ObservedAt, ExpiresAt time.Time
}

type bundleSpec struct {
	HostName, HostID string
	Seed             string
	Proofs           []proofSpec
	GeneratedAt      time.Time // zero keeps the export's own timestamp
}

// makeBundle exports a real signed bundle with bundle.Export and, when
// GeneratedAt is set, re-signs its manifest with that time. Export stamps
// time.Now(), and regression and lapse tests need bundles generated at chosen
// moments, so this is the one place a manifest is rewritten — with the same
// key, so the archive still verifies.
func makeBundle(t *testing.T, spec bundleSpec) []byte {
	t.Helper()
	dir := t.TempDir()
	var yml strings.Builder
	yml.WriteString("version: 2\nguards:\n  - id: g1\n    kind: guard\n    match: {paths: [\"/data/**\"]}\n    requires: {proofs: [")
	for i, p := range spec.Proofs {
		if i > 0 {
			yml.WriteString(", ")
		}
		yml.WriteString(p.ID)
	}
	yml.WriteString("]}\nproofs:\n")
	for _, p := range spec.Proofs {
		fmt.Fprintf(&yml, "  - id: %s\n    status: validated\n    observed_at: %q\n    expires_at: %q\n    scope: {environment: prod}\n",
			p.ID, p.ObservedAt.UTC().Format(time.RFC3339), p.ExpiresAt.UTC().Format(time.RFC3339))
	}
	ctxPath := filepath.Join(dir, "restoregap.yml")
	if err := os.WriteFile(ctxPath, []byte(yml.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	hostid.Override = &hostid.Identity{HostName: spec.HostName, HostID: spec.HostID, Epoch: "0123456789ab"}
	t.Cleanup(func() { hostid.Override = nil })
	out := filepath.Join(dir, "out.tgz")
	if _, err := bundle.Export(bundle.ExportRequest{ContextPaths: []string{ctxPath}, SigningKey: spec.Seed, Out: out}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	archive, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if spec.GeneratedAt.IsZero() {
		return archive
	}
	return regenerate(t, archive, spec.Seed, spec.GeneratedAt)
}

// regenerate rewrites an archive's manifest generated_at and re-signs it.
func regenerate(t *testing.T, archive []byte, seed string, at time.Time) []byte {
	t.Helper()
	members := untar(t, archive)
	var m bundle.Manifest
	if err := json.Unmarshal(members["manifest.json"], &m); err != nil {
		t.Fatal(err)
	}
	m.GeneratedAt = at.UTC()
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := hex.DecodeString(seed)
	priv := ed25519.NewKeyFromSeed(sb)
	sig, _ := json.MarshalIndent(bundle.Signature{
		PublicKeyHex: hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
		SignatureHex: hex.EncodeToString(ed25519.Sign(priv, raw)),
	}, "", "  ")
	members["manifest.json"], members["manifest.sig"] = raw, sig
	return tarball(t, members)
}

func untar(t *testing.T, archive []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = b
	}
}

func tarball(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range members {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Now()}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write(data)
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// freshBundle is a one-proof bundle whose proof is inside its freshness window.
func freshBundle(t *testing.T, host, hostID, seed, proof string) []byte {
	t.Helper()
	now := time.Now().UTC()
	return makeBundle(t, bundleSpec{HostName: host, HostID: hostID, Seed: seed,
		Proofs: []proofSpec{{ID: proof, ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(48 * time.Hour)}}})
}

// regexpFind returns the first submatch of pattern in s or fails the test.
func regexpFind(t *testing.T, pattern, s string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("pattern %q not found in:\n%s", pattern, s)
	}
	return m[1]
}
