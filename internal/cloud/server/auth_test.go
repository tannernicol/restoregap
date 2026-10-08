// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestLoginAuthSessionAndEmptyDashboard(t *testing.T) {
	e := newEnv(t)
	c := e.browser()

	// Not signed in: /app bounces to the home page, which has the form.
	resp, _ := e.get(c, "/app")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("anonymous /app = %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body := e.get(c, "/")
	if resp.StatusCode != 200 || !strings.Contains(body, `action="/login"`) || !strings.Contains(body, "docs/CLOUD.md") {
		t.Fatalf("home = %d, missing login form or docs link", resp.StatusCode)
	}

	c = e.loginViaLink("Owner@Example.com")
	if resp, _ := e.get(c, "/"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/app" {
		t.Fatalf("signed-in / = %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp, body = e.get(c, "/app")
	if resp.StatusCode != 200 {
		t.Fatalf("/app = %d", resp.StatusCode)
	}
	// The empty state names this instance's base URL in the exact push command.
	want := "restoregap bundle push \\\n  --to " + e.cfg.BaseURL + " \\\n  --token &#34;$RESTOREGAP_PUSH_TOKEN&#34; \\\n"
	if !strings.Contains(body, want) {
		t.Fatalf("empty state lacks the push command with the base URL; body:\n%s", body)
	}
	if !strings.Contains(body, "0 hosts") {
		t.Fatal("stats line missing")
	}

	// First login created the workspace: unlimited, because billing is off.
	ws := e.workspaceOf("owner@example.com")
	if ws.Plan != "unlimited" || ws.BillingStatus != "unlimited" || ws.TrialEndsAt != nil || ws.Name != "owner@example.com's workspace" {
		t.Fatalf("workspace = %+v", ws)
	}
	m, err := e.st.ListMembers(ws.ID)
	if err != nil || len(m) != 1 || m[0].Role != "owner" {
		t.Fatalf("members = %+v, %v", m, err)
	}
}

func TestFirstLoginStartsTeamTrialWhenBillingOn(t *testing.T) {
	stripe := newStripeStub(t)
	e := newEnv(t, stripe.configure)
	e.loginViaLink("new@example.com")
	ws := e.workspaceOf("new@example.com")
	if ws.Plan != "team" || ws.BillingStatus != "trialing" || ws.TrialEndsAt == nil {
		t.Fatalf("workspace = %+v", ws)
	}
	if d := ws.TrialEndsAt.Sub(e.clock.Now()); d < 14*24*3600*1e9-1e9 || d > 14*24*3600*1e9+1e9 {
		t.Fatalf("trial length = %v, want 14 days", d)
	}
}

func TestLoginDoesNotRevealAccounts(t *testing.T) {
	e := newEnv(t)
	e.loginViaLink("known@example.com")

	bodies := map[string]string{}
	for _, addr := range []string{"known@example.com", "stranger@example.com", "not an email", ""} {
		resp, body := e.postForm(e.browser(), "/login", url.Values{"email": {addr}})
		if resp.StatusCode != 200 {
			t.Fatalf("POST /login %q = %d", addr, resp.StatusCode)
		}
		bodies[addr] = body
	}
	for addr, b := range bodies {
		if b != bodies["known@example.com"] {
			t.Fatalf("response for %q differs from the response for a known address", addr)
		}
	}
	if !strings.Contains(bodies[""], "If that address can sign in, a link is on its way") {
		t.Fatal("login page text changed")
	}
}

func TestLoginRateLimitIsFivePerAddress(t *testing.T) {
	e := newEnv(t)
	c := e.browser()
	for i := 0; i < 8; i++ {
		resp, body := e.postForm(c, "/login", url.Values{"email": {"flood@example.com"}})
		if resp.StatusCode != 200 || !strings.Contains(body, "link is on its way") {
			t.Fatalf("request %d = %d; the limited answer must look the same", i, resp.StatusCode)
		}
	}
	if n := len(loginLinkRE.FindAllString(e.logs.String(), -1)); n != 5 {
		t.Fatalf("links minted = %d, want 5", n)
	}
	// Another address is unaffected, and the window slides.
	e.postForm(c, "/login", url.Values{"email": {"other@example.com"}})
	if n := len(loginLinkRE.FindAllString(e.logs.String(), -1)); n != 6 {
		t.Fatalf("links minted = %d, want 6", n)
	}
	e.clock.Advance(loginWindow + 1)
	e.postForm(c, "/login", url.Values{"email": {"flood@example.com"}})
	if n := len(loginLinkRE.FindAllString(e.logs.String(), -1)); n != 7 {
		t.Fatalf("links minted after the window = %d, want 7", n)
	}
}

func TestAuthLinkSurvivesPrefetchIsSingleUseAndInvalidIsRefused(t *testing.T) {
	e := newEnv(t)
	c := e.browser()
	e.postForm(c, "/login", url.Values{"email": {"once@example.com"}})
	link := loginLinkRE.FindStringSubmatch(e.logs.String())[1]
	path := strings.TrimPrefix(link, e.ts.URL)

	// A mail scanner fetching the link any number of times burns nothing and sets no session.
	for i := 0; i < 3; i++ {
		resp, body := e.get(e.browser(), path)
		if resp.StatusCode != 200 || !strings.Contains(body, "Sign in to Restore Gap Cloud") || !strings.Contains(body, `action="`+path+`"`) {
			t.Fatalf("prefetch %d = %d", i, resp.StatusCode)
		}
		if len(resp.Cookies()) != 0 {
			t.Fatal("GET /auth set a cookie")
		}
		if strings.Contains(body, "once@example.com") {
			t.Fatal("the confirm page shows account details")
		}
	}
	if _, err := e.st.UserByEmail("once@example.com"); err == nil {
		t.Fatal("GET /auth created the account")
	}
	// A GET of garbage looks the same: it validates nothing.
	if resp, _ := e.get(e.browser(), "/auth/garbage"); resp.StatusCode != 200 {
		t.Fatalf("GET of an unknown token = %d, want the same confirm page", resp.StatusCode)
	}

	if resp, _ := e.postForm(c, path, url.Values{}); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/app" {
		t.Fatalf("first POST = %d", resp.StatusCode)
	}
	resp, body := e.postForm(e.browser(), path, url.Values{})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "invalid, already used") {
		t.Fatalf("second POST = %d %q", resp.StatusCode, body)
	}
	if resp, _ := e.postForm(e.browser(), "/auth/garbage", url.Values{}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("garbage token POST = %d", resp.StatusCode)
	}
}

func TestClosedSignup(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.AllowSignup = false })
	c := e.browser()

	if _, body := e.get(c, "/"); !strings.Contains(body, "closed to new workspaces") {
		t.Fatal("home page does not say signup is closed")
	}
	// A stranger gets the usual page but no link.
	if resp, _ := e.postForm(c, "/login", url.Values{"email": {"stranger@example.com"}}); resp.StatusCode != 200 {
		t.Fatalf("POST /login = %d", resp.StatusCode)
	}
	if loginLinkRE.MatchString(e.logs.String()) {
		t.Fatal("a link was minted for an unknown address on a closed instance")
	}
	// Even a link that exists (minted before signup closed) cannot open a workspace.
	tok, err := e.st.CreateLoginToken("late@example.com", loginTokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := e.postForm(c, "/auth/"+tok, url.Values{})
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "Signup is closed") {
		t.Fatalf("closed-signup auth = %d %q", resp.StatusCode, body)
	}
	if wss, _ := e.st.ListWorkspaces(); len(wss) != 0 {
		t.Fatalf("a workspace was created on a closed instance: %+v", wss)
	}

	// An account the operator created can sign in.
	u, _ := e.st.EnsureUser("owner@example.com")
	if _, err := e.st.CreateWorkspace("ops", "unlimited", "unlimited", nil, u.ID); err != nil {
		t.Fatal(err)
	}
	e.loginViaLink("owner@example.com")
}

func TestCSRFIsRequiredOnEveryAppPost(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("csrf@example.com")
	csrf := e.csrfOf(c)

	for name, form := range map[string]url.Values{
		"missing": {"name": {"x"}},
		"wrong":   {"name": {"x"}, "csrf": {csrf + "x"}},
		"empty":   {"name": {"x"}, "csrf": {""}},
	} {
		resp, body := e.postForm(c, "/app/settings/tokens", form)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "security token") {
			t.Fatalf("%s token: status %d", name, resp.StatusCode)
		}
	}
	ws := e.workspaceOf("csrf@example.com")
	if toks, _ := e.st.ListTokens(ws.ID); len(toks) != 0 {
		t.Fatal("a token was created without a valid CSRF token")
	}
	for _, p := range []string{"/app/settings/notify", "/app/share", "/logout", "/app/hosts/x", "/app/hosts/x/key", "/app/settings/tokens/x/revoke", "/app/share/x/revoke"} {
		if resp, _ := e.postForm(c, p, url.Values{"x": {"y"}}); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("POST %s without CSRF = %d, want 403", p, resp.StatusCode)
		}
	}
	// The cookie alone is not enough: a form posted with a token that does not
	// match the cookie (another session's) fails too.
	other := e.loginViaLink("other@example.com")
	resp, _ := e.postForm(c, "/app/settings/tokens", url.Values{"name": {"x"}, "csrf": {e.csrfOf(other)}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign CSRF token = %d", resp.StatusCode)
	}
	if resp, _ := e.postForm(c, "/app/settings/tokens", url.Values{"name": {"ok"}, "csrf": {csrf}}); resp.StatusCode != 200 {
		t.Fatalf("valid CSRF token = %d", resp.StatusCode)
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("bye@example.com")
	resp, _ := e.post(c, "/logout", nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("logout = %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := e.get(c, "/app"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("after logout /app = %d", resp.StatusCode)
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	check := func(resp *http.Response, secure bool) {
		t.Helper()
		cookies := map[string]*http.Cookie{}
		for _, ck := range resp.Cookies() {
			cookies[ck.Name] = ck
		}
		for _, name := range []string{sessionCookie, csrfCookie} {
			ck := cookies[name]
			if ck == nil {
				t.Fatalf("no %s cookie", name)
			}
			if !ck.HttpOnly || ck.Secure != secure || ck.SameSite != http.SameSiteLaxMode || ck.MaxAge != 30*24*3600 {
				t.Fatalf("%s cookie = %+v (want Secure=%v)", name, ck, secure)
			}
		}
		if cookies[sessionCookie].Value == cookies[csrfCookie].Value {
			t.Fatal("session and CSRF cookie must be independent secrets")
		}
	}

	// Over https the cookies are Secure.
	e := newEnv(t, func(c *Config) { c.BaseURL = "https://cloud.example.com" })
	c := e.browser()
	e.postForm(c, "/login", url.Values{"email": {"secure@example.com"}})
	link := loginLinkRE.FindStringSubmatch(e.logs.String())[1]
	if !strings.HasPrefix(link, "https://cloud.example.com/auth/") {
		t.Fatalf("link = %q", link)
	}
	resp, _ := e.postForm(c, "/auth/"+link[strings.LastIndex(link, "/")+1:], url.Values{})
	check(resp, true)

	// Over plain http (the dev default) they must not be, or no one could log in.
	plain := newEnv(t)
	_, resp = plain.loginResponse("plain@example.com")
	check(resp, false)
}

func TestSecurityHeadersAndCSPMatchTheInlineScripts(t *testing.T) {
	e := newEnv(t)
	resp, body := e.get(e.browser(), "/")
	csp := resp.Header.Get("Content-Security-Policy")
	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Cache-Control"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	scripts := regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`).FindAllStringSubmatch(body, -1)
	if len(scripts) != 2 {
		t.Fatalf("the page carries %d scripts, want exactly the theme bootstrap and the design-system module", len(scripts))
	}
	for _, s := range scripts {
		sum := sha256.Sum256([]byte(s[1]))
		if want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"; !strings.Contains(csp, want) {
			t.Fatalf("CSP does not allow inline script hash %s\nCSP: %s", want, csp)
		}
	}
	if strings.Contains(csp, "script-src 'unsafe-inline'") || strings.Contains(csp, "unsafe-eval") {
		t.Fatalf("script-src must be hash-pinned: %s", csp)
	}
	for _, bad := range []string{"http://", "https://"} {
		// Nothing is LOADED from elsewhere: no src= points off-host. The only
		// absolute hrefs are the docs link and the terms/privacy pages on
		// restoregap.com, which a visitor follows by choice — not a request
		// the page makes on its own.
		for _, m := range regexp.MustCompile(`src="(`+bad+`[^"]*)"`).FindAllStringSubmatch(body, -1) {
			t.Fatalf("page loads external resource %s", m[1])
		}
		for _, m := range regexp.MustCompile(`href="(`+bad+`[^"]*)"`).FindAllStringSubmatch(body, -1) {
			if m[1] != docsURL && !strings.HasPrefix(m[1], "https://restoregap.com/") {
				t.Fatalf("page references external %s", m[1])
			}
		}
	}
}

func TestAPIRequiresABearerToken(t *testing.T) {
	e := newEnv(t)
	_, tok := e.newWorkspace("w", "unlimited", "unlimited")
	for _, hdr := range []map[string]string{nil, {"Authorization": "Bearer nope"}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer "}} {
		for _, req := range []struct{ method, path string }{{"POST", "/api/v1/bundles"}, {"GET", "/api/v1/fleet.json"}} {
			resp, body := e.do(e.ts.Client(), req.method, req.path, strings.NewReader("x"), hdr)
			if resp.StatusCode != 401 || strings.TrimSpace(body) != `{"error":"unknown or revoked token"}` {
				t.Fatalf("%s %s with %v = %d %q", req.method, req.path, hdr, resp.StatusCode, body)
			}
		}
	}
	if resp, _ := e.do(e.ts.Client(), "GET", "/api/v1/fleet.json", nil, map[string]string{"Authorization": "bearer " + tok}); resp.StatusCode != 200 {
		t.Fatalf("lowercase scheme = %d", resp.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	e := newEnv(t)
	resp, body := e.get(e.browser(), "/healthz")
	if resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("healthz = %d %q", resp.StatusCode, body)
	}
}
