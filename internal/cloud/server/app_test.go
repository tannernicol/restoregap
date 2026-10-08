// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAppPagesRenderForAPopulatedWorkspace(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("owner@example.com")
	ws := e.workspaceOf("owner@example.com")
	_, tok, _ := e.st.CreateToken(ws.ID, "ci")
	seed := newSeed(t)
	now := e.clock.Now()
	proof := []proofSpec{{ID: "p1", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour)}}
	e.push(tok, makeBundle(t, bundleSpec{HostName: "web-1", HostID: "aaaaaaaaaaaaaaaa", Seed: seed, Proofs: proof, GeneratedAt: now}))
	e.push(tok, makeBundle(t, bundleSpec{HostName: "web-1", HostID: "aaaaaaaaaaaaaaaa", Seed: seed, Proofs: proof, GeneratedAt: now.Add(48 * time.Hour)}))
	h, _ := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")

	pages := map[string][]string{
		"/app":       {"Dashboard", "web-1", "2 bundles", "rgs-taxlayer"},
		"/app/hosts": {"web-1", "aaaaaaaa", pubOf(seed)[:8], `href="/app/hosts/` + h.ID + `"`},
		"/app/hosts/" + h.ID: {pubOf(seed), "restoregap bundle verify --expected-key " + pubOf(seed), "Recent bundles", "Latest proofs",
			`id="b-`, "Rotate pinned key", "every hour", "Expected cadence"},
		"/app/hosts/" + h.ID + "/proofs/p1": {"state changed 1 time in 2 bundles", "observed", "expired", `#b-`},
		"/app/alerts":                       {"proof_regressed", "pending"},
		"/app/settings":                     {"Push tokens", "Notifications", "Share links", "Members", "owner@example.com", "owner"},
	}
	// cadence option text only appears with the select; "every hour" is in the menu.
	for path, wants := range pages {
		resp, body := e.get(c, path)
		if resp.StatusCode != 200 {
			t.Errorf("GET %s = %d", path, resp.StatusCode)
			continue
		}
		for _, w := range wants {
			if !strings.Contains(body, w) {
				t.Errorf("GET %s lacks %q", path, w)
			}
		}
		// The shell contract: theme bootstrap first in <head>, then style, then the module.
		iBoot, iStyle, iMod := strings.Index(body, "<script>"), strings.Index(body, "<style>"), strings.Index(body, `<script type="module">`)
		if !(iBoot > 0 && iBoot < iStyle && iStyle < iMod) {
			t.Errorf("GET %s: script/style order is wrong (%d %d %d)", path, iBoot, iStyle, iMod)
		}
		for _, shell := range []string{`class="rg-topbar"`, `class="rg-footer"`, `name="viewport"`} {
			if !strings.Contains(body, shell) {
				t.Errorf("GET %s lacks shell piece %s", path, shell)
			}
		}
		if i, j := strings.Index(body, `class="rg-topbar"`), strings.Index(body, `class="rg-footer"`); i > j {
			t.Errorf("GET %s: topbar after footer", path)
		}
	}

	// Unknown things are 404 pages, not errors, and never another workspace's.
	for _, path := range []string{"/app/hosts/nope", "/app/hosts/" + h.ID + "/proofs/nope"} {
		if resp, _ := e.get(c, path); resp.StatusCode != 404 {
			t.Errorf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
	other := e.loginViaLink("other@example.com")
	if resp, _ := e.get(other, "/app/hosts/"+h.ID); resp.StatusCode != 404 {
		t.Errorf("another workspace's host = %d, want 404", resp.StatusCode)
	}
	if _, body := e.get(other, "/app"); strings.Contains(body, "web-1") {
		t.Error("another workspace's dashboard shows this workspace's host")
	}
	if resp, _ := e.post(other, "/app/hosts/"+h.ID, url.Values{"name": {"x"}, "cadence": {"1h"}}); resp.StatusCode != 404 {
		t.Errorf("updating another workspace's host = %d", resp.StatusCode)
	}
	if resp, _ := e.post(other, "/app/hosts/"+h.ID+"/key", url.Values{"public_key": {strings.Repeat("a", 64)}}); resp.StatusCode != 404 {
		t.Errorf("rotating another workspace's host key = %d", resp.StatusCode)
	}
}

func TestHostSettingsRenameCadenceAndKeyRotation(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("owner@example.com")
	ws := e.workspaceOf("owner@example.com")
	_, tok, _ := e.st.CreateToken(ws.ID, "ci")
	seed, newKeySeed := newSeed(t), newSeed(t)
	e.push(tok, freshBundle(t, "machine-name", "aaaaaaaaaaaaaaaa", seed, "p1"))
	h, _ := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")
	path := "/app/hosts/" + h.ID

	// Bad input is refused with a reason.
	for name, form := range map[string]url.Values{
		"bad cadence": {"name": {"x"}, "cadence": {"5m"}},
		"no name":     {"name": {"  "}, "cadence": {"1h"}},
	} {
		if resp, _ := e.post(c, path, form); resp.StatusCode != 400 {
			t.Errorf("%s = %d, want 400", name, resp.StatusCode)
		}
	}
	// Rename + cadence; the new name survives the next push and shows in the fleet tree.
	resp, _ := e.post(c, path, url.Values{"name": {"Web One"}, "cadence": {"24h"}})
	if resp.StatusCode != 303 || resp.Header.Get("Location") != path+"?saved=1" {
		t.Fatalf("update = %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, body := e.get(c, path+"?saved=1"); !strings.Contains(body, "Saved.") || !strings.Contains(body, "Web One") {
		t.Fatal("host page does not show the saved name")
	}
	got, _ := e.st.GetHost(ws.ID, h.ID)
	if got.Name != "Web One" || got.ExpectedEvery != 24*time.Hour {
		t.Fatalf("host = %+v", got)
	}
	e.push(tok, makeBundle(t, bundleSpec{HostName: "machine-name", HostID: "aaaaaaaaaaaaaaaa", Seed: seed,
		Proofs:      []proofSpec{{ID: "p1", ObservedAt: e.clock.Now().Add(-time.Hour), ExpiresAt: e.clock.Now().Add(24 * time.Hour)}},
		GeneratedAt: e.clock.Now().Add(time.Hour)}))
	if got, _ = e.st.GetHost(ws.ID, h.ID); got.Name != "Web One" {
		t.Fatalf("a push overwrote the chosen name: %q", got.Name)
	}
	if _, body := e.get(c, "/app"); !strings.Contains(body, "Web One") || strings.Contains(body, "machine-name") {
		t.Fatal("the fleet tree does not use the chosen host name")
	}

	// Key rotation: validated, owner-only, and it unblocks the new key.
	for _, bad := range []string{"", "xyz", strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 66)} {
		if resp, _ := e.post(c, path+"/key", url.Values{"public_key": {bad}}); resp.StatusCode != 400 {
			t.Errorf("key %q = %d, want 400", bad, resp.StatusCode)
		}
	}
	if resp, _ := e.push(tok, freshBundle(t, "x", "aaaaaaaaaaaaaaaa", newKeySeed, "p1")); resp.StatusCode != 409 {
		t.Fatalf("new key before rotation = %d", resp.StatusCode)
	}
	resp, _ = e.post(c, path+"/key", url.Values{"public_key": {strings.ToUpper(pubOf(newKeySeed))}})
	if resp.StatusCode != 303 || resp.Header.Get("Location") != path+"?saved=key" {
		t.Fatalf("rotate = %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if got, _ = e.st.GetHost(ws.ID, h.ID); got.PublicKeyHex != pubOf(newKeySeed) {
		t.Fatalf("pinned key = %q (hex is normalized to lowercase)", got.PublicKeyHex)
	}
	if resp, out := e.push(tok, freshBundle(t, "x", "aaaaaaaaaaaaaaaa", newKeySeed, "p1")); resp.StatusCode != 201 {
		t.Fatalf("new key after rotation = %d %v", resp.StatusCode, out)
	}
	if resp, _ := e.push(tok, freshBundle(t, "x", "aaaaaaaaaaaaaaaa", seed, "p1")); resp.StatusCode != 409 {
		t.Fatalf("old key after rotation = %d, want 409", resp.StatusCode)
	}

	// A non-owner cannot rotate.
	member, _ := e.st.EnsureUser("member@example.com")
	if err := e.st.AddMembership(ws.ID, member.ID, "member"); err != nil {
		t.Fatal(err)
	}
	mc := e.loginViaLink("member@example.com")
	if _, body := e.get(mc, path); strings.Contains(body, "Rotate pinned key") {
		t.Error("a member is offered key rotation")
	}
	if resp, _ := e.post(mc, path+"/key", url.Values{"public_key": {strings.Repeat("b", 64)}}); resp.StatusCode != 403 {
		t.Errorf("member rotating a key = %d, want 403", resp.StatusCode)
	}
	if got, _ = e.st.GetHost(ws.ID, h.ID); got.PublicKeyHex != pubOf(newKeySeed) {
		t.Fatal("a member's rotation changed the key")
	}
}

func TestTokensCreateOnceRevokeAndStayInTheirWorkspace(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("owner@example.com")
	other := e.loginViaLink("other@example.com")

	resp, body := e.post(c, "/app/settings/tokens", url.Values{"name": {"web-1 cron"}})
	m := regexpFind(t, `class="cl-secret">(rgp_[A-Za-z0-9_-]+)<`, body)
	if resp.StatusCode != 200 || !strings.Contains(body, "web-1 cron") {
		t.Fatalf("create token = %d", resp.StatusCode)
	}
	if _, again := e.get(c, "/app/settings"); strings.Contains(again, m) || !strings.Contains(again, m[:8]) {
		t.Fatal("settings must show only the token's prefix after creation")
	}
	if resp, _ := e.do(e.ts.Client(), "GET", "/api/v1/fleet.json", nil, map[string]string{"Authorization": "Bearer " + m}); resp.StatusCode != 200 {
		t.Fatalf("the new token does not work: %d", resp.StatusCode)
	}
	if resp, _ := e.post(c, "/app/settings/tokens", url.Values{"name": {""}}); resp.StatusCode != 400 {
		t.Fatalf("nameless token = %d", resp.StatusCode)
	}

	ws := e.workspaceOf("owner@example.com")
	toks, _ := e.st.ListTokens(ws.ID)
	id := toks[0].ID
	// Another workspace's user cannot revoke it, and gets the same 404 as for a made-up id.
	if resp, _ := e.post(other, "/app/settings/tokens/"+id+"/revoke", nil); resp.StatusCode != 404 {
		t.Fatalf("cross-workspace revoke = %d, want 404", resp.StatusCode)
	}
	if resp, _ := e.do(e.ts.Client(), "GET", "/api/v1/fleet.json", nil, map[string]string{"Authorization": "Bearer " + m}); resp.StatusCode != 200 {
		t.Fatal("another workspace revoked the token")
	}
	if resp, _ := e.post(c, "/app/settings/tokens/"+id+"/revoke", nil); resp.StatusCode != 303 {
		t.Fatalf("revoke = %d", resp.StatusCode)
	}
	if resp, _ := e.do(e.ts.Client(), "GET", "/api/v1/fleet.json", nil, map[string]string{"Authorization": "Bearer " + m}); resp.StatusCode != 401 {
		t.Fatalf("revoked token = %d, want 401", resp.StatusCode)
	}
}

func TestNotificationSettings(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("owner@example.com")
	ws := e.workspaceOf("owner@example.com")

	// No secret supplied: one is generated and shown exactly once.
	resp, body := e.post(c, "/app/settings/notify", url.Values{"email": {"oncall@example.com"}, "webhook_url": {"https://hooks.example.com/x"}})
	secret := regexpFind(t, `class="cl-secret">([A-Za-z0-9_-]{40,})<`, body)
	if resp.StatusCode != 200 {
		t.Fatalf("save = %d", resp.StatusCode)
	}
	got, _ := e.st.GetWorkspace(ws.ID)
	if got.NotifyEmail != "oncall@example.com" || got.NotifyWebhookURL != "https://hooks.example.com/x" || got.NotifyWebhookSecret != secret {
		t.Fatalf("workspace = %+v", got)
	}
	if _, again := e.get(c, "/app/settings"); strings.Contains(again, secret) || !strings.Contains(again, "leave blank to keep it") {
		t.Fatal("the stored webhook secret is rendered back")
	}
	// Blank keeps it; a checkbox regenerates it; a typed one is used and shown once.
	e.post(c, "/app/settings/notify", url.Values{"email": {"oncall@example.com"}, "webhook_url": {"https://hooks.example.com/x"}})
	if got, _ = e.st.GetWorkspace(ws.ID); got.NotifyWebhookSecret != secret {
		t.Fatal("a blank secret field changed the secret")
	}
	e.post(c, "/app/settings/notify", url.Values{"webhook_url": {"https://hooks.example.com/x"}, "regenerate": {"1"}})
	if got, _ = e.st.GetWorkspace(ws.ID); got.NotifyWebhookSecret == secret || got.NotifyWebhookSecret == "" || got.NotifyEmail != "" {
		t.Fatalf("regenerate: %+v", got)
	}
	_, body = e.post(c, "/app/settings/notify", url.Values{"webhook_url": {"https://hooks.example.com/x"}, "webhook_secret": {"a-long-enough-typed-secret"}})
	if !strings.Contains(body, "a-long-enough-typed-secret") {
		t.Fatal("a newly typed secret is not shown on save")
	}
	// Clearing the URL clears the secret.
	e.post(c, "/app/settings/notify", url.Values{"email": {"oncall@example.com"}})
	if got, _ = e.st.GetWorkspace(ws.ID); got.NotifyWebhookURL != "" || got.NotifyWebhookSecret != "" {
		t.Fatalf("cleared: %+v", got)
	}

	for name, form := range map[string]url.Values{
		"not an email":   {"email": {"not-an-email"}},
		"display name":   {"email": {"Bob <bob@example.com>"}},
		"ftp url":        {"webhook_url": {"ftp://example.com/x"}},
		"relative url":   {"webhook_url": {"/x"}},
		"credentials":    {"webhook_url": {"https://user:pw@example.com/x"}},
		"short secret":   {"webhook_url": {"https://example.com/x"}, "webhook_secret": {"short"}},
		"javascript url": {"webhook_url": {"javascript:alert(1)"}},
		"no host":        {"webhook_url": {"https:///x"}},
	} {
		if resp, _ := e.post(c, "/app/settings/notify", form); resp.StatusCode != 400 {
			t.Errorf("%s = %d, want 400", name, resp.StatusCode)
		}
	}
}

func TestRelTime(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		t    time.Time
		want string
	}{
		{now.Add(-10 * time.Second), "just now"},
		{now.Add(-5 * time.Minute), "5m ago"},
		{now.Add(-3 * time.Hour), "3h ago"},
		{now.Add(-47 * time.Hour), "47h ago"},
		{now.Add(-72 * time.Hour), "3d ago"},
		{now.Add(-90 * 24 * time.Hour), "2026-07-09"},
		{now.Add(2 * time.Hour), "in 2h"},
		{now.Add(10 * time.Second), "just now"},
		{time.Time{}, "never"},
	} {
		if got := relTime(tc.t, now); got != tc.want {
			t.Errorf("relTime(%v) = %q, want %q", tc.t, got, tc.want)
		}
	}
	if relTimePtr(nil, now) != "never" {
		t.Error("nil time must read 'never'")
	}
}

func TestCoarseUnknownPagesAndMethods(t *testing.T) {
	e := newEnv(t)
	for path, want := range map[string]int{"/nope": 404, "/app/nope": 404, "/s/": 404, "/auth/": 404} {
		if resp, _ := e.get(e.browser(), path); resp.StatusCode != want {
			t.Errorf("GET %s = %d, want %d", path, resp.StatusCode, want)
		}
	}
	if resp, _ := e.do(e.browser(), http.MethodDelete, "/app", nil, nil); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /app = %d", resp.StatusCode)
	}
}
