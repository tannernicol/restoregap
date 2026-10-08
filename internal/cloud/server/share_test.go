// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/bundle"
	"github.com/tannernicol/restoregap/internal/status"
)

var shareURLRE = regexp.MustCompile(`class="cl-secret">(http[^<]*/s/[A-Za-z0-9_-]+)<`)

func TestShareLinkRendersVerifiesAndRevokes(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("owner@example.com")
	ws := e.workspaceOf("owner@example.com")
	_, tok, _ := e.st.CreateToken(ws.ID, "ci")
	seed := newSeed(t)
	if resp, out := e.push(tok, freshBundle(t, "web-1", "aaaaaaaaaaaaaaaa", seed, "pg-restore")); resp.StatusCode != 201 {
		t.Fatalf("push = %d %v", resp.StatusCode, out)
	}
	h, _ := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")

	// Create the link: the plaintext URL is in this response and nowhere else.
	resp, body := e.post(c, "/app/share", url.Values{"scope": {"fleet"}, "expires": {"7d"}})
	m := shareURLRE.FindStringSubmatch(body)
	if resp.StatusCode != 200 || m == nil {
		t.Fatalf("create share = %d, no URL in body", resp.StatusCode)
	}
	shareURL := m[1]
	if !strings.HasPrefix(shareURL, e.cfg.BaseURL+"/s/") {
		t.Fatalf("share URL = %q", shareURL)
	}
	sharePath := strings.TrimPrefix(shareURL, e.cfg.BaseURL)
	token := strings.TrimPrefix(sharePath, "/s/")
	if _, body := e.get(c, "/app/settings"); strings.Contains(body, token) {
		t.Fatal("the share token is shown again after creation")
	} else if !strings.Contains(body, "Whole fleet") || !strings.Contains(body, `data-kind="active"`) {
		t.Fatal("settings does not list the link")
	}

	// A stranger (no cookies) sees the tree and the verification section.
	anon := e.browser()
	resp, page := e.get(anon, sharePath)
	if resp.StatusCode != 200 {
		t.Fatalf("share page = %d", resp.StatusCode)
	}
	for _, want := range []string{"pg-restore", "web-1", "Verify this yourself", pubOf(seed), "Archive SHA-256", "manifest.json and manifest.sig"} {
		if !strings.Contains(page, want) {
			t.Errorf("share page lacks %q", want)
		}
	}
	b, _ := e.st.ListBundles(ws.ID, h.ID, 1)
	if !strings.Contains(page, b[0].SignatureHex) || !strings.Contains(page, b[0].SHA256) {
		t.Error("share page lacks the bundle's signature or archive hash")
	}
	// Nothing about the workspace leaks, there are no forms, and rows do not link into /app.
	for _, bad := range []string{"owner@example.com", ws.Name, "rgp_", "<form", "/app", "csrf", "Sign out", tok} {
		if strings.Contains(page, bad) {
			t.Errorf("share page contains %q", bad)
		}
	}
	if resp.Header.Get("Referrer-Policy") != "no-referrer" || !strings.Contains(resp.Header.Get("X-Robots-Tag"), "noindex") {
		t.Errorf("share headers: %v", resp.Header)
	}

	// The same scope as fleet.json.
	resp, js := e.get(anon, sharePath+".json")
	var f status.Fleet
	if resp.StatusCode != 200 || json.Unmarshal([]byte(js), &f) != nil || len(f.Proofs) != 1 || f.Proofs[0].Proof != "pg-restore" {
		t.Fatalf("share json = %d %s", resp.StatusCode, js)
	}
	if strings.Contains(js, "owner@example.com") || strings.Contains(js, ws.Name) {
		t.Fatal("share json leaks the workspace")
	}

	// The signed material: manifest.json and manifest.sig, and the signature checks out.
	manifestPath := sharePath + "/bundles/" + b[0].ID + "/manifest.json"
	if !strings.Contains(page, manifestPath) {
		t.Fatalf("page does not link %s", manifestPath)
	}
	resp, mj := e.get(anon, manifestPath)
	if resp.StatusCode != 200 {
		t.Fatalf("manifest endpoint = %d %s", resp.StatusCode, mj)
	}
	var mr manifestResponse
	if err := json.Unmarshal([]byte(mj), &mr); err != nil {
		t.Fatal(err)
	}
	manifest, err1 := base64.StdEncoding.DecodeString(mr.ManifestJSON)
	sigFile, err2 := base64.StdEncoding.DecodeString(mr.ManifestSig)
	if err1 != nil || err2 != nil {
		t.Fatalf("base64: %v %v", err1, err2)
	}
	var sig bundle.Signature
	if err := json.Unmarshal(sigFile, &sig); err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(sig.PublicKeyHex)
	raw, _ := hex.DecodeString(sig.SignatureHex)
	if sig.PublicKeyHex != pubOf(seed) || !ed25519.Verify(pub, manifest, raw) {
		t.Fatal("the manifest and signature the share link serves do not verify under the host's key")
	}
	if mr.ArchiveSHA256 != b[0].SHA256 || mr.Host != "web-1" || mr.BundleID != b[0].ID {
		t.Fatalf("manifest response = %+v", mr)
	}
	// And the manifest is metadata only: no context file contents, no ledger.
	for _, bad := range []string{`/data/**`, "requires:", "guards:", "pg-restore\n"} {
		if strings.Contains(string(manifest), bad) {
			t.Errorf("manifest contains context text %q", bad)
		}
	}
	var m2 bundle.Manifest
	if err := json.Unmarshal(manifest, &m2); err != nil || m2.Host.ID != "aaaaaaaaaaaaaaaa" {
		t.Fatalf("manifest = %s (%v)", manifest, err)
	}
	// There is no archive download.
	for _, p := range []string{sharePath + "/bundles/" + b[0].ID + ".tgz", sharePath + "/bundles/" + b[0].ID} {
		if resp, _ := e.get(anon, p); resp.StatusCode != 404 {
			t.Errorf("GET %s = %d, want 404", p, resp.StatusCode)
		}
	}
	// A bundle id that does not belong to this link's view is not served.
	if resp, _ := e.get(anon, sharePath+"/bundles/ffffffffffffffffffffffffffffffff/manifest.json"); resp.StatusCode != 404 {
		t.Errorf("unknown bundle id = %d", resp.StatusCode)
	}

	// Revoke: every URL for the link answers 404, indistinguishable from unknown.
	var linkID string
	links, _ := e.st.ListShareLinks(ws.ID)
	linkID = links[0].ID
	if resp, _ := e.post(c, "/app/share/"+linkID+"/revoke", nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke = %d", resp.StatusCode)
	}
	unknown := "/s/" + strings.Repeat("A", 43)
	_, unknownPage := e.get(anon, unknown)
	for _, p := range []string{sharePath, sharePath + ".json", manifestPath} {
		resp, body := e.get(anon, p)
		if resp.StatusCode != 404 {
			t.Errorf("revoked %s = %d, want 404", p, resp.StatusCode)
		}
		if strings.HasSuffix(p, ".json") || strings.HasSuffix(p, "manifest.json") {
			continue
		}
		if body != unknownPage {
			t.Errorf("revoked link's 404 differs from an unknown link's")
		}
	}
	if _, body := e.get(c, "/app/settings"); !strings.Contains(body, `data-kind="revoked"`) {
		t.Error("settings does not show the link as revoked")
	}
}

func TestShareLinkScopeAndExpiry(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("owner@example.com")
	ws := e.workspaceOf("owner@example.com")
	_, tok, _ := e.st.CreateToken(ws.ID, "ci")
	e.push(tok, freshBundle(t, "alpha", "aaaaaaaaaaaaaaaa", newSeed(t), "proof-a"))
	e.push(tok, freshBundle(t, "beta", "bbbbbbbbbbbbbbbb", newSeed(t), "proof-b"))
	alpha, _ := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")

	// One host only.
	_, body := e.post(c, "/app/share", url.Values{"scope": {"host:" + alpha.ID}, "expires": {"none"}})
	path := strings.TrimPrefix(shareURLRE.FindStringSubmatch(body)[1], e.cfg.BaseURL)
	_, page := e.get(e.browser(), path)
	if !strings.Contains(page, "proof-a") || strings.Contains(page, "proof-b") || strings.Contains(page, "beta") {
		t.Fatal("a host-scoped link shows more than its host")
	}
	if !strings.Contains(page, "Host alpha") {
		t.Error("page does not say what it covers")
	}

	// A host id from another workspace cannot be shared.
	other, _ := e.newWorkspace("other", "team", "active")
	foreign, _ := e.st.UpsertHostOnBundle(other.ID, "cccccccccccccccc", "c", "e", "k", e.clock.Now())
	for _, scope := range []string{"host:" + foreign.ID, "host:nope", "everything", ""} {
		if resp, _ := e.post(c, "/app/share", url.Values{"scope": {scope}, "expires": {"none"}}); resp.StatusCode != 400 {
			t.Errorf("scope %q = %d, want 400", scope, resp.StatusCode)
		}
	}
	if resp, _ := e.post(c, "/app/share", url.Values{"scope": {"fleet"}, "expires": {"forever"}}); resp.StatusCode != 400 {
		t.Errorf("bad expiry = %d", resp.StatusCode)
	}

	// An expired link is a 404 (the store's clock decides; create one already past).
	past := time.Now().Add(-time.Hour)
	_, plain, err := e.st.CreateShareLink(ws.ID, "fleet", &past)
	if err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.get(e.browser(), "/s/"+plain); resp.StatusCode != 404 {
		t.Fatalf("expired link = %d", resp.StatusCode)
	}
	// A link to a host that no longer resolves is also just not found.
	_, plain2, _ := e.st.CreateShareLink(ws.ID, "host:"+foreign.ID, nil)
	if resp, _ := e.get(e.browser(), "/s/"+plain2); resp.StatusCode != 404 {
		t.Fatalf("link to another workspace's host = %d", resp.StatusCode)
	}
}

func TestEmptyShareLink(t *testing.T) {
	e := newEnv(t)
	ws, _ := e.newWorkspace("empty", "team", "active")
	_, plain, _ := e.st.CreateShareLink(ws.ID, "fleet", nil)
	resp, body := e.get(e.browser(), "/s/"+plain)
	if resp.StatusCode != 200 || !strings.Contains(body, "No bundles have been received yet") {
		t.Fatalf("empty share = %d", resp.StatusCode)
	}
	resp, js := e.get(e.browser(), "/s/"+plain+".json")
	if resp.StatusCode != 200 || !strings.Contains(js, `"proofs": []`) {
		t.Fatalf("empty share json = %d %s", resp.StatusCode, js)
	}
}
