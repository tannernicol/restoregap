// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/cloud/store"
	"github.com/tannernicol/restoregap/internal/status"
)

func alertsOf(t *testing.T, e *testEnv, ws store.Workspace) []store.Alert {
	t.Helper()
	a, err := e.st.ListAlerts(ws.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func countKind(alerts []store.Alert, kind string) int {
	n := 0
	for _, a := range alerts {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

func TestIngestHappyPathAndFleetShowsTheProof(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("owner@example.com")
	ws := e.workspaceOf("owner@example.com")
	_, tok, err := e.st.CreateToken(ws.ID, "ci")
	if err != nil {
		t.Fatal(err)
	}
	seed := newSeed(t)

	resp, out := e.push(tok, freshBundle(t, "web-1", "aaaaaaaaaaaaaaaa", seed, "pg-restore"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("push = %d %v", resp.StatusCode, out)
	}
	host, err := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if out["host"] != "web-1" || out["host_id"] != "aaaaaaaaaaaaaaaa" || out["bundle_id"] == "" ||
		out["url"] != e.cfg.BaseURL+"/app/hosts/"+host.ID {
		t.Fatalf("response = %v", out)
	}
	if _, err := time.Parse(time.RFC3339, out["generated_at"]); err != nil {
		t.Fatalf("generated_at = %q", out["generated_at"])
	}
	if host.PublicKeyHex != pubOf(seed) {
		t.Fatalf("pinned key = %q, want the bundle signer's", host.PublicKeyHex)
	}
	b, err := e.st.GetBundle(ws.ID, out["bundle_id"])
	if err != nil || b.Proofs != 1 || b.SignatureHex == "" || len(b.SHA256) != 64 {
		t.Fatalf("stored bundle = %+v, %v", b, err)
	}
	rows, _ := e.st.ProofsForBundle(ws.ID, b.ID)
	if len(rows) != 1 || rows[0].Proof != "pg-restore" || rows[0].State != status.StateObserved || rows[0].Environment != "prod" {
		t.Fatalf("proof rows = %+v", rows)
	}

	// The dashboard shows the proof, links it to its history, and is quiet about alerts.
	resp, body := e.get(c, "/app")
	if resp.StatusCode != 200 {
		t.Fatalf("/app = %d", resp.StatusCode)
	}
	link := `href="/app/hosts/` + host.ID + `/proofs/pg-restore"`
	for _, want := range []string{"pg-restore", "web-1", link, "1 host", "1 bundle", "rgs-taxrow"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard lacks %q", want)
		}
	}
	if strings.Contains(body, "No bundles yet") {
		t.Fatal("dashboard still shows the empty state")
	}

	// The API serves the same merge.
	resp, body = e.do(e.ts.Client(), "GET", "/api/v1/fleet.json", nil, map[string]string{"Authorization": "Bearer " + tok})
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("fleet.json = %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var f status.Fleet
	if err := json.Unmarshal([]byte(body), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Proofs) != 1 || f.Proofs[0].Proof != "pg-restore" || f.Proofs[0].Host != "web-1" || f.Proofs[0].SourceBundle != "web-1" ||
		len(f.Bundles) != 1 || f.Bundles[0].HostID != "aaaaaaaaaaaaaaaa" || len(f.Conflicts) != 0 {
		t.Fatalf("fleet = %+v", f)
	}
}

func TestFleetJSONHasThePublishedShape(t *testing.T) {
	e := newEnv(t)
	_, tok := e.newWorkspace("w", "unlimited", "unlimited")
	get := func() (status.Fleet, map[string]json.RawMessage) {
		resp, body := e.do(e.ts.Client(), "GET", "/api/v1/fleet.json", nil, map[string]string{"Authorization": "Bearer " + tok})
		if resp.StatusCode != 200 {
			t.Fatalf("fleet.json = %d %s", resp.StatusCode, body)
		}
		var f status.Fleet
		if err := json.Unmarshal([]byte(body), &f); err != nil {
			t.Fatal(err)
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal([]byte(body), &raw)
		return f, raw
	}

	// Empty: every key `bundle merge` writes is present, and lists are [] not null.
	_, raw := get()
	for _, k := range []string{"generated_at", "bundles", "proofs", "conflicts"} {
		v, ok := raw[k]
		if !ok || string(v) == "null" {
			t.Fatalf("empty fleet.json: key %q = %s", k, v)
		}
	}

	e.push(tok, freshBundle(t, "a", "aaaaaaaaaaaaaaaa", newSeed(t), "p1"))
	e.push(tok, freshBundle(t, "b", "bbbbbbbbbbbbbbbb", newSeed(t), "p1"))
	f, _ := get()
	if len(f.Bundles) != 2 || len(f.Proofs) != 2 {
		t.Fatalf("two hosts must merge to two bundles and two rows (same proof id, different host): %+v", f)
	}
	hosts := map[string]bool{}
	for _, p := range f.Proofs {
		hosts[p.Host] = true
		if p.Layer == "" || p.State == "" || p.GeneratedAt.IsZero() {
			t.Fatalf("incomplete row %+v", p)
		}
	}
	if !hosts["a"] || !hosts["b"] {
		t.Fatalf("rows by host = %v", hosts)
	}
}

func TestSecondKeyForTheSameHostIsRefused(t *testing.T) {
	e := newEnv(t)
	ws, tok := e.newWorkspace("w", "team", "active")
	seedA, seedB := newSeed(t), newSeed(t)
	if resp, out := e.push(tok, freshBundle(t, "web-1", "aaaaaaaaaaaaaaaa", seedA, "p1")); resp.StatusCode != 201 {
		t.Fatalf("first push = %d %v", resp.StatusCode, out)
	}
	resp, out := e.push(tok, freshBundle(t, "web-1", "aaaaaaaaaaaaaaaa", seedB, "p1"))
	want := "key mismatch: host aaaaaaaaaaaaaaaa is pinned to key " + pubOf(seedA)[:12] + "…; rotate it in the host's settings"
	if resp.StatusCode != http.StatusConflict || out["error"] != want {
		t.Fatalf("second key = %d %v\nwant error %q", resp.StatusCode, out, want)
	}
	if n, _ := e.st.CountBundlesPerHost(ws.ID); len(n) != 1 {
		t.Fatalf("bundles per host = %v", n)
	}
	h, _ := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")
	if h.PublicKeyHex != pubOf(seedA) {
		t.Fatal("the pinned key moved")
	}
}

func TestHostLimitOnSolo(t *testing.T) {
	e := newEnv(t)
	_, tok := e.newWorkspace("w", "solo", "active")
	for i, id := range []string{"1111111111111111", "2222222222222222", "3333333333333333"} {
		if resp, out := e.push(tok, freshBundle(t, fmt.Sprintf("h%d", i), id, newSeed(t), "p1")); resp.StatusCode != 201 {
			t.Fatalf("host %d = %d %v", i, resp.StatusCode, out)
		}
	}
	resp, out := e.push(tok, freshBundle(t, "h4", "4444444444444444", newSeed(t), "p1"))
	if resp.StatusCode != http.StatusConflict || out["error"] != "host limit reached (3 of 3 on plan Solo)" {
		t.Fatalf("fourth host = %d %v", resp.StatusCode, out)
	}
}

func TestKnownHostCanKeepPushingAtTheLimit(t *testing.T) {
	e := newEnv(t)
	ws, tok := e.newWorkspace("w", "solo", "active")
	seed := newSeed(t)
	now := time.Now().UTC()
	ids := []string{"1111111111111111", "2222222222222222", "3333333333333333"}
	for i, id := range ids {
		s := newSeed(t)
		if i == 0 {
			s = seed
		}
		e.push(tok, makeBundle(t, bundleSpec{HostName: "h", HostID: id, Seed: s,
			Proofs: []proofSpec{{ID: "p1", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(48 * time.Hour)}}, GeneratedAt: now.Add(-3 * time.Hour)}))
	}
	resp, out := e.push(tok, makeBundle(t, bundleSpec{HostName: "h", HostID: ids[0], Seed: seed,
		Proofs: []proofSpec{{ID: "p1", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(48 * time.Hour)}}, GeneratedAt: now.Add(-time.Hour)}))
	if resp.StatusCode != 201 {
		t.Fatalf("known host at the limit = %d %v", resp.StatusCode, out)
	}
	if n, _ := e.st.CountHosts(ws.ID); n != 3 {
		t.Fatalf("hosts = %d", n)
	}
}

func TestInactiveWorkspacesCannotPush(t *testing.T) {
	e := newEnv(t)
	ws, tok := e.newWorkspace("w", "team", "trialing")
	archive := freshBundle(t, "web-1", "aaaaaaaaaaaaaaaa", newSeed(t), "p1")

	past := e.clock.Now().Add(-time.Hour)
	if err := e.st.UpdateWorkspaceBilling(ws.ID, "team", "trialing", "", "", &past); err != nil {
		t.Fatal(err)
	}
	resp, out := e.push(tok, archive)
	if resp.StatusCode != http.StatusPaymentRequired || out["error"] != "workspace is not active" {
		t.Fatalf("expired trial = %d %v", resp.StatusCode, out)
	}
	for _, st := range []string{"past_due", "canceled"} {
		if err := e.st.UpdateWorkspaceBilling(ws.ID, "team", st, "", "", nil); err != nil {
			t.Fatal(err)
		}
		if resp, _ := e.push(tok, archive); resp.StatusCode != http.StatusPaymentRequired {
			t.Fatalf("%s = %d", st, resp.StatusCode)
		}
	}
	// A running trial and an active subscription both push.
	future := e.clock.Now().Add(time.Hour)
	if err := e.st.UpdateWorkspaceBilling(ws.ID, "team", "trialing", "", "", &future); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.push(tok, archive); resp.StatusCode != 201 {
		t.Fatalf("running trial = %d", resp.StatusCode)
	}
	// Reading still works for a workspace that cannot push.
	if err := e.st.UpdateWorkspaceBilling(ws.ID, "team", "canceled", "", "", nil); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.do(e.ts.Client(), "GET", "/api/v1/fleet.json", nil, map[string]string{"Authorization": "Bearer " + tok}); resp.StatusCode != 200 {
		t.Fatalf("fleet.json on a canceled workspace = %d", resp.StatusCode)
	}
}

func TestCorruptAndTamperedArchivesAreRefused(t *testing.T) {
	e := newEnv(t)
	ws, tok := e.newWorkspace("w", "team", "active")

	for name, body := range map[string][]byte{
		"not gzip": []byte("this is not a tarball"),
		"empty":    {},
	} {
		resp, out := e.push(tok, body)
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.HasPrefix(out["error"], "bundle failed verification: ") {
			t.Fatalf("%s = %d %v", name, resp.StatusCode, out)
		}
	}

	good := freshBundle(t, "web-1", "aaaaaaaaaaaaaaaa", newSeed(t), "p1")
	members := untar(t, good)
	members["manifest.json"] = append(members["manifest.json"], ' ') // signed bytes changed
	resp, out := e.push(tok, tarball(t, members))
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(out["error"], "signature does not verify") {
		t.Fatalf("tampered manifest = %d %v", resp.StatusCode, out)
	}
	members = untar(t, good)
	for name := range members {
		if strings.HasPrefix(name, "context/") {
			members[name] = []byte("version: 2\n# edited after signing\n")
		}
	}
	resp, out = e.push(tok, tarball(t, members))
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(out["error"], "digest mismatch") {
		t.Fatalf("tampered context = %d %v", resp.StatusCode, out)
	}
	// The tar member name ("context/tmp__…") is the pusher's own path, mangled
	// by the pusher; what must never appear is the SERVER's staging directory.
	// On Linux os.TempDir() is "/tmp", so the check needs the trailing slash
	// or it would match the member name's "context/tmp__" and fail for the
	// wrong reason.
	if strings.Contains(out["error"], "restoregap-bundle-ctx") || strings.Contains(out["error"], filepath.Clean(os.TempDir())+string(filepath.Separator)) {
		t.Fatalf("error leaks a server path: %q", out["error"])
	}
	if n, _ := e.st.CountHosts(ws.ID); n != 0 {
		t.Fatalf("a refused bundle created a host")
	}
}

func TestOversizedBodyIs413(t *testing.T) {
	e := newEnv(t)
	_, tok := e.newWorkspace("w", "team", "active")
	big := bytes.Repeat([]byte{0}, maxBundleBytes+1)
	resp, out := e.push(tok, big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge || out["error"] != "bundle too large" {
		t.Fatalf("oversized = %d %v", resp.StatusCode, out)
	}
	// Exactly at the cap is read, then rejected as not-a-bundle rather than as too large.
	resp, out = e.push(tok, big[:maxBundleBytes])
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("at the cap = %d %v", resp.StatusCode, out)
	}
}

func TestDuplicateArchiveIs200AndChangesNothing(t *testing.T) {
	e := newEnv(t)
	ws, tok := e.newWorkspace("w", "team", "active")
	archive := freshBundle(t, "web-1", "aaaaaaaaaaaaaaaa", newSeed(t), "p1")
	resp, first := e.push(tok, archive)
	if resp.StatusCode != 201 {
		t.Fatalf("first = %d %v", resp.StatusCode, first)
	}
	h, _ := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")

	// A replay must not look like the host being alive, so lapse state is untouched.
	if err := e.st.SetHostExpectedEvery(h.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(5 * time.Hour)
	if err := e.srv.Tick(t.Context(), e.clock.Now()); err != nil {
		t.Fatal(err)
	}
	resp, second := e.push(tok, archive)
	if resp.StatusCode != http.StatusOK || second["bundle_id"] != first["bundle_id"] || second["url"] != first["url"] {
		t.Fatalf("duplicate = %d %v, first %v", resp.StatusCode, second, first)
	}
	if counts, _ := e.st.CountBundlesPerHost(ws.ID); counts[h.ID] != 1 {
		t.Fatalf("bundles = %v", counts)
	}
	h2, _ := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")
	if h2.LapsedAt == nil {
		t.Fatal("a replayed archive cleared the lapse")
	}
	if countKind(alertsOf(t, e, ws), store.AlertRecovered) != 0 {
		t.Fatal("a replayed archive raised a recovery")
	}
}

func TestProofRegressionRaisesAnAlert(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("owner@example.com")
	ws := e.workspaceOf("owner@example.com")
	_, tok, _ := e.st.CreateToken(ws.ID, "ci")
	seed := newSeed(t)
	now := e.clock.Now()
	proof := []proofSpec{{ID: "p1", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour)}}

	// Bundle A: p1 is fresh. Bundle B, generated two days later: the same
	// proof's expiry has passed as of B's own generated_at.
	a := makeBundle(t, bundleSpec{HostName: "web-1", HostID: "aaaaaaaaaaaaaaaa", Seed: seed, Proofs: proof, GeneratedAt: now})
	if resp, out := e.push(tok, a); resp.StatusCode != 201 {
		t.Fatalf("A = %d %v", resp.StatusCode, out)
	}
	if n := len(alertsOf(t, e, ws)); n != 0 {
		t.Fatalf("the first bundle raised %d alerts", n)
	}
	b := makeBundle(t, bundleSpec{HostName: "web-1", HostID: "aaaaaaaaaaaaaaaa", Seed: seed, Proofs: proof, GeneratedAt: now.Add(48 * time.Hour)})
	if resp, out := e.push(tok, b); resp.StatusCode != 201 {
		t.Fatalf("B = %d %v", resp.StatusCode, out)
	}
	alerts := alertsOf(t, e, ws)
	if len(alerts) != 1 || alerts[0].Kind != store.AlertProofRegressed {
		t.Fatalf("alerts = %+v", alerts)
	}
	for _, want := range []string{"p1", "web-1", "from observed to expired"} {
		if !strings.Contains(alerts[0].Message, want) {
			t.Fatalf("alert message %q lacks %q", alerts[0].Message, want)
		}
	}

	// Still expired in C: unhealthy to unhealthy is not a new regression.
	cc := makeBundle(t, bundleSpec{HostName: "web-1", HostID: "aaaaaaaaaaaaaaaa", Seed: seed, Proofs: proof, GeneratedAt: now.Add(72 * time.Hour)})
	e.push(tok, cc)
	if got := countKind(alertsOf(t, e, ws), store.AlertProofRegressed); got != 1 {
		t.Fatalf("regression alerts after a second bad bundle = %d, want 1", got)
	}

	// A late-arriving OLD bundle says nothing about the host's current state.
	old := makeBundle(t, bundleSpec{HostName: "web-1", HostID: "aaaaaaaaaaaaaaaa", Seed: seed,
		Proofs: []proofSpec{{ID: "p1", ObservedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-40 * time.Hour)}}, GeneratedAt: now.Add(-30 * time.Hour)})
	e.push(tok, old)
	if got := len(alertsOf(t, e, ws)); got != 1 {
		t.Fatalf("a late old bundle changed the alerts: %d", got)
	}

	// The history page and alerts page reflect it.
	h, _ := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")
	resp, body := e.get(c, "/app/hosts/"+h.ID+"/proofs/p1")
	if resp.StatusCode != 200 || !strings.Contains(body, "state changed 2 times in 4 bundles") {
		t.Fatalf("history = %d\n%s", resp.StatusCode, body)
	}
	if _, body := e.get(c, "/app/alerts"); !strings.Contains(body, "proof_regressed") || !strings.Contains(body, "from observed to expired") {
		t.Fatal("alerts page lacks the regression")
	}
}

func TestRegressionAlertsAreCapped(t *testing.T) {
	e := newEnv(t)
	ws, tok := e.newWorkspace("w", "team", "active")
	seed := newSeed(t)
	now := e.clock.Now()
	var proofs []proofSpec
	for i := 0; i < maxRegressionAlerts+7; i++ {
		proofs = append(proofs, proofSpec{ID: fmt.Sprintf("p%02d", i), ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour)})
	}
	e.push(tok, makeBundle(t, bundleSpec{HostName: "h", HostID: "aaaaaaaaaaaaaaaa", Seed: seed, Proofs: proofs, GeneratedAt: now}))
	e.push(tok, makeBundle(t, bundleSpec{HostName: "h", HostID: "aaaaaaaaaaaaaaaa", Seed: seed, Proofs: proofs, GeneratedAt: now.Add(48 * time.Hour)}))
	alerts := alertsOf(t, e, ws)
	if len(alerts) != maxRegressionAlerts+1 {
		t.Fatalf("alerts = %d, want %d plus one roll-up", len(alerts), maxRegressionAlerts)
	}
	found := false
	for _, a := range alerts {
		found = found || strings.Contains(a.Message, "7 more proofs")
	}
	if !found {
		t.Fatal("no roll-up alert for the capped remainder")
	}
}

func TestIsRegressionVocabulary(t *testing.T) {
	healthy := []string{status.StateRestored, status.StateObserved, status.StateAccepted}
	unhealthy := []string{status.StateDisputed, status.StateExpired, status.StateUnreachable, status.StateLapsed, status.StateUnreviewed, "something-new", ""}
	for _, from := range healthy {
		for _, to := range unhealthy {
			if !isRegression(from, to) {
				t.Errorf("%s -> %q must regress", from, to)
			}
		}
		for _, to := range healthy {
			if isRegression(from, to) {
				t.Errorf("%s -> %s must not regress", from, to)
			}
		}
	}
	for _, from := range unhealthy {
		for _, to := range append(append([]string{}, healthy...), unhealthy...) {
			if isRegression(from, to) {
				t.Errorf("%q -> %q must not regress", from, to)
			}
		}
	}
}

func TestLapseAlertAndRecovery(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("owner@example.com")
	ws := e.workspaceOf("owner@example.com")
	_, tok, _ := e.st.CreateToken(ws.ID, "ci")
	seed := newSeed(t)
	ctx := t.Context()

	if resp, out := e.push(tok, freshBundle(t, "web-1", "aaaaaaaaaaaaaaaa", seed, "p1")); resp.StatusCode != 201 {
		t.Fatalf("push = %d %v", resp.StatusCode, out)
	}
	h, _ := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")

	// No cadence: silence is not a lapse.
	e.clock.Advance(100 * time.Hour)
	if err := e.srv.Tick(ctx, e.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.st.GetHost(ws.ID, h.ID); got.LapsedAt != nil {
		t.Fatal("a host without a cadence lapsed")
	}

	// Set a one-hour cadence through the form, like an owner would.
	resp, _ := e.post(c, "/app/hosts/"+h.ID, url.Values{"name": {"web-1"}, "cadence": {"1h"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("set cadence = %d", resp.StatusCode)
	}
	if got, _ := e.st.GetHost(ws.ID, h.ID); got.ExpectedEvery != time.Hour {
		t.Fatalf("cadence = %v", got.ExpectedEvery)
	}

	// 1.5x the interval has not passed: no alert. Two hours have: lapsed.
	if err := e.srv.Tick(ctx, e.clock.Now().Add(-100*time.Hour+80*time.Minute)); err != nil { // 1h20m after the last bundle
		t.Fatal(err)
	}
	if got := countKind(alertsOf(t, e, ws), store.AlertLapsed); got != 0 {
		t.Fatalf("lapsed after 1h20m of a 1h cadence: %d alerts", got)
	}
	if err := e.srv.Tick(ctx, e.clock.Now()); err != nil {
		t.Fatal(err)
	}
	alerts := alertsOf(t, e, ws)
	if len(alerts) != 1 || alerts[0].Kind != store.AlertLapsed || !strings.Contains(alerts[0].Message, "web-1 last sent a bundle at") ||
		!strings.Contains(alerts[0].Message, "expected every 1h0m0s") {
		t.Fatalf("alerts = %+v", alerts)
	}
	if got, _ := e.st.GetHost(ws.ID, h.ID); got.LapsedAt == nil {
		t.Fatal("host not marked lapsed")
	}
	// Ticking again must not re-alert a host that is already lapsed.
	e.clock.Advance(time.Hour)
	if err := e.srv.Tick(ctx, e.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if got := countKind(alertsOf(t, e, ws), store.AlertLapsed); got != 1 {
		t.Fatalf("lapsed alerts = %d, want 1", got)
	}
	// The dashboard and hosts list show it.
	if _, body := e.get(c, "/app"); !strings.Contains(body, "stopped sending") {
		t.Fatal("dashboard does not call out the silent host")
	}
	if _, body := e.get(c, "/app/hosts"); !strings.Contains(body, `data-kind="lapsed"`) {
		t.Fatal("hosts list does not show the lapsed badge")
	}

	// The next bundle records recovery and clears the lapse.
	next := makeBundle(t, bundleSpec{HostName: "web-1", HostID: "aaaaaaaaaaaaaaaa", Seed: seed,
		Proofs:      []proofSpec{{ID: "p1", ObservedAt: e.clock.Now().Add(-time.Hour), ExpiresAt: e.clock.Now().Add(48 * time.Hour)}},
		GeneratedAt: e.clock.Now()})
	if resp, out := e.push(tok, next); resp.StatusCode != 201 {
		t.Fatalf("recovery push = %d %v", resp.StatusCode, out)
	}
	alerts = alertsOf(t, e, ws)
	if countKind(alerts, store.AlertRecovered) != 1 || countKind(alerts, store.AlertLapsed) != 1 {
		t.Fatalf("alerts = %+v", alerts)
	}
	if got, _ := e.st.GetHost(ws.ID, h.ID); got.LapsedAt != nil {
		t.Fatal("lapse not cleared")
	}
}

func TestHostNamesAreEscapedEverywhere(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("owner@example.com")
	ws := e.workspaceOf("owner@example.com")
	_, tok, _ := e.st.CreateToken(ws.ID, "ci")
	evil := `<img src=x onerror=alert(1)>"'`
	e.push(tok, freshBundle(t, evil, "aaaaaaaaaaaaaaaa", newSeed(t), "p1"))
	h, _ := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")
	for _, path := range []string{"/app", "/app/hosts", "/app/hosts/" + h.ID, "/app/settings"} {
		resp, body := e.get(c, path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s = %d", path, resp.StatusCode)
		}
		if strings.Contains(body, "<img src=x") {
			t.Fatalf("%s renders a host name unescaped", path)
		}
		if n := strings.Count(body, "<script"); n != 2 {
			t.Fatalf("%s has %d script tags, want 2", path, n)
		}
	}
}
