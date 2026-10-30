// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/cloud/store"
)

// receiver is a webhook endpoint that records deliveries and can be told to fail.
type receiver struct {
	srv  *httptest.Server
	mu   sync.Mutex
	fail bool
	got  []delivery
}

type delivery struct {
	body []byte
	sig  string
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		defer r.mu.Unlock()
		r.got = append(r.got, delivery{body: b, sig: req.Header.Get("X-RestoreGap-Signature")})
		if r.fail {
			http.Error(w, "down", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func (r *receiver) setFail(f bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fail = f
}

// alertFixture makes a workspace with a webhook destination and one alert.
func alertFixture(t *testing.T, e *testEnv, name, hookURL, secret string) (store.Workspace, store.Alert) {
	t.Helper()
	ws, _ := e.newWorkspace(name, "team", "active")
	if err := e.st.UpdateWorkspaceNotify(ws.ID, "", hookURL, secret); err != nil {
		t.Fatal(err)
	}
	h, err := e.st.UpsertHostOnBundle(ws.ID, "aaaaaaaaaaaaaaaa", "web-1", "e", "key", e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, err := e.st.CreateAlert(ws.ID, h.ID, store.AlertLapsed, "host web-1 went quiet")
	if err != nil {
		t.Fatal(err)
	}
	return ws, a
}

func alertByID(t *testing.T, e *testEnv, ws store.Workspace, id string) store.Alert {
	t.Helper()
	for _, a := range alertsOf(t, e, ws) {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("alert %s not found", id)
	return store.Alert{}
}

func TestDeliveryToASignedWebhook(t *testing.T) {
	e := newEnv(t)
	rcv := newReceiver(t)
	ws, a := alertFixture(t, e, "w", rcv.srv.URL+"/hook", "s3cret-s3cret-s3cret")

	if err := e.srv.Tick(t.Context(), e.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if rcv.count() != 1 {
		t.Fatalf("deliveries = %d", rcv.count())
	}
	d := rcv.got[0]
	mac := hmac.New(sha256.New, []byte("s3cret-s3cret-s3cret"))
	mac.Write(d.body)
	if d.sig != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("signature %q does not match the body", d.sig)
	}
	var env struct {
		Kind, Subject, Text string
		Payload             map[string]string
	}
	if err := json.Unmarshal(d.body, &env); err != nil {
		t.Fatal(err)
	}
	h, _ := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")
	if env.Kind != "lapsed" || !strings.Contains(env.Subject, "web-1") || !strings.Contains(env.Text, "went quiet") ||
		env.Payload["url"] != e.cfg.BaseURL+"/app/hosts/"+h.ID || env.Payload["alert_id"] != a.ID {
		t.Fatalf("payload = %+v", env)
	}
	if got := alertByID(t, e, ws, a.ID); got.DeliveredAt == nil || got.DeliveryError != "" {
		t.Fatalf("alert = %+v", got)
	}
	// Delivered alerts are not sent again.
	if err := e.srv.Tick(t.Context(), e.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if rcv.count() != 1 {
		t.Fatalf("re-delivered: %d", rcv.count())
	}
}

func TestFailedDeliveryRetriesThenGivesUpAfter24Hours(t *testing.T) {
	e := newEnv(t)
	rcv := newReceiver(t)
	rcv.setFail(true)
	ws, a := alertFixture(t, e, "w", rcv.srv.URL, "")

	for i := 0; i < 3; i++ {
		if err := e.srv.Tick(t.Context(), e.clock.Now()); err != nil {
			t.Fatal(err)
		}
		if got := alertByID(t, e, ws, a.ID); got.DeliveredAt != nil {
			t.Fatalf("tick %d: a failing alert left the queue", i)
		}
		e.clock.Advance(time.Hour)
	}
	if rcv.count() != 3 {
		t.Fatalf("attempts = %d, want one per tick", rcv.count())
	}
	// Recovered endpoint: the next tick delivers the same alert.
	rcv.setFail(false)
	if err := e.srv.Tick(t.Context(), e.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if got := alertByID(t, e, ws, a.ID); got.DeliveredAt == nil || got.DeliveryError != "" {
		t.Fatalf("after recovery: %+v", got)
	}

	// An alert still failing past 24 hours is marked processed with the error.
	rcv.setFail(true)
	ws2, a2 := alertFixture(t, e, "w2", rcv.srv.URL+"/two", "")
	e.clock.Advance(25 * time.Hour)
	if err := e.srv.Tick(t.Context(), e.clock.Now()); err != nil {
		t.Fatal(err)
	}
	got := alertByID(t, e, ws2, a2.ID)
	if got.DeliveredAt == nil || !strings.Contains(got.DeliveryError, "gave up after 24h") || !strings.Contains(got.DeliveryError, "HTTP 500") {
		t.Fatalf("after 25h: %+v", got)
	}
}

func TestOneWorkspacesBrokenWebhookDoesNotBlockAnother(t *testing.T) {
	e := newEnv(t)
	bad, good := newReceiver(t), newReceiver(t)
	bad.setFail(true)
	wsBad, aBad := alertFixture(t, e, "bad", bad.srv.URL, "")
	// More failing alerts queued ahead of the good one must not starve it.
	for i := 0; i < 3; i++ {
		h, _ := e.st.GetHostByHostID(wsBad.ID, "aaaaaaaaaaaaaaaa")
		if _, err := e.st.CreateAlert(wsBad.ID, h.ID, store.AlertRecovered, "more"); err != nil {
			t.Fatal(err)
		}
	}
	wsGood, aGood := alertFixture(t, e, "good", good.srv.URL, "")

	if err := e.srv.Tick(t.Context(), e.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if got := alertByID(t, e, wsGood, aGood.ID); got.DeliveredAt == nil {
		t.Fatal("the healthy workspace's alert was not delivered")
	}
	if got := alertByID(t, e, wsBad, aBad.ID); got.DeliveredAt != nil {
		t.Fatal("the failing alert was marked delivered")
	}
	// After the first failure the rest of that workspace's queue waits for the
	// next tick instead of each one timing out against a dead endpoint.
	if bad.count() != 1 {
		t.Fatalf("attempts against the failing endpoint = %d, want 1 per tick", bad.count())
	}
}

func TestAlertsGoToTheLogWhenNothingIsConfigured(t *testing.T) {
	e := newEnv(t)
	ws, a := alertFixture(t, e, "w", "", "")
	if err := e.srv.Tick(t.Context(), e.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if got := alertByID(t, e, ws, a.ID); got.DeliveredAt == nil {
		t.Fatal("alert not processed")
	}
	if !strings.Contains(e.logs.String(), "alert notification") || !strings.Contains(e.logs.String(), "host web-1 went quiet") {
		t.Fatalf("log does not carry the alert:\n%s", e.logs.String())
	}
}

func TestRetentionPrunesOldBundlesButKeepsEachHostsNewest(t *testing.T) {
	e := newEnv(t)
	ws, tok := e.newWorkspace("w", "solo", "active") // 90 days
	now := e.clock.Now()
	seedA, seedB := newSeed(t), newSeed(t)
	proof := []proofSpec{{ID: "p1", ObservedAt: now.Add(-300 * 24 * time.Hour), ExpiresAt: now.Add(10 * 24 * time.Hour)}}
	push := func(name, id, seed string, age time.Duration) {
		t.Helper()
		resp, out := e.push(tok, makeBundle(t, bundleSpec{HostName: name, HostID: id, Seed: seed, Proofs: proof, GeneratedAt: now.Add(-age)}))
		if resp.StatusCode != 201 {
			t.Fatalf("push %s -%v = %d %v", name, age, resp.StatusCode, out)
		}
	}
	day := 24 * time.Hour
	push("busy", "aaaaaaaaaaaaaaaa", seedA, 200*day)
	push("busy", "aaaaaaaaaaaaaaaa", seedA, 100*day)
	push("busy", "aaaaaaaaaaaaaaaa", seedA, 10*day)
	push("busy", "aaaaaaaaaaaaaaaa", seedA, time.Hour)
	push("quiet", "bbbbbbbbbbbbbbbb", seedB, 200*day) // its only bundle is older than retention

	if err := e.srv.Tick(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	counts, _ := e.st.CountBundlesPerHost(ws.ID)
	busy, _ := e.st.GetHostByHostID(ws.ID, "aaaaaaaaaaaaaaaa")
	quiet, _ := e.st.GetHostByHostID(ws.ID, "bbbbbbbbbbbbbbbb")
	if counts[busy.ID] != 2 || counts[quiet.ID] != 1 {
		t.Fatalf("bundles after retention = %v (busy %s, quiet %s)", counts, busy.ID, quiet.ID)
	}
	left, _ := e.st.ListBundles(ws.ID, busy.ID, 0)
	if !left[0].GeneratedAt.After(now.Add(-2*time.Hour)) || !left[1].GeneratedAt.After(now.Add(-11*day)) {
		t.Fatalf("kept the wrong bundles: %v %v", left[0].GeneratedAt, left[1].GeneratedAt)
	}
	// The pruned bundles' archives are gone from disk, and the quiet host's newest still reads.
	if _, err := e.st.ReadBundle(ws.ID, left[0].ID); err != nil {
		t.Fatal(err)
	}
	qb, _ := e.st.ListBundles(ws.ID, quiet.ID, 0)
	if _, err := e.st.ReadBundle(ws.ID, qb[0].ID); err != nil {
		t.Fatalf("the quiet host lost its only bundle: %v", err)
	}

	// Unlimited retention (0 days) deletes nothing.
	un, utok := e.newWorkspace("u", "unlimited", "unlimited")
	e.push(utok, makeBundle(t, bundleSpec{HostName: "h", HostID: "cccccccccccccccc", Seed: seedA, Proofs: proof, GeneratedAt: now.Add(-900 * day)}))
	e.push(utok, makeBundle(t, bundleSpec{HostName: "h", HostID: "cccccccccccccccc", Seed: seedA, Proofs: proof, GeneratedAt: now.Add(-800 * day)}))
	if err := e.srv.Tick(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.st.CountBundlesPerHost(un.ID); c[firstKey(c)] != 2 {
		t.Fatalf("unlimited workspace was pruned: %v", c)
	}
}

func firstKey(m map[string]int) string {
	for k := range m {
		return k
	}
	return ""
}

func TestRunMonitorTicksAndStops(t *testing.T) {
	e := newEnv(t)
	ws, a := alertFixture(t, e, "w", "", "")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { e.srv.RunMonitor(ctx, 10*time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for alertByID(t, e, ws, a.ID).DeliveredAt == nil {
		if time.Now().After(deadline) {
			t.Fatal("RunMonitor never delivered the alert")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunMonitor did not stop when its context was cancelled")
	}
}

func TestWebhookClientRefusesLinkLocalAddresses(t *testing.T) {
	// 169.254.169.254 is the cloud metadata service; the check runs before any
	// packet is sent, so this needs no network.
	_, err := webhookClient().Get("http://169.254.169.254/latest/meta-data/")
	if err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("err = %v, want a link-local refusal", err)
	}
	// Loopback stays reachable: self-hosters point alerts at services on their own box.
	rcv := newReceiver(t)
	resp, err := webhookClient().Get(rcv.srv.URL)
	if err != nil {
		t.Fatalf("loopback webhook refused: %v", err)
	}
	_ = resp.Body.Close()
}
