// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/cloud/store"
)

const (
	testStripeSecret  = "sk_test_secret"
	testWebhookSecret = "whsec_test"
)

// stripeStub stands in for api.stripe.com: it records what the server asks
// for and answers with a subscription the test controls.
type stripeStub struct {
	srv *httptest.Server
	mu  sync.Mutex
	// What the stub returns for GET /v1/subscriptions/{id}.
	subStatus, subPrice string
	subCustomer         string
	failReads           bool // answer subscription reads with 500
	// What it saw.
	checkouts []url.Values
	portals   []url.Values
	subReads  []string
	auth      []string
}

func newStripeStub(t *testing.T) *stripeStub {
	t.Helper()
	s := &stripeStub{subStatus: "active", subPrice: "price_fleet", subCustomer: "cus_1"}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = r.ParseForm()
		user, _, _ := r.BasicAuth()
		s.auth = append(s.auth, user)
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/checkout/sessions":
			s.checkouts = append(s.checkouts, r.PostForm)
			fmt.Fprintf(w, `{"id":"cs_1","url":"%s/pay"}`, s.srv.URL)
		case r.Method == "POST" && r.URL.Path == "/v1/billing_portal/sessions":
			s.portals = append(s.portals, r.PostForm)
			fmt.Fprintf(w, `{"url":"%s/portal"}`, s.srv.URL)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/subscriptions/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/subscriptions/")
			s.subReads = append(s.subReads, id)
			if s.failReads {
				http.Error(w, `{"error":{"message":"boom"}}`, http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, `{"id":%q,"customer":%q,"status":%q,"current_period_end":%d,"cancel_at_period_end":false,"items":{"data":[{"price":{"id":%q}}]}}`,
				id, s.subCustomer, s.subStatus, time.Now().Add(30*24*time.Hour).Unix(), s.subPrice)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stripeStub) configure(c *Config) {
	c.StripeSecret, c.StripeWebhookSecret, c.StripeBaseURL = testStripeSecret, testWebhookSecret, s.srv.URL
}

func (s *stripeStub) reads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.subReads)
}

func signedWebhook(payload, secret string, ts time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.%s", ts.Unix(), payload)
	return fmt.Sprintf("t=%d,v1=%s", ts.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

func (e *testEnv) webhook(payload, sig string) *http.Response {
	e.t.Helper()
	resp, _ := e.do(e.ts.Client(), "POST", "/webhooks/stripe", strings.NewReader(payload), map[string]string{"Stripe-Signature": sig})
	return resp
}

func (e *testEnv) goodWebhook(payload string) *http.Response {
	return e.webhook(payload, signedWebhook(payload, testWebhookSecret, e.clock.Now()))
}

func checkoutEvent(id, wsID string) string {
	return fmt.Sprintf(`{"id":%q,"type":"checkout.session.completed","created":%d,"data":{"object":{"id":"cs_1","client_reference_id":%q,"customer":"cus_1","subscription":"sub_1"}}}`,
		id, time.Now().Unix(), wsID)
}

func subEvent(id, typ, subID, customer, statusText, price string) string {
	return fmt.Sprintf(`{"id":%q,"type":%q,"created":%d,"data":{"object":{"id":%q,"customer":%q,"status":%q,"items":{"data":[{"price":{"id":%q}}]}}}}`,
		id, typ, time.Now().Unix(), subID, customer, statusText, price)
}

func TestBillingRoutesDoNotExistWithoutStripe(t *testing.T) {
	e := newEnv(t)
	c := e.loginViaLink("a@example.com")
	if resp, _ := e.get(c, "/app/billing"); resp.StatusCode != 404 {
		t.Fatalf("/app/billing = %d", resp.StatusCode)
	}
	if resp := e.webhook("{}", "t=1,v1=00"); resp.StatusCode != 404 {
		t.Fatalf("webhook = %d", resp.StatusCode)
	}
	if _, body := e.get(c, "/app"); strings.Contains(body, "/app/billing") {
		t.Fatal("billing link shown with billing off")
	}
}

func TestStripeWebhookSignatureAndLifecycle(t *testing.T) {
	stripe := newStripeStub(t)
	e := newEnv(t, stripe.configure)
	ws, tok := e.newWorkspace("w", "team", "trialing")
	future := e.clock.Now().Add(24 * time.Hour)
	if err := e.st.UpdateWorkspaceBilling(ws.ID, "team", "trialing", "", "", &future); err != nil {
		t.Fatal(err)
	}
	payload := checkoutEvent("evt_1", ws.ID)

	// Bad signatures: wrong secret, missing header, stale timestamp, tampered body.
	for name, sig := range map[string]string{
		"wrong secret": signedWebhook(payload, "whsec_other", e.clock.Now()),
		"missing":      "",
		"stale":        signedWebhook(payload, testWebhookSecret, e.clock.Now().Add(-10*time.Minute)),
		"tampered":     signedWebhook(payload+" ", testWebhookSecret, e.clock.Now()),
	} {
		if resp := e.webhook(payload, sig); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", name, resp.StatusCode)
		}
	}
	if got, _ := e.st.GetWorkspace(ws.ID); got.StripeCustomerID != "" || got.BillingStatus != "trialing" {
		t.Fatalf("a refused webhook changed the workspace: %+v", got)
	}
	if stripe.reads() != 0 {
		t.Fatal("a refused webhook caused a Stripe call")
	}

	// checkout.session.completed links the customer and sets plan and status from Stripe.
	if resp := e.goodWebhook(payload); resp.StatusCode != 200 {
		t.Fatalf("checkout.session.completed = %d", resp.StatusCode)
	}
	got, _ := e.st.GetWorkspace(ws.ID)
	if got.Plan != "fleet" || got.BillingStatus != "active" || got.StripeCustomerID != "cus_1" || got.StripeSubscriptionID != "sub_1" || got.TrialEndsAt != nil {
		t.Fatalf("workspace after checkout = %+v", got)
	}
	if stripe.reads() != 1 || stripe.auth[0] != testStripeSecret {
		t.Fatalf("subscription reads = %d, auth %v", stripe.reads(), stripe.auth)
	}

	// A replay (Stripe redelivering) is a 200 no-op: no second Stripe call, no change.
	if err := e.st.UpdateWorkspaceBilling(ws.ID, "solo", "active", "cus_1", "sub_1", nil); err != nil {
		t.Fatal(err)
	}
	if resp := e.goodWebhook(payload); resp.StatusCode != 200 {
		t.Fatalf("replay = %d", resp.StatusCode)
	}
	if stripe.reads() != 1 {
		t.Fatalf("replay re-read the subscription (%d reads)", stripe.reads())
	}
	if got, _ := e.st.GetWorkspace(ws.ID); got.Plan != "solo" {
		t.Fatalf("replay re-applied the event: plan %s", got.Plan)
	}

	// Subscription updates are matched by customer: past_due blocks pushing.
	e.goodWebhook(subEvent("evt_2", "customer.subscription.updated", "sub_1", "cus_1", "past_due", "price_team"))
	got, _ = e.st.GetWorkspace(ws.ID)
	if got.Plan != "team" || got.BillingStatus != "past_due" {
		t.Fatalf("after past_due = %+v", got)
	}
	if resp, out := e.push(tok, freshBundle(t, "h", "aaaaaaaaaaaaaaaa", newSeed(t), "p")); resp.StatusCode != 402 {
		t.Fatalf("push while past_due = %d %v", resp.StatusCode, out)
	}
	// Back to trialing carries Stripe's trial end.
	e.goodWebhook(subEvent("evt_3", "customer.subscription.updated", "sub_1", "cus_1", "active", "price_solo"))
	if got, _ = e.st.GetWorkspace(ws.ID); got.Plan != "solo" || got.BillingStatus != "active" {
		t.Fatalf("after active = %+v", got)
	}

	// An event about a subscription the workspace no longer has is ignored.
	e.goodWebhook(subEvent("evt_4", "customer.subscription.deleted", "sub_OLD", "cus_1", "canceled", "price_team"))
	if got, _ = e.st.GetWorkspace(ws.ID); got.BillingStatus != "active" {
		t.Fatalf("a stale subscription's deletion canceled the live one: %+v", got)
	}
	// The real one's deletion cancels, and keeps the ids (no second free trial).
	e.goodWebhook(subEvent("evt_5", "customer.subscription.deleted", "sub_1", "cus_1", "canceled", "price_solo"))
	got, _ = e.st.GetWorkspace(ws.ID)
	if got.BillingStatus != "canceled" || got.StripeSubscriptionID != "sub_1" || got.StripeCustomerID != "cus_1" {
		t.Fatalf("after deletion = %+v", got)
	}

	// Unknown events and unknown customers are acknowledged, not retried.
	if resp := e.goodWebhook(`{"id":"evt_6","type":"invoice.paid","created":1,"data":{"object":{}}}`); resp.StatusCode != 200 {
		t.Fatalf("unrelated event = %d", resp.StatusCode)
	}
	if resp := e.goodWebhook(subEvent("evt_7", "customer.subscription.updated", "sub_9", "cus_unknown", "active", "price_team")); resp.StatusCode != 200 {
		t.Fatalf("unlinked customer = %d", resp.StatusCode)
	}
	if resp := e.goodWebhook(checkoutEvent("evt_8", "no-such-workspace")); resp.StatusCode != 200 {
		t.Fatalf("checkout for an unknown workspace = %d", resp.StatusCode)
	}
}

func TestWebhookIsRetriedWhenStripeIsDown(t *testing.T) {
	stripe := newStripeStub(t)
	e := newEnv(t, stripe.configure)
	ws, _ := e.newWorkspace("w", "team", "trialing")
	payload := checkoutEvent("evt_1", ws.ID)

	stripe.mu.Lock()
	stripe.failReads = true
	stripe.mu.Unlock()
	if resp := e.goodWebhook(payload); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("with Stripe failing = %d, want 500 so Stripe retries", resp.StatusCode)
	}
	if got, _ := e.st.GetWorkspace(ws.ID); got.StripeCustomerID != "" {
		t.Fatalf("a failed event half-applied: %+v", got)
	}

	// The failure was not remembered as handled: the redelivery goes through.
	stripe.mu.Lock()
	stripe.failReads = false
	stripe.mu.Unlock()
	if resp := e.goodWebhook(payload); resp.StatusCode != 200 {
		t.Fatalf("redelivery = %d", resp.StatusCode)
	}
	if got, _ := e.st.GetWorkspace(ws.ID); got.StripeSubscriptionID != "sub_1" || got.BillingStatus != "active" {
		t.Fatalf("redelivered event not applied: %+v", got)
	}
}

func TestBillingPageAndCheckout(t *testing.T) {
	stripe := newStripeStub(t)
	e := newEnv(t, stripe.configure, func(c *Config) {
		for i := range c.Plans {
			if c.Plans[i].Key == "fleet" {
				c.Plans[i].PriceID = "" // not configured on this instance
			}
		}
	})
	c := e.loginViaLink("buyer@example.com")
	ws := e.workspaceOf("buyer@example.com")

	resp, body := e.get(c, "/app/billing")
	if resp.StatusCode != 200 {
		t.Fatalf("/app/billing = %d", resp.StatusCode)
	}
	for _, want := range []string{"Solo", "Team", "Fleet", "$19", "$79", "$249", "Current plan", "Unavailable", "Switch", "trialing"} {
		if !strings.Contains(body, want) {
			t.Errorf("billing page lacks %q", want)
		}
	}
	if strings.Contains(body, "Manage billing") {
		t.Error("portal button shown before there is a Stripe customer")
	}
	if _, dash := e.get(c, "/app"); !strings.Contains(dash, "14 days left in your trial") {
		t.Errorf("dashboard lacks the trial banner")
	}

	// Checkout: 303 to the Stripe page; first subscription carries the trial.
	resp, _ = e.post(c, "/app/billing/checkout", url.Values{"plan": {"solo"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != stripe.srv.URL+"/pay" {
		t.Fatalf("checkout = %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	f := stripe.checkouts[0]
	for k, want := range map[string]string{
		"client_reference_id": ws.ID, "line_items[0][price]": "price_solo", "customer_email": "buyer@example.com",
		"success_url": e.cfg.BaseURL + "/app/billing?ok=1", "cancel_url": e.cfg.BaseURL + "/app/billing",
		"subscription_data[trial_period_days]": "14", "mode": "subscription",
	} {
		if f.Get(k) != want {
			t.Errorf("checkout %s = %q, want %q", k, f.Get(k), want)
		}
	}
	// Unavailable and unknown plans are refused.
	for _, plan := range []string{"fleet", "gold", ""} {
		if resp, _ := e.post(c, "/app/billing/checkout", url.Values{"plan": {plan}}); resp.StatusCode != 400 {
			t.Errorf("checkout plan %q = %d, want 400", plan, resp.StatusCode)
		}
	}
	// No customer yet: the portal is not available.
	if resp, _ := e.post(c, "/app/billing/portal", nil); resp.StatusCode != 400 {
		t.Fatalf("portal without a customer = %d", resp.StatusCode)
	}

	// Once subscribed, a "switch" goes to the portal (a second Checkout would
	// bill twice), and a returning customer gets no second trial.
	e.goodWebhook(checkoutEvent("evt_1", ws.ID))
	if got, _ := e.st.GetWorkspace(ws.ID); got.StripeSubscriptionID != "sub_1" {
		t.Fatalf("subscription not linked: %+v", got)
	}
	resp, _ = e.post(c, "/app/billing/checkout", url.Values{"plan": {"team"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != stripe.srv.URL+"/portal" || len(stripe.checkouts) != 1 {
		t.Fatalf("plan change while subscribed = %d -> %q (checkouts %d)", resp.StatusCode, resp.Header.Get("Location"), len(stripe.checkouts))
	}
	resp, _ = e.post(c, "/app/billing/portal", nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != stripe.srv.URL+"/portal" {
		t.Fatalf("portal = %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if got := stripe.portals[len(stripe.portals)-1]; got.Get("customer") != "cus_1" || got.Get("return_url") != e.cfg.BaseURL+"/app/billing" {
		t.Fatalf("portal request = %v", got)
	}
	_, body = e.get(c, "/app/billing")
	for _, want := range []string{"Manage billing", "Renews", "Fleet"} {
		if !strings.Contains(body, want) {
			t.Errorf("subscribed billing page lacks %q", want)
		}
	}

	// A canceled workspace that subscribes again gets no second free trial.
	e.goodWebhook(subEvent("evt_2", "customer.subscription.deleted", "sub_1", "cus_1", "canceled", "price_solo"))
	if resp, _ := e.post(c, "/app/billing/checkout", url.Values{"plan": {"solo"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("re-subscribe = %d", resp.StatusCode)
	}
	if v := stripe.checkouts[len(stripe.checkouts)-1]; v.Get("subscription_data[trial_period_days]") != "" || v.Get("customer") != "cus_1" {
		t.Fatalf("returning customer checkout = %v", v)
	}
	if _, dash := e.get(c, "/app"); !strings.Contains(dash, "read-only") {
		t.Fatal("dashboard lacks the read-only notice for a canceled workspace")
	}
}

func TestBillingBannerWording(t *testing.T) {
	stripe := newStripeStub(t)
	e := newEnv(t, stripe.configure)
	now := e.clock.Now()
	soon, past := now.Add(30*time.Hour), now.Add(-time.Hour)
	for _, tc := range []struct {
		status string
		trial  *time.Time
		want   string
	}{
		{"trialing", &soon, "2 days left in your trial"},
		{"trialing", &past, "Your trial has ended"},
		{"past_due", nil, "PAYMENT PAST DUE"},
		{"canceled", nil, "CANCELED"},
		{"active", nil, ""},
	} {
		ws := store.Workspace{BillingStatus: tc.status, TrialEndsAt: tc.trial}
		b := e.srv.billingBanner(ws)
		if tc.want == "" {
			if b != nil {
				t.Errorf("%s: unexpected banner %+v", tc.status, b)
			}
			continue
		}
		if b == nil || !strings.Contains(b.Title+" "+b.Text, tc.want) {
			t.Errorf("%s: banner %+v lacks %q", tc.status, b, tc.want)
		}
	}
}
