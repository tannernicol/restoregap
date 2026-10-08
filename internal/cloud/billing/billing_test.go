// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testKey = "sk_test_SECRET123"

type captured struct {
	method, path, auth, version, ctype string
	form                               url.Values
}

func stripeServer(t *testing.T, status int, body string) (*Client, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.method, got.path = r.Method, r.URL.Path
		got.auth = r.Header.Get("Authorization")
		got.version = r.Header.Get("Stripe-Version")
		got.ctype = r.Header.Get("Content-Type")
		got.form, _ = url.ParseQuery(string(b))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return &Client{SecretKey: testKey, BaseURL: srv.URL}, got
}

func wantAuth(t *testing.T, got *captured) {
	t.Helper()
	// Basic auth: key as username, empty password.
	want := "Basic " + "c2tfdGVzdF9TRUNSRVQxMjM6" // base64("sk_test_SECRET123:")
	if got.auth != want {
		t.Errorf("Authorization = %q, want %q", got.auth, want)
	}
	if got.version != "2024-06-20" {
		t.Errorf("Stripe-Version = %q", got.version)
	}
}

func TestCreateCheckoutSessionNewCustomer(t *testing.T) {
	c, got := stripeServer(t, 200, `{"id":"cs_test_a1","object":"checkout.session","url":"https://checkout.stripe.com/c/pay/cs_test_a1","mode":"subscription"}`)
	id, u, err := c.CreateCheckoutSession(context.Background(), CheckoutParams{
		WorkspaceID: "ws_1", CustomerEmail: "a@example.com", PriceID: "price_team",
		SuccessURL: "https://c.example/ok?x=1&y=2", CancelURL: "https://c.example/no", TrialDays: 14,
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != "cs_test_a1" || u != "https://checkout.stripe.com/c/pay/cs_test_a1" {
		t.Errorf("id=%q url=%q", id, u)
	}
	if got.method != "POST" || got.path != "/v1/checkout/sessions" {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	if got.ctype != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", got.ctype)
	}
	wantAuth(t, got)
	want := url.Values{
		"mode":                                 {"subscription"},
		"line_items[0][price]":                 {"price_team"},
		"line_items[0][quantity]":              {"1"},
		"client_reference_id":                  {"ws_1"},
		"success_url":                          {"https://c.example/ok?x=1&y=2"},
		"cancel_url":                           {"https://c.example/no"},
		"customer_email":                       {"a@example.com"},
		"subscription_data[trial_period_days]": {"14"},
		"allow_promotion_codes":                {"true"},
	}
	if !reflect.DeepEqual(got.form, want) {
		t.Errorf("form = %v\nwant %v", got.form, want)
	}
}

func TestCreateCheckoutSessionExistingCustomerNoTrial(t *testing.T) {
	c, got := stripeServer(t, 200, `{"id":"cs_2","url":"https://checkout.stripe.com/c/2"}`)
	_, _, err := c.CreateCheckoutSession(context.Background(), CheckoutParams{
		WorkspaceID: "ws_1", CustomerID: "cus_9", CustomerEmail: "ignored@example.com", PriceID: "price_solo",
		SuccessURL: "s", CancelURL: "c",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.form.Get("customer") != "cus_9" {
		t.Errorf("customer = %q", got.form.Get("customer"))
	}
	for _, k := range []string{"customer_email", "subscription_data[trial_period_days]"} {
		if _, ok := got.form[k]; ok {
			t.Errorf("%s must be absent", k)
		}
	}
}

func TestCreatePortalSession(t *testing.T) {
	c, got := stripeServer(t, 200, `{"id":"bps_1","object":"billing_portal.session","url":"https://billing.stripe.com/p/session/abc"}`)
	u, err := c.CreatePortalSession(context.Background(), "cus_9", "https://c.example/billing")
	if err != nil {
		t.Fatal(err)
	}
	if u != "https://billing.stripe.com/p/session/abc" {
		t.Errorf("url = %q", u)
	}
	if got.method != "POST" || got.path != "/v1/billing_portal/sessions" {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	wantAuth(t, got)
	want := url.Values{"customer": {"cus_9"}, "return_url": {"https://c.example/billing"}}
	if !reflect.DeepEqual(got.form, want) {
		t.Errorf("form = %v", got.form)
	}
}

const subFixture = `{
  "id": "sub_123", "object": "subscription", "customer": "cus_9", "status": "trialing",
  "current_period_end": 1790000000, "cancel_at_period_end": true, "trial_end": 1789000000,
  "items": {"object": "list", "data": [{"id": "si_1", "price": {"id": "price_team", "object": "price"}}]}
}`

func TestGetSubscription(t *testing.T) {
	c, got := stripeServer(t, 200, subFixture)
	s, err := c.GetSubscription(context.Background(), "sub_123")
	if err != nil {
		t.Fatal(err)
	}
	if got.method != "GET" || got.path != "/v1/subscriptions/sub_123" {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	if got.ctype != "" {
		t.Errorf("GET must not set a form content-type, got %q", got.ctype)
	}
	wantAuth(t, got)
	if s.ID != "sub_123" || s.CustomerID != "cus_9" || s.Status != "trialing" || s.PriceID != "price_team" || !s.CancelAtPeriodEnd {
		t.Errorf("sub = %+v", s)
	}
	if !s.CurrentPeriodEnd.Equal(time.Unix(1790000000, 0)) {
		t.Errorf("period end = %v", s.CurrentPeriodEnd)
	}
	if s.TrialEnd == nil || !s.TrialEnd.Equal(time.Unix(1789000000, 0)) {
		t.Errorf("trial end = %v", s.TrialEnd)
	}
}

func TestGetSubscriptionNullTrialEnd(t *testing.T) {
	c, _ := stripeServer(t, 200, `{"id":"sub_1","customer":"c","status":"active","current_period_end":1790000000,"trial_end":null,"items":{"data":[]}}`)
	s, err := c.GetSubscription(context.Background(), "sub_1")
	if err != nil {
		t.Fatal(err)
	}
	if s.TrialEnd != nil || s.PriceID != "" {
		t.Errorf("sub = %+v", s)
	}
}

func TestAPIErrorSurfacesMessageNotSecrets(t *testing.T) {
	body := `{"error":{"type":"invalid_request_error","code":"resource_missing","message":"No such price: 'price_x'"}}`
	c, _ := stripeServer(t, 400, body)
	_, _, err := c.CreateCheckoutSession(context.Background(), CheckoutParams{WorkspaceID: "ws_1", PriceID: "price_x", CustomerEmail: "leak@example.com"})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "400") || !strings.Contains(msg, "No such price: 'price_x'") {
		t.Errorf("error = %q", msg)
	}
	for _, bad := range []string{testKey, "leak@example.com", "client_reference_id"} {
		if strings.Contains(msg, bad) {
			t.Errorf("error leaks %q: %q", bad, msg)
		}
	}
}

func TestNonJSONErrorBodyNotEchoed(t *testing.T) {
	c, _ := stripeServer(t, 502, "<html>upstream secret-ish body</html>")
	_, err := c.GetSubscription(context.Background(), "sub_1")
	if err == nil || strings.Contains(err.Error(), "upstream") || !strings.Contains(err.Error(), "502") {
		t.Errorf("error = %v", err)
	}
}

func TestTransportErrorHasNoKey(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	c := &Client{SecretKey: testKey, BaseURL: base}
	_, err := c.GetSubscription(context.Background(), "sub_1")
	if err == nil || strings.Contains(err.Error(), testKey) {
		t.Errorf("error = %v", err)
	}
}

func TestPlans(t *testing.T) {
	env := map[string]string{"RESTOREGAP_CLOUD_PRICE_SOLO": "price_s", "RESTOREGAP_CLOUD_PRICE_FLEET": "price_f"}
	ps := Plans(func(k string) string { return env[k] })
	if len(ps) != 3 {
		t.Fatalf("plans = %d", len(ps))
	}
	want := []Plan{
		{"solo", "Solo", "price_s", 19, 3, 90},
		{"team", "Team", "", 79, 25, 365},
		{"fleet", "Fleet", "price_f", 249, 100, 1095},
	}
	if !reflect.DeepEqual(ps, want) {
		t.Errorf("plans = %+v", ps)
	}
	if p, ok := PlanByKey(ps, "team"); !ok || p.MaxHosts != 25 {
		t.Errorf("PlanByKey team = %+v %v", p, ok)
	}
	if _, ok := PlanByKey(ps, "nope"); ok {
		t.Error("unknown key matched")
	}
	if p, ok := PlanByPriceID(ps, "price_f"); !ok || p.Key != "fleet" {
		t.Errorf("PlanByPriceID = %+v %v", p, ok)
	}
	if _, ok := PlanByPriceID(ps, ""); ok {
		t.Error("empty price id must not match the unconfigured team plan")
	}
	if Unlimited.MaxHosts != 0 || Unlimited.Key != "unlimited" {
		t.Errorf("Unlimited = %+v", Unlimited)
	}
}

func sign(secret string, ts int64, payload string) string {
	m := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(m, "%d.%s", ts, payload)
	return hex.EncodeToString(m.Sum(nil))
}

func TestVerifyWebhook(t *testing.T) {
	const secret = "whsec_test"
	payload := `{"id":"evt_1","type":"x"}`
	now := time.Unix(1_790_000_000, 0)
	ts := now.Unix()
	good := sign(secret, ts, payload)
	other := strings.Repeat("ab", 32)
	tol := 5 * time.Minute

	cases := []struct {
		name    string
		payload string
		header  string
		now     time.Time
		wantErr bool
	}{
		{"valid", payload, fmt.Sprintf("t=%d,v1=%s", ts, good), now, false},
		{"valid with spaces and v0", payload, fmt.Sprintf("t=%d, v0=%s, v1=%s", ts, other, good), now, false},
		{"tampered payload", payload + " ", fmt.Sprintf("t=%d,v1=%s", ts, good), now, true},
		{"wrong secret", payload, fmt.Sprintf("t=%d,v1=%s", ts, sign("whsec_other", ts, payload)), now, true},
		{"expired", payload, fmt.Sprintf("t=%d,v1=%s", ts, good), now.Add(tol + time.Second), true},
		{"future beyond tolerance", payload, fmt.Sprintf("t=%d,v1=%s", ts, good), now.Add(-tol - time.Second), true},
		{"within tolerance", payload, fmt.Sprintf("t=%d,v1=%s", ts, good), now.Add(tol), false},
		{"second v1 matches", payload, fmt.Sprintf("t=%d,v1=%s,v1=%s", ts, other, good), now, false},
		{"first v1 matches", payload, fmt.Sprintf("t=%d,v1=%s,v1=%s", ts, good, other), now, false},
		{"no v1 matches", payload, fmt.Sprintf("t=%d,v1=%s,v1=%s", ts, other, other), now, true},
		{"empty header", payload, "", now, true},
		{"no timestamp", payload, "v1=" + good, now, true},
		{"no v1", payload, fmt.Sprintf("t=%d", ts), now, true},
		{"bad timestamp", payload, "t=abc,v1=" + good, now, true},
		{"non-hex signature", payload, fmt.Sprintf("t=%d,v1=zzzz", ts), now, true},
		{"garbage", payload, "hello", now, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyWebhook([]byte(tc.payload), tc.header, secret, tc.now, tol)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), secret) {
				t.Errorf("error leaks secret: %v", err)
			}
		})
	}
}

func TestParseEventAndHelpers(t *testing.T) {
	co := `{"id":"evt_1","object":"event","type":"checkout.session.completed","created":1790000000,
	  "data":{"object":{"id":"cs_1","client_reference_id":"ws_1","customer":"cus_9","subscription":"sub_123","customer_email":null,"customer_details":{"email":"a@example.com"}}}}`
	e, err := ParseEvent([]byte(co))
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != "evt_1" || e.Type != "checkout.session.completed" || !e.Created.Equal(time.Unix(1790000000, 0)) {
		t.Errorf("event = %+v", e)
	}
	cs, err := e.CheckoutSession()
	if err != nil {
		t.Fatal(err)
	}
	want := CheckoutSession{ID: "cs_1", ClientReferenceID: "ws_1", Customer: "cus_9", Subscription: "sub_123", CustomerEmail: "a@example.com"}
	if cs != want {
		t.Errorf("cs = %+v", cs)
	}

	se, err := ParseEvent([]byte(`{"id":"evt_2","type":"customer.subscription.updated","created":1790000100,"data":{"object":` + subFixture + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := se.Subscription()
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "sub_123" || s.PriceID != "price_team" || s.Status != "trialing" || s.TrialEnd == nil {
		t.Errorf("sub = %+v", s)
	}

	for _, bad := range []string{`not json`, `{"type":"x"}`, `{"id":"e"}`} {
		if _, err := ParseEvent([]byte(bad)); err == nil {
			t.Errorf("ParseEvent(%q) should fail", bad)
		}
	}
	if _, err := (Event{Data: []byte(`[]`)}).Subscription(); err == nil {
		t.Error("non-object Data should fail to decode")
	}
}

func TestStatusFromStripe(t *testing.T) {
	for in, want := range map[string]string{
		"trialing": "trialing", "active": "active", "past_due": "past_due", "unpaid": "past_due",
		"canceled": "canceled", "incomplete_expired": "canceled", "incomplete": "trialing", "paused": "past_due", "": "past_due",
	} {
		if got := StatusFromStripe(in); got != want {
			t.Errorf("StatusFromStripe(%q) = %q, want %q", in, got, want)
		}
	}
}
