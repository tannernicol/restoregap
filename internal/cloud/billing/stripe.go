// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://api.stripe.com"
	// stripeVersion is pinned so a Stripe-side default bump cannot change
	// response shapes under a running deployment.
	stripeVersion = "2024-06-20"
	maxRespBytes  = 1 << 20
)

// Client talks to the Stripe REST API. Zero values for BaseURL and HTTP
// select the real API and a 15s timeout.
type Client struct {
	SecretKey string
	BaseURL   string
	HTTP      *http.Client
}

// CheckoutParams describes a subscription Checkout Session.
type CheckoutParams struct {
	WorkspaceID, CustomerID, CustomerEmail, PriceID, SuccessURL, CancelURL string
	TrialDays                                                              int
}

// Subscription is the subset of a Stripe subscription the server needs.
type Subscription struct {
	ID, CustomerID, Status, PriceID string
	CurrentPeriodEnd                time.Time
	CancelAtPeriodEnd               bool
	TrialEnd                        *time.Time
}

// CreateCheckoutSession starts a subscription checkout and returns the
// session id and the hosted page URL to redirect the browser to.
func (c *Client) CreateCheckoutSession(ctx context.Context, p CheckoutParams) (id, pageURL string, err error) {
	f := url.Values{}
	f.Set("mode", "subscription")
	f.Set("line_items[0][price]", p.PriceID)
	f.Set("line_items[0][quantity]", "1")
	f.Set("client_reference_id", p.WorkspaceID)
	f.Set("success_url", p.SuccessURL)
	f.Set("cancel_url", p.CancelURL)
	// Reusing the customer keeps one Stripe customer per workspace; the
	// email is only a prefill for first-time checkouts.
	if p.CustomerID != "" {
		f.Set("customer", p.CustomerID)
	} else if p.CustomerEmail != "" {
		f.Set("customer_email", p.CustomerEmail)
	}
	if p.TrialDays > 0 {
		f.Set("subscription_data[trial_period_days]", strconv.Itoa(p.TrialDays))
	}
	f.Set("allow_promotion_codes", "true")

	var out struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/checkout/sessions", f, &out); err != nil {
		return "", "", err
	}
	if out.ID == "" || out.URL == "" {
		return "", "", errors.New("stripe: checkout session response missing id or url")
	}
	return out.ID, out.URL, nil
}

// CreatePortalSession returns a customer-portal URL for managing the
// subscription and payment method.
func (c *Client) CreatePortalSession(ctx context.Context, customerID, returnURL string) (string, error) {
	f := url.Values{}
	f.Set("customer", customerID)
	f.Set("return_url", returnURL)
	var out struct {
		URL string `json:"url"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/billing_portal/sessions", f, &out); err != nil {
		return "", err
	}
	if out.URL == "" {
		return "", errors.New("stripe: portal session response missing url")
	}
	return out.URL, nil
}

// GetSubscription fetches the current state of a subscription.
func (c *Client) GetSubscription(ctx context.Context, id string) (Subscription, error) {
	var raw subscriptionJSON
	if err := c.do(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(id), nil, &raw); err != nil {
		return Subscription{}, err
	}
	return raw.subscription(), nil
}

func (c *Client) do(ctx context.Context, method, path string, form url.Values, out any) error {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return fmt.Errorf("stripe: build request: %w", err)
	}
	req.SetBasicAuth(c.SecretKey, "")
	req.Header.Set("Stripe-Version", stripeVersion)
	req.Header.Set("Accept", "application/json")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := hc.Do(req)
	if err != nil {
		// url.Error wraps the cause with the URL; the URL carries no
		// secret, but unwrapping keeps messages short and uniform.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("stripe: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if err != nil {
		return fmt.Errorf("stripe: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return apiError(resp.StatusCode, data)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("stripe: decode response: %w", err)
	}
	return nil
}

// apiError reports Stripe's own error.message with the status. The raw body
// is deliberately not echoed when it is not Stripe-shaped.
func apiError(status int, body []byte) error {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return fmt.Errorf("stripe: HTTP %d: %s", status, e.Error.Message)
	}
	return fmt.Errorf("stripe: HTTP %d", status)
}

type subscriptionJSON struct {
	ID                string `json:"id"`
	Customer          string `json:"customer"`
	Status            string `json:"status"`
	CurrentPeriodEnd  int64  `json:"current_period_end"`
	CancelAtPeriodEnd bool   `json:"cancel_at_period_end"`
	TrialEnd          *int64 `json:"trial_end"`
	Items             struct {
		Data []struct {
			Price struct {
				ID string `json:"id"`
			} `json:"price"`
		} `json:"data"`
	} `json:"items"`
}

func (s subscriptionJSON) subscription() Subscription {
	sub := Subscription{
		ID:                s.ID,
		CustomerID:        s.Customer,
		Status:            s.Status,
		CancelAtPeriodEnd: s.CancelAtPeriodEnd,
	}
	if s.CurrentPeriodEnd > 0 {
		sub.CurrentPeriodEnd = time.Unix(s.CurrentPeriodEnd, 0).UTC()
	}
	if s.TrialEnd != nil && *s.TrialEnd > 0 {
		t := time.Unix(*s.TrialEnd, 0).UTC()
		sub.TrialEnd = &t
	}
	if len(s.Items.Data) > 0 {
		sub.PriceID = s.Items.Data[0].Price.ID
	}
	return sub
}
