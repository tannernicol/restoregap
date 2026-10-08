// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// VerifyWebhook checks a Stripe-Signature header against the raw payload.
// Stripe may send several v1 entries during secret rotation, so any match
// passes; the timestamp bound limits replay of a captured request.
func VerifyWebhook(payload []byte, sigHeader, secret string, now time.Time, tolerance time.Duration) error {
	var ts int64
	var haveTS bool
	var sigs [][]byte
	for _, part := range strings.Split(sigHeader, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return errors.New("webhook: malformed signature header")
			}
			ts, haveTS = n, true
		case "v1":
			if b, err := hex.DecodeString(v); err == nil {
				sigs = append(sigs, b)
			}
		}
	}
	if !haveTS || len(sigs) == 0 {
		return errors.New("webhook: malformed signature header")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write(payload)
	want := mac.Sum(nil)
	matched := false
	for _, s := range sigs {
		// No early exit: keep timing independent of which entry matches.
		if hmac.Equal(s, want) {
			matched = true
		}
	}
	if !matched {
		return errors.New("webhook: signature mismatch")
	}

	// Checked after the signature so an unauthenticated caller cannot
	// probe the clock window.
	age := now.Sub(time.Unix(ts, 0))
	if age < 0 {
		age = -age
	}
	if age > tolerance {
		return errors.New("webhook: timestamp outside tolerance")
	}
	return nil
}

// Event is a Stripe webhook event; Data holds data.object undecoded.
type Event struct {
	ID, Type string
	Created  time.Time
	Data     json.RawMessage
}

// ParseEvent decodes the envelope of a webhook payload.
func ParseEvent(payload []byte) (Event, error) {
	var raw struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Created int64  `json:"created"`
		Data    struct {
			Object json.RawMessage `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Event{}, fmt.Errorf("webhook: decode event: %w", err)
	}
	if raw.ID == "" || raw.Type == "" {
		return Event{}, errors.New("webhook: event missing id or type")
	}
	return Event{ID: raw.ID, Type: raw.Type, Created: time.Unix(raw.Created, 0).UTC(), Data: raw.Data.Object}, nil
}

// CheckoutSession is the part of checkout.session.completed the server uses.
type CheckoutSession struct {
	ID, ClientReferenceID, Customer, Subscription, CustomerEmail string
}

// CheckoutSession decodes Data for checkout.session.completed.
func (e Event) CheckoutSession() (CheckoutSession, error) {
	var raw struct {
		ID                string `json:"id"`
		ClientReferenceID string `json:"client_reference_id"`
		Customer          string `json:"customer"`
		Subscription      string `json:"subscription"`
		CustomerEmail     string `json:"customer_email"`
		CustomerDetails   struct {
			Email string `json:"email"`
		} `json:"customer_details"`
	}
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return CheckoutSession{}, fmt.Errorf("webhook: decode checkout session: %w", err)
	}
	cs := CheckoutSession{ID: raw.ID, ClientReferenceID: raw.ClientReferenceID, Customer: raw.Customer, Subscription: raw.Subscription, CustomerEmail: raw.CustomerEmail}
	if cs.CustomerEmail == "" {
		cs.CustomerEmail = raw.CustomerDetails.Email
	}
	return cs, nil
}

// Subscription decodes Data for customer.subscription.* events.
func (e Event) Subscription() (Subscription, error) {
	var raw subscriptionJSON
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return Subscription{}, fmt.Errorf("webhook: decode subscription: %w", err)
	}
	return raw.subscription(), nil
}

// StatusFromStripe collapses Stripe's subscription states into the four
// workspace states. incomplete maps to trialing because the first payment
// is still resolving and access should not flap; an unknown status is
// treated as past_due so it fails closed without destroying data.
func StatusFromStripe(s string) string {
	switch s {
	case "trialing", "incomplete":
		return "trialing"
	case "active":
		return "active"
	case "past_due", "unpaid":
		return "past_due"
	case "canceled", "incomplete_expired":
		return "canceled"
	}
	return "past_due"
}
