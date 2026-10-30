// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/tannernicol/restoregap/internal/cloud/billing"
	"github.com/tannernicol/restoregap/internal/cloud/store"
)

const (
	webhookTolerance = 5 * time.Minute
	maxWebhookBody   = 1 << 20
	// eventMemory is how many handled Stripe event ids are remembered for
	// replay protection. Stripe retries over days, but the signature's
	// five-minute timestamp window already bounds a captured-request replay;
	// this only absorbs Stripe's own redeliveries, which arrive close together.
	eventMemory = 2048
)

// ---- webhook ----

func (s *Server) handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			jsonError(w, http.StatusRequestEntityTooLarge, "payload too large")
		} else {
			jsonError(w, http.StatusBadRequest, "could not read payload")
		}
		return
	}
	if err := billing.VerifyWebhook(body, r.Header.Get("Stripe-Signature"), s.cfg.StripeWebhookSecret, s.now(), webhookTolerance); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid signature")
		return
	}
	ev, err := billing.ParseEvent(body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid event")
		return
	}

	// One event at a time: a Stripe redelivery racing the original must see
	// the original's result, and webhook volume is far too low for this to matter.
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if _, done := s.eventSeen[ev.ID]; done {
		writeJSON(w, http.StatusOK, map[string]string{"status": "already handled"})
		return
	}
	if err := s.applyStripeEvent(r.Context(), ev); err != nil {
		// Not remembered: a 5xx makes Stripe retry, which is what a transient
		// Stripe or database failure needs.
		s.log.Error("stripe webhook failed", "event", ev.ID, "type", ev.Type, "err", err)
		jsonError(w, http.StatusInternalServerError, "could not process event")
		return
	}
	s.rememberEvent(ev.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// rememberEvent records a handled event id, forgetting the oldest past the
// bound. Callers hold eventMu.
func (s *Server) rememberEvent(id string) {
	s.eventSeen[id] = struct{}{}
	s.eventOrder = append(s.eventOrder, id)
	if len(s.eventOrder) > eventMemory {
		delete(s.eventSeen, s.eventOrder[0])
		s.eventOrder = s.eventOrder[1:]
	}
}

// applyStripeEvent updates the workspace an event is about. A nil return
// means "handled or deliberately ignored"; an error means "retry me".
func (s *Server) applyStripeEvent(ctx context.Context, ev billing.Event) error {
	switch ev.Type {
	case "checkout.session.completed":
		cs, err := ev.CheckoutSession()
		if err != nil || cs.ClientReferenceID == "" || cs.Subscription == "" {
			s.log.Warn("ignoring checkout session without a workspace or subscription", "event", ev.ID)
			return nil
		}
		ws, err := s.st.GetWorkspace(cs.ClientReferenceID)
		if errors.Is(err, store.ErrNotFound) {
			s.log.Warn("checkout for an unknown workspace", "event", ev.ID)
			return nil
		}
		if err != nil {
			return err
		}
		// The session says a subscription exists; what plan and state it is in
		// is Stripe's to say, so ask rather than infer from the session.
		sub, err := s.stripe.GetSubscription(ctx, cs.Subscription)
		if err != nil {
			return err
		}
		return s.applySubscription(ws, cs.Customer, sub, false)

	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted":
		sub, err := ev.Subscription()
		if err != nil {
			s.log.Warn("ignoring unreadable subscription event", "event", ev.ID)
			return nil
		}
		ws, err := s.st.WorkspaceByStripeCustomer(sub.CustomerID)
		if errors.Is(err, store.ErrNotFound) {
			// Stripe does not order events: this can arrive before the checkout
			// event that links the customer. That event reads the subscription
			// itself, so nothing is lost by ignoring this one.
			s.log.Info("subscription event for an unlinked customer", "event", ev.ID, "type", ev.Type)
			return nil
		}
		if err != nil {
			return err
		}
		if ws.StripeSubscriptionID != "" && ws.StripeSubscriptionID != sub.ID {
			// A late event about a subscription the workspace has since replaced
			// must not cancel the new one.
			s.log.Info("ignoring event for a replaced subscription", "event", ev.ID, "workspace", ws.ID)
			return nil
		}
		return s.applySubscription(ws, ws.StripeCustomerID, sub, ev.Type == "customer.subscription.deleted")
	}
	return nil // every other event type is not ours to act on
}

// applySubscription writes a subscription's plan, state and ids to its
// workspace. The Stripe ids are kept even after cancellation so the workspace
// is remembered as having had a subscription (no second free trial).
func (s *Server) applySubscription(ws store.Workspace, customerID string, sub billing.Subscription, deleted bool) error {
	plan := ws.Plan
	if p, ok := billing.PlanByPriceID(s.cfg.Plans, sub.PriceID); ok {
		plan = p.Key
	} else {
		s.log.Warn("subscription price matches no configured plan; keeping the current plan", "workspace", ws.ID)
	}
	if plan == billing.Unlimited.Key {
		plan = "team" // an unlimited plan has no meaning once Stripe is in charge
	}
	state := billing.StatusFromStripe(sub.Status)
	if deleted {
		state = "canceled"
	}
	var trial *time.Time
	if state == "trialing" {
		trial = sub.TrialEnd
	}
	err := s.st.UpdateWorkspaceBilling(ws.ID, plan, state, customerID, sub.ID, trial)
	if errors.Is(err, store.ErrConflict) {
		// The customer id belongs to another workspace: retrying cannot fix it.
		s.log.Error("stripe customer already linked to another workspace", "workspace", ws.ID)
		return nil
	}
	return err
}

// ---- billing page ----

type planRow struct {
	Plan     billing.Plan
	Current  bool
	Disabled bool   // the operator has not set this plan's price id
	Action   string // Upgrade | Switch
}

type billingData struct {
	WS        store.Workspace
	Plan      billing.Plan
	Plans     []planRow
	PeriodEnd *time.Time
	Cancels   bool // cancel_at_period_end
	Live      bool // there is a subscription to manage in the portal
}

func (s *Server) handleBilling(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	ws := sc.WS
	d := billingData{WS: ws, Plan: s.planFor(ws.Plan), Live: ws.StripeCustomerID != ""}
	for _, p := range s.cfg.Plans {
		row := planRow{Plan: p, Current: p.Key == ws.Plan, Disabled: p.PriceID == ""}
		row.Action = "Upgrade"
		if p.MonthlyUSD < d.Plan.MonthlyUSD {
			row.Action = "Switch"
		}
		d.Plans = append(d.Plans, row)
	}
	if ws.StripeSubscriptionID != "" {
		// The period end is not stored (Stripe owns it); a short, best-effort
		// read keeps the page honest, and the page works without it.
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if sub, err := s.stripe.GetSubscription(ctx, ws.StripeSubscriptionID); err != nil {
			s.log.Warn("could not read the subscription for the billing page", "workspace", ws.ID, "err", err)
		} else if !sub.CurrentPeriodEnd.IsZero() {
			t := sub.CurrentPeriodEnd
			d.PeriodEnd, d.Cancels = &t, sub.CancelAtPeriodEnd
		}
	}
	p := s.authedPage(sc, "Billing", "billing", d)
	if r.URL.Query().Get("ok") == "1" {
		p.Flash = "Thanks. Stripe confirms the subscription to us in the background; this page shows the new plan as soon as it does."
	}
	s.render(w, http.StatusOK, "billing.html", p)
}

// liveSubscription: the workspace already pays (or is past due on) a
// subscription. A second Checkout would bill it twice, so plan changes go
// through the customer portal instead.
func liveSubscription(ws store.Workspace) bool {
	if ws.StripeSubscriptionID == "" || ws.StripeCustomerID == "" {
		return false
	}
	switch ws.BillingStatus {
	case "active", "past_due", "trialing":
		return true
	}
	return false
}

func (s *Server) handleBillingCheckout(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	plan, ok := billing.PlanByKey(s.cfg.Plans, r.PostForm.Get("plan"))
	if !ok || plan.PriceID == "" {
		s.message(w, r, http.StatusBadRequest, "Bad request", "That plan is not available for purchase on this instance.")
		return
	}
	ws := sc.WS
	if liveSubscription(ws) {
		s.redirectToPortal(w, r, ws)
		return
	}
	trialDays := 0
	if ws.StripeSubscriptionID == "" { // a workspace that has never subscribed gets the trial once
		trialDays = s.cfg.TrialDays
	}
	_, pageURL, err := s.stripe.CreateCheckoutSession(r.Context(), billing.CheckoutParams{
		WorkspaceID: ws.ID, CustomerID: ws.StripeCustomerID, CustomerEmail: sc.User.Email,
		PriceID:    plan.PriceID,
		SuccessURL: s.cfg.BaseURL + "/app/billing?ok=1", CancelURL: s.cfg.BaseURL + "/app/billing",
		TrialDays: trialDays,
	})
	if err != nil {
		s.log.Error("create checkout session failed", "workspace", ws.ID, "err", err)
		s.message(w, r, http.StatusBadGateway, "Stripe unavailable", "Stripe could not start the checkout. Try again in a moment.")
		return
	}
	http.Redirect(w, r, pageURL, http.StatusSeeOther)
}

func (s *Server) handleBillingPortal(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	s.redirectToPortal(w, r, sc.WS)
}

func (s *Server) redirectToPortal(w http.ResponseWriter, r *http.Request, ws store.Workspace) {
	if ws.StripeCustomerID == "" {
		s.message(w, r, http.StatusBadRequest, "No billing account", "There is no billing account yet. Choose a plan first.")
		return
	}
	u, err := s.stripe.CreatePortalSession(r.Context(), ws.StripeCustomerID, s.cfg.BaseURL+"/app/billing")
	if err != nil {
		s.log.Error("create portal session failed", "workspace", ws.ID, "err", err)
		s.message(w, r, http.StatusBadGateway, "Stripe unavailable", "Stripe could not open the billing portal. Try again in a moment.")
		return
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}
