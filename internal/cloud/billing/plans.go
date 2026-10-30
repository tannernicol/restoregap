// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package billing is a minimal Stripe client: Checkout, the customer portal,
// subscription reads and webhook verification. It uses only the standard
// library and never places the secret key in an error or log line.
package billing

// Plan is one purchasable tier. Limits mirror docs/CLOUD.md; PriceID comes
// from the operator's Stripe account, so it is configuration, not code.
type Plan struct {
	Key, Name, PriceID string
	MonthlyUSD         int
	MaxHosts           int // 0 means no limit
	RetentionDays      int // 0 means no limit
}

// Unlimited is the workspace plan for a self-hosted Cloud without Stripe.
var Unlimited = Plan{Key: "unlimited", Name: "Self-hosted", MaxHosts: 0, RetentionDays: 0}

// Plans returns solo, team and fleet in ascending order. A plan whose price
// env var is unset is still returned so the UI can show it as unavailable
// instead of silently hiding a tier.
func Plans(env func(string) string) []Plan {
	return []Plan{
		{Key: "solo", Name: "Solo", PriceID: env("RESTOREGAP_CLOUD_PRICE_SOLO"), MonthlyUSD: 19, MaxHosts: 3, RetentionDays: 90},
		{Key: "team", Name: "Team", PriceID: env("RESTOREGAP_CLOUD_PRICE_TEAM"), MonthlyUSD: 79, MaxHosts: 25, RetentionDays: 365},
		{Key: "fleet", Name: "Fleet", PriceID: env("RESTOREGAP_CLOUD_PRICE_FLEET"), MonthlyUSD: 249, MaxHosts: 100, RetentionDays: 1095},
	}
}

// PlanByKey finds a plan by its stable key.
func PlanByKey(plans []Plan, key string) (Plan, bool) {
	for _, p := range plans {
		if p.Key == key {
			return p, true
		}
	}
	return Plan{}, false
}

// PlanByPriceID maps a Stripe price back to a plan. An empty id never
// matches: unconfigured plans all have an empty PriceID and must not collide.
func PlanByPriceID(plans []Plan, priceID string) (Plan, bool) {
	if priceID == "" {
		return Plan{}, false
	}
	for _, p := range plans {
		if p.PriceID == priceID {
			return p, true
		}
	}
	return Plan{}, false
}
