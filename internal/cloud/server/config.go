// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package server is the HTTP service of Restore Gap Cloud (docs/CLOUD.md):
// bundle ingest, the dashboard, share links, monitoring and Stripe billing.
// It owns no persistence of its own; everything durable lives in
// internal/cloud/store.
package server

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/cloud/billing"
	"github.com/tannernicol/restoregap/internal/cloud/notify"
)

// Config is the whole service configuration. Every field comes from the
// environment (ConfigFromEnv) or, for ListenAddr, the serve command's flag;
// nothing is read from a file so a container needs no mounted config.
type Config struct {
	// BaseURL is the public URL, used in emails, share links and Stripe
	// return URLs. It decides whether cookies are marked Secure.
	BaseURL    string
	DataDir    string
	ListenAddr string
	// SMTPURL is smtp://user:pass@host:587?from=cloud@example.com. Unset is
	// the documented dev mode: magic links go to the log instead of a mailbox.
	SMTPURL     string
	AllowSignup bool

	// Billing is enabled iff StripeSecret is non-empty. Without it every
	// workspace is "unlimited" and the billing pages and webhook do not exist.
	StripeSecret, StripeWebhookSecret string
	Plans                             []billing.Plan
	// StripeBaseURL points the Stripe client somewhere other than
	// api.stripe.com. It exists for tests (a stub server) and is deliberately
	// not settable from the environment.
	StripeBaseURL string
	TrialDays     int // length of the Team trial a new workspace starts with (14)

	// Now and Logger are injectable so tests can move time and read logs.
	Now    func() time.Time
	Logger *slog.Logger
}

// BillingEnabled reports whether Stripe is configured.
func (c Config) BillingEnabled() bool { return c.StripeSecret != "" }

// ConfigFromEnv reads the RESTOREGAP_CLOUD_* variables docs/CLOUD.md lists.
// It validates what it can up front (URLs, the SMTP URL, the booleans) so a
// typo fails at startup instead of at the first login email.
func ConfigFromEnv(env func(string) string) (Config, error) {
	cfg := Config{
		BaseURL:             strings.TrimSpace(env("RESTOREGAP_CLOUD_BASE_URL")),
		DataDir:             strings.TrimSpace(env("RESTOREGAP_CLOUD_DATA")),
		ListenAddr:          "127.0.0.1:8080",
		SMTPURL:             strings.TrimSpace(env("RESTOREGAP_CLOUD_SMTP_URL")),
		StripeSecret:        strings.TrimSpace(env("RESTOREGAP_CLOUD_STRIPE_SECRET")),
		StripeWebhookSecret: strings.TrimSpace(env("RESTOREGAP_CLOUD_STRIPE_WEBHOOK_SECRET")),
		Plans:               billing.Plans(env),
		AllowSignup:         true,
		TrialDays:           14,
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:8080"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	if v := strings.TrimSpace(env("RESTOREGAP_CLOUD_ALLOW_SIGNUP")); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			cfg.AllowSignup = true
		case "0", "false", "no", "off":
			cfg.AllowSignup = false
		default:
			return Config{}, fmt.Errorf("RESTOREGAP_CLOUD_ALLOW_SIGNUP must be true or false, got %q", v)
		}
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validate checks the fields that would otherwise fail late and confusingly,
// and normalizes BaseURL (no trailing slash, so path joins are unambiguous).
func (c *Config) validate() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("RESTOREGAP_CLOUD_BASE_URL must be an absolute http(s) URL, got %q", c.BaseURL)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("RESTOREGAP_CLOUD_BASE_URL must not carry credentials, a query or a fragment")
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if c.SMTPURL != "" {
		// ParseSMTPURL's errors never echo the credentials in the URL.
		if _, err := notify.ParseSMTPURL(c.SMTPURL); err != nil {
			return fmt.Errorf("RESTOREGAP_CLOUD_SMTP_URL: %w", err)
		}
	}
	// With a Stripe key but no webhook secret every webhook would be refused,
	// so subscriptions would never activate. Refuse to start instead.
	if c.StripeSecret != "" && c.StripeWebhookSecret == "" {
		return fmt.Errorf("RESTOREGAP_CLOUD_STRIPE_WEBHOOK_SECRET is required when RESTOREGAP_CLOUD_STRIPE_SECRET is set")
	}
	return nil
}

// secureCookies is true when the public URL is https: only then may cookies
// carry the Secure attribute, or a plain-http dev instance could never log in.
func (c Config) secureCookies() bool { return strings.HasPrefix(c.BaseURL, "https://") }
