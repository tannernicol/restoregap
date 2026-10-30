// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"strings"
	"testing"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestConfigFromEnvDefaults(t *testing.T) {
	cfg, err := ConfigFromEnv(envOf(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "./data" || cfg.BaseURL != "http://localhost:8080" || !cfg.AllowSignup || cfg.TrialDays != 14 ||
		cfg.ListenAddr != "127.0.0.1:8080" || cfg.BillingEnabled() || cfg.SMTPURL != "" {
		t.Fatalf("defaults = %+v", cfg)
	}
	if len(cfg.Plans) != 3 || cfg.Plans[0].Key != "solo" || cfg.Plans[0].PriceID != "" {
		t.Fatalf("plans = %+v", cfg.Plans)
	}
}

func TestConfigFromEnvReadsEverythingDocumented(t *testing.T) {
	cfg, err := ConfigFromEnv(envOf(map[string]string{
		"RESTOREGAP_CLOUD_DATA":                  "/var/lib/rg",
		"RESTOREGAP_CLOUD_BASE_URL":              "https://cloud.example.com/",
		"RESTOREGAP_CLOUD_SMTP_URL":              "smtp://u:p@mail.example.com:587?from=cloud@example.com",
		"RESTOREGAP_CLOUD_STRIPE_SECRET":         "sk_x",
		"RESTOREGAP_CLOUD_STRIPE_WEBHOOK_SECRET": "whsec_x",
		"RESTOREGAP_CLOUD_PRICE_SOLO":            "price_a",
		"RESTOREGAP_CLOUD_PRICE_TEAM":            "price_b",
		"RESTOREGAP_CLOUD_PRICE_FLEET":           "price_c",
		"RESTOREGAP_CLOUD_ALLOW_SIGNUP":          "false",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "/var/lib/rg" || cfg.BaseURL != "https://cloud.example.com" || cfg.AllowSignup || !cfg.BillingEnabled() ||
		cfg.StripeWebhookSecret != "whsec_x" || cfg.Plans[0].PriceID != "price_a" || cfg.Plans[1].PriceID != "price_b" ||
		cfg.Plans[2].PriceID != "price_c" || !strings.HasPrefix(cfg.SMTPURL, "smtp://") || !cfg.secureCookies() {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestConfigFromEnvRejectsMistakesAtStartup(t *testing.T) {
	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"bad bool":          {map[string]string{"RESTOREGAP_CLOUD_ALLOW_SIGNUP": "maybe"}, "ALLOW_SIGNUP"},
		"relative base":     {map[string]string{"RESTOREGAP_CLOUD_BASE_URL": "cloud.example.com"}, "BASE_URL"},
		"ftp base":          {map[string]string{"RESTOREGAP_CLOUD_BASE_URL": "ftp://example.com"}, "BASE_URL"},
		"base with creds":   {map[string]string{"RESTOREGAP_CLOUD_BASE_URL": "https://u:p@example.com"}, "BASE_URL"},
		"bad smtp":          {map[string]string{"RESTOREGAP_CLOUD_SMTP_URL": "http://mail.example.com"}, "SMTP_URL"},
		"smtp without from": {map[string]string{"RESTOREGAP_CLOUD_SMTP_URL": "smtp://mail.example.com"}, "SMTP_URL"},
		"stripe no webhook": {map[string]string{"RESTOREGAP_CLOUD_STRIPE_SECRET": "sk_x"}, "WEBHOOK_SECRET"},
	} {
		_, err := ConfigFromEnv(envOf(tc.env))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want mention of %s", name, err, tc.want)
		}
	}
	// The SMTP password must never reach an error message.
	_, err := ConfigFromEnv(envOf(map[string]string{"RESTOREGAP_CLOUD_SMTP_URL": "smtp://u:hunter2@mail.example.com"}))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewAppliesDefaultsAndRejectsBadConfig(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.TrialDays = 0; c.Plans = nil; c.Now = nil; c.Logger = nil })
	if e.srv.cfg.TrialDays != 14 || len(e.srv.cfg.Plans) != 3 || e.srv.now == nil || e.srv.log == nil {
		t.Fatalf("defaults not applied: %+v", e.srv.cfg)
	}
	if _, err := New(Config{BaseURL: "nope"}, e.st); err == nil {
		t.Fatal("New accepted a relative base URL")
	}
	if _, err := New(Config{BaseURL: "http://x.test"}, nil); err == nil {
		t.Fatal("New accepted a nil store")
	}
	if _, err := New(Config{BaseURL: "http://x.test", StripeSecret: "sk"}, e.st); err == nil {
		t.Fatal("New accepted a Stripe key without a webhook secret")
	}
}
