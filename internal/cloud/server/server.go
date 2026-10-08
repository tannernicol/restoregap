// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tannernicol/restoregap/internal/bundle"
	"github.com/tannernicol/restoregap/internal/cloud/billing"
	"github.com/tannernicol/restoregap/internal/cloud/store"
	"github.com/tannernicol/restoregap/internal/status"
	"github.com/tannernicol/restoregap/ui"
)

// docsURL is where the home page points for the product contract. It is the
// one external link in the whole service and is plain navigation, not a
// request the server makes.
const docsURL = "https://github.com/tannernicol/restoregap/blob/main/docs/CLOUD.md"

//go:embed templates/*.html
var templateFS embed.FS

// Server is the Restore Gap Cloud HTTP service. Create it with New and mount
// Handler; run RunMonitor beside it for lapse alerts, delivery and retention.
type Server struct {
	cfg     Config
	st      *store.Store
	log     *slog.Logger
	now     func() time.Time
	stripe  *billing.Client // nil when billing is disabled
	pages   map[string]*template.Template
	csp     string
	css     template.CSS
	secure  bool
	started time.Time

	loginMu   sync.Mutex
	loginHits map[string][]time.Time

	// ingestMu serializes the host-limit check, the key pin and the bundle
	// save, so two first pushes cannot both pass a "3 of 3 hosts" check.
	ingestMu sync.Mutex

	eventMu    sync.Mutex
	eventSeen  map[string]struct{}
	eventOrder []string

	loadMu sync.Mutex
	loaded map[string]bundle.Loaded // verified archives by bundle id; archives are immutable
}

// New validates cfg, parses the embedded templates and returns a Server over
// an already open store.
func New(cfg Config, st *store.Store) (*Server, error) {
	if st == nil {
		return nil, errors.New("server: nil store")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.TrialDays <= 0 {
		cfg.TrialDays = 14
	}
	if len(cfg.Plans) == 0 {
		cfg.Plans = billing.Plans(func(string) string { return "" })
	}
	s := &Server{
		cfg: cfg, st: st, log: cfg.Logger, now: cfg.Now,
		secure:    cfg.secureCookies(),
		started:   cfg.Now(),
		loginHits: map[string][]time.Time{},
		eventSeen: map[string]struct{}{},
		loaded:    map[string]bundle.Loaded{},
	}
	if cfg.BillingEnabled() {
		s.stripe = &billing.Client{SecretKey: cfg.StripeSecret, BaseURL: cfg.StripeBaseURL}
	}
	pages, err := s.parseTemplates()
	if err != nil {
		return nil, err
	}
	s.pages = pages
	s.csp = s.contentSecurityPolicy()
	s.css = template.CSS(status.StyleSheet() + appCSS)
	return s, nil
}

// contentSecurityPolicy pins the only two inline scripts the pages carry (the
// theme bootstrap and the design system's module) by hash, so the service
// needs no 'unsafe-inline' for scripts and an injected <script> cannot run.
// Styles stay 'unsafe-inline': the fleet tree's filter bar is a generated
// <style> block, the same mechanism fleet.html uses.
func (s *Server) contentSecurityPolicy() string {
	hash := func(js string) string {
		sum := sha256.Sum256([]byte(js))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	formAction := "'self'"
	if s.stripe != nil {
		// Chrome checks redirect targets of a form POST against form-action, and
		// the checkout and portal forms 303 to Stripe's hosted pages.
		formAction += " https://checkout.stripe.com https://billing.stripe.com"
	}
	return strings.Join([]string{
		"default-src 'none'",
		"script-src " + hash(ui.ThemeBoot) + " " + hash(ui.JS),
		"style-src 'unsafe-inline'",
		"img-src data:",
		"form-action " + formAction,
		"base-uri 'none'",
		"frame-ancestors 'none'",
	}, "; ")
}

// Handler returns the service's routes behind the security-header and
// panic-recovery wrappers.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public.
	mux.HandleFunc("GET /{$}", s.handleHome)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /auth/{token}", s.handleAuthConfirm)
	mux.HandleFunc("POST /auth/{token}", s.handleAuth)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /s/{token}", s.handleShare)
	mux.HandleFunc("GET /s/{token}/bundles/{id}/manifest.json", s.handleShareManifest)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	if s.stripe != nil {
		mux.HandleFunc("POST /webhooks/stripe", s.handleStripeWebhook)
	}

	// API (bearer token).
	mux.HandleFunc("POST /api/v1/bundles", s.handleIngest)
	mux.HandleFunc("GET /api/v1/fleet.json", s.handleAPIFleet)

	// App (session cookie).
	mux.HandleFunc("GET /app", s.app(s.handleDashboard))
	mux.HandleFunc("GET /app/hosts", s.app(s.handleHosts))
	mux.HandleFunc("GET /app/hosts/{id}", s.app(s.handleHost))
	mux.HandleFunc("POST /app/hosts/{id}", s.app(s.handleHostUpdate))
	mux.HandleFunc("POST /app/hosts/{id}/key", s.app(s.handleHostRotateKey))
	mux.HandleFunc("GET /app/hosts/{id}/proofs/{proof}", s.app(s.handleProofHistory))
	mux.HandleFunc("GET /app/alerts", s.app(s.handleAlerts))
	mux.HandleFunc("GET /app/settings", s.app(s.handleSettings))
	mux.HandleFunc("POST /app/settings/tokens", s.app(s.handleTokenCreate))
	mux.HandleFunc("POST /app/settings/tokens/{id}/revoke", s.app(s.handleTokenRevoke))
	mux.HandleFunc("POST /app/settings/notify", s.app(s.handleNotify))
	mux.HandleFunc("POST /app/share", s.app(s.handleShareCreate))
	mux.HandleFunc("POST /app/share/{id}/revoke", s.app(s.handleShareRevoke))
	if s.stripe != nil {
		mux.HandleFunc("GET /app/billing", s.app(s.handleBilling))
		mux.HandleFunc("POST /app/billing/checkout", s.app(s.handleBillingCheckout))
		mux.HandleFunc("POST /app/billing/portal", s.app(s.handleBillingPortal))
	}
	return s.wrap(mux)
}

// wrap adds the headers every response carries and turns a handler panic into
// a 500 instead of a dropped connection.
func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", s.csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// Share links and login links carry their secret in the URL; no-referrer
		// keeps it out of any request the page's links lead to.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				// Pattern, not Path: paths can carry share and login secrets.
				s.log.Error("handler panic", "route", r.Pattern, "panic", fmt.Sprint(rec))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

// ---- responses ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// page is what every template receives. Data carries the page-specific value.
type page struct {
	Title     string
	Active    string // nav entry to highlight
	Authed    bool
	Email     string
	CSRF      string
	BillingOn bool
	Flash     string // fixed strings chosen by handlers, never request text
	Error     string
	Data      any

	ThemeBoot template.JS
	CSS       template.CSS
	JS        template.JS
	Mark      template.HTML
	DocsURL   string
}

func (s *Server) newPage(title string, data any) page {
	return page{
		Title: title, Data: data, BillingOn: s.stripe != nil,
		ThemeBoot: template.JS(ui.ThemeBoot), CSS: s.css, JS: template.JS(ui.JS),
		Mark:    inlineMark(),
		DocsURL: docsURL,
	}
}

func inlineMark() template.HTML {
	svg := strings.Replace(ui.Mark, "<svg ", `<svg class="cl-mark" aria-hidden="true" `, 1)
	return template.HTML(strings.TrimSpace(svg)) //nolint:gosec // our own committed asset, not user input
}

// render executes a template into a buffer first so a template error becomes
// a clean 500 rather than a half-written page.
func (s *Server) render(w http.ResponseWriter, status int, name string, p page) {
	t, ok := s.pages[name]
	if !ok {
		s.log.Error("unknown template", "name", name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", p); err != nil {
		s.log.Error("render", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// message renders a small page for an error or a one-line outcome, for
// browser flows where a JSON body would be useless.
func (s *Server) message(w http.ResponseWriter, r *http.Request, status int, title, text string) {
	p := s.newPage(title, text)
	if sc, ok := s.sessionQuiet(r); ok {
		p.Authed, p.Email, p.CSRF = true, sc.User.Email, sc.CSRF
	}
	s.render(w, status, "message.html", p)
}

func (s *Server) parseTemplates() (map[string]*template.Template, error) {
	entries, err := fs.ReadDir(templateFS, "templates")
	if err != nil {
		return nil, err
	}
	out := map[string]*template.Template{}
	for _, e := range entries {
		name := e.Name()
		if name == "base.html" || strings.HasPrefix(name, "_") {
			continue
		}
		t, err := template.New("base").Funcs(s.funcMap()).ParseFS(templateFS,
			"templates/base.html", "templates/_*.html", "templates/"+name)
		if err != nil {
			return nil, fmt.Errorf("server: parse template %s: %w", name, err)
		}
		out[name] = t
	}
	return out, nil
}
