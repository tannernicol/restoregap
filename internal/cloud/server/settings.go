// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/cloud/store"
)

type shareRow struct {
	Link  store.ShareLink
	Scope string // human label: "Whole fleet" or the host's name
	State string // active | expired | revoked
}

type shareOption struct {
	Value, Label string
}

type settingsData struct {
	WS      store.Workspace
	Tokens  []store.APIToken
	Links   []shareRow
	Hosts   []store.Host
	Members []store.Member
	// Secrets shown exactly once, on the response to the POST that made them.
	NewToken, NewTokenName string
	NewShareURL            string
	NewWebhookSecret       string
	HasSecret              bool
	MailEnabled            bool
	Expiries               []shareOption
}

var shareExpiries = []struct {
	Value, Label string
	D            time.Duration
}{
	{"none", "never", 0},
	{"1d", "1 day", 24 * time.Hour},
	{"7d", "7 days", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour},
	{"90d", "90 days", 90 * 24 * time.Hour},
}

// settingsPage loads everything the settings page shows. mutate, when given,
// adds the one-time secret of the action that just ran.
func (s *Server) settingsPage(sc *sessionCtx, flash string, mutate func(*settingsData)) (page, error) {
	ws, err := s.st.GetWorkspace(sc.WS.ID) // fresh: the POST that got us here may have changed it
	if err != nil {
		return page{}, err
	}
	tokens, err := s.st.ListTokens(ws.ID)
	if err != nil {
		return page{}, err
	}
	links, err := s.st.ListShareLinks(ws.ID)
	if err != nil {
		return page{}, err
	}
	hosts, err := s.st.ListHosts(ws.ID)
	if err != nil {
		return page{}, err
	}
	members, err := s.st.ListMembers(ws.ID)
	if err != nil {
		return page{}, err
	}
	byID := make(map[string]store.Host, len(hosts))
	for _, h := range hosts {
		byID[h.ID] = h
	}
	now := s.now()
	d := settingsData{WS: ws, Tokens: tokens, Hosts: hosts, Members: members,
		HasSecret: ws.NotifyWebhookSecret != "", MailEnabled: s.cfg.SMTPURL != ""}
	for _, e := range shareExpiries {
		d.Expiries = append(d.Expiries, shareOption{Value: e.Value, Label: e.Label})
	}
	for _, l := range links {
		row := shareRow{Link: l, Scope: "Whole fleet", State: "active"}
		if host, ok := strings.CutPrefix(l.Scope, "host:"); ok {
			if h, found := byID[host]; found {
				row.Scope = "Host " + h.Name
			} else {
				row.Scope = "Host (removed)"
			}
		}
		switch {
		case l.RevokedAt != nil:
			row.State = "revoked"
		case l.ExpiresAt != nil && !now.Before(*l.ExpiresAt):
			row.State = "expired"
		}
		d.Links = append(d.Links, row)
	}
	if mutate != nil {
		mutate(&d)
	}
	sc.WS = ws
	p := s.authedPage(sc, "Settings", "settings", d)
	p.Flash = flash
	return p, nil
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	p, err := s.settingsPage(sc, flashFor(r), nil)
	if err != nil {
		s.serverError(w, r, "settings", err)
		return
	}
	s.render(w, http.StatusOK, "settings.html", p)
}

// handleTokenCreate answers the POST with the page itself, not a redirect:
// the plaintext token exists only in this response.
func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" || len(name) > 100 {
		s.message(w, r, http.StatusBadRequest, "Bad request", "Give the token a name of 1 to 100 characters, such as the host or job that will use it.")
		return
	}
	_, plain, err := s.st.CreateToken(sc.WS.ID, name)
	if err != nil {
		s.serverError(w, r, "create token", err)
		return
	}
	p, err := s.settingsPage(sc, "Token created. Copy it now; it is not shown again.", func(d *settingsData) {
		d.NewToken, d.NewTokenName = plain, name
	})
	if err != nil {
		s.serverError(w, r, "settings", err)
		return
	}
	s.render(w, http.StatusOK, "settings.html", p)
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	// RevokeToken is scoped by workspace, so another tenant's id is just "not found".
	err := s.st.RevokeToken(sc.WS.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, "revoke token", err)
		return
	}
	http.Redirect(w, r, "/app/settings?saved=1", http.StatusSeeOther)
}

// handleNotify saves where alerts go. The webhook secret is never rendered
// back: a blank field keeps the stored secret, and a new or generated one is
// shown once on this response.
func (s *Server) handleNotify(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	email := strings.TrimSpace(r.PostForm.Get("email"))
	if email != "" {
		a, err := mail.ParseAddress(email)
		if err != nil || a.Address != email || len(email) > 254 {
			s.message(w, r, http.StatusBadRequest, "Bad request", "That is not a plain email address.")
			return
		}
	}
	hook := strings.TrimSpace(r.PostForm.Get("webhook_url"))
	if hook != "" {
		if msg := validateWebhookURL(hook); msg != "" {
			s.message(w, r, http.StatusBadRequest, "Bad request", msg)
			return
		}
	}
	secret, shown := sc.WS.NotifyWebhookSecret, ""
	switch {
	case hook == "":
		secret = "" // a secret without a URL to sign for would just linger
	case strings.TrimSpace(r.PostForm.Get("webhook_secret")) != "":
		secret = strings.TrimSpace(r.PostForm.Get("webhook_secret"))
		if len(secret) < 16 || len(secret) > 200 {
			s.message(w, r, http.StatusBadRequest, "Bad request", "A webhook secret must be 16 to 200 characters. Leave it blank to have one generated.")
			return
		}
		shown = secret
	case secret == "" || r.PostForm.Get("regenerate") == "1":
		gen, err := randomToken()
		if err != nil {
			s.serverError(w, r, "generate webhook secret", err)
			return
		}
		secret, shown = gen, gen
	}
	if err := s.st.UpdateWorkspaceNotify(sc.WS.ID, email, hook, secret); err != nil {
		s.serverError(w, r, "save notify", err)
		return
	}
	p, err := s.settingsPage(sc, "Notification settings saved.", func(d *settingsData) { d.NewWebhookSecret = shown })
	if err != nil {
		s.serverError(w, r, "settings", err)
		return
	}
	s.render(w, http.StatusOK, "settings.html", p)
}

// validateWebhookURL returns a user-facing problem, or "" when the URL is
// acceptable. Credentials in the URL are refused because alerts are logged and
// shown with it; the secret field is the supported way to authenticate.
func validateWebhookURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || len(raw) > 2000 {
		return "The webhook URL must be an absolute http:// or https:// URL."
	}
	if u.User != nil {
		return "Leave credentials out of the webhook URL; use the secret field to sign deliveries."
	}
	return ""
}

func (s *Server) handleShareCreate(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	scope := r.PostForm.Get("scope")
	if scope != "fleet" {
		id, ok := strings.CutPrefix(scope, "host:")
		if !ok {
			s.message(w, r, http.StatusBadRequest, "Bad request", "Choose the whole fleet or one host.")
			return
		}
		if _, err := s.st.GetHost(sc.WS.ID, id); errors.Is(err, store.ErrNotFound) {
			s.message(w, r, http.StatusBadRequest, "Bad request", "That host is not in this workspace.")
			return
		} else if err != nil {
			s.serverError(w, r, "get host", err)
			return
		}
	}
	var expires *time.Time
	valid := false
	for _, e := range shareExpiries {
		if e.Value == r.PostForm.Get("expires") {
			valid = true
			if e.D > 0 {
				t := s.now().Add(e.D)
				expires = &t
			}
		}
	}
	if !valid {
		s.message(w, r, http.StatusBadRequest, "Bad request", "Choose one of the listed expiries.")
		return
	}
	_, plain, err := s.st.CreateShareLink(sc.WS.ID, scope, expires)
	if err != nil {
		s.serverError(w, r, "create share link", err)
		return
	}
	link := s.cfg.BaseURL + "/s/" + plain
	p, err := s.settingsPage(sc, "Share link created. Copy it now; it is not shown again.", func(d *settingsData) { d.NewShareURL = link })
	if err != nil {
		s.serverError(w, r, "settings", err)
		return
	}
	s.render(w, http.StatusOK, "settings.html", p)
}

func (s *Server) handleShareRevoke(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	err := s.st.RevokeShareLink(sc.WS.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, "revoke share link", err)
		return
	}
	http.Redirect(w, r, "/app/settings?saved=1", http.StatusSeeOther)
}
