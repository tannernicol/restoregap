// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/cloud/notify"
	"github.com/tannernicol/restoregap/internal/cloud/store"
)

const (
	sessionCookie = "rg_session"
	csrfCookie    = "rg_csrf"
	sessionTTL    = 30 * 24 * time.Hour
	loginTokenTTL = 15 * time.Minute

	// At most loginLimit link requests per address per loginWindow. Past that
	// the page still answers the same way, so the limit leaks nothing either.
	loginLimit  = 5
	loginWindow = 15 * time.Minute
	// loginTrackMax bounds the in-memory limiter so a flood of distinct
	// addresses cannot grow it without limit.
	loginTrackMax = 10000

	maxFormBytes = 1 << 20
)

// sessionCtx is everything an app handler knows about the caller.
type sessionCtx struct {
	Sess store.Session
	User store.User
	WS   store.Workspace
	Role string
	CSRF string
}

func (sc *sessionCtx) isOwner() bool { return sc.Role == "owner" }

func (s *Server) cookie(name, value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteLaxMode,
	}
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// lookupSession resolves the session cookie to a session, its user, its
// workspace and the user's role there. Any failure is simply "not logged in".
func (s *Server) lookupSession(r *http.Request) (*sessionCtx, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, false
	}
	sess, err := s.st.LookupSession(c.Value, s.now())
	if err != nil {
		return nil, false
	}
	user, err := s.st.GetUser(sess.UserID)
	if err != nil {
		return nil, false
	}
	ws, err := s.st.GetWorkspace(sess.WorkspaceID)
	if err != nil {
		return nil, false
	}
	m, err := s.st.GetMembership(ws.ID, user.ID)
	if err != nil {
		return nil, false
	}
	sc := &sessionCtx{Sess: sess, User: user, WS: ws, Role: m.Role}
	if cc, err := r.Cookie(csrfCookie); err == nil {
		sc.CSRF = cc.Value
	}
	return sc, true
}

// sessionQuiet is lookupSession for pages that only want to know who is
// looking (error pages) and must not set cookies.
func (s *Server) sessionQuiet(r *http.Request) (*sessionCtx, bool) { return s.lookupSession(r) }

// app wraps a handler that needs a logged-in caller. Unauthenticated callers
// go to the home page; every POST must carry the CSRF token the forms render,
// compared in constant time against the rg_csrf cookie.
func (s *Server) app(h func(http.ResponseWriter, *http.Request, *sessionCtx)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sc, ok := s.lookupSession(r)
		if !ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if sc.CSRF == "" {
			// A session older than the CSRF cookie (or one whose cookie was
			// cleared): mint a fresh value. It cannot match a form rendered
			// before, which is the point.
			tok, err := randomToken()
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			sc.CSRF = tok
			http.SetCookie(w, s.cookie(csrfCookie, tok, sessionTTL))
		}
		if r.Method == http.MethodPost {
			if !s.checkCSRF(w, r, sc) {
				return
			}
		}
		h(w, r, sc)
	}
}

// checkCSRF parses the form and verifies the token. It reports false after
// writing the error response.
func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request, sc *sessionCtx) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			s.message(w, r, http.StatusRequestEntityTooLarge, "Too large", "That request is too large.")
		} else {
			s.message(w, r, http.StatusBadRequest, "Bad request", "That request could not be read.")
		}
		return false
	}
	got := r.PostForm.Get("csrf")
	// A zero-length token must never match, even against a zero-length cookie.
	if sc.CSRF == "" || got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sc.CSRF)) != 1 {
		s.message(w, r, http.StatusForbidden, "Forbidden", "The form's security token is missing or stale. Reload the page and try again.")
		return false
	}
	return true
}

// authedPage returns a page pre-filled with what the app shell needs.
func (s *Server) authedPage(sc *sessionCtx, title, active string, data any) page {
	p := s.newPage(title, data)
	p.Authed, p.Active, p.Email, p.CSRF = true, active, sc.User.Email, sc.CSRF
	return p
}

// ---- public pages ----

type homeData struct{ AllowSignup bool }

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.lookupSession(r); ok {
		http.Redirect(w, r, "/app", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "home.html", s.newPage("Sign in", homeData{AllowSignup: s.cfg.AllowSignup}))
}

// handleLogin always answers with the same page. Whether the address is
// valid, known, rate limited or mailed is invisible to the caller, so the
// form cannot be used to find out who has an account.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err == nil {
		if email, ok := normalizeLoginEmail(r.PostForm.Get("email")); ok && s.allowLogin(email) {
			s.sendLogin(email)
		}
	}
	s.render(w, http.StatusOK, "login_sent.html", s.newPage("Check your email", nil))
}

// normalizeLoginEmail accepts a bare address only: no display name, no list,
// bounded length.
func normalizeLoginEmail(raw string) (string, bool) {
	e := strings.ToLower(strings.TrimSpace(raw))
	if e == "" || len(e) > 254 {
		return "", false
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e {
		return "", false
	}
	return e, true
}

// allowLogin is the in-memory limiter: loginLimit requests per address per
// loginWindow. It resets on restart, which is fine for what it protects (a
// mailbox from being flooded), and is bounded in size.
func (s *Server) allowLogin(email string) bool {
	now := s.now()
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if len(s.loginHits) >= loginTrackMax {
		for k, hits := range s.loginHits {
			if len(recentHits(hits, now)) == 0 {
				delete(s.loginHits, k)
			}
		}
		if len(s.loginHits) >= loginTrackMax {
			return false
		}
	}
	hits := recentHits(s.loginHits[email], now)
	if len(hits) >= loginLimit {
		s.loginHits[email] = hits
		return false
	}
	s.loginHits[email] = append(hits, now)
	return true
}

func recentHits(hits []time.Time, now time.Time) []time.Time {
	out := hits[:0:0]
	for _, t := range hits {
		if now.Sub(t) < loginWindow {
			out = append(out, t)
		}
	}
	return out
}

// sendLogin mints a link and delivers it: by email when SMTP is configured,
// otherwise to the log (the documented dev mode).
func (s *Server) sendLogin(email string) {
	if !s.cfg.AllowSignup {
		// Closed instance: only addresses that already have an account get a
		// link. The page the caller sees is identical either way.
		if _, err := s.st.UserByEmail(email); errors.Is(err, store.ErrNotFound) {
			s.log.Info("login requested for an unknown address while signup is closed; no link sent")
			return
		} else if err != nil {
			s.log.Error("login lookup failed", "err", err)
			return
		}
	}
	tok, err := s.st.CreateLoginToken(email, loginTokenTTL)
	if err != nil {
		s.log.Error("create login token failed", "err", err)
		return
	}
	link := s.cfg.BaseURL + "/auth/" + tok
	if s.cfg.SMTPURL == "" {
		s.log.Info("login link: "+link, "email", email)
		return
	}
	// Off the request path: an SMTP relay can take seconds, and a fast reply
	// for unknown addresses versus a slow one for known ones would be a tell.
	// Every valid request is mailed, so timing carries nothing either way.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		err := notify.Email{SMTPURL: s.cfg.SMTPURL, To: email}.Send(ctx, notify.Message{
			Subject: "Your Restore Gap Cloud sign-in link",
			Text: "Open this link within 15 minutes to sign in to Restore Gap Cloud:\n\n" + link +
				"\n\nIf you did not ask for it, ignore this message; nothing happens until the link is opened.\n",
			Kind: "login",
		})
		if err != nil {
			s.log.Error("send login email failed", "err", err) // never logs the link
		}
	}()
}

// handleAuthConfirm answers GET /auth/{token} with a page whose one button
// POSTs back to the same path. It deliberately reads nothing: mail scanners and
// link previewers fetch every URL in a message, and a GET that consumed the
// token would burn the link before its owner clicked it.
func (s *Server) handleAuthConfirm(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "auth_confirm.html", s.newPage("Sign in", r.PathValue("token")))
}

// handleAuth is POST /auth/{token}: it consumes a login link, creates the
// account on first use, and starts a session.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	user, err := s.st.ConsumeLoginToken(r.PathValue("token"), now)
	if errors.Is(err, store.ErrNotFound) {
		s.message(w, r, http.StatusBadRequest, "Link expired", "This sign-in link is invalid, already used, or older than 15 minutes. Request a new one from the home page.")
		return
	}
	if err != nil {
		s.log.Error("consume login token failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	wss, err := s.st.WorkspacesForUser(user.ID)
	if err != nil {
		s.log.Error("list workspaces failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var ws store.Workspace
	switch {
	case len(wss) > 0:
		ws = wss[0]
	case !s.cfg.AllowSignup:
		s.message(w, r, http.StatusForbidden, "Signup is closed", "This Restore Gap Cloud does not accept new workspaces. Ask its operator to create one for you.")
		return
	default:
		ws, err = s.createWorkspaceFor(user, now)
		if err != nil {
			s.log.Error("create workspace failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	secret, err := s.st.CreateSession(user.ID, ws.ID, sessionTTL)
	csrf, err2 := randomToken()
	if err != nil || err2 != nil {
		s.log.Error("create session failed", "err", errors.Join(err, err2))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, s.cookie(sessionCookie, secret, sessionTTL))
	http.SetCookie(w, s.cookie(csrfCookie, csrf, sessionTTL))
	http.Redirect(w, r, "/app", http.StatusSeeOther)
}

// createWorkspaceFor is first-login signup: with Stripe configured the new
// workspace starts a Team trial; without it, it is the one unlimited
// workspace a self-hoster gets (docs/CLOUD.md "Plans").
func (s *Server) createWorkspaceFor(u store.User, now time.Time) (store.Workspace, error) {
	name := u.Email + "'s workspace"
	if s.stripe == nil {
		return s.st.CreateWorkspace(name, "unlimited", "unlimited", nil, u.ID)
	}
	end := now.Add(time.Duration(s.cfg.TrialDays) * 24 * time.Hour)
	return s.st.CreateWorkspace(name, "team", "trialing", &end, u.ID)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.lookupSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.checkCSRF(w, r, sc) {
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := s.st.DeleteSession(c.Value); err != nil {
			s.log.Error("delete session failed", "err", err)
		}
	}
	http.SetCookie(w, s.cookie(sessionCookie, "", -1))
	http.SetCookie(w, s.cookie(csrfCookie, "", -1))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
