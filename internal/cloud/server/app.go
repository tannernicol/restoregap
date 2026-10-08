// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/cloud/store"
)

// banner is the one-line billing notice at the top of the dashboard.
type banner struct {
	Level string // block | warn, the design system's verdict vocabulary
	Title string
	Text  string
}

type dashboardData struct {
	WS          store.Workspace
	Stats       store.Stats
	Banner      *banner
	Lapsed      []store.Host
	View        fleetView
	PushCommand string
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	stats, err := s.st.WorkspaceStats(sc.WS.ID)
	if err != nil {
		s.serverError(w, r, "workspace stats", err)
		return
	}
	hosts, err := s.st.ListHosts(sc.WS.ID)
	if err != nil {
		s.serverError(w, r, "list hosts", err)
		return
	}
	view, err := s.buildFleet(sc.WS, "", true)
	if err != nil {
		s.serverError(w, r, "build fleet", err)
		return
	}
	d := dashboardData{WS: sc.WS, Stats: stats, Banner: s.billingBanner(sc.WS), View: view}
	for _, h := range hosts {
		if h.LapsedAt != nil {
			d.Lapsed = append(d.Lapsed, h)
		}
	}
	d.PushCommand = "restoregap bundle push \\\n  --to " + s.cfg.BaseURL + " \\\n  --token \"$RESTOREGAP_PUSH_TOKEN\" \\\n" +
		"  --context restoregap.yml --ledger ledger.jsonl \\\n  --signing-key \"$RESTOREGAP_SIGNING_SEED\" --since 168h"
	s.render(w, http.StatusOK, "dashboard.html", s.authedPage(sc, "Dashboard", "dashboard", d))
}

// billingBanner explains a workspace that is trialing, or that cannot push.
// It says nothing for active and self-hosted workspaces.
func (s *Server) billingBanner(ws store.Workspace) *banner {
	now := s.now()
	switch ws.BillingStatus {
	case "trialing":
		if ws.TrialEndsAt == nil {
			return nil
		}
		if now.Before(*ws.TrialEndsAt) {
			days := int((ws.TrialEndsAt.Sub(now) + 24*time.Hour - 1) / (24 * time.Hour))
			unit := "days"
			if days == 1 {
				unit = "day"
			}
			return &banner{Level: "warn", Title: "TRIAL",
				Text: fmt.Sprintf("%d %s left in your trial (ends %s).", days, unit, ws.TrialEndsAt.UTC().Format("2006-01-02"))}
		}
		return &banner{Level: "block", Title: "TRIAL ENDED",
			Text: "Your trial has ended, so Cloud is read-only: new bundles are refused until you choose a plan."}
	case "past_due":
		return &banner{Level: "block", Title: "PAYMENT PAST DUE",
			Text: "Cloud is read-only: new bundles are refused until billing is fixed. Everything you have stored is still here."}
	case "canceled":
		return &banner{Level: "block", Title: "CANCELED",
			Text: "The subscription is canceled, so Cloud is read-only: new bundles are refused. Everything you have stored is still here."}
	}
	return nil
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.Error(what+" failed", "route", r.Pattern, "err", err)
	s.message(w, r, http.StatusInternalServerError, "Something went wrong", "That did not work and the error was logged. Try again in a moment.")
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.message(w, r, http.StatusNotFound, "Not found", "There is nothing at that address in this workspace.")
}

// ---- hosts ----

type hostRow struct {
	Host    store.Host
	Bundles int
}

type hostsData struct {
	Rows []hostRow
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	hosts, err := s.st.ListHosts(sc.WS.ID)
	if err != nil {
		s.serverError(w, r, "list hosts", err)
		return
	}
	counts, err := s.st.CountBundlesPerHost(sc.WS.ID)
	if err != nil {
		s.serverError(w, r, "count bundles", err)
		return
	}
	d := hostsData{}
	for _, h := range hosts {
		d.Rows = append(d.Rows, hostRow{Host: h, Bundles: counts[h.ID]})
	}
	s.render(w, http.StatusOK, "hosts.html", s.authedPage(sc, "Hosts", "hosts", d))
}

type hostData struct {
	Host    store.Host
	Bundles []store.Bundle
	Proofs  []store.ProofRow
	Cadence string
	IsOwner bool
	Verify  string
}

// flashFor maps the ?saved= query value a redirect carries to a fixed
// sentence. Request text is never echoed.
func flashFor(r *http.Request) string {
	switch r.URL.Query().Get("saved") {
	case "1":
		return "Saved."
	case "key":
		return "Pinned key replaced. The next bundle must be signed by the new key."
	}
	return ""
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	h, err := s.st.GetHost(sc.WS.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, "get host", err)
		return
	}
	bundles, err := s.st.ListBundles(sc.WS.ID, h.ID, 50)
	if err != nil {
		s.serverError(w, r, "list bundles", err)
		return
	}
	d := hostData{Host: h, Bundles: bundles, Cadence: cadenceValue(h.ExpectedEvery), IsOwner: sc.isOwner(),
		Verify: "restoregap bundle verify --expected-key " + h.PublicKeyHex + " <bundle.tgz>"}
	if len(bundles) > 0 {
		if d.Proofs, err = s.st.ProofsForBundle(sc.WS.ID, bundles[0].ID); err != nil {
			s.serverError(w, r, "list proofs", err)
			return
		}
	}
	p := s.authedPage(sc, h.Name, "hosts", d)
	p.Flash = flashFor(r)
	s.render(w, http.StatusOK, "host.html", p)
}

func (s *Server) handleHostUpdate(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	h, err := s.st.GetHost(sc.WS.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, "get host", err)
		return
	}
	cad, ok := cadenceByValue(r.PostForm.Get("cadence"))
	if !ok {
		s.message(w, r, http.StatusBadRequest, "Bad request", "Choose one of the listed cadences.")
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" || len(name) > 200 {
		s.message(w, r, http.StatusBadRequest, "Bad request", "The host name must be 1 to 200 characters.")
		return
	}
	if name != h.Name {
		if err := s.st.SetHostName(sc.WS.ID, h.ID, name); err != nil {
			s.serverError(w, r, "rename host", err)
			return
		}
	}
	if err := s.st.SetHostExpectedEvery(h.ID, cad.D); err != nil {
		s.serverError(w, r, "set cadence", err)
		return
	}
	http.Redirect(w, r, "/app/hosts/"+h.ID+"?saved=1", http.StatusSeeOther)
}

// handleHostRotateKey replaces a host's pinned key (trust on first use, then
// only an owner can move it). The new key is validated as what it must be: 32
// bytes of hex.
func (s *Server) handleHostRotateKey(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	if !sc.isOwner() {
		s.message(w, r, http.StatusForbidden, "Forbidden", "Only a workspace owner can rotate a host's pinned key.")
		return
	}
	h, err := s.st.GetHost(sc.WS.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, "get host", err)
		return
	}
	key := strings.ToLower(strings.TrimSpace(r.PostForm.Get("public_key")))
	if raw, err := hex.DecodeString(key); err != nil || len(raw) != 32 {
		s.message(w, r, http.StatusBadRequest, "Bad request", "The key must be 64 hexadecimal characters (a 32-byte Ed25519 public key).")
		return
	}
	if err := s.st.SetHostPublicKey(h.ID, key); err != nil {
		s.serverError(w, r, "rotate key", err)
		return
	}
	s.log.Info("host key rotated", "workspace", sc.WS.ID, "host", h.ID, "by", sc.User.ID)
	http.Redirect(w, r, "/app/hosts/"+h.ID+"?saved=key", http.StatusSeeOther)
}

type proofData struct {
	Host    store.Host
	Proof   string
	Rows    []store.ProofRow
	Changes int
	Summary string
}

func (s *Server) handleProofHistory(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	h, err := s.st.GetHost(sc.WS.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, "get host", err)
		return
	}
	proof := r.PathValue("proof")
	rows, err := s.st.ProofHistory(sc.WS.ID, h.ID, proof, 500)
	if err != nil {
		s.serverError(w, r, "proof history", err)
		return
	}
	if len(rows) == 0 {
		s.notFound(w, r)
		return
	}
	changes := 0
	for i := 0; i+1 < len(rows); i++ { // newest first: row i follows row i+1 in time
		if rows[i].State != rows[i+1].State {
			changes++
		}
	}
	d := proofData{Host: h, Proof: proof, Rows: rows, Changes: changes,
		Summary: fmt.Sprintf("state changed %d %s in %d %s", changes, plural(changes, "time", "times"),
			len(rows), plural(len(rows), "bundle", "bundles"))}
	s.render(w, http.StatusOK, "proof.html", s.authedPage(sc, proof, "hosts", d))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// ---- alerts ----

type alertRow struct {
	Alert store.Alert
	Host  store.Host
	Known bool
}

type alertsData struct{ Rows []alertRow }

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	alerts, err := s.st.ListAlerts(sc.WS.ID, 200)
	if err != nil {
		s.serverError(w, r, "list alerts", err)
		return
	}
	hosts, err := s.st.ListHosts(sc.WS.ID)
	if err != nil {
		s.serverError(w, r, "list hosts", err)
		return
	}
	byID := make(map[string]store.Host, len(hosts))
	for _, h := range hosts {
		byID[h.ID] = h
	}
	d := alertsData{}
	for _, a := range alerts {
		h, ok := byID[a.HostRowID]
		d.Rows = append(d.Rows, alertRow{Alert: a, Host: h, Known: ok})
	}
	s.render(w, http.StatusOK, "alerts.html", s.authedPage(sc, "Alerts", "alerts", d))
}
