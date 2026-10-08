// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/bundle"
	"github.com/tannernicol/restoregap/internal/cloud/billing"
	"github.com/tannernicol/restoregap/internal/cloud/store"
	"github.com/tannernicol/restoregap/internal/status"
)

// maxBundleBytes is the compressed body cap docs/CLOUD.md promises. The
// decompressed size is capped separately by bundle.MaxDecompressedBytes.
const maxBundleBytes = 8 << 20

// maxRegressionAlerts bounds the alerts one bundle can raise. A host whose
// whole estate expires at once would otherwise send one email per proof; past
// the cap a single roll-up alert says how many more there were.
const maxRegressionAlerts = 25

// healthyStates are the proof states that mean "provably recoverable, or an
// owner knowingly accepted the gap" (internal/status/layers.go): restored,
// observed (fresh, re-observed evidence) and accepted. A proof regresses when
// it moves from one of these to any state NOT in this set — the four attention
// states (disputed, expired, unreachable, lapsed) and unreviewed. docs/CLOUD.md
// names the destinations "stale, missing, failed or contradicted"; those are
// the spec's words for the same conditions the status package calls expired
// (stale folds into it), unreachable, and disputed. Defining the healthy side
// once, and treating everything else as unhealthy, keeps a state added to
// internal/status later from silently becoming "healthy" here.
var healthyStates = map[string]bool{
	status.StateRestored: true,
	status.StateObserved: true,
	status.StateAccepted: true,
}

func isRegression(prev, cur string) bool { return healthyStates[prev] && !healthyStates[cur] }

// bearer extracts the token from an Authorization: Bearer header.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// apiAuth resolves the bearer token or writes the 401.
func (s *Server) apiAuth(w http.ResponseWriter, r *http.Request) (store.Workspace, bool) {
	tok := bearer(r)
	if tok != "" {
		if _, ws, err := s.st.LookupToken(tok); err == nil {
			return ws, true
		} else if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("token lookup failed", "err", err)
			jsonError(w, http.StatusInternalServerError, "internal error")
			return store.Workspace{}, false
		}
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="restoregap-cloud"`)
	jsonError(w, http.StatusUnauthorized, "unknown or revoked token")
	return store.Workspace{}, false
}

// workspaceActive: ingest needs a paying (or trialing, or self-hosted)
// workspace. Reading stays available in every state so a lapsed customer can
// still see and export what they have.
func (s *Server) workspaceActive(ws store.Workspace) bool {
	switch ws.BillingStatus {
	case "active", "unlimited":
		return true
	case "trialing":
		return ws.TrialEndsAt == nil || s.now().Before(*ws.TrialEndsAt)
	}
	return false
}

// planFor resolves a workspace's plan key to its limits. Configured plans win
// (an operator may have changed them); the built-in table is the fallback.
func (s *Server) planFor(key string) billing.Plan {
	if key == billing.Unlimited.Key {
		return billing.Unlimited
	}
	if p, ok := billing.PlanByKey(s.cfg.Plans, key); ok {
		return p
	}
	if p, ok := billing.PlanByKey(billing.Plans(func(string) string { return "" }), key); ok {
		return p
	}
	return billing.Unlimited
}

type ingestResponse struct {
	BundleID    string `json:"bundle_id"`
	Host        string `json:"host"`
	HostID      string `json:"host_id"`
	GeneratedAt string `json:"generated_at"`
	URL         string `json:"url"`
}

type ingestError struct {
	status int
	msg    string
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.apiAuth(w, r)
	if !ok {
		return
	}
	if !s.workspaceActive(ws) {
		jsonError(w, http.StatusPaymentRequired, "workspace is not active")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBundleBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			jsonError(w, http.StatusRequestEntityTooLarge, "bundle too large")
		} else {
			jsonError(w, http.StatusBadRequest, "could not read request body")
		}
		return
	}
	loaded, err := bundle.LoadVerifiedBytes(body)
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "bundle failed verification: "+verificationReason(err))
		return
	}
	m := loaded.Manifest
	if m.Host.ID == "" || len(m.Host.ID) > 128 || len(m.Host.Name) > 256 {
		jsonError(w, http.StatusUnprocessableEntity, "bundle failed verification: manifest has no usable host id")
		return
	}

	resp, code, ierr := s.ingest(ws, body, loaded)
	if ierr != nil {
		jsonError(w, ierr.status, ierr.msg)
		return
	}
	writeJSON(w, code, resp)
}

// verificationReason turns a bundle package error into the reason a pusher can
// act on: the package's own prefixes are noise, and the staging directory name
// must not leak.
func verificationReason(err error) string {
	msg := scrubPaths(err.Error())
	for _, p := range []string{"bundle: ", "failed verification: ", "bundle verify: "} {
		msg = strings.TrimPrefix(msg, p)
	}
	return msg
}

// ingest stores one verified bundle and raises the alerts it implies. It
// returns the HTTP status to answer with: 201 for a new bundle, 200 for an
// archive this host already pushed.
func (s *Server) ingest(ws store.Workspace, archive []byte, loaded bundle.Loaded) (ingestResponse, int, *ingestError) {
	m := loaded.Manifest
	now := s.now()
	sum := sha256.Sum256(archive)
	sha := hex.EncodeToString(sum[:])
	pub := loaded.Signature.PublicKeyHex

	// The label is only a name for status.FleetRows' SourceBundle column; the
	// stored proof rows do not keep it, and the bundle's own id does not exist
	// until SaveBundle assigns it.
	rows := proofRows(status.VerifiedBundle{Label: sha[:12], Manifest: m, Context: loaded.Context})

	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()

	known := true
	existing, err := s.st.GetHostByHostID(ws.ID, m.Host.ID)
	if errors.Is(err, store.ErrNotFound) {
		known = false
	} else if err != nil {
		s.log.Error("host lookup failed", "err", err)
		return ingestResponse{}, 0, &ingestError{http.StatusInternalServerError, "internal error"}
	}

	if known {
		if existing.PublicKeyHex != pub {
			return ingestResponse{}, 0, &ingestError{http.StatusConflict, keyMismatchMessage(existing)}
		}
		// Same archive again (a retried cron, a double click): answer with the
		// bundle we already hold and change nothing — in particular, do not
		// count a replay as the host being alive.
		bundles, err := s.st.ListBundles(ws.ID, existing.ID, 0)
		if err != nil {
			s.log.Error("list bundles failed", "err", err)
			return ingestResponse{}, 0, &ingestError{http.StatusInternalServerError, "internal error"}
		}
		for _, b := range bundles {
			if b.SHA256 == sha {
				return s.ingestResponse(existing, b), http.StatusOK, nil
			}
		}
	} else {
		plan := s.planFor(ws.Plan)
		n, err := s.st.CountHosts(ws.ID)
		if err != nil {
			s.log.Error("count hosts failed", "err", err)
			return ingestResponse{}, 0, &ingestError{http.StatusInternalServerError, "internal error"}
		}
		if plan.MaxHosts > 0 && n >= plan.MaxHosts {
			return ingestResponse{}, 0, &ingestError{http.StatusConflict,
				fmt.Sprintf("host limit reached (%d of %d on plan %s)", n, plan.MaxHosts, plan.Name)}
		}
	}

	// existing was read BEFORE the upsert on purpose: the upsert clears
	// LapsedAt, and a recovered alert needs to know the host had lapsed.
	host, err := s.st.UpsertHostOnBundle(ws.ID, m.Host.ID, m.Host.Name, m.Epoch, pub, now)
	if errors.Is(err, store.ErrKeyMismatch) {
		pinned, _ := s.st.GetHostByHostID(ws.ID, m.Host.ID)
		return ingestResponse{}, 0, &ingestError{http.StatusConflict, keyMismatchMessage(pinned)}
	}
	if err != nil {
		s.log.Error("upsert host failed", "err", err)
		return ingestResponse{}, 0, &ingestError{http.StatusInternalServerError, "internal error"}
	}

	// Regression detection compares against the bundle just before this one in
	// generation order, and only when this bundle is the host's newest: a late
	// arrival of an old bundle says nothing about the host's state now.
	var prevRows []store.ProofRow
	newest := true
	if known {
		if latest, err := s.st.ListBundles(ws.ID, host.ID, 1); err == nil && len(latest) > 0 && m.GeneratedAt.Before(latest[0].GeneratedAt) {
			newest = false
		}
		if prev, ok, err := s.st.PreviousBundle(ws.ID, host.ID, m.GeneratedAt); err != nil {
			s.log.Error("previous bundle lookup failed", "err", err)
		} else if ok && newest {
			if prevRows, err = s.st.ProofsForBundle(ws.ID, prev.ID); err != nil {
				s.log.Error("previous proofs lookup failed", "err", err)
				prevRows = nil
			}
		}
	}

	saved, err := s.st.SaveBundle(store.Bundle{
		WorkspaceID: ws.ID, HostRowID: host.ID, GeneratedAt: m.GeneratedAt.UTC(), ReceivedAt: now,
		Epoch: m.Epoch, PolicyRevision: m.PolicyRevision,
		PublicKeyHex: pub, SignatureHex: loaded.Signature.SignatureHex,
		Guards: m.Counts.Guards, Proofs: m.Counts.Proofs, LedgerEntries: m.Counts.LedgerEntries,
	}, archive, rows)
	if err != nil {
		s.log.Error("save bundle failed", "err", err)
		return ingestResponse{}, 0, &ingestError{http.StatusInternalServerError, "internal error"}
	}

	if known && newest {
		if existing.LapsedAt != nil {
			s.raise(ws.ID, host.ID, store.AlertRecovered, fmt.Sprintf(
				"host %s is sending again; its previous bundle was received at %s",
				host.Name, existing.LastSeenAt.UTC().Format(time.RFC3339)))
		}
		s.raiseRegressions(ws.ID, host, prevRows, rows)
	}
	return s.ingestResponse(host, saved), http.StatusCreated, nil
}

func keyMismatchMessage(h store.Host) string {
	return fmt.Sprintf("key mismatch: host %s is pinned to key %s…; rotate it in the host's settings",
		h.HostID, shortHex(h.PublicKeyHex, 12))
}

func (s *Server) ingestResponse(h store.Host, b store.Bundle) ingestResponse {
	return ingestResponse{
		BundleID: b.ID, Host: h.Name, HostID: h.HostID,
		GeneratedAt: b.GeneratedAt.UTC().Format(time.RFC3339),
		URL:         s.cfg.BaseURL + "/app/hosts/" + h.ID,
	}
}

// proofRows classifies a bundle's proofs with the same pipeline `status` and
// `bundle merge` use and shapes them for storage. A proof id is the table's
// key within a bundle, so a repeated id keeps its first row.
func proofRows(item status.VerifiedBundle) []store.ProofRow {
	fleetRows := status.FleetRows(item)
	seen := make(map[string]bool, len(fleetRows))
	out := make([]store.ProofRow, 0, len(fleetRows))
	for _, p := range fleetRows {
		if seen[p.Proof] {
			continue
		}
		seen[p.Proof] = true
		out = append(out, store.ProofRow{
			Proof: p.Proof, Layer: p.Layer, Category: p.Category, State: p.State, Level: p.Level, Why: p.Why,
			Host: p.Host, Epoch: p.Epoch, Environment: p.Scope.Environment, System: p.Scope.System,
			Artifact: p.Artifact, GeneratedAt: p.GeneratedAt,
		})
	}
	return out
}

// raiseRegressions compares the new bundle's proofs with the previous
// bundle's and records an alert for each proof that went from healthy to not.
func (s *Server) raiseRegressions(workspaceID string, host store.Host, prev, cur []store.ProofRow) {
	if len(prev) == 0 {
		return
	}
	was := make(map[string]string, len(prev))
	for _, p := range prev {
		was[p.Proof] = p.State
	}
	raised, extra := 0, 0
	for _, p := range cur {
		old, existed := was[p.Proof]
		if !existed || !isRegression(old, p.State) {
			continue
		}
		if raised >= maxRegressionAlerts {
			extra++
			continue
		}
		raised++
		msg := fmt.Sprintf("proof %s on host %s moved from %s to %s", p.Proof, host.Name, old, p.State)
		if p.Why != "" {
			msg += ": " + p.Why
		}
		s.raise(workspaceID, host.ID, store.AlertProofRegressed, msg)
	}
	if extra > 0 {
		s.raise(workspaceID, host.ID, store.AlertProofRegressed,
			fmt.Sprintf("%d more proofs on host %s regressed in the same bundle", extra, host.Name))
	}
}

// raise records an alert. A failure is logged and swallowed: the bundle it
// describes is already stored, and refusing it now would only make the host
// retry the push.
func (s *Server) raise(workspaceID, hostRowID, kind, msg string) {
	if _, err := s.st.CreateAlert(workspaceID, hostRowID, kind, msg); err != nil {
		s.log.Error("create alert failed", "kind", kind, "err", err)
	}
}

func (s *Server) handleAPIFleet(w http.ResponseWriter, r *http.Request) {
	ws, ok := s.apiAuth(w, r)
	if !ok {
		return
	}
	v, err := s.buildFleet(ws, "", false)
	if err != nil {
		s.log.Error("build fleet failed", "err", err)
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeFleetJSON(w, v.Fleet)
}

// writeFleetJSON writes fleet.json exactly as `bundle merge` does (indented).
func writeFleetJSON(w http.ResponseWriter, f status.Fleet) {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(append(raw, '\n'))
}
