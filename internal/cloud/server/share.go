// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/cloud/store"
)

type shareData struct {
	Token        string
	Scope        string // "Whole fleet" or "Host <name>"
	GeneratedAt  time.Time
	View         fleetView
	Contributors []contributor
}

// resolveShare turns a link secret into its workspace and the host scope it is
// limited to ("" = whole fleet). Unknown, expired and revoked links, and links
// whose host no longer exists, are all the same "not found": the response must
// not tell a guesser which kind of miss it hit.
func (s *Server) resolveShare(token string) (ws store.Workspace, hostRowID, scopeLabel string, ok bool) {
	link, ws, err := s.st.LookupShareLink(token)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("share lookup failed", "err", err)
		}
		return store.Workspace{}, "", "", false
	}
	if link.Scope == "fleet" {
		return ws, "", "Whole fleet", true
	}
	id, isHost := strings.CutPrefix(link.Scope, "host:")
	if !isHost {
		return store.Workspace{}, "", "", false
	}
	h, err := s.st.GetHost(ws.ID, id)
	if err != nil {
		return store.Workspace{}, "", "", false
	}
	return ws, h.ID, "Host " + h.Name, true
}

// handleShare serves both /s/{token} (the page) and /s/{token}.json (the same
// scope in fleet.json shape). A wildcard must be a whole path segment, so the
// ".json" suffix is split off here; tokens are base64url and never contain a dot.
func (s *Server) handleShare(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	asJSON := strings.HasSuffix(token, ".json")
	token = strings.TrimSuffix(token, ".json")

	ws, hostRowID, scope, ok := s.resolveShare(token)
	if !ok {
		s.shareNotFound(w, asJSON)
		return
	}
	view, err := s.buildFleet(ws, hostRowID, false)
	if err != nil {
		s.log.Error("build share fleet failed", "err", err)
		if asJSON {
			jsonError(w, http.StatusInternalServerError, "internal error")
		} else {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if asJSON {
		writeFleetJSON(w, view.Fleet)
		return
	}
	d := shareData{Token: token, Scope: scope, GeneratedAt: view.Fleet.GeneratedAt, View: view, Contributors: view.Contributors}
	// Deliberately not authedPage: a share page carries no workspace name, no
	// email, no nav and no forms, so there is nothing of the workspace to leak.
	s.render(w, http.StatusOK, "share.html", s.newPage("Recovery record", d))
}

func (s *Server) shareNotFound(w http.ResponseWriter, asJSON bool) {
	if asJSON {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	p := s.newPage("Not found", "There is nothing at this address.")
	s.render(w, http.StatusNotFound, "message.html", p)
}

type manifestResponse struct {
	BundleID      string `json:"bundle_id"`
	Host          string `json:"host"`
	GeneratedAt   string `json:"generated_at"`
	ArchiveSHA256 string `json:"archive_sha256"`
	// ManifestJSON and ManifestSig are the exact bytes of the archive's
	// manifest.json and manifest.sig members, base64 so no encoding step can
	// alter the bytes the signature covers.
	ManifestJSON string `json:"manifest_json"`
	ManifestSig  string `json:"manifest_sig"`
	Verify       string `json:"verify"`
}

// handleShareManifest returns the two signed members of one contributing
// bundle: enough to check the Ed25519 signature, and nothing from the
// context files or the ledger slice. Only a bundle currently shown on the
// link's page is served.
func (s *Server) handleShareManifest(w http.ResponseWriter, r *http.Request) {
	ws, hostRowID, _, ok := s.resolveShare(r.PathValue("token"))
	if !ok {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	cands, err := s.latestContributors(ws, hostRowID)
	if err != nil {
		s.log.Error("share contributors failed", "err", err)
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}
	var found *contributor
	for i := range cands {
		if cands[i].Bundle.ID == r.PathValue("id") {
			found = &cands[i]
		}
	}
	if found == nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	archive, err := s.st.ReadBundle(ws.ID, found.Bundle.ID)
	if err != nil {
		s.log.Error("read bundle for share manifest failed", "bundle", found.Bundle.ID, "err", err)
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	manifest, sig, err := signedManifest(archive)
	if err != nil {
		s.log.Error("extract manifest failed", "bundle", found.Bundle.ID, "err", err)
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	writeJSON(w, http.StatusOK, manifestResponse{
		BundleID: found.Bundle.ID, Host: found.Host.Name,
		GeneratedAt:   found.Bundle.GeneratedAt.UTC().Format(time.RFC3339),
		ArchiveSHA256: found.Bundle.SHA256,
		ManifestJSON:  base64.StdEncoding.EncodeToString(manifest),
		ManifestSig:   base64.StdEncoding.EncodeToString(sig),
		Verify:        "Decode both fields from base64. manifest.sig is JSON {public_key, signature} (hex); signature is an Ed25519 signature over the exact decoded manifest_json bytes under public_key.",
	})
}
