// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"

	"github.com/tannernicol/restoregap/internal/bundle"
	"github.com/tannernicol/restoregap/internal/cloud/store"
	"github.com/tannernicol/restoregap/internal/status"
)

// maxLoadedCache bounds the verified-archive cache. Archives never change once
// stored, so entries never go stale; the bound only limits memory.
const maxLoadedCache = 256

// contributor is one host's latest bundle as the fleet view uses it.
type contributor struct {
	Host   store.Host
	Bundle store.Bundle
	Label  string // unique within the view; what the bundle is merged under
}

// fleetView is a workspace's merged latest-per-host fleet plus what a page
// needs to link rows back to hosts and to list the contributing bundles.
type fleetView struct {
	Fleet        status.Fleet
	Page         status.FleetPageData
	Contributors []contributor
	Links        map[string]string // merge label -> host row id; nil on share pages
	Skipped      int               // hosts whose latest archive could not be loaded
	Empty        bool
}

// loadBundle verifies and decodes a stored archive, caching the result by
// bundle id. Verification runs again here rather than trusting the database:
// the archive file is what a reader is shown, so it is what gets checked.
func (s *Server) loadBundle(workspaceID string, b store.Bundle) (bundle.Loaded, error) {
	s.loadMu.Lock()
	if l, ok := s.loaded[b.ID]; ok {
		s.loadMu.Unlock()
		return l, nil
	}
	s.loadMu.Unlock()

	archive, err := s.st.ReadBundle(workspaceID, b.ID)
	if err != nil {
		return bundle.Loaded{}, err
	}
	l, err := bundle.LoadVerifiedBytes(archive)
	if err != nil {
		return bundle.Loaded{}, err
	}
	s.loadMu.Lock()
	if len(s.loaded) >= maxLoadedCache {
		s.loaded = map[string]bundle.Loaded{}
	}
	s.loaded[b.ID] = l
	s.loadMu.Unlock()
	return l, nil
}

// latestContributors lists each host's newest bundle (only hostRowID's when
// set), labelled by host name, made unique with a short id suffix when two
// hosts share a name so a rendered row traces back to exactly one host. It
// reads rows only; no archive is opened.
func (s *Server) latestContributors(ws store.Workspace, hostRowID string) ([]contributor, error) {
	latest, err := s.st.LatestBundlePerHost(ws.ID)
	if err != nil {
		return nil, err
	}
	hosts, err := s.st.ListHosts(ws.ID)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]store.Host, len(hosts))
	nameCount := map[string]int{}
	for _, h := range hosts {
		byID[h.ID] = h
		nameCount[h.Name]++
	}
	var out []contributor
	for _, b := range latest {
		if hostRowID != "" && b.HostRowID != hostRowID {
			continue
		}
		h, ok := byID[b.HostRowID]
		if !ok {
			continue
		}
		label := h.Name
		if nameCount[h.Name] > 1 {
			label = fmt.Sprintf("%s (%s)", h.Name, shortHex(h.ID, 6))
		}
		out = append(out, contributor{Host: h, Bundle: b, Label: label})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}

// buildFleet merges every host's latest bundle (or only hostRowID's when set)
// through status.MergeVerified, the same merge `restoregap bundle merge` uses.
func (s *Server) buildFleet(ws store.Workspace, hostRowID string, withLinks bool) (fleetView, error) {
	cands, err := s.latestContributors(ws, hostRowID)
	if err != nil {
		return fleetView{}, err
	}
	var v fleetView
	var items []status.VerifiedBundle
	for _, c := range cands {
		l, err := s.loadBundle(ws.ID, c.Bundle)
		if err != nil {
			// One unreadable archive must not blank the whole fleet.
			s.log.Error("load bundle for fleet view", "bundle", c.Bundle.ID, "host", c.Host.ID, "err", err)
			v.Skipped++
			continue
		}
		manifest := l.Manifest
		// Show the owner's chosen name (store.SetHostName), not the machine's.
		// This changes only the in-memory copy; the stored archive and its
		// signature are untouched.
		manifest.Host.Name = c.Host.Name
		items = append(items, status.VerifiedBundle{Label: c.Label, Manifest: manifest, Context: l.Context})
		v.Contributors = append(v.Contributors, c)
	}
	if len(items) == 0 {
		v.Empty = true
		v.Fleet = status.Fleet{GeneratedAt: s.now(), Bundles: []status.FleetBundleInfo{},
			Proofs: []status.FleetProof{}, Conflicts: []status.FleetConflict{}}
		return v, nil
	}
	fleet, err := status.MergeVerified(items, s.now())
	if err != nil {
		return fleetView{}, err
	}
	if fleet.Bundles == nil {
		fleet.Bundles = []status.FleetBundleInfo{}
	}
	if fleet.Proofs == nil {
		fleet.Proofs = []status.FleetProof{}
	}
	if fleet.Conflicts == nil {
		fleet.Conflicts = []status.FleetConflict{}
	}
	v.Fleet = fleet
	v.Page = fleet.PageData()
	if withLinks {
		v.Links = make(map[string]string, len(v.Contributors))
		for _, c := range v.Contributors {
			v.Links[c.Label] = c.Host.ID
		}
	}
	return v, nil
}

// tempPathRE matches the private directory bundle.LoadVerifiedBytes stages
// context files in; it appears in merge errors and must not reach a caller.
var tempPathRE = regexp.MustCompile(`\S*restoregap-bundle-ctx-\d+[/\\]?`)

// scrubPaths removes the service's temp directory names from an error string.
func scrubPaths(msg string) string { return tempPathRE.ReplaceAllString(msg, "") }

// signedManifest returns the exact bytes of manifest.json and manifest.sig
// from a stored archive: the two members a reader needs to check the signing
// key's signature, and nothing else. Neither carries context file contents —
// the manifest holds file names and SHA-256 digests (bundle.Manifest
// ContextFiles, LedgerSlice), evidence metadata (path, size, hash) and counts;
// the context files and ledger slice are separate tar members that are never
// read here.
func signedManifest(archive []byte) (manifest, sig []byte, err error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	const maxMember = 4 << 20 // a manifest is kilobytes; this only bounds a hostile one
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if hdr.Typeflag != tar.TypeReg || (hdr.Name != "manifest.json" && hdr.Name != "manifest.sig") {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxMember+1))
		if err != nil {
			return nil, nil, err
		}
		if len(data) > maxMember {
			return nil, nil, fmt.Errorf("%s is larger than %d bytes", hdr.Name, maxMember)
		}
		if hdr.Name == "manifest.json" {
			manifest = data
		} else {
			sig = data
		}
	}
	if manifest == nil || sig == nil {
		return nil, nil, errors.New("archive lacks manifest.json or manifest.sig")
	}
	return manifest, sig, nil
}
