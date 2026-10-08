// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustWS(t *testing.T, s *Store, name string) Workspace {
	t.Helper()
	ws, err := s.CreateWorkspace(name, "team", "active", nil, "")
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	return ws
}

func mustHost(t *testing.T, s *Store, ws Workspace, hostID string) Host {
	t.Helper()
	h, err := s.UpsertHostOnBundle(ws.ID, hostID, hostID, "e1", "key-"+hostID, time.Now().UTC())
	if err != nil {
		t.Fatalf("UpsertHostOnBundle: %v", err)
	}
	return h
}

func saveAt(t *testing.T, s *Store, h Host, gen time.Time, proofs ...ProofRow) Bundle {
	t.Helper()
	b, err := s.SaveBundle(Bundle{
		WorkspaceID: h.WorkspaceID, HostRowID: h.ID, GeneratedAt: gen, ReceivedAt: gen,
		PublicKeyHex: h.PublicKeyHex, SignatureHex: "sig", Proofs: len(proofs),
	}, []byte("archive-"+gen.Format(time.RFC3339Nano)), proofs)
	if err != nil {
		t.Fatalf("SaveBundle: %v", err)
	}
	return b
}

func TestMigrationsIdempotentOnReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ws := mustWS(t, s, "acme")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		s, err = Open(dir)
		if err != nil {
			t.Fatalf("reopen %d: %v", i, err)
		}
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&n); err != nil || n != len(migrations) {
			t.Fatalf("schema_version rows = %d, %v; want %d", n, err, len(migrations))
		}
		if _, err := s.GetWorkspace(ws.ID); err != nil {
			t.Fatalf("data lost across reopen: %v", err)
		}
		var fk int
		if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
			t.Fatalf("foreign_keys = %d, %v", fk, err)
		}
		var mode string
		if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
			t.Fatalf("journal_mode = %q, %v", mode, err)
		}
		_ = s.Close()
	}
	if fi, err := os.Stat(filepath.Join(dir, "cloud.db")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cloud.db mode = %v, %v; want 0600", fi.Mode().Perm(), err)
	}
}

// allDBBytes reads the main db and its WAL: committed rows may live only in
// the WAL until a checkpoint.
func allDBBytes(t *testing.T, s *Store) []byte {
	t.Helper()
	var all []byte
	for _, suffix := range []string{"", "-wal"} {
		b, err := os.ReadFile(filepath.Join(s.DataDir(), "cloud.db"+suffix))
		if err == nil {
			all = append(all, b...)
		}
	}
	return all
}

func TestTokenLifecycleAndNoPlaintextAtRest(t *testing.T) {
	s := openTemp(t)
	ws := mustWS(t, s, "acme")
	tok, plain, err := s.CreateToken(ws.ID, "ci")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, "rgp_") || len(plain) != 4+43 {
		t.Fatalf("plaintext shape wrong: %q", plain)
	}
	if tok.Prefix != plain[:8] {
		t.Fatalf("prefix = %q, want %q", tok.Prefix, plain[:8])
	}
	if bytes.Contains(allDBBytes(t, s), []byte(plain)) {
		t.Fatal("plaintext token found in database bytes")
	}
	if bytes.Contains(allDBBytes(t, s), []byte(plain[8:])) {
		t.Fatal("token body found in database bytes")
	}

	got, gotWS, err := s.LookupToken(plain)
	if err != nil {
		t.Fatalf("LookupToken: %v", err)
	}
	if got.ID != tok.ID || gotWS.ID != ws.ID || got.LastUsedAt == nil {
		t.Fatalf("lookup = %+v, ws %q", got, gotWS.ID)
	}
	if _, _, err := s.LookupToken(plain + "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown token err = %v", err)
	}
	other := mustWS(t, s, "other")
	if err := s.RevokeToken(other.ID, tok.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-workspace revoke err = %v", err)
	}
	if _, _, err := s.LookupToken(plain); err != nil {
		t.Fatalf("cross-workspace revoke must not disable the token: %v", err)
	}
	if err := s.RevokeToken(ws.ID, tok.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(ws.ID, tok.ID); err != nil {
		t.Fatalf("second revoke should be idempotent: %v", err)
	}
	if _, _, err := s.LookupToken(plain); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked token err = %v", err)
	}
	if err := s.RevokeToken(ws.ID, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke unknown err = %v", err)
	}
	list, err := s.ListTokens(ws.ID)
	if err != nil || len(list) != 1 || list[0].RevokedAt == nil {
		t.Fatalf("ListTokens = %+v, %v", list, err)
	}
}

func TestHostTOFUAndKeyMismatch(t *testing.T) {
	s := openTemp(t)
	ws := mustWS(t, s, "acme")
	t0 := time.Now().UTC().Truncate(time.Second)

	h, err := s.UpsertHostOnBundle(ws.ID, "web-1", "web-1", "e1", "aa", t0)
	if err != nil {
		t.Fatal(err)
	}
	if h.PublicKeyHex != "aa" || !h.FirstSeenAt.Equal(t0) {
		t.Fatalf("first sight = %+v", h)
	}
	if err := s.MarkHostLapsed(h.ID, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertHostOnBundle(ws.ID, "web-1", "web-1", "e1", "bb", t0.Add(2*time.Hour)); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("mismatch err = %v", err)
	}
	if got, _ := s.GetHost(ws.ID, h.ID); got.LapsedAt == nil || got.PublicKeyHex != "aa" {
		t.Fatalf("mismatch must not change the host: %+v", got)
	}
	h2, err := s.UpsertHostOnBundle(ws.ID, "web-1", "web-one", "e2", "aa", t0.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if h2.ID != h.ID || h2.Name != "web-one" || h2.Epoch != "e2" || h2.LapsedAt != nil ||
		!h2.LastSeenAt.Equal(t0.Add(3*time.Hour)) || !h2.FirstSeenAt.Equal(t0) {
		t.Fatalf("second sight = %+v", h2)
	}
	// An older bundle arriving late must not move last-seen backwards.
	h3, _ := s.UpsertHostOnBundle(ws.ID, "web-1", "web-one", "e2", "aa", t0)
	if !h3.LastSeenAt.Equal(t0.Add(3 * time.Hour)) {
		t.Fatalf("last seen moved backwards: %v", h3.LastSeenAt)
	}

	if err := s.SetHostPublicKey(h.ID, "bb"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertHostOnBundle(ws.ID, "web-1", "web-one", "e2", "bb", t0.Add(4*time.Hour)); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if err := s.SetHostExpectedEvery(h.ID, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetHostByHostID(ws.ID, "web-1"); got.ExpectedEvery != 24*time.Hour {
		t.Fatalf("expected every = %v", got.ExpectedEvery)
	}

	// Same host id in another workspace is a different host with its own key.
	ws2 := mustWS(t, s, "other")
	if _, err := s.UpsertHostOnBundle(ws2.ID, "web-1", "web-1", "e1", "cc", t0); err != nil {
		t.Fatalf("same host id in other workspace: %v", err)
	}
	if n, _ := s.CountHosts(ws.ID); n != 1 {
		t.Fatalf("CountHosts = %d", n)
	}
	if _, err := s.GetHost(ws2.ID, h.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-workspace GetHost err = %v", err)
	}
}

func TestSaveBundleWritesFileAndProofRows(t *testing.T) {
	s := openTemp(t)
	ws := mustWS(t, s, "acme")
	h := mustHost(t, s, ws, "web-1")
	gen := time.Date(2026, 5, 1, 12, 0, 0, 500, time.UTC)

	b := saveAt(t, s, h, gen,
		ProofRow{Proof: "db", State: "healthy", Layer: "data", Why: "ok"},
		ProofRow{Proof: "files", State: "stale"})
	if len(b.ID) != 32 || b.SizeBytes == 0 || len(b.SHA256) != 64 {
		t.Fatalf("bundle = %+v", b)
	}
	path := s.BundlePath(b)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode = %v", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
	data, err := s.ReadBundle(ws.ID, b.ID)
	if err != nil || !strings.HasPrefix(string(data), "archive-") {
		t.Fatalf("ReadBundle = %q, %v", data, err)
	}
	if _, err := s.ReadBundle(ws.ID, "../../etc/passwd"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("traversal id err = %v", err)
	}
	ws2 := mustWS(t, s, "other")
	if _, err := s.ReadBundle(ws2.ID, b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-workspace read err = %v", err)
	}

	got, err := s.GetBundle(ws.ID, b.ID)
	if err != nil || !got.GeneratedAt.Equal(gen) {
		t.Fatalf("GetBundle = %+v, %v", got, err)
	}
	rows, err := s.ProofsForBundle(ws.ID, b.ID)
	if err != nil || len(rows) != 2 || rows[0].Proof != "db" || rows[0].Why != "ok" ||
		rows[0].BundleID != b.ID || rows[0].HostRowID != h.ID || !rows[0].GeneratedAt.Equal(gen) {
		t.Fatalf("proof rows = %+v, %v", rows, err)
	}

	// A host from another workspace is refused and leaves no file behind.
	h2 := mustHost(t, s, ws2, "db-1")
	_, err = s.SaveBundle(Bundle{WorkspaceID: ws.ID, HostRowID: h2.ID, GeneratedAt: gen}, []byte("x"), nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant save err = %v", err)
	}
	if es, _ := os.ReadDir(filepath.Dir(path)); len(es) != 1 {
		t.Fatalf("failed save left files: %v", es)
	}
	// A duplicate proof name rolls the whole bundle back, file included.
	_, err = s.SaveBundle(Bundle{WorkspaceID: ws.ID, HostRowID: h.ID, GeneratedAt: gen}, []byte("y"),
		[]ProofRow{{Proof: "p"}, {Proof: "p"}})
	if err == nil {
		t.Fatal("duplicate proof accepted")
	}
	if es, _ := os.ReadDir(filepath.Dir(path)); len(es) != 1 {
		t.Fatalf("rolled-back save left files: %v", es)
	}
	if n, _ := s.ListBundles(ws.ID, "", 0); len(n) != 1 {
		t.Fatalf("rolled-back save left rows: %d", len(n))
	}
}

func TestLatestPreviousListAndProofHistory(t *testing.T) {
	s := openTemp(t)
	ws := mustWS(t, s, "acme")
	a, b := mustHost(t, s, ws, "a"), mustHost(t, s, ws, "b")
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	a1 := saveAt(t, s, a, base, ProofRow{Proof: "db", State: "healthy"})
	a2 := saveAt(t, s, a, base.Add(time.Hour+500*time.Millisecond), ProofRow{Proof: "db", State: "failed"})
	a3 := saveAt(t, s, a, base.Add(2*time.Hour), ProofRow{Proof: "db", State: "healthy"})
	b1 := saveAt(t, s, b, base.Add(30*time.Minute))

	latest, err := s.LatestBundlePerHost(ws.ID)
	if err != nil || len(latest) != 2 {
		t.Fatalf("latest = %+v, %v", latest, err)
	}
	ids := map[string]string{}
	for _, l := range latest {
		ids[l.HostRowID] = l.ID
	}
	if ids[a.ID] != a3.ID || ids[b.ID] != b1.ID {
		t.Fatalf("latest ids = %v", ids)
	}

	prev, ok, err := s.PreviousBundle(ws.ID, a.ID, a3.GeneratedAt)
	if err != nil || !ok || prev.ID != a2.ID {
		t.Fatalf("previous = %+v ok=%v err=%v", prev, ok, err)
	}
	if _, ok, _ := s.PreviousBundle(ws.ID, a.ID, a1.GeneratedAt); ok {
		t.Fatal("no bundle precedes the first")
	}

	list, _ := s.ListBundles(ws.ID, a.ID, 2)
	if len(list) != 2 || list[0].ID != a3.ID || list[1].ID != a2.ID {
		t.Fatalf("ListBundles = %+v", list)
	}
	if all, _ := s.ListBundles(ws.ID, "", 0); len(all) != 4 {
		t.Fatalf("all bundles = %d", len(all))
	}

	hist, err := s.ProofHistory(ws.ID, a.ID, "db", 0)
	if err != nil || len(hist) != 3 || hist[0].State != "healthy" || hist[1].State != "failed" {
		t.Fatalf("history = %+v, %v", hist, err)
	}
	if hist, _ = s.ProofHistory(ws.ID, a.ID, "db", 1); len(hist) != 1 {
		t.Fatalf("limited history = %d", len(hist))
	}

	st, err := s.WorkspaceStats(ws.ID)
	if err != nil || st.Hosts != 2 || st.Bundles != 4 || st.LastBundleAt == nil || !st.LastBundleAt.Equal(a3.ReceivedAt) {
		t.Fatalf("stats = %+v, %v", st, err)
	}
}

func TestShareLinkExpiryAndRevocation(t *testing.T) {
	s := openTemp(t)
	ws := mustWS(t, s, "acme")
	h := mustHost(t, s, ws, "a")

	future := time.Now().UTC().Add(time.Hour)
	link, plain, err := s.CreateShareLink(ws.ID, "host:"+h.ID, &future)
	if err != nil {
		t.Fatal(err)
	}
	if link.Token != plain || bytes.Contains(allDBBytes(t, s), []byte(plain)) {
		t.Fatal("share token plaintext stored or not returned")
	}
	got, gotWS, err := s.LookupShareLink(plain)
	if err != nil || got.ID != link.ID || gotWS.ID != ws.ID || got.Token != "" {
		t.Fatalf("lookup = %+v ws=%q err=%v", got, gotWS.ID, err)
	}

	past := time.Now().UTC().Add(-time.Minute)
	_, expired, err := s.CreateShareLink(ws.ID, "fleet", &past)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LookupShareLink(expired); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired err = %v", err)
	}

	if err := s.RevokeShareLink(ws.ID, link.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LookupShareLink(plain); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked err = %v", err)
	}
	ws2 := mustWS(t, s, "other")
	if err := s.RevokeShareLink(ws2.ID, link.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-workspace revoke err = %v", err)
	}
	if _, _, err := s.CreateShareLink(ws.ID, "bogus", nil); err == nil {
		t.Fatal("invalid scope accepted")
	}
	if ls, _ := s.ListShareLinks(ws.ID); len(ls) != 2 {
		t.Fatalf("ListShareLinks = %d", len(ls))
	}
}

func TestLoginTokenSingleUse(t *testing.T) {
	s := openTemp(t)
	plain, err := s.CreateLoginToken("  Person@Example.COM ", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(allDBBytes(t, s), []byte(plain)) {
		t.Fatal("login token stored in plaintext")
	}
	now := time.Now().UTC()
	u, err := s.ConsumeLoginToken(plain, now)
	if err != nil || u.Email != "person@example.com" || u.ID == "" {
		t.Fatalf("consume = %+v, %v", u, err)
	}
	if _, err := s.ConsumeLoginToken(plain, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume err = %v", err)
	}
	if _, err := s.ConsumeLoginToken("unknown", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown consume err = %v", err)
	}
	// Second login for the same email reuses the user.
	plain2, _ := s.CreateLoginToken("person@example.com", time.Hour)
	u2, err := s.ConsumeLoginToken(plain2, now)
	if err != nil || u2.ID != u.ID {
		t.Fatalf("returning user = %+v, %v", u2, err)
	}
	// Expired link is refused and stays unusable.
	plain3, _ := s.CreateLoginToken("person@example.com", time.Minute)
	if _, err := s.ConsumeLoginToken(plain3, now.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired consume err = %v", err)
	}
}

func TestSessionExpiryAndMembership(t *testing.T) {
	s := openTemp(t)
	plain, _ := s.CreateLoginToken("o@example.com", time.Hour)
	now := time.Now().UTC()
	u, err := s.ConsumeLoginToken(plain, now)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := s.CreateWorkspace("acme", "team", "trialing", &now, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if m, err := s.GetMembership(ws.ID, u.ID); err != nil || m.Role != "owner" {
		t.Fatalf("membership = %+v, %v", m, err)
	}
	if err := s.AddMembership(ws.ID, u.ID, "member"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate membership err = %v", err)
	}
	if wss, err := s.WorkspacesForUser(u.ID); err != nil || len(wss) != 1 || wss[0].ID != ws.ID {
		t.Fatalf("WorkspacesForUser = %+v, %v", wss, err)
	}

	sess, err := s.CreateSession(u.ID, ws.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(allDBBytes(t, s), []byte(sess)) {
		t.Fatal("session secret stored in plaintext")
	}
	got, err := s.LookupSession(sess, now)
	if err != nil || got.UserID != u.ID || got.WorkspaceID != ws.ID || got.ID == "" {
		t.Fatalf("session = %+v, %v", got, err)
	}
	if _, err := s.LookupSession(sess, now.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session err = %v", err)
	}
	if err := s.DeleteSession(sess); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSession(sess, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session err = %v", err)
	}
}

func TestWorkspaceBillingNotifyAndValidation(t *testing.T) {
	s := openTemp(t)
	ws := mustWS(t, s, "acme")
	if _, err := s.CreateWorkspace("x", "gold", "active", nil, ""); err == nil {
		t.Fatal("invalid plan accepted")
	}
	trial := time.Now().UTC().Add(14 * 24 * time.Hour)
	if err := s.UpdateWorkspaceBilling(ws.ID, "fleet", "past_due", "cus_1", "sub_1", &trial); err != nil {
		t.Fatal(err)
	}
	got, err := s.WorkspaceByStripeCustomer("cus_1")
	if err != nil || got.ID != ws.ID || got.Plan != "fleet" || got.BillingStatus != "past_due" ||
		got.StripeSubscriptionID != "sub_1" || got.TrialEndsAt == nil || !got.TrialEndsAt.Equal(trial) {
		t.Fatalf("by customer = %+v, %v", got, err)
	}
	other := mustWS(t, s, "other")
	if err := s.UpdateWorkspaceBilling(other.ID, "solo", "active", "cus_1", "", nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate customer err = %v", err)
	}
	if _, err := s.WorkspaceByStripeCustomer(""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty customer err = %v", err)
	}
	if err := s.UpdateWorkspaceNotify(ws.ID, "a@b.c", "https://h/x", "sek"); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetWorkspace(ws.ID); got.NotifyEmail != "a@b.c" || got.NotifyWebhookSecret != "sek" {
		t.Fatalf("notify = %+v", got)
	}
	if err := s.UpdateWorkspaceNotify("nope", "", "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("notify unknown err = %v", err)
	}
	if all, _ := s.ListWorkspaces(); len(all) != 2 {
		t.Fatalf("ListWorkspaces = %d", len(all))
	}
}

func TestAlertsLifecycle(t *testing.T) {
	s := openTemp(t)
	ws := mustWS(t, s, "acme")
	h := mustHost(t, s, ws, "a")
	a1, err := s.CreateAlert(ws.ID, h.ID, AlertLapsed, "silent")
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := s.CreateAlert(ws.ID, h.ID, AlertRecovered, "back")
	if _, err := s.CreateAlert(ws.ID, h.ID, "bogus", "x"); err == nil {
		t.Fatal("invalid kind accepted")
	}
	if und, _ := s.UndeliveredAlerts(10); len(und) != 2 || und[0].ID != a1.ID {
		t.Fatalf("undelivered = %+v", und)
	}
	if err := s.MarkAlertDelivered(a1.ID, time.Now().UTC(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkAlertDelivered(a2.ID, time.Now().UTC(), "webhook 500"); err != nil {
		t.Fatal(err)
	}
	if und, _ := s.UndeliveredAlerts(10); len(und) != 0 {
		t.Fatalf("still undelivered: %+v", und)
	}
	list, err := s.ListAlerts(ws.ID, 10)
	if err != nil || len(list) != 2 || list[0].ID != a2.ID || list[0].DeliveryError != "webhook 500" || list[1].DeliveredAt == nil {
		t.Fatalf("ListAlerts = %+v, %v", list, err)
	}
	if err := s.MarkAlertDelivered("nope", time.Now(), ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown alert err = %v", err)
	}
}

func TestPruneBundlesKeepsNewestPerHost(t *testing.T) {
	s := openTemp(t)
	ws := mustWS(t, s, "acme")
	a, b := mustHost(t, s, ws, "a"), mustHost(t, s, ws, "b")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	a1 := saveAt(t, s, a, base, ProofRow{Proof: "p"})
	a2 := saveAt(t, s, a, base.Add(24*time.Hour), ProofRow{Proof: "p"})
	a3 := saveAt(t, s, a, base.Add(10*24*time.Hour), ProofRow{Proof: "p"})
	b1 := saveAt(t, s, b, base, ProofRow{Proof: "p"}) // only bundle, and older than the cutoff

	cutoff := base.Add(30 * 24 * time.Hour) // everything is older than this
	n, err := s.PruneBundles(ws.ID, cutoff)
	if err != nil || n != 2 {
		t.Fatalf("pruned %d, %v; want 2", n, err)
	}
	for _, gone := range []Bundle{a1, a2} {
		if _, err := s.GetBundle(ws.ID, gone.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("bundle %s survived", gone.ID)
		}
		if _, err := os.Stat(s.BundlePath(gone)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("archive %s survived: %v", gone.ID, err)
		}
		if rows, _ := s.ProofsForBundle(ws.ID, gone.ID); len(rows) != 0 {
			t.Fatalf("proof rows of %s survived", gone.ID)
		}
	}
	for _, kept := range []Bundle{a3, b1} {
		if _, err := s.ReadBundle(ws.ID, kept.ID); err != nil {
			t.Fatalf("newest bundle %s lost: %v", kept.ID, err)
		}
		if rows, _ := s.ProofsForBundle(ws.ID, kept.ID); len(rows) != 1 {
			t.Fatalf("proof rows of %s lost", kept.ID)
		}
	}
	// Idempotent.
	if n, err := s.PruneBundles(ws.ID, cutoff); err != nil || n != 0 {
		t.Fatalf("second prune = %d, %v", n, err)
	}
}

func TestConcurrentSaveBundle(t *testing.T) {
	s := openTemp(t)
	ws := mustWS(t, s, "acme")
	h := mustHost(t, s, ws, "a")
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n*2)
	ids := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b, err := s.SaveBundle(Bundle{
				WorkspaceID: h.WorkspaceID, HostRowID: h.ID, PublicKeyHex: "k", SignatureHex: "s",
				GeneratedAt: base.Add(time.Duration(i) * time.Minute),
			}, []byte(fmt.Sprintf("archive-%d", i)), []ProofRow{{Proof: "db", State: "healthy"}, {Proof: "files", State: "ok"}})
			if err != nil {
				errs <- err
				return
			}
			ids <- b.ID
			if _, err := s.UpsertHostOnBundle(ws.ID, "a", "a", "e", "key-a", b.GeneratedAt); err != nil {
				errs <- err
			}
			if _, err := s.LatestBundlePerHost(ws.ID); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		t.Errorf("concurrent op: %v", err)
	}
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Errorf("duplicate bundle id %s", id)
		}
		seen[id] = true
	}
	all, err := s.ListBundles(ws.ID, h.ID, 0)
	if err != nil || len(all) != n {
		t.Fatalf("saved %d bundles, %v; want %d", len(all), err, n)
	}
	for _, b := range all {
		if rows, _ := s.ProofsForBundle(ws.ID, b.ID); len(rows) != 2 {
			t.Errorf("bundle %s has %d proof rows", b.ID, len(rows))
		}
	}
}

func TestEnsureUserAndListMembers(t *testing.T) {
	s := openTemp(t)
	u, err := s.EnsureUser("  Owner@Example.COM ")
	if err != nil || u.Email != "owner@example.com" {
		t.Fatalf("EnsureUser = %+v, %v", u, err)
	}
	again, err := s.EnsureUser("owner@example.com")
	if err != nil || again.ID != u.ID {
		t.Fatalf("EnsureUser must be idempotent: %+v, %v", again, err)
	}
	if _, err := s.EnsureUser("not-an-email"); err == nil {
		t.Fatal("EnsureUser accepted an address without @")
	}

	ws, err := s.CreateWorkspace("acme", "team", "active", nil, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.EnsureUser("b-member@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddMembership(ws.ID, m.ID, "member"); err != nil {
		t.Fatal(err)
	}
	other := mustWS(t, s, "other")
	members, err := s.ListMembers(ws.ID)
	if err != nil || len(members) != 2 || members[0].Role != "owner" || members[0].Email != u.Email ||
		members[1].Email != "b-member@example.com" {
		t.Fatalf("ListMembers = %+v, %v", members, err)
	}
	if none, _ := s.ListMembers(other.ID); len(none) != 0 {
		t.Fatalf("members leaked across workspaces: %+v", none)
	}
}

func TestSetHostNameSurvivesPush(t *testing.T) {
	s := openTemp(t)
	ws := mustWS(t, s, "acme")
	other := mustWS(t, s, "other")
	t0 := time.Now().UTC().Truncate(time.Second)
	h, err := s.UpsertHostOnBundle(ws.ID, "web-1", "machine-name", "e1", "aa", t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetHostName(other.ID, h.ID, "hijack"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-workspace rename err = %v", err)
	}
	if err := s.SetHostName(ws.ID, h.ID, "   "); err == nil {
		t.Fatal("blank host name accepted")
	}
	if err := s.SetHostName(ws.ID, h.ID, "Web One"); err != nil {
		t.Fatal(err)
	}
	h2, err := s.UpsertHostOnBundle(ws.ID, "web-1", "renamed-by-machine", "e2", "aa", t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if h2.Name != "Web One" || h2.Epoch != "e2" {
		t.Fatalf("owner name must survive a push while epoch still updates: %+v", h2)
	}
}

func TestCountBundlesPerHost(t *testing.T) {
	s := openTemp(t)
	ws := mustWS(t, s, "acme")
	a, b := mustHost(t, s, ws, "a"), mustHost(t, s, ws, "b")
	t0 := time.Now().UTC().Truncate(time.Second)
	saveAt(t, s, a, t0)
	saveAt(t, s, a, t0.Add(time.Hour))
	saveAt(t, s, b, t0)
	got, err := s.CountBundlesPerHost(ws.ID)
	if err != nil || got[a.ID] != 2 || got[b.ID] != 1 || len(got) != 2 {
		t.Fatalf("CountBundlesPerHost = %v, %v", got, err)
	}
}
