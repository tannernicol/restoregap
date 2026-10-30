// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/cli"
	"github.com/tannernicol/restoregap/internal/cloud/server"
	"github.com/tannernicol/restoregap/internal/cloud/store"
)

func testEnv(t *testing.T) func(string) string {
	t.Helper()
	m := map[string]string{
		"RESTOREGAP_CLOUD_DATA":     filepath.Join(t.TempDir(), "data"),
		"RESTOREGAP_CLOUD_BASE_URL": "https://cloud.example.com",
	}
	return func(k string) string { return m[k] }
}

func run(t *testing.T, env func(string) string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errb bytes.Buffer
	cmd := newRootCmd(env, &out, &errb)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

func TestVersionPrintsTheCLIVersion(t *testing.T) {
	out, _, err := run(t, testEnv(t), "--version")
	if err != nil || !strings.Contains(out, cli.Version) {
		t.Fatalf("--version = %q, %v", out, err)
	}
}

func TestAdminWorkspaceTokenLifecycle(t *testing.T) {
	env := testEnv(t)

	out, _, err := run(t, env, "admin", "workspace", "list")
	if err != nil || !strings.HasPrefix(out, "ID") || strings.Count(out, "\n") != 1 {
		t.Fatalf("empty list = %q, %v", out, err)
	}

	out, _, err = run(t, env, "admin", "workspace", "create", "--email", "Ops@Example.com")
	if err != nil {
		t.Fatal(err)
	}
	link := regexp.MustCompile(`sign-in link \(single use, valid 24h\): (https://cloud\.example\.com/auth/[A-Za-z0-9_-]+)`).FindStringSubmatch(out)
	if link == nil || !strings.Contains(out, "ops@example.com's workspace") || !strings.Contains(out, "plan unlimited") {
		t.Fatalf("create output = %q", out)
	}
	wsID := regexp.MustCompile(`workspace ([0-9a-f]{32}) `).FindStringSubmatch(out)[1]

	// The link is real: consuming it yields the owner, who belongs to the workspace.
	st, err := store.Open(env("RESTOREGAP_CLOUD_DATA"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.ConsumeLoginToken(link[1][strings.LastIndex(link[1], "/")+1:], time.Now().UTC())
	if err != nil || u.Email != "ops@example.com" {
		t.Fatalf("login link did not yield the owner: %+v, %v", u, err)
	}
	if m, err := st.GetMembership(wsID, u.ID); err != nil || m.Role != "owner" {
		t.Fatalf("membership = %+v, %v", m, err)
	}
	_ = st.Close()

	out, _, _ = run(t, env, "admin", "workspace", "list")
	if !strings.Contains(out, wsID) || !strings.Contains(out, "unlimited") {
		t.Fatalf("list = %q", out)
	}

	// set-plan: a limited plan on a self-hosted workspace becomes "active"; back to unlimited resets.
	out, _, err = run(t, env, "admin", "workspace", "set-plan", wsID, "solo")
	if err != nil || !strings.Contains(out, "plan solo (active)") {
		t.Fatalf("set-plan = %q, %v", out, err)
	}
	out, _, _ = run(t, env, "admin", "workspace", "list")
	if !strings.Contains(out, "solo") || !strings.Contains(out, "active") {
		t.Fatalf("list after set-plan = %q", out)
	}
	if _, _, err := run(t, env, "admin", "workspace", "set-plan", wsID, "platinum"); err == nil {
		t.Fatal("set-plan accepted an unknown plan")
	}
	if _, _, err := run(t, env, "admin", "workspace", "set-plan", "nope", "solo"); err == nil {
		t.Fatal("set-plan accepted an unknown workspace")
	}
	if out, _, _ = run(t, env, "admin", "workspace", "set-plan", wsID, "unlimited"); !strings.Contains(out, "(unlimited)") {
		t.Fatalf("set-plan unlimited = %q", out)
	}

	// token create: the plaintext alone on stdout, the explanation on stderr.
	out, errOut, err := run(t, env, "admin", "token", "create", wsID, "--name", "web-1 cron")
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimSpace(out)
	if !regexp.MustCompile(`^rgp_[A-Za-z0-9_-]{43}$`).MatchString(tok) || !strings.Contains(errOut, "only time it is shown") || strings.Contains(errOut, tok) {
		t.Fatalf("token output = %q, stderr = %q", out, errOut)
	}
	st, _ = store.Open(env("RESTOREGAP_CLOUD_DATA"))
	defer st.Close()
	if _, ws, err := st.LookupToken(tok); err != nil || ws.ID != wsID {
		t.Fatalf("token does not authenticate against its workspace: %v", err)
	}
	if _, _, err := run(t, env, "admin", "token", "create", wsID); err == nil {
		t.Fatal("token create without --name succeeded")
	}
	if _, _, err := run(t, env, "admin", "token", "create", "nope", "--name", "x"); err == nil {
		t.Fatal("token create for an unknown workspace succeeded")
	}
	if _, _, err := run(t, env, "admin", "workspace", "create"); err == nil {
		t.Fatal("workspace create without --email succeeded")
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func TestServeAnswersAndShutsDownGracefully(t *testing.T) {
	cfg, err := server.ConfigFromEnv(testEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ListenAddr = "127.0.0.1:0"
	logs := &lockedBuf{}
	cfg.Logger = slogTo(logs)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, 20*time.Millisecond) }()

	var addr string
	deadline := time.Now().Add(10 * time.Second)
	for addr == "" {
		if m := regexp.MustCompile(`addr=(127\.0\.0\.1:\d+)`).FindStringSubmatch(logs.String()); m != nil {
			addr = m[1]
		} else if time.Now().After(deadline) {
			t.Fatalf("server never reported its address:\n%s", logs.String())
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "ok" {
		t.Fatalf("healthz = %d %q", resp.StatusCode, b)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned %v after cancellation", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not shut down")
	}
	if _, err := http.Get("http://" + addr + "/healthz"); err == nil {
		t.Fatal("the listener is still open after shutdown")
	}
}

func TestServeRefusesBadInput(t *testing.T) {
	m := map[string]string{"RESTOREGAP_CLOUD_DATA": t.TempDir(), "RESTOREGAP_CLOUD_ALLOW_SIGNUP": "perhaps"}
	if _, _, err := run(t, func(k string) string { return m[k] }, "serve"); err == nil || !strings.Contains(err.Error(), "ALLOW_SIGNUP") {
		t.Fatalf("serve with bad env: %v", err)
	}
	if _, _, err := run(t, testEnv(t), "serve", "--monitor-every", "0s"); err == nil {
		t.Fatal("serve accepted a zero monitor interval")
	}
}

func slogTo(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }

func TestAdminHostListAndSetKey(t *testing.T) {
	env := testEnv(t)
	out, _, err := run(t, env, "admin", "workspace", "create", "--email", "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	wsID := regexp.MustCompile(`workspace ([0-9a-f]{32}) `).FindStringSubmatch(out)[1]

	st, err := store.Open(env("RESTOREGAP_CLOUD_DATA"))
	if err != nil {
		t.Fatal(err)
	}
	oldKey := strings.Repeat("ab", 32)
	if _, err := st.UpsertHostOnBundle(wsID, "deadbeefdeadbeef", "box", "epoch1", oldKey, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	out, _, err = run(t, env, "admin", "host", "list", wsID)
	if err != nil || !strings.Contains(out, "deadbeefdeadbeef") || !strings.Contains(out, oldKey) {
		t.Fatalf("host list = %q, %v", out, err)
	}

	if _, _, err := run(t, env, "admin", "host", "set-key", wsID, "deadbeefdeadbeef", "not-hex"); err == nil {
		t.Fatal("a malformed key was accepted")
	}
	if _, _, err := run(t, env, "admin", "host", "set-key", wsID, "0000000000000000", strings.Repeat("cd", 32)); err == nil {
		t.Fatal("an unknown host was accepted")
	}
	newKey := strings.ToUpper(strings.Repeat("cd", 32))
	out, _, err = run(t, env, "admin", "host", "set-key", wsID, "deadbeefdeadbeef", newKey)
	if err != nil || !strings.Contains(out, "now pinned to key cdcdcdcdcdcd") {
		t.Fatalf("set-key = %q, %v", out, err)
	}
	st, err = store.Open(env("RESTOREGAP_CLOUD_DATA"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	h, err := st.GetHostByHostID(wsID, "deadbeefdeadbeef")
	if err != nil || h.PublicKeyHex != strings.ToLower(newKey) {
		t.Fatalf("pinned key after rotation = %q, %v", h.PublicKeyHex, err)
	}
}
