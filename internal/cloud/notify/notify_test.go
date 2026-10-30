// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWebhookSignedBody(t *testing.T) {
	var gotBody []byte
	var gotHdr http.Header
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotHdr, gotMethod = r.Header.Clone(), r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	wh := Webhook{URL: srv.URL, Secret: "s3cret", now: func() time.Time { return time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC) }}
	err := wh.Send(context.Background(), Message{
		Kind: "lapsed", Subject: "host a lapsed", Text: "no bundle for 3h",
		Payload: map[string]any{"host": "a", "hours": 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != "POST" || gotHdr.Get("Content-Type") != "application/json" {
		t.Errorf("method=%s ctype=%q", gotMethod, gotHdr.Get("Content-Type"))
	}
	var body map[string]any
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"kind": "lapsed", "subject": "host a lapsed", "text": "no bundle for 3h",
		"payload": map[string]any{"host": "a", "hours": float64(3)}, "sent_at": "2026-05-01T12:00:00Z",
	}
	if !reflect.DeepEqual(body, want) {
		t.Errorf("body = %v", body)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(gotBody)
	if got, want := gotHdr.Get("X-RestoreGap-Signature"), "sha256="+hex.EncodeToString(mac.Sum(nil)); got != want {
		t.Errorf("signature = %q, want %q", got, want)
	}
}

func TestWebhookNoSecretNoHeader(t *testing.T) {
	var sig string
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["X-Restoregap-Signature"]
		sig = r.Header.Get("X-RestoreGap-Signature")
	}))
	defer srv.Close()
	if err := (Webhook{URL: srv.URL}).Send(context.Background(), Message{Kind: "k"}); err != nil {
		t.Fatal(err)
	}
	if present || sig != "" {
		t.Errorf("signature header should be absent, got %q", sig)
	}
}

func TestWebhookNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom body", http.StatusInternalServerError)
	}))
	defer srv.Close()
	err := (Webhook{URL: srv.URL}).Send(context.Background(), Message{})
	if err == nil || !strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v", err)
	}
}

func TestWebhookErrorDoesNotLeakURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL + "/hook/TOKEN123"
	srv.Close()
	err := (Webhook{URL: u}).Send(context.Background(), Message{})
	if err == nil || strings.Contains(err.Error(), "TOKEN123") {
		t.Errorf("err = %v", err)
	}
}

func TestParseSMTPURL(t *testing.T) {
	good := []struct {
		in   string
		want SMTPConfig
	}{
		{"smtp://user:p%40ss@mail.example.com:587?from=cloud@example.com",
			SMTPConfig{Host: "mail.example.com", Port: "587", Username: "user", Password: "p@ss", From: "cloud@example.com", StartTLS: true}},
		{"smtp://mail.example.com:2525?from=cloud@example.com&starttls=1",
			SMTPConfig{Host: "mail.example.com", Port: "2525", From: "cloud@example.com", StartTLS: true}},
		{"smtp://localhost:1025?from=cloud@example.com",
			SMTPConfig{Host: "localhost", Port: "1025", From: "cloud@example.com"}},
		{"smtp://mail.example.com?from=cloud@example.com",
			SMTPConfig{Host: "mail.example.com", Port: "587", From: "cloud@example.com", StartTLS: true}},
		{"smtps://u:p@mail.example.com?from=cloud@example.com",
			SMTPConfig{Host: "mail.example.com", Port: "465", Username: "u", Password: "p", From: "cloud@example.com", ImplicitTLS: true}},
	}
	for _, tc := range good {
		got, err := ParseSMTPURL(tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.in, got, tc.want)
		}
	}
	if a := (SMTPConfig{Host: "h", Port: "25"}).Addr(); a != "h:25" {
		t.Errorf("Addr = %q", a)
	}

	bad := map[string]string{
		"missing from":    "smtp://u:p@mail.example.com:587",
		"bad scheme":      "http://mail.example.com?from=a@example.com",
		"no scheme":       "mail.example.com:587?from=a@example.com",
		"no host":         "smtp://?from=a@example.com",
		"invalid from":    "smtp://mail.example.com?from=not-an-address",
		"invalid port":    "smtp://mail.example.com:99999?from=a@example.com",
		"unparseable url": "smtp://u:p@%zz?from=a@example.com",
	}
	for name, in := range bad {
		_, err := ParseSMTPURL(in)
		if err == nil {
			t.Errorf("%s: expected error", name)
		} else if strings.Contains(err.Error(), "u:p") {
			t.Errorf("%s: error leaks credentials: %v", name, err)
		}
	}
}

func TestEmailAssemblesMessage(t *testing.T) {
	var gotAddr, gotFrom string
	var gotCfg SMTPConfig
	var gotRcpts []string
	var gotMsg []byte
	orig := smtpSend
	smtpSend = func(_ context.Context, addr string, cfg SMTPConfig, from string, rcpts []string, msg []byte) error {
		gotAddr, gotCfg, gotFrom, gotRcpts, gotMsg = addr, cfg, from, rcpts, msg
		return nil
	}
	defer func() { smtpSend = orig }()

	e := Email{SMTPURL: "smtp://u:p@mail.example.com:587?from=Restore%20Gap%20%3Ccloud@example.com%3E", To: "ops@example.com, Boss <boss@example.com>"}
	err := e.Send(context.Background(), Message{Subject: "Lapsed: web-1\r\nBcc: evil@example.com", Text: "line one\nline two"})
	if err != nil {
		t.Fatal(err)
	}
	if gotAddr != "mail.example.com:587" || !gotCfg.StartTLS || gotCfg.Username != "u" {
		t.Errorf("addr=%q cfg=%+v", gotAddr, gotCfg)
	}
	if gotFrom != "cloud@example.com" {
		t.Errorf("envelope from = %q", gotFrom)
	}
	if !reflect.DeepEqual(gotRcpts, []string{"ops@example.com", "boss@example.com"}) {
		t.Errorf("rcpts = %v", gotRcpts)
	}

	parsed, err := mail.ReadMessage(bytes.NewReader(gotMsg))
	if err != nil {
		t.Fatalf("message does not parse: %v\n%s", err, gotMsg)
	}
	h := parsed.Header
	if h.Get("From") != "Restore Gap <cloud@example.com>" {
		t.Errorf("From = %q", h.Get("From"))
	}
	if h.Get("To") != `<ops@example.com>, "Boss" <boss@example.com>` {
		t.Errorf("To = %q", h.Get("To"))
	}
	if h.Get("Subject") != "Lapsed: web-1 Bcc: evil@example.com" {
		t.Errorf("Subject = %q", h.Get("Subject"))
	}
	if h.Get("Bcc") != "" {
		t.Error("subject newline injected a Bcc header")
	}
	if !strings.HasPrefix(h.Get("Content-Type"), "text/plain") || h.Get("MIME-Version") != "1.0" || h.Get("Date") == "" {
		t.Errorf("headers = %v", h)
	}
	body, _ := io.ReadAll(parsed.Body)
	if string(body) != "line one\r\nline two\r\n" {
		t.Errorf("body = %q", body)
	}
}

func TestEmailNonASCIISubjectEncoded(t *testing.T) {
	orig := smtpSend
	var msg []byte
	smtpSend = func(_ context.Context, _ string, _ SMTPConfig, _ string, _ []string, m []byte) error {
		msg = m
		return nil
	}
	defer func() { smtpSend = orig }()
	e := Email{SMTPURL: "smtp://localhost:1025?from=a@example.com", To: "b@example.com"}
	if err := e.Send(context.Background(), Message{Subject: "Résumé gap", Text: "x"}); err != nil {
		t.Fatal(err)
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(parsed.Header.Get("Subject"), "=?utf-8?q?") {
		t.Errorf("raw subject not Q-encoded: %q", parsed.Header.Get("Subject"))
	}
}

func TestEmailErrors(t *testing.T) {
	orig := smtpSend
	defer func() { smtpSend = orig }()
	called := false
	smtpSend = func(context.Context, string, SMTPConfig, string, []string, []byte) error {
		called = true
		return errors.New("relay down")
	}
	if err := (Email{SMTPURL: "smtp://h?from=a@example.com", To: "not an address"}).Send(context.Background(), Message{}); err == nil || called {
		t.Errorf("bad recipient: err=%v called=%v", err, called)
	}
	if err := (Email{SMTPURL: "smtp://h", To: "b@example.com"}).Send(context.Background(), Message{}); err == nil || called {
		t.Errorf("bad url: err=%v called=%v", err, called)
	}
	err := (Email{SMTPURL: "smtp://h?from=a@example.com", To: "b@example.com"}).Send(context.Background(), Message{})
	if err == nil || !called || !strings.Contains(err.Error(), "relay down") {
		t.Errorf("send error: %v", err)
	}
}

type stub struct {
	err   error
	calls int
}

func (s *stub) Send(context.Context, Message) error { s.calls++; return s.err }

func TestMultiJoinsErrors(t *testing.T) {
	e1, e2 := errors.New("first failed"), errors.New("second failed")
	a, b, c := &stub{err: e1}, &stub{}, &stub{err: e2}
	err := Multi{a, b, c}.Send(context.Background(), Message{})
	if err == nil || !errors.Is(err, e1) || !errors.Is(err, e2) {
		t.Fatalf("err = %v", err)
	}
	if a.calls != 1 || b.calls != 1 || c.calls != 1 {
		t.Errorf("calls = %d %d %d; every notifier must run", a.calls, b.calls, c.calls)
	}
	if err := (Multi{b}).Send(context.Background(), Message{}); err != nil {
		t.Errorf("all-ok err = %v", err)
	}
	if err := (Multi{}).Send(context.Background(), Message{}); err != nil {
		t.Errorf("empty err = %v", err)
	}
}

func TestLog(t *testing.T) {
	var buf bytes.Buffer
	if err := (Log{W: &buf}).Send(context.Background(), Message{Subject: "Sign in", Text: "https://x/y"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Sign in") || !strings.Contains(buf.String(), "https://x/y") {
		t.Errorf("log = %q", buf.String())
	}
}
