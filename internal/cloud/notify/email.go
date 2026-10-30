// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SMTPConfig is a parsed RESTOREGAP_CLOUD_SMTP_URL.
type SMTPConfig struct {
	Host, Port         string
	Username, Password string
	From               string
	StartTLS           bool // upgrade a plain connection
	ImplicitTLS        bool // TLS from the first byte (smtps)
}

// Addr is host:port for dialing.
func (c SMTPConfig) Addr() string { return net.JoinHostPort(c.Host, c.Port) }

// ParseSMTPURL parses smtp://user:pass@host:587?from=addr&starttls=1 and
// smtps://... . The from address is mandatory because every provider
// rejects a message without an envelope sender.
func ParseSMTPURL(s string) (SMTPConfig, error) {
	u, err := url.Parse(s)
	if err != nil {
		// Do not wrap: url.Error would echo the credentials.
		return SMTPConfig{}, errors.New("notify: invalid SMTP URL")
	}
	var cfg SMTPConfig
	switch u.Scheme {
	case "smtp":
		cfg.Port = "587"
	case "smtps":
		cfg.Port = "465"
		cfg.ImplicitTLS = true
	default:
		return SMTPConfig{}, fmt.Errorf("notify: SMTP URL scheme must be smtp or smtps, got %q", u.Scheme)
	}
	cfg.Host = u.Hostname()
	if cfg.Host == "" {
		return SMTPConfig{}, errors.New("notify: SMTP URL has no host")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return SMTPConfig{}, errors.New("notify: SMTP URL has an invalid port")
		}
		cfg.Port = p
	}
	if u.User != nil {
		cfg.Username = u.User.Username()
		cfg.Password, _ = u.User.Password()
	}
	q := u.Query()
	cfg.From = q.Get("from")
	if cfg.From == "" {
		return SMTPConfig{}, errors.New("notify: SMTP URL needs a from= address")
	}
	if _, err := mail.ParseAddress(cfg.From); err != nil {
		return SMTPConfig{}, errors.New("notify: SMTP URL from= is not a valid address")
	}
	// Port 587 is the submission port and providers require STARTTLS
	// there, so it is implied rather than a silent plaintext default.
	if !cfg.ImplicitTLS && (q.Get("starttls") == "1" || cfg.Port == "587") {
		cfg.StartTLS = true
	}
	return cfg, nil
}

// Email sends plain-text mail through an SMTP relay.
type Email struct {
	SMTPURL string
	To      string // one address or a comma-separated list
}

// smtpSend is the network edge, replaced in tests.
var smtpSend = sendSMTP

func (e Email) Send(ctx context.Context, m Message) error {
	cfg, err := ParseSMTPURL(e.SMTPURL)
	if err != nil {
		return err
	}
	to, err := mail.ParseAddressList(e.To)
	if err != nil || len(to) == 0 {
		return errors.New("notify: invalid recipient address")
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return errors.New("notify: SMTP URL from= is not a valid address")
	}
	rcpts := make([]string, len(to))
	for i, a := range to {
		rcpts[i] = a.Address
	}
	msg := buildMessage(cfg.From, to, m, time.Now())
	if err := smtpSend(ctx, cfg.Addr(), cfg, from.Address, rcpts, msg); err != nil {
		return fmt.Errorf("notify: send email: %w", err)
	}
	return nil
}

// buildMessage assembles an RFC 5322 message. Addresses were already parsed
// (which rejects CR/LF), and the subject is Q-encoded with newlines removed,
// so no caller-controlled text can inject headers.
func buildMessage(from string, to []*mail.Address, m Message, date time.Time) []byte {
	addrs := make([]string, len(to))
	for i, a := range to {
		addrs[i] = a.String()
	}
	subject := strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ").Replace(m.Subject)
	body := strings.ReplaceAll(strings.ReplaceAll(m.Text, "\r\n", "\n"), "\n", "\r\n")

	var b bytes.Buffer
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(addrs, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("Date: " + date.Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	if !strings.HasSuffix(body, "\r\n") {
		b.WriteString("\r\n")
	}
	return b.Bytes()
}

func sendSMTP(ctx context.Context, addr string, cfg SMTPConfig, from string, rcpts []string, msg []byte) error {
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if cfg.ImplicitTLS {
		tc := tls.Client(conn, &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return err
		}
		conn = tc
	}
	// A hung relay must not wedge the caller past its context.
	deadline := time.Now().Add(30 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if cfg.StartTLS {
		if err := c.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if cfg.Username != "" {
		// PlainAuth itself refuses to send credentials over an
		// unencrypted non-localhost connection.
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
