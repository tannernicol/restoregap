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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Webhook POSTs a JSON envelope to URL. When Secret is set the body is
// signed so the receiver can reject forged alerts.
type Webhook struct {
	URL, Secret string
	HTTP        *http.Client // default: 10s timeout

	now func() time.Time // test hook
}

type webhookBody struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
	Payload any    `json:"payload"`
	SentAt  string `json:"sent_at"`
}

func (w Webhook) Send(ctx context.Context, m Message) error {
	now := time.Now
	if w.now != nil {
		now = w.now
	}
	body, err := json.Marshal(webhookBody{
		Kind: m.Kind, Subject: m.Subject, Text: m.Text, Payload: m.Payload,
		SentAt: now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("notify: encode webhook body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		// The URL may embed a token; report the cause without echoing it.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("notify: build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "restoregap-cloud")
	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write(body)
		req.Header.Set("X-RestoreGap-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	hc := w.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		// Webhook URLs often carry secrets in the path or query, and
		// url.Error would put them in logs; keep only the cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("notify: webhook delivery failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notify: webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}
