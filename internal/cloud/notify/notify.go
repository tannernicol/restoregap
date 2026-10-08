// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package notify delivers alert and login messages by email, signed webhook
// or log line. Failures are returned, never retried here: the caller decides
// whether a missed notification matters.
package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// Message is one notification. Subject and Text serve humans; Kind and
// Payload serve machines (webhooks).
type Message struct {
	Subject, Text string
	Kind          string // alert kind, e.g. "lapsed"
	Payload       any    // JSON-encodable body for webhooks
}

// Notifier sends a Message somewhere.
type Notifier interface {
	Send(ctx context.Context, m Message) error
}

// Multi fans a message out to every notifier. One failing target must not
// suppress the others, so all run and the errors are joined.
type Multi []Notifier

func (m Multi) Send(ctx context.Context, msg Message) error {
	var errs []error
	for _, n := range m {
		if err := n.Send(ctx, msg); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Log writes messages to W; used in development when no SMTP is configured
// so magic links still reach the operator.
type Log struct{ W io.Writer }

func (l Log) Send(_ context.Context, m Message) error {
	_, err := fmt.Fprintf(l.W, "notify: %s\n%s\n", m.Subject, m.Text)
	return err
}
