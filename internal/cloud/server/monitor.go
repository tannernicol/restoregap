// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/tannernicol/restoregap/internal/cloud/notify"
	"github.com/tannernicol/restoregap/internal/cloud/store"
)

const (
	// lapseFactor: a host lapses when it is silent for 1.5x its expected
	// interval, so one late push does not page anyone (docs/CLOUD.md).
	lapseFactor = 1.5
	// deliveryGiveUp is how long a failing alert is retried before it is
	// marked processed with its error, so a dead webhook cannot retry forever.
	deliveryGiveUp = 24 * time.Hour
	sendTimeout    = 30 * time.Second
)

// RunMonitor runs Tick every `every` until ctx is cancelled, starting with one
// immediate pass so a restart does not delay overdue alerts by a full interval.
func (s *Server) RunMonitor(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	run := func() {
		if err := s.Tick(ctx, s.now()); err != nil && ctx.Err() == nil {
			s.log.Error("monitor tick finished with errors", "err", err)
		}
	}
	run()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// Tick is one monitor pass: lapse detection, alert delivery, retention. A
// failure in one workspace is logged and joined into the result but never
// stops the others; tests drive Tick directly with a chosen "now".
func (s *Server) Tick(ctx context.Context, now time.Time) error {
	workspaces, err := s.st.ListWorkspaces()
	if err != nil {
		return fmt.Errorf("list workspaces: %w", err)
	}
	var errs []error
	for _, ws := range workspaces {
		if err := s.detectLapses(ws, now); err != nil {
			s.log.Error("lapse detection failed", "workspace", ws.ID, "err", err)
			errs = append(errs, fmt.Errorf("lapse %s: %w", ws.ID, err))
		}
	}
	if err := s.deliverAlerts(ctx, now); err != nil {
		errs = append(errs, err)
	}
	for _, ws := range workspaces {
		if err := s.enforceRetention(ws, now); err != nil {
			s.log.Error("retention failed", "workspace", ws.ID, "err", err)
			errs = append(errs, fmt.Errorf("retention %s: %w", ws.ID, err))
		}
	}
	return errors.Join(errs...)
}

// detectLapses marks every host that has gone quiet past 1.5x its expected
// cadence and records one lapsed alert for it. LapsedAt != nil is the "already
// alerted" memory, so a silent host alerts once, not every tick; the next
// bundle clears it (store.UpsertHostOnBundle) and ingest records recovery.
func (s *Server) detectLapses(ws store.Workspace, now time.Time) error {
	hosts, err := s.st.ListHosts(ws.ID)
	if err != nil {
		return err
	}
	var errs []error
	for _, h := range hosts {
		if h.ExpectedEvery <= 0 || h.LapsedAt != nil {
			continue
		}
		grace := time.Duration(float64(h.ExpectedEvery) * lapseFactor)
		if !h.LastSeenAt.Add(grace).Before(now) {
			continue
		}
		if err := s.st.MarkHostLapsed(h.ID, now); err != nil {
			errs = append(errs, err)
			continue
		}
		s.raise(ws.ID, h.ID, store.AlertLapsed, fmt.Sprintf("host %s last sent a bundle at %s; expected every %s",
			h.Name, h.LastSeenAt.UTC().Format(time.RFC3339), h.ExpectedEvery))
		s.log.Info("host lapsed", "workspace", ws.ID, "host", h.ID)
	}
	return errors.Join(errs...)
}

// deliverAlerts sends every undelivered alert through its workspace's
// notifiers. Success marks it delivered. Failure leaves it queued for the next
// tick until it is deliveryGiveUp old, then marks it processed with the error
// (MarkAlertDelivered always sets DeliveredAt, so that is how it leaves the
// queue). After one workspace's send fails, its remaining alerts wait for the
// next tick instead of each burning a full timeout against a dead endpoint.
func (s *Server) deliverAlerts(ctx context.Context, now time.Time) error {
	alerts, err := s.st.UndeliveredAlerts(0)
	if err != nil {
		return fmt.Errorf("list undelivered alerts: %w", err)
	}
	if len(alerts) == 0 {
		return nil
	}
	type target struct {
		ws       store.Workspace
		notifier notify.Notifier
		failed   bool
	}
	targets := map[string]*target{}
	var errs []error
	for _, a := range alerts {
		if ctx.Err() != nil {
			break
		}
		t, ok := targets[a.WorkspaceID]
		if !ok {
			ws, err := s.st.GetWorkspace(a.WorkspaceID)
			if err != nil {
				s.log.Error("alert delivery: workspace lookup failed", "workspace", a.WorkspaceID, "err", err)
				errs = append(errs, err)
				targets[a.WorkspaceID] = &target{failed: true}
				continue
			}
			t = &target{ws: ws, notifier: s.notifierFor(ws)}
			targets[a.WorkspaceID] = t
		}
		if t.failed {
			s.expireIfOld(a, now, "an earlier delivery in this pass failed")
			continue
		}
		host, _ := s.st.GetHost(a.WorkspaceID, a.HostRowID) // zero Host if gone; the message still stands
		sctx, cancel := context.WithTimeout(ctx, sendTimeout)
		err := t.notifier.Send(sctx, s.alertMessage(a, host))
		cancel()
		if err != nil {
			t.failed = true
			s.log.Warn("alert delivery failed", "workspace", a.WorkspaceID, "alert", a.ID, "kind", a.Kind, "err", err)
			s.expireIfOld(a, now, err.Error())
			continue
		}
		if err := s.st.MarkAlertDelivered(a.ID, now, ""); err != nil {
			errs = append(errs, err)
			continue
		}
		s.log.Info("alert delivered", "workspace", a.WorkspaceID, "alert", a.ID, "kind", a.Kind)
	}
	return errors.Join(errs...)
}

// expireIfOld gives up on an alert older than deliveryGiveUp by marking it
// processed with the last error; younger alerts stay queued to retry.
func (s *Server) expireIfOld(a store.Alert, now time.Time, reason string) {
	if now.Sub(a.CreatedAt) < deliveryGiveUp {
		return
	}
	if err := s.st.MarkAlertDelivered(a.ID, now, "gave up after 24h: "+reason); err != nil {
		s.log.Error("mark alert delivered failed", "alert", a.ID, "err", err)
	}
}

func (s *Server) alertMessage(a store.Alert, h store.Host) notify.Message {
	link := s.cfg.BaseURL + "/app/alerts"
	if h.ID != "" {
		link = s.cfg.BaseURL + "/app/hosts/" + h.ID
	}
	name := h.Name
	if name == "" {
		name = "(removed host)"
	}
	return notify.Message{
		Subject: fmt.Sprintf("[Restore Gap] %s: %s", a.Kind, name),
		Text:    a.Message + "\n\n" + link + "\n",
		Kind:    a.Kind,
		Payload: map[string]string{
			"alert_id": a.ID, "kind": a.Kind, "host": name, "host_id": h.HostID,
			"message": a.Message, "created_at": a.CreatedAt.UTC().Format(time.RFC3339), "url": link,
		},
	}
}

// notifierFor builds a workspace's destinations: email when both an address
// and SMTP are configured, the signed webhook when a URL is set. A workspace
// with neither (or a dev instance with no SMTP and no webhook) gets the log,
// so alerts are never silently dropped.
func (s *Server) notifierFor(ws store.Workspace) notify.Notifier {
	var multi notify.Multi
	if ws.NotifyEmail != "" && s.cfg.SMTPURL != "" {
		multi = append(multi, notify.Email{SMTPURL: s.cfg.SMTPURL, To: ws.NotifyEmail})
	}
	if ws.NotifyWebhookURL != "" {
		multi = append(multi, notify.Webhook{URL: ws.NotifyWebhookURL, Secret: ws.NotifyWebhookSecret, HTTP: webhookClient()})
	}
	if len(multi) == 0 {
		return notify.Log{W: slogWriter{log: s.log}}
	}
	return multi
}

// slogWriter adapts notify.Log's io.Writer to the structured logger.
type slogWriter struct{ log *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	w.log.Info("alert notification: " + string(p))
	return len(p), nil
}

var _ io.Writer = slogWriter{}

// webhookClient is the HTTP client alert webhooks use. The URL is typed in by
// a workspace member, so on a shared instance it is a request the server makes
// to an address of the member's choosing. The one target worth refusing
// outright is link-local space, home of the cloud metadata services that hand
// out instance credentials; loopback and private ranges stay reachable
// because self-hosters legitimately point alerts at services on their own
// network. The check runs at connect time, on the address actually dialed, so
// a hostname that resolves to link-local is refused too.
func webhookClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip != nil && isLinkLocal(ip) {
				return errors.New("refusing to connect to a link-local address")
			}
			return nil
		},
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext, Proxy: nil},
		// A webhook receiver answering with a redirect should not steer the
		// request (and its signature header) somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func isLinkLocal(ip net.IP) bool {
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// enforceRetention deletes bundles older than the plan's retention window,
// always keeping each host's newest bundle (store.PruneBundles).
func (s *Server) enforceRetention(ws store.Workspace, now time.Time) error {
	days := s.planFor(ws.Plan).RetentionDays
	if days <= 0 {
		return nil
	}
	n, err := s.st.PruneBundles(ws.ID, now.Add(-time.Duration(days)*24*time.Hour))
	if n > 0 {
		s.log.Info("retention pruned bundles", "workspace", ws.ID, "removed", n, "retention_days", days)
	}
	return err
}
