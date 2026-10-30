// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Command restoregap-cloud runs Restore Gap Cloud (docs/CLOUD.md): the HTTP
// service that receives pushed bundles, and the admin commands that manage
// workspaces from the shell of the host it runs on.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/cli"
	"github.com/tannernicol/restoregap/internal/cloud/server"
	"github.com/tannernicol/restoregap/internal/cloud/store"
)

func main() {
	if err := newRootCmd(os.Getenv, os.Stdout, os.Stderr).Execute(); err != nil {
		// Contract shared with restoregap: one human line on stderr, exit 2.
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(2)
	}
}

// defaultListen binds loopback only: Cloud is meant to sit behind a
// TLS-terminating proxy (docs/CLOUD.md), so exposing it directly is opt-in.
const defaultListen = "127.0.0.1:8080"

func newRootCmd(env func(string) string, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "restoregap-cloud",
		Short:         "Restore Gap Cloud: receive signed bundles, watch for silence, share a verifiable record",
		Version:       cli.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newServeCmd(env, stdout), newAdminCmd(env, stdout, stderr))
	return root
}

func newServeCmd(env func(string) string, stdout io.Writer) *cobra.Command {
	var listen string
	var monitorEvery time.Duration
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the Cloud HTTP service and its monitor loop",
		Long: "Serves the API, the dashboard and share links, and runs the monitor loop (lapse alerts,\n" +
			"alert delivery, retention) in the same process. Configuration is environment only:\n" +
			"RESTOREGAP_CLOUD_DATA, _BASE_URL, _SMTP_URL, _STRIPE_SECRET, _STRIPE_WEBHOOK_SECRET,\n" +
			"_PRICE_SOLO/_TEAM/_FLEET and _ALLOW_SIGNUP (docs/CLOUD.md).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if monitorEvery <= 0 {
				return errors.New("--monitor-every must be positive")
			}
			cfg, err := server.ConfigFromEnv(env)
			if err != nil {
				return err
			}
			cfg.ListenAddr = listen
			// Logs go to stdout: docs/CLOUD.md promises dev-mode login links
			// appear there, and a container's log driver reads stdout.
			cfg.Logger = slog.New(slog.NewTextHandler(stdout, nil))
			return serve(cmd.Context(), cfg, monitorEvery)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", defaultListen, "address to listen on")
	cmd.Flags().DurationVar(&monitorEvery, "monitor-every", time.Minute, "how often the monitor checks for lapsed hosts, undelivered alerts and retention")
	return cmd
}

// serve runs until SIGINT/SIGTERM, then drains in-flight requests.
func serve(parent context.Context, cfg server.Config, monitorEvery time.Duration) error {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	srv, err := server.New(cfg, st)
	if err != nil {
		return err
	}
	// Listen before starting anything else so a port conflict fails fast and
	// the address logged is the one actually bound (":0" in tests).
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Handler: srv.Handler(),
		// A client that opens a connection and dribbles headers must not hold it.
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
		// Bundles are capped at 8 MiB; two minutes is generous for that over a
		// slow link and still bounds a stalled body.
		ReadTimeout:  2 * time.Minute,
		WriteTimeout: 2 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}

	cfg.Logger.Info("restoregap-cloud listening", "addr", ln.Addr().String(), "base_url", cfg.BaseURL,
		"billing", cfg.BillingEnabled(), "signup", cfg.AllowSignup, "smtp", cfg.SMTPURL != "", "data", st.DataDir())

	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		srv.RunMonitor(ctx, monitorEvery)
	}()
	errc := make(chan error, 1)
	go func() { errc <- httpSrv.Serve(ln) }()

	select {
	case err := <-errc:
		stop()
		<-monitorDone
		return err
	case <-ctx.Done():
	}
	cfg.Logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = httpSrv.Shutdown(shutdownCtx)
	<-monitorDone
	if err != nil {
		return err
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
