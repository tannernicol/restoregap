// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/cloud/server"
	"github.com/tannernicol/restoregap/internal/cloud/store"
)

// adminLoginTTL is longer than the 15 minutes an emailed link lives: an
// operator mints this link in a shell and hands it over by hand, possibly
// across timezones. It is still single-use.
const adminLoginTTL = 24 * time.Hour

// openAdmin loads the same environment configuration serve uses and opens the
// store it names, so an admin command and the running service always agree on
// which database they are touching.
func openAdmin(env func(string) string) (server.Config, *store.Store, error) {
	cfg, err := server.ConfigFromEnv(env)
	if err != nil {
		return server.Config{}, nil, err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return server.Config{}, nil, err
	}
	return cfg, st, nil
}

func newAdminCmd(env func(string) string, stdout, stderr io.Writer) *cobra.Command {
	admin := &cobra.Command{
		Use:   "admin",
		Short: "Manage workspaces and tokens from the shell (self-hosting, no Stripe needed)",
		Long: "Admin commands act directly on the database RESTOREGAP_CLOUD_DATA names, so they work\n" +
			"whether or not the service is running. Run them as the user that owns that directory.",
	}
	ws := &cobra.Command{Use: "workspace", Short: "List, create and re-plan workspaces"}
	ws.AddCommand(newWorkspaceListCmd(env, stdout), newWorkspaceCreateCmd(env, stdout),
		newWorkspaceSetPlanCmd(env, stdout))
	tok := &cobra.Command{Use: "token", Short: "Create push tokens"}
	tok.AddCommand(newTokenCreateCmd(env, stdout, stderr))
	host := &cobra.Command{Use: "host", Short: "List hosts and rotate a pinned signing key"}
	host.AddCommand(newHostListCmd(env, stdout), newHostSetKeyCmd(env, stdout))
	admin.AddCommand(ws, tok, host)
	return admin
}

func newHostListCmd(env func(string) string, stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "list <workspace-id>",
		Short: "List a workspace's hosts with their pinned keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			_, st, err := openAdmin(env)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			hosts, err := st.ListHosts(args[0])
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "HOST-ID\tNAME\tPUBLIC-KEY\tLAST-SEEN\tLAPSED")
			for _, h := range hosts {
				lapsed := ""
				if h.LapsedAt != nil {
					lapsed = h.LapsedAt.UTC().Format(time.RFC3339)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", h.HostID, h.Name, h.PublicKeyHex, h.LastSeenAt.UTC().Format(time.RFC3339), lapsed)
			}
			return tw.Flush()
		},
	}
}

// newHostSetKeyCmd is the shell form of the owner's key rotation on the host
// page: a self-hoster without SMTP has no quick way to a browser session, and
// the first push from a machine pins whatever key it happened to sign with.
func newHostSetKeyCmd(env func(string) string, stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "set-key <workspace-id> <host-id> <hex-ed25519-public-key>",
		Short: "Replace the signing key pinned to a host (owner key rotation)",
		Args:  cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			key := strings.ToLower(strings.TrimSpace(args[2]))
			if len(key) != 64 || strings.Trim(key, "0123456789abcdef") != "" {
				return fmt.Errorf("public key must be 64 hex characters (an Ed25519 public key)")
			}
			_, st, err := openAdmin(env)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			h, err := st.GetHostByHostID(args[0], args[1])
			if err != nil {
				return fmt.Errorf("host %q in workspace %q: %w", args[1], args[0], err)
			}
			if err := st.SetHostPublicKey(h.ID, key); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "host %s (%s) now pinned to key %s…\n", h.HostID, h.Name, key[:12])
			return nil
		},
	}
}

func newWorkspaceListCmd(env func(string) string, stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List workspaces",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			_, st, err := openAdmin(env)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			list, err := st.ListWorkspaces()
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tPLAN\tSTATUS\tHOSTS\tCREATED")
			for _, w := range list {
				n, err := st.CountHosts(w.ID)
				if err != nil {
					return err
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", w.ID, w.Name, w.Plan, w.BillingStatus, n,
					w.CreatedAt.UTC().Format(time.RFC3339))
			}
			return tw.Flush()
		},
	}
}

func newWorkspaceCreateCmd(env func(string) string, stdout io.Writer) *cobra.Command {
	var email, name, plan string
	cmd := &cobra.Command{
		Use:   "create --email <owner> [--name <name>] [--plan unlimited]",
		Short: "Create a workspace for an owner and print their sign-in link",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			cfg, st, err := openAdmin(env)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			user, err := st.EnsureUser(email)
			if err != nil {
				return err
			}
			if strings.TrimSpace(name) == "" {
				name = user.Email + "'s workspace"
			}
			w, err := st.CreateWorkspace(name, plan, statusForPlan(plan), nil, user.ID)
			if err != nil {
				return err
			}
			tok, err := st.CreateLoginToken(user.Email, adminLoginTTL)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "workspace %s (%s) created for %s on plan %s\n", w.ID, w.Name, user.Email, w.Plan)
			fmt.Fprintf(stdout, "sign-in link (single use, valid 24h): %s/auth/%s\n", cfg.BaseURL, tok)
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "owner's email address (required)")
	cmd.Flags().StringVar(&name, "name", "", "workspace name (default: \"<email>'s workspace\")")
	cmd.Flags().StringVar(&plan, "plan", "unlimited", "plan: solo, team, fleet or unlimited")
	_ = cmd.MarkFlagRequired("email")
	return cmd
}

func newWorkspaceSetPlanCmd(env func(string) string, stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "set-plan <workspace-id> <plan>",
		Short: "Change a workspace's plan (solo, team, fleet or unlimited)",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			_, st, err := openAdmin(env)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			w, err := st.GetWorkspace(args[0])
			if err != nil {
				return fmt.Errorf("workspace %q: %w", args[0], err)
			}
			plan := args[1]
			// Only the plan changes by hand. The billing status moves with it just
			// far enough to stay valid: an unlimited workspace is "unlimited", and
			// leaving "unlimited" for a limited plan makes the workspace "active"
			// (an admin grant); any Stripe-driven status is left alone.
			status := w.BillingStatus
			if plan == "unlimited" {
				status = "unlimited"
			} else if status == "unlimited" {
				status = "active"
			}
			if err := st.UpdateWorkspaceBilling(w.ID, plan, status, w.StripeCustomerID, w.StripeSubscriptionID, w.TrialEndsAt); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "workspace %s is now on plan %s (%s)\n", w.ID, plan, status)
			return nil
		},
	}
}

func newTokenCreateCmd(env func(string) string, stdout, stderr io.Writer) *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "create <workspace-id> --name <name>",
		Short: "Create a push token; the plaintext is printed once, on stdout",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			_, st, err := openAdmin(env)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			w, err := st.GetWorkspace(args[0])
			if err != nil {
				return fmt.Errorf("workspace %q: %w", args[0], err)
			}
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("--name is required")
			}
			tok, plain, err := st.CreateToken(w.ID, strings.TrimSpace(name))
			if err != nil {
				return err
			}
			// Token alone on stdout so `TOKEN=$(restoregap-cloud admin token create …)`
			// works; the explanation goes to stderr.
			fmt.Fprintln(stdout, plain)
			fmt.Fprintf(stderr, "token %q (%s…) created for workspace %s; this is the only time it is shown\n", tok.Name, tok.Prefix, w.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "a name for the token, such as the host or job that will use it (required)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

// statusForPlan: an unlimited workspace is "unlimited"; a limited plan an
// admin grants by hand is "active" (no Stripe subscription backs it).
func statusForPlan(plan string) string {
	if plan == "unlimited" {
		return "unlimited"
	}
	return "active"
}
