// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/status"
)

// newNextCmd builds `restoregap next`: the shortest path to green, one line
// per proof that is not there yet. Ordered worst first — the four
// attention states (disputed/unreachable/expired/lapsed), then unreviewed
// attestations, then drilled-but-unproven — and every line ends in the
// exact command that moves that proof: drill what can be drilled, accept
// (with a reason) what cannot. A proof currently "observed" (has both
// observed_at and expires_at, and is still inside its own freshness window
// — max(48h, TTL/7) since it was last observed) is NOT a gap and never
// appears here. Exit 0 with "nothing to do" when every declared proof is
// restored, observed, or accepted; exit 1 otherwise, so a cron/agent loop
// can tell "converged" from "work left" by exit code alone.
func newNextCmd() *cobra.Command {
	var contextPaths []string
	var format string
	var prompt bool
	var layers, states, envs, systems, owners, tags []string

	cmd := &cobra.Command{
		Use:   "next",
		Short: "The path to green: what to drill or accept, worst first, one exact command per proof",
		Long: "Lists every declared proof that is not green (restored/observed/accepted), ordered worst\n" +
			"first: the four attention states (disputed/unreachable/expired/lapsed), then unreviewed\n" +
			"attestations, then drills that have not produced a verified proof yet. A proof with both\n" +
			"observed_at and expires_at is \"observed\" (not a gap) only while still inside its own\n" +
			"freshness window — max(48h, TTL/7) since it was last observed; once that window passes it is\n" +
			"unreviewed again, well before it technically expires. Each line is <proof-id>  <why>  →\n" +
			"<exact command> — `restoregap drill --context <file> --proof <id>` for a drilled proof,\n" +
			"`restoregap accept <id> --reason \"…\"` for an attestation the owner has decided not to drill.\n" +
			"Exit 0 (nothing to do) or 1 (work left). --layer/--state/--env/--system/--owner/--tag\n" +
			"(repeatable) narrow which gaps are listed — a brief can be cut per layer, per owner, or per\n" +
			"system. --format json emits id/layer/category/state/why/command/context_file/artifact/scope\n" +
			"per gap. --prompt emits a ready-to-hand agent brief: header (host, generated-at, scope, counts\n" +
			"by layer), one bullet per gap with its exact command, and the fixed rules block. Context\n" +
			"discovery is the same as `restoregap status`: " + contextDiscoveryHelpRepeatable + ".",
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths := discoverContextPaths(cmd, contextPaths)
			s, err := status.Gather(status.Request{ContextPaths: paths})
			if err != nil {
				return err
			}
			filter := status.NewTreeFilter(layers, states, envs, systems, owners, tags)
			steps := status.FilterNextSteps(s.NextSteps(), filter)
			out := cmd.OutOrStdout()

			switch {
			case prompt:
				if _, err := fmt.Fprint(out, status.RenderPrompt(steps, promptHeader(layers, states, envs, systems, owners, tags))); err != nil {
					return err
				}
			case format == "json":
				encodable := steps
				if encodable == nil {
					encodable = []status.NextStep{}
				}
				encoded, err := json.MarshalIndent(encodable, "", "  ")
				if err != nil {
					return err
				}
				if _, err := fmt.Fprintln(out, string(encoded)); err != nil {
					return err
				}
			case len(steps) == 0:
				if _, err := fmt.Fprintln(out, "nothing to do — all proofs green"); err != nil {
					return err
				}
			default:
				for _, line := range status.ToGreenLines(steps) {
					if _, err := fmt.Fprintln(out, line); err != nil {
						return err
					}
				}
			}
			if len(steps) == 0 {
				return nil
			}
			cmd.SilenceUsage = true
			return &ExitError{Code: 1, Message: fmt.Sprintf("%d proof(s) not green", len(steps))}
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&contextPaths, "context", nil,
		"path to restoregap.yml / restoregap.local.yml; "+contextDiscoveryHelpRepeatable+
			" (when omitted entirely: "+contextDiscoveryHelp+"; falls back further to the built-in zero-config policy)")
	f.StringVar(&format, "format", "text", "output format: text or json")
	f.BoolVar(&prompt, "prompt", false, "emit a ready-to-hand agent brief instead of the plain line-per-gap output")
	f.StringArrayVar(&layers, "layer", nil, "only this layer's gaps (repeatable)")
	f.StringArrayVar(&states, "state", nil, "only gaps in this state (repeatable)")
	f.StringArrayVar(&envs, "env", nil, "only this scope environment's gaps (repeatable)")
	f.StringArrayVar(&systems, "system", nil, "only this scope system's gaps (repeatable)")
	f.StringArrayVar(&owners, "owner", nil, "only this scope owner's gaps (repeatable)")
	f.StringArrayVar(&tags, "tag", nil, "only gaps carrying this scope tag (repeatable)")
	return cmd
}

// promptHeader builds --prompt's header: the current host, now, and a
// human-readable description of whichever filters were passed ("all" when
// none) — section F: "the header states the scope it was cut for".
func promptHeader(layers, states, envs, systems, owners, tags []string) status.PromptHeader {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return status.PromptHeader{Host: host, GeneratedAt: time.Now().UTC(), Scope: describeScope(layers, states, envs, systems, owners, tags)}
}

// describeScope renders the filters actually passed as one short label,
// "all" when none were.
func describeScope(layers, states, envs, systems, owners, tags []string) string {
	var parts []string
	add := func(name string, vs []string) {
		if len(vs) > 0 {
			parts = append(parts, name+"="+strings.Join(vs, ","))
		}
	}
	add("layer", layers)
	add("state", states)
	add("env", envs)
	add("system", systems)
	add("owner", owners)
	add("tag", tags)
	if len(parts) == 0 {
		return "all"
	}
	return strings.Join(parts, " ")
}

func init() { extraCommands = append(extraCommands, newNextCmd) }
