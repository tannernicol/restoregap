// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/ledger"
	"github.com/tannernicol/restoregap/internal/policy"
)

// defaultReviewWindow is how long an acceptance holds before the proof
// returns to the unreviewed bucket: 90 days, long enough that a reasoned
// "this cannot be drilled unattended" is not paperwork every week, short
// enough that a decision made in one context gets re-examined.
const defaultReviewWindow = 90 * 24 * time.Hour

// newAcceptCmd builds `restoregap accept <proof-id>`: record (or clear) an
// owner's reasoned acceptance that a proof will not be drilled. This is the
// convergence path for proofs that CANNOT be drilled — a phone that must be
// physically present, a vendor-only step — so `restoregap status` can reach
// an honest green without pretending those proofs were verified. The write
// lands on the proof in the context file that declares it (found via the
// same discovery status uses), with a timestamped sibling backup first, and
// an append-only ledger entry records who accepted what and why.
func newAcceptCmd() *cobra.Command {
	var contextPaths []string
	var reason, reviewIn, by string
	var clear bool

	cmd := &cobra.Command{
		Use:   "accept <proof-id>",
		Short: "Accept, with a reason, that a proof will not be drilled (or clear that acceptance)",
		Long: "Records an owner's decision to stop carrying one proof as a gap: it will not be drilled\n" +
			"within the review window, and that is accepted WITH a reason rather than left as silence.\n" +
			"The accepted: block (by, at, reason, review_by) is written onto the proof in the context\n" +
			"file that declares it — the file is backed up to a sibling .bak.<UTC-timestamp> first, and\n" +
			"an append-only ledger entry (kind \"accept\") records by/reason. An acceptance is only\n" +
			"meaningful for a proof still at the declared rung (attested, no drill); accepting a proof\n" +
			"that already restores is allowed but prints a note. Default review window is 90d\n" +
			"(--review-in); --by defaults to owner/$USER. `--clear <proof-id>` removes the acceptance\n" +
			"(ledger kind \"accept_clear\"), returning the proof to the unreviewed bucket.\n" +
			"Context discovery is the same as `restoregap status`: " + contextDiscoveryHelpRepeatable + ".",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			proofID := args[0]
			if !clear && reason == "" {
				return &ExitError{Code: 2, Message: "accept: --reason is required — an acceptance without a reason is a rubber stamp"}
			}
			window := defaultReviewWindow
			if reviewIn != "" {
				d, err := time.ParseDuration(reviewIn)
				if err != nil || d <= 0 {
					return &ExitError{Code: 2, Message: fmt.Sprintf("accept: --review-in must be a positive Go duration like 2160h (90 days), got %q", reviewIn)}
				}
				window = d
			}
			owner := by
			if owner == "" {
				owner = defaultAcceptBy()
			}

			paths := discoverContextPaths(cmd, contextPaths)
			file, proof, allIDs := findProofAcrossContexts(paths, proofID)
			if file == "" {
				msg := "no proof " + proofID
				if candidates := closestIDs(proofID, allIDs, 3); len(candidates) > 0 {
					msg += "; did you mean: " + strings.Join(candidates, ", ")
				}
				return &ExitError{Code: 2, Message: msg}
			}

			now := time.Now().UTC()
			if clear {
				return runAcceptClear(cmd, file, proofID, owner)
			}

			level, _ := contextspec.LevelOf(proof, now)
			if level > contextspec.LevelDeclared {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),
					"note: %s already %s — an acceptance only means something for a proof still at declared (attested, no drill)\n",
					proofID, level)
			}

			reviewBy := now.Add(window)
			if err := writeAcceptance(file, proofID, map[string]any{
				"by":        owner,
				"at":        now.Format(time.RFC3339),
				"reason":    reason,
				"review_by": reviewBy.Format(time.RFC3339),
			}); err != nil {
				return fmt.Errorf("accept: %w", err)
			}

			appendAcceptLedger(cmd.ErrOrStderr(), file, ledger.EntryAccept, owner, ledger.Payload{Accept: &ledger.AcceptPayload{
				ProofID: proofID, By: owner, Reason: reason, ReviewAt: &reviewBy,
			}})

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "accepted %s in %s — review by %s\n", proofID, file, reviewBy.Format("2006-01-02"))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&contextPaths, "context", nil,
		"path to restoregap.yml / restoregap.local.yml; "+contextDiscoveryHelpRepeatable)
	f.StringVar(&reason, "reason", "", "why this proof will not be drilled (required)")
	f.StringVar(&reviewIn, "review-in", "",
		"how long the acceptance holds, as a Go duration (default 2160h = 90 days)")
	f.StringVar(&by, "by", "", "who accepted (default: owner/$USER)")
	f.BoolVar(&clear, "clear", false, "remove the acceptance from <proof-id> instead of recording one")
	return cmd
}

func init() { extraCommands = append(extraCommands, newAcceptCmd) }

// runAcceptClear removes an existing acceptance. Clearing a proof with no
// acceptance recorded is a no-op that says so — idempotent, and silent in
// the ledger, because a no-op clear asserts nothing worth auditing.
func runAcceptClear(cmd *cobra.Command, file, proofID, owner string) error {
	wrote, err := clearAcceptance(file, proofID)
	if err != nil {
		return fmt.Errorf("accept --clear: %w", err)
	}
	if !wrote {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "no acceptance recorded on %s — nothing to clear\n", proofID)
		return nil
	}
	appendAcceptLedger(cmd.ErrOrStderr(), file, ledger.EntryAcceptClear, owner, ledger.Payload{AcceptClear: &ledger.AcceptClearPayload{
		ProofID: proofID, By: owner,
	}})
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "cleared acceptance on %s in %s — the proof is unreviewed again\n", proofID, file)
	return nil
}

// appendAcceptLedger writes the accept/accept_clear telemetry entry, stamped
// with the host/epoch/policy it was recorded under. The context-file write
// has already succeeded by the time this runs, so a ledger failure is a loud
// warning on stderr rather than a failed command — same precedence as drill
// telemetry: the state change outranks its own history.
func appendAcceptLedger(warnOut io.Writer, contextFile string, entryType ledger.EntryType, actor string, payload ledger.Payload) {
	path, err := defaultLedgerPath()
	if err != nil {
		_, _ = fmt.Fprintf(warnOut, "accept: WARNING: could not resolve the ledger path: %v\n", err)
		return
	}
	stamps := policy.StampOptions([]string{contextFile})
	if _, err := ledger.AppendNow(path, entryType, actor, payload, stamps...); err != nil {
		_, _ = fmt.Fprintf(warnOut, "accept: WARNING: ledger append failed: %v\n", err)
	}
}

// defaultAcceptBy renders the default --by: owner/$USER (owner/unknown when
// USER is unset), matching the owner/<name> shape --by documents.
func defaultAcceptBy() string {
	user := os.Getenv("USER")
	if user == "" {
		user = "unknown"
	}
	return "owner/" + user
}

// findProofAcrossContexts loads every discovered context file and returns
// the one declaring proofID plus its parsed Proof, along with every
// declared proof id across all files (for the did-you-mean list). An empty
// file means the proof is declared nowhere — including the zero-path case,
// where the built-in default policy declares no proofs at all.
func findProofAcrossContexts(paths []string, proofID string) (file string, proof contextspec.Proof, allIDs []string) {
	for _, p := range paths {
		ctx, err := contextspec.Load(p)
		if err != nil {
			continue // a load error here surfaces from status; accept only needs the files that parse
		}
		for _, pr := range ctx.Proofs {
			allIDs = append(allIDs, pr.ID)
			if pr.ID == proofID {
				file, proof = p, pr
			}
		}
	}
	return file, proof, allIDs
}

// writeAcceptance backs the context file up to a sibling .bak.<UTC
// timestamp> (the same shape the estate refreshers leave beside every file
// they rewrite), then sets accepted: on the named proof via the same
// map round-trip recordDrillProofs uses — everything the command does not
// own is preserved, and field order/format matches every other writer.
func writeAcceptance(path, proofID string, accepted map[string]any) error {
	doc, bakPath, err := backupAndDecode(path)
	if err != nil {
		return err
	}
	proofs, _ := doc["proofs"].([]any)
	for _, p := range proofs {
		pm, ok := p.(map[string]any)
		if !ok || pm["id"] != proofID {
			continue
		}
		pm["accepted"] = accepted
		stampProofHost(pm)
		return writeYAMLWithBackup(path, doc, bakPath)
	}
	return fmt.Errorf("%s: no proof %s", path, proofID)
}

// clearAcceptance removes accepted: from the named proof, returning false
// when there was nothing to clear. No backup is written for a no-op.
func clearAcceptance(path, proofID string) (wrote bool, err error) {
	doc, bakPath, err := backupAndDecode(path)
	if err != nil {
		return false, err
	}
	proofs, _ := doc["proofs"].([]any)
	for _, p := range proofs {
		pm, ok := p.(map[string]any)
		if !ok || pm["id"] != proofID {
			continue
		}
		if _, present := pm["accepted"]; !present {
			return false, nil
		}
		delete(pm, "accepted")
		return true, writeYAMLWithBackup(path, doc, bakPath)
	}
	return false, fmt.Errorf("%s: no proof %s", path, proofID)
}

// backupAndDecode reads the context file, copies it to a sibling
// .bak.<UTC-timestamp> backup, and decodes it into the generic map shape
// every context-file writer in this package round-trips through.
func backupAndDecode(path string) (doc map[string]any, bakPath string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	bakPath = path + ".bak." + time.Now().UTC().Format("20060102T150405Z")
	if err := os.WriteFile(bakPath, raw, 0o644); err != nil {
		return nil, "", fmt.Errorf("backup %s: %w", bakPath, err)
	}
	doc = map[string]any{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, "", err
	}
	return doc, bakPath, nil
}

// writeYAMLWithBackup marshals the round-tripped document back to path,
// noting the backup it stands behind in its error messages.
func writeYAMLWithBackup(path string, doc map[string]any, bakPath string) error {
	encoded, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return fmt.Errorf("%w (backup preserved at %s)", err, bakPath)
	}
	return nil
}
