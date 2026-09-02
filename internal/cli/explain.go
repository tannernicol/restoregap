// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/status"
)

// emDash matches the placeholder status.InventoryRow uses for an absent
// display value (status.emDash is unexported, so explain keeps its own copy
// of the same literal rather than reaching into that package's internals).
const emDash = "—"

// labelWidth is the column every explain field label ("status", "earned
// by", "last drill", "satisfies") is left-padded to, so their values line up
// in one column regardless of label length.
const labelWidth = 12

// newExplainCmd builds `restoregap explain <proof-id>`: a human-readable
// account of one proof — its earned recovery level, the evidence behind it,
// and every guard it satisfies. It answers "why does/doesn't this proof
// clear a guard" without making someone read the ledger or the context YAML
// by hand.
//
// explain deliberately re-derives nothing status.Gather already computes:
// the recovery level comes from contextspec.LevelOf (the one true rung
// derivation), and the per-check breakdown/RPO/RTO/evidence timestamps come
// straight off the status.InventoryRow status.Gather already builds for the
// exact same proof — reusing that avoids a second, drifting implementation
// of "is this proof currently good" and ledger-adjacent history parsing.
func newExplainCmd() *cobra.Command {
	var contextPaths []string
	cmd := &cobra.Command{
		Use:   "explain <proof-id>",
		Short: "Explain one proof: its recovery level, evidence, and which guards it satisfies",
		Long: "Prints the recovery level a proof has earned (and what that level actually means), the\n" +
			"evidence behind it (a drill's recover/source/artifact, or an attestation's command/evidence\n" +
			"URL), its last measured RTO/RPO and per-check results, and every guard whose requires.proofs\n" +
			"names it. Uses the same context discovery as `restoregap status`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			proofID := args[0]
			paths := discoverContextPaths(cmd, contextPaths)

			s, err := status.Gather(status.Request{ContextPaths: paths})
			if err != nil {
				return err
			}
			ctx, err := loadExplainContext(paths)
			if err != nil {
				return err
			}

			row, ok := findInventoryRow(s.Inventory, proofID)
			if !ok {
				candidates := closestIDs(proofID, inventoryIDs(s.Inventory), 3)
				msg := "no proof " + proofID
				if len(candidates) > 0 {
					msg += "; did you mean: " + strings.Join(candidates, ", ")
				}
				return &ExitError{Code: 2, Message: msg}
			}

			level := contextspec.LevelDeclared
			if proof, ok := findProof(ctx.Proofs, proofID); ok {
				level, _ = contextspec.LevelOf(proof, time.Now().UTC())
			}
			proofState, hasState := findProofState(s.Proofs, proofID)
			artifact := findDrillArtifact(ctx.Drills, proofID)
			guards := guardsRequiring(ctx.Guards, proofID)
			classification := status.Classify(ctx, proofID, row, proofState, hasState)

			_, err = cmd.OutOrStdout().Write(renderExplain(proofID, level, row, proofState, hasState, artifact, guards, classification))
			return err
		},
	}
	cmd.Flags().StringArrayVar(&contextPaths, "context", nil,
		"path to restoregap.yml / restoregap.local.yml; "+contextDiscoveryHelpRepeatable+
			" (when omitted entirely: "+contextDiscoveryHelp+"; falls back further to the built-in zero-config policy)")
	return cmd
}

func init() { extraCommands = append(extraCommands, newExplainCmd) }

// loadExplainContext loads and merges every declared context path (or the
// built-in zero-config default when none are declared) — the same
// dispatch status.Gather makes internally, needed here only because explain
// also reads guards and each drill's declared artifact, neither of which
// status.Summary carries forward.
func loadExplainContext(paths []string) (contextspec.Context, error) {
	if len(paths) == 0 {
		return contextspec.Default(), nil
	}
	ctx, err := contextspec.LoadAll(paths)
	if err != nil {
		return contextspec.Context{}, fmt.Errorf("explain: %w", err)
	}
	return ctx, nil
}

// levelMeaning renders the one-line, plain-language claim a recovery level
// actually makes — the answer to "what does this rung mean" a bare level
// word never carries on its own.
func levelMeaning(l contextspec.RecoveryLevel) string {
	switch l {
	case contextspec.LevelRestores:
		return "restored into a sandbox, files present"
	case contextspec.LevelDataValid:
		return "restored and the data passed typed checks"
	case contextspec.LevelServes:
		return "restored, booted, answered"
	default:
		return "someone observed it; nothing was restored"
	}
}

func findInventoryRow(rows []status.InventoryRow, id string) (status.InventoryRow, bool) {
	for _, r := range rows {
		if r.Proof == id {
			return r, true
		}
	}
	return status.InventoryRow{}, false
}

func inventoryIDs(rows []status.InventoryRow) []string {
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.Proof
	}
	return ids
}

func findProofState(states []status.ProofState, id string) (status.ProofState, bool) {
	for _, p := range states {
		if p.ID == id {
			return p, true
		}
	}
	return status.ProofState{}, false
}

func findProof(proofs []contextspec.Proof, id string) (contextspec.Proof, bool) {
	for _, p := range proofs {
		if p.ID == id {
			return p, true
		}
	}
	return contextspec.Proof{}, false
}

func findDrillArtifact(drills []contextspec.Drill, proofID string) string {
	for _, d := range drills {
		if d.Proof == proofID {
			return d.Artifact
		}
	}
	return ""
}

// guardsRequiring returns every guard whose requires.proofs names proofID,
// in declared order.
func guardsRequiring(guards []contextspec.Guard, proofID string) []contextspec.Guard {
	var out []contextspec.Guard
	for _, g := range guards {
		for _, want := range g.Requires.Proofs {
			if want == proofID {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// renderExplain builds the full plain-text explanation for one proof.
func renderExplain(proofID string, level contextspec.RecoveryLevel, row status.InventoryRow, ps status.ProofState, hasState bool, artifact string, guards []contextspec.Guard, c status.ProofClassification) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s — %s (%s)\n", proofID, level.String(), levelMeaning(level))

	field(&b, "layer", layerCategoryLine(c))
	field(&b, "status", statusLine(row, ps, hasState))

	if earned := earnedByLine(row, artifact); earned != "" {
		field(&b, "earned by", earned)
	}

	if row.AcceptedReason != "" {
		field(&b, "accepted", fmt.Sprintf("%s — %s (review by %s)", row.AcceptedBy, row.AcceptedReason, row.AcceptedReviewBy))
	} else if row.AcceptanceLapsedOn != "" {
		field(&b, "accepted", fmt.Sprintf("lapsed %s — this proof is unreviewed again", row.AcceptanceLapsedOn))
	}

	if row.IsDrilled && row.ObservedAtDisplay != emDash {
		field(&b, "last drill", fmt.Sprintf("%s · RTO %s · RPO %s", row.ObservedAtDisplay, row.RTO, row.RPO))
	}
	for _, c := range row.Checks {
		mark := "✓"
		if !c.Pass {
			mark = "✗"
		}
		fmt.Fprintf(&b, "    %s %s\n", mark, c.Detail)
	}

	for _, g := range guards {
		field(&b, "satisfies", fmt.Sprintf("%s (%s)", g.ID, g.Enforcement))
	}

	return []byte(b.String())
}

// layerCategoryLine renders explain's "layer" field: "<layer> / <category>"
// (category omitted when unset), plus a note when the guards requiring this
// proof disagreed on layer (contextspec.EffectiveProofLayer's conflict
// case).
func layerCategoryLine(c status.ProofClassification) string {
	line := c.Layer
	if c.Category != "" {
		line += " / " + c.Category
	}
	if c.Conflict {
		line += " (" + c.ConflictDetail + ")"
	}
	return line
}

// field prints one "  <label padded>value" line, the two-space-indent,
// fixed-label-column layout every field of the explanation shares.
func field(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, "  %-*s%s\n", labelWidth, label, value)
}

// statusLine renders the proof's presence/expiry line: the freshness word
// status.Gather already assigned it (present/expiring/expired/stale/
// disputed/unreachable), plus the observed/expiry timestamps
// status.InventoryRow already formatted — nothing here re-derives freshness.
func statusLine(row status.InventoryRow, ps status.ProofState, hasState bool) string {
	if !hasState {
		// A declared drill with no proof record at all: ProofAge already
		// carries "no proof recorded yet" for exactly this case.
		return row.ProofAge
	}
	parts := []string{ps.Status}
	if row.ObservedAtDisplay != emDash {
		parts = append(parts, "observed "+row.ObservedAtDisplay)
	}
	if row.ExpiresAtDisplay != emDash {
		expires := "expires " + row.ExpiresAtDisplay
		if row.ExpiresInDisplay != emDash {
			expires += " (" + strings.TrimPrefix(row.ExpiresInDisplay, "expires ") + ")"
		}
		parts = append(parts, expires)
	}
	return strings.Join(parts, " · ")
}

// earnedByLine renders the evidence line: a drill's recover/source/artifact,
// or an attestation's verifier command (falling back to its evidence URL).
// Empty when neither is available. The recover command is collapsed to one
// line — `drill propose` emits it as a YAML block scalar, whose trailing
// newline would otherwise break the field's single-line layout.
func earnedByLine(row status.InventoryRow, artifact string) string {
	if row.IsDrilled {
		parts := []string{"drill: " + strings.Join(strings.Fields(row.RecoverCmd), " ")}
		if row.RecoverySource != "" {
			parts = append(parts, "source: "+row.RecoverySource)
		}
		if artifact != "" {
			parts = append(parts, "artifact: "+artifact)
		}
		return strings.Join(parts, "   ")
	}
	switch {
	case row.AttestCommand != "" && row.AttestCommand != emDash:
		return "attestation: " + row.AttestCommand
	case row.AttestEvidenceURL != "" && row.AttestEvidenceURL != emDash:
		return "attestation: " + row.AttestEvidenceURL
	default:
		return ""
	}
}

// closestIDs returns up to max ids from candidates, nearest first by
// Levenshtein distance to id (ties broken alphabetically for a stable
// suggestion order) — the "did you mean" list for an unknown proof id.
func closestIDs(id string, candidates []string, max int) []string {
	type scored struct {
		id   string
		dist int
	}
	scoredIDs := make([]scored, 0, len(candidates))
	for _, c := range candidates {
		scoredIDs = append(scoredIDs, scored{c, levenshtein(id, c)})
	}
	sort.Slice(scoredIDs, func(i, j int) bool {
		if scoredIDs[i].dist != scoredIDs[j].dist {
			return scoredIDs[i].dist < scoredIDs[j].dist
		}
		return scoredIDs[i].id < scoredIDs[j].id
	})
	if len(scoredIDs) > max {
		scoredIDs = scoredIDs[:max]
	}
	out := make([]string, len(scoredIDs))
	for i, s := range scoredIDs {
		out[i] = s.id
	}
	return out
}

// levenshtein computes the classic edit distance between a and b — the
// nearest-neighbor metric closestIDs ranks suggestions by.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	dp := make([][]int, la+1)
	for i := range dp {
		dp[i] = make([]int, lb+1)
		dp[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		dp[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := dp[i-1][j] + 1
			ins := dp[i][j-1] + 1
			sub := dp[i-1][j-1] + cost
			dp[i][j] = min3(del, ins, sub)
		}
	}
	return dp[la][lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
