// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	commandrunner "github.com/tannernicol/restoregap/internal/command"
	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/drill"
	"github.com/tannernicol/restoregap/internal/hostid"
	"github.com/tannernicol/restoregap/internal/ledger"
	"github.com/tannernicol/restoregap/internal/policy"
	"github.com/tannernicol/restoregap/internal/proofstore"
)

// newDrillCmd runs every declared drill and records the outcome as a proof.
//
// A drill is the only thing here that produces verified: true, because it is the
// only one that actually performs the recovery. Everything else attests; this
// reconstructs the artifact in a sandbox and checks it against typed, measurable
// outcomes — byte-identity by default, or whatever validate: checks and RTO/RPO
// budgets the drill declares.
//
// A failure is recorded rather than silently left alone, in one of two honest
// flavors. A drill that ran and did not verify (a check or budget failed, the
// artifact came back wrong) records `disputed` — that state must be loud,
// because leaving the old passing proof in place would mean the guard keeps
// clearing changes on evidence that has since been contradicted. A drill whose
// recovery SOURCE could not be reached (missing mount, connection refused,
// permission denied on the source, timeout), and every pin_check failure,
// records `unreachable` instead: nothing was proven either way, and reporting
// that as "disputed" would read as backup corruption when the truth is the NAS
// was asleep. Both statuses fail closed identically — this distinction is
// about the report, never the gate.
//
// --pins-only runs a cheaper, more frequent check: for each drill that declares
// pin_check, prove the pinned recovery source still exists WITHOUT performing a
// recovery. A pin failure flips the proof to unreachable immediately; a pin
// success leaves the existing proof record completely untouched — a pin check
// is not a drill and must never refresh observed_at or expiry.
//
// --lint statically checks every declared drill without running or writing
// anything — see internal/drill.Lint. It is the step an agent authoring a new
// drill config runs before ever invoking a real recovery command.
func newDrillCmd() *cobra.Command {
	var contextPath, only, expiresIn, signingKey, ledgerPath, actor, sandboxDir string
	var timeout time.Duration
	var pinsOnly, lint, calibrate, apply bool
	var minRuns int
	var margin float64

	cmd := &cobra.Command{
		Use:   "drill",
		Short: "Prove a recovery for real: run it in a sandbox, verify the result, record a verified proof",
		Long: "For each declared drill, restoregap reconstructs the artifact from its recovery source in an\n" +
			"isolated sandbox and checks the recovered result against typed, measurable outcomes —\n" +
			"byte-identity by default, or explicit sqlite/git/file_tree/command checks — plus any declared\n" +
			"RTO/RPO budgets. Only a real reconstruction records a verified proof (verified: true);\n" +
			"staleness, a deleted source, a failing check, a missed budget, or a command that \"succeeds\"\n" +
			"while restoring garbage all fail closed. Guards marked require_verified only accept proofs\n" +
			"produced this way. --pins-only runs the cheaper pin_check instead of a full recovery. --lint\n" +
			"statically checks the declared drills — no recovery, no writes — and is the step to run right\n" +
			"after authoring or editing a drills: block, before the first real `drill` invocation. --calibrate\n" +
			"derives RTO/RPO budgets from real ledger telemetry instead of a guess; `drill propose` drafts a\n" +
			"whole new drills: entry from a live artifact — see `restoregap drill propose --help`.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if timeout <= 0 {
				return fmt.Errorf("drill: --timeout must be positive")
			}
			resolvedContext, err := requireContext(cmd, contextPath, "drill")
			if err != nil {
				return err
			}
			contextPath = resolvedContext

			ctx, err := contextspec.Load(contextPath)
			if err != nil {
				return fmt.Errorf("drill: %w", err)
			}
			if len(ctx.Drills) == 0 {
				return fmt.Errorf("drill: %s declares no drills: block", contextPath)
			}

			if calibrate {
				// --calibrate reads back accumulated telemetry rather than
				// writing it, so an omitted --ledger stays a hard requirement
				// here (a silent default would just mean "no runs found,
				// skip everything", which reads as a bug, not a decision) —
				// unlike the two writer modes below, this one keeps its
				// original required-flag behavior.
				return runDrillCalibrateCmd(cmd, contextPath, ctx.Drills, ledgerPath, minRuns, margin, apply)
			}
			if lint {
				return runDrillLintCmd(cmd, ctx.Drills, only)
			}

			resolvedLedger, _, err := resolveLedger(ledgerPath)
			if err != nil {
				return err
			}
			ledgerPath = resolvedLedger

			if pinsOnly {
				return runPinsOnlyCmd(cmd, contextPath, ctx.Drills, only, ledgerPath, actor, timeout)
			}
			return runFullDrillCmd(cmd, contextPath, ctx.Drills, only, expiresIn, signingKey, ledgerPath, actor, sandboxDir, timeout)
		},
	}

	cmd.Flags().StringVar(&contextPath, "context", "",
		"v2 context file with a drills: block (required; "+contextDiscoveryHelp+")")
	cmd.Flags().StringVar(&only, "proof", "", "drill only this proof id (default: all declared drills)")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "720h", "validity window for verified proofs (default 30 days — a proof that never expires would let a months-old drill satisfy the gate forever; pass 0 for no expiry)")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "hex ed25519 seed to sign verified proofs")
	cmd.Flags().StringVar(&ledgerPath, "ledger", "",
		"append one telemetry entry per drill result to this ledger; required with --calibrate, which reads it "+
			"back; for a real run or --pins-only, "+ledgerDiscoveryHelp)
	cmd.Flags().StringVar(&actor, "actor", "", "acting identity recorded in the ledger, e.g. agent/claude")
	cmd.Flags().StringVar(&sandboxDir, "sandbox-dir", "",
		"parent directory for throwaway sandboxes (default: OS temp dir, which is often tmpfs/RAM — "+
			"point this at disk when the restored artifact is large)")
	cmd.Flags().DurationVar(&timeout, "timeout", commandrunner.DefaultTimeout,
		"maximum runtime for each recovery, validation, and pin command (RTO budgets are measured separately)")
	cmd.Flags().BoolVar(&pinsOnly, "pins-only", false,
		"only run each drill's pin_check: prove the pinned recovery source still exists, without recovering")
	cmd.Flags().BoolVar(&lint, "lint", false,
		"statically check declared drills for problems; no recovery, no writes (exit 1 if any error-level finding)")
	cmd.Flags().BoolVar(&calibrate, "calibrate", false,
		"derive RTO/RPO budgets from verified ledger telemetry instead of a guess (needs --ledger); prints "+
			"proposals and headroom warnings, writes nothing unless --apply")
	cmd.Flags().IntVar(&minRuns, "min-runs", drill.DefaultMinRuns,
		"minimum verified runs a drill needs before --calibrate proposes a budget for it")
	cmd.Flags().Float64Var(&margin, "margin", drill.DefaultMargin,
		"safety multiplier --calibrate applies to the observed RTO p95")
	cmd.Flags().BoolVar(&apply, "apply", false,
		"with --calibrate, rewrite the budgets: block of every matched drill in --context (nothing is written without this)")

	cmd.AddCommand(newDrillProposeCmd())
	return cmd
}

// runDrillLintCmd statically checks every declared drill (optionally
// filtered to a single proof id via only) and prints one agent-parseable
// "error: <proof>: <message>" or "warn: <proof>: <message>" line per finding.
// It performs no recovery and writes nothing — required-field/enum/duration
// validity is already enforced by contextspec.Load before ctx.Drills exists
// at all, so a document that fails to parse never reaches here; that failure
// surfaces as the standard "drill: <path>: <err>" load error, same as every
// other drill subcommand.
func runDrillLintCmd(cmd *cobra.Command, drills []contextspec.Drill, only string) error {
	if only != "" && !anyDrillMatches(drills, only) {
		return fmt.Errorf("drill: no drill matches --proof %q", only)
	}
	out := cmd.OutOrStdout()
	errCount := 0
	for _, d := range drills {
		if only != "" && d.Proof != only {
			continue
		}
		for _, f := range drill.Lint(d) {
			_, _ = fmt.Fprintf(out, "%s: %s: %s\n", f.Severity, f.Proof, f.Message)
			if f.Severity == drill.LintError {
				errCount++
			}
		}
	}
	if errCount > 0 {
		cmd.SilenceUsage = true
		return &ExitError{Code: 1, Message: fmt.Sprintf("drill --lint: %d error-level finding(s)", errCount)}
	}
	return nil
}

// runFullDrillCmd runs every declared drill end to end: recover, validate,
// measure, record the proof, append telemetry, and fail the command if
// anything did not verify.
func runFullDrillCmd(cmd *cobra.Command, contextPath string, drills []contextspec.Drill, only, expiresIn, signingKey, ledgerPath, actor, sandboxDir string, timeout time.Duration) error {
	var ttl time.Duration
	if expiresIn != "" && expiresIn != "0" {
		d, err := time.ParseDuration(expiresIn)
		if err != nil {
			return fmt.Errorf("drill: --expires-in: %w", err)
		}
		ttl = d
	}

	results, err := runDrillsContext(cmd.Context(), cmd.OutOrStdout(), drills, only, sandboxDir, timeout)
	if err != nil {
		return err
	}

	signer, err := parseDrillSigningKey(signingKey)
	if err != nil {
		return err
	}

	if err := recordDrillProofs(contextPath, results, drills, ttl, signer, "drill"); err != nil {
		return fmt.Errorf("drill: recording proofs: %w", err)
	}

	appendDrillLedgerEntries(cmd.ErrOrStderr(), ledgerPath, contextPath, actor, "drill", results, drills)

	if err := checkDrillsVerified(results); err != nil {
		cmd.SilenceUsage = true
		return err
	}
	return nil
}

// runPinsOnlyCmd runs pin_check for every drill that declares one. Failing
// pins rewrite their proof to unreachable (reusing recordDrillProofs) — a pin
// check attempts nothing but reaching the source, so its failure can only ever
// mean "could not reach", never "recovered and did not verify"; passing pins
// leave their proof untouched. Every attempted pin still gets a ledger
// telemetry entry, pass or fail.
func runPinsOnlyCmd(cmd *cobra.Command, contextPath string, drills []contextspec.Drill, only, ledgerPath, actor string, timeout time.Duration) error {
	results, err := runPinChecksContext(cmd.Context(), cmd.OutOrStdout(), drills, only, timeout)
	if err != nil {
		return err
	}

	var failed []drill.Result
	for _, res := range results {
		if !res.Verified {
			failed = append(failed, res)
		}
	}
	if len(failed) > 0 {
		if err := recordDrillProofs(contextPath, failed, drills, 0, nil, "pin_check"); err != nil {
			return fmt.Errorf("drill --pins-only: recording unreachable proofs: %w", err)
		}
	}

	appendDrillLedgerEntries(cmd.ErrOrStderr(), ledgerPath, contextPath, actor, "pin_check", results, drills)

	if len(failed) > 0 {
		cmd.SilenceUsage = true
		return fmt.Errorf("drill --pins-only: %d pinned recovery source(s) could not be reached — proofs recorded as unreachable; re-run the drill once the source is reachable", len(failed))
	}
	return nil
}

// runDrills executes each declared drill (optionally filtered to a single
// proof id via only), printing a pass/fail line per drill as it runs, and
// returns the accumulated results.
func runDrills(out io.Writer, drills []contextspec.Drill, only, sandboxDir string) ([]drill.Result, error) {
	return runDrillsContext(context.Background(), out, drills, only, sandboxDir, commandrunner.DefaultTimeout)
}

func runDrillsContext(ctx context.Context, out io.Writer, drills []contextspec.Drill, only, sandboxDir string, timeout time.Duration) ([]drill.Result, error) {
	if only != "" && !anyDrillMatches(drills, only) {
		return nil, fmt.Errorf("drill: no drill matches --proof %q", only)
	}
	runner := drill.Runner{Now: time.Now, SandboxDir: sandboxDir, Timeout: timeout}
	results := make([]drill.Result, 0, len(drills))

	for _, d := range drills {
		if only != "" && d.Proof != only {
			continue
		}
		res := runner.RunContext(ctx, drill.Spec{
			Proof:          d.Proof,
			Artifact:       d.Artifact,
			Recover:        d.Recover,
			RecoverySource: d.RecoverySource,
			Validate:       d.Validate,
			Budgets:        d.Budgets,
			PinCheck:       d.PinCheck,
		})
		results = append(results, res)
		_, _ = fmt.Fprintln(out, formatDrillLine(res, d.Budgets))
	}
	return results, nil
}

// formatDrillLine renders one drill's CLI-facing line. The stopwatch clause
// leads: how long the recovery took, held up against the declared RTO budget
// when there is one — "restored in 0.4s (budget 5m)" on plenty of headroom,
// "restored in 6m12s, budget 5m EXCEEDED" past it, or just "restored in 0.4s"
// with no budget declared at all. A pass then names the recovery level it
// earned (contextspec.LevelFromChecks — the same mapping LevelOf uses for a
// recorded proof, so a live run and the status inventory never disagree)
// alongside its detail; a failure names the failing check(s) first
// (summarizeDetail in the drill package already orders them that way) so the
// cause is visible before anything else. The one exception is a run whose
// data checks all passed but which missed its RTO budget: the data really
// was recovered and verified, just too slowly, so that line still earns and
// shows a level — everything else that fails a check never claims one,
// because LevelOf's own rule is that "verified" is a precondition for any
// rung above declared.
func formatDrillLine(res drill.Result, budgets contextspec.DrillBudgets) string {
	if res.Err != nil {
		return fmt.Sprintf("✗ %s — %v", res.Proof, res.Err)
	}
	elapsed := formatFriendlyRTO(time.Duration(res.RTOSeconds * float64(time.Second)).Round(time.Millisecond))
	rpo := ""
	if res.RPOSeconds != nil {
		rpo = fmt.Sprintf(", RPO %s", contextspec.FormatRPO(*res.RPOSeconds))
	}
	rtoExceeded := budgets.RTO > 0 && res.RTOSeconds > budgets.RTO.Seconds()
	stopwatch := fmt.Sprintf("restored in %s%s", elapsed, rpo)
	switch {
	case rtoExceeded:
		stopwatch = fmt.Sprintf("%s, budget %s EXCEEDED", stopwatch, formatFriendlyRTO(budgets.RTO))
	case budgets.RTO > 0:
		stopwatch = fmt.Sprintf("%s (budget %s)", stopwatch, formatFriendlyRTO(budgets.RTO))
	}

	if res.Verified || (rtoExceeded && nonBudgetChecksPassed(res.Checks)) {
		level := contextspec.LevelFromChecks(res.Checks)
		mark := "✓"
		if !res.Verified {
			mark = "✗"
		}
		return fmt.Sprintf("%s %s — %s — %s (L%d): %s", mark, res.Proof, stopwatch, level, level.Rung(), res.Detail)
	}
	return fmt.Sprintf("✗ %s — NOT verified (%s%s): %s", res.Proof, elapsed, rpo, res.Detail)
}

// nonBudgetChecksPassed reports whether every declared (non-budget) check
// passed — the synthetic budget_rto/budget_rpo outcomes applyBudgets appends
// are excluded, since a budget miss is judged separately from data validity.
func nonBudgetChecksPassed(checks []contextspec.CheckOutcome) bool {
	for _, c := range checks {
		if c.Type == "budget_rto" || c.Type == "budget_rpo" {
			continue
		}
		if !c.Pass {
			return false
		}
	}
	return true
}

// formatFriendlyRTO renders an RTO-scale duration the way an operator would
// say it: tenths of a second below one second ("0.4s"), and Go's own
// duration string at or above it ("12.3s", "6m12s") with a trailing
// zero-seconds component trimmed ("5m0s" -> "5m") so a round budget reads
// back the way it was declared. RTO budgets/measurements live in the
// seconds-to-minutes range in practice (calibrate.go's own roundUpFriendlyRTO
// only ever rounds to a whole 30s or a whole minute), so minutes are as far
// as this needs to go.
func formatFriendlyRTO(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	s := d.String()
	if trimmed := strings.TrimSuffix(s, "0s"); trimmed != s && strings.HasSuffix(trimmed, "m") {
		return trimmed
	}
	return s
}

// anyDrillMatches reports whether any declared drill has the given proof id.
func anyDrillMatches(drills []contextspec.Drill, proof string) bool {
	for _, d := range drills {
		if d.Proof == proof {
			return true
		}
	}
	return false
}

func runPinChecksContext(ctx context.Context, out io.Writer, drills []contextspec.Drill, only string, timeout time.Duration) ([]drill.Result, error) {
	if only != "" && !anyDrillMatches(drills, only) {
		return nil, fmt.Errorf("drill: no drill matches --proof %q", only)
	}
	var results []drill.Result
	for _, d := range drills {
		if only != "" && d.Proof != only {
			continue
		}
		if d.PinCheck == "" {
			continue
		}
		res := runPinCheckContext(ctx, d, timeout)
		results = append(results, res)
		if res.Verified {
			_, _ = fmt.Fprintf(out, "✓ %s — pin ok: %s\n", d.Proof, res.Detail)
		} else {
			_, _ = fmt.Fprintf(out, "✗ %s — pin FAILED: %s\n", d.Proof, res.Detail)
		}
	}
	return results, nil
}

func runPinCheckContext(ctx context.Context, d contextspec.Drill, timeout time.Duration) drill.Result {
	res := drill.Result{Proof: d.Proof}
	r := commandrunner.Shell(ctx, d.PinCheck, commandrunner.Options{Env: append(os.Environ(), "RG_RECOVERY_SOURCE="+d.RecoverySource), Timeout: timeout})
	if r.Err != nil {
		res.SourceUnreachable = true
		res.Detail = fmt.Sprintf("could not reach the pinned recovery source: %s", pinCheckFirstLine(r.Output))
		return res
	}
	res.Verified = true
	res.Detail = "pinned recovery source still exists"
	return res
}

func pinCheckFirstLine(b []byte) string {
	s := string(b)
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// parseDrillSigningKey decodes a hex ed25519 seed into a signer via
// contextspec.ParseSigningKeySeed (shared with `bundle export
// --signing-key` so the two commands can never drift on what counts as a
// valid key), wrapping its error with this command's own name. It returns a
// nil signer (and no error) when signingKey is empty, so verified proofs are
// simply left unsigned.
func parseDrillSigningKey(signingKey string) (ed25519.PrivateKey, error) {
	signer, err := contextspec.ParseSigningKeySeed(signingKey)
	if err != nil {
		return nil, fmt.Errorf("drill: %w", err)
	}
	return signer, nil
}

// checkDrillsVerified returns an error if any drill result failed to verify,
// saying WHY in the operator's vocabulary: unreachable results (the source
// could not be reached, nothing was proven) and disputed results (the
// recovery ran and did not verify) get separate counts so a transient NAS
// outage never reads as backup corruption.
func checkDrillsVerified(results []drill.Result) error {
	unreachable, disputed := 0, 0
	for _, r := range results {
		if r.Verified {
			continue
		}
		if r.SourceUnreachable {
			unreachable++
		} else {
			disputed++
		}
	}
	if unreachable == 0 && disputed == 0 {
		return nil
	}
	var parts []string
	if unreachable > 0 {
		parts = append(parts, fmt.Sprintf("%d recovery source(s) could not be reached — proofs recorded as unreachable; re-run the drill once the source is reachable (no data loss is implied)", unreachable))
	}
	if disputed > 0 {
		parts = append(parts, fmt.Sprintf("%d recovery(ies) did not verify — proofs recorded as disputed", disputed))
	}
	return fmt.Errorf("drill: %s", strings.Join(parts, "; "))
}

// recordDrillProofs merges results back into the context document, preserving
// everything it does not own via a map round-trip. mode selects which
// declared command ("recover" for a full drill, "pin_check" for pins-only)
// is recorded as the proof's command field.
func recordDrillProofs(path string, results []drill.Result, drills []contextspec.Drill, ttl time.Duration, signer ed25519.PrivateKey, mode string) error {
	commandBy := map[string]string{}
	drillByProof := map[string]contextspec.Drill{}
	for _, d := range drills {
		drillByProof[d.Proof] = d
		if mode == "pin_check" {
			commandBy[d.Proof] = d.PinCheck
		} else {
			commandBy[d.Proof] = d.Recover
		}
	}

	now := time.Now().UTC()
	entries := make([]map[string]any, 0, len(results))
	for _, res := range results {
		drill, declared := drillByProof[res.Proof]
		if !declared {
			return fmt.Errorf("proof %q has no declared drill", res.Proof)
		}
		command := commandBy[res.Proof]
		// The standalone helper retains its legacy signing contract for callers
		// that exercise the map builder directly. Persisted full-drill records
		// are signed below only after binding and host/epoch stamping are final.
		entry := buildDrillProofEntry(res, command, now, ttl, nil)
		clearDrillGeneratedFields(entry)
		if mode == "pin_check" && res.Verified {
			// A passing pin only observes that the recovery source is reachable.
			// It did not recover or validate the artifact, so it must not retain
			// the full-drill authority that may already be stored for this proof.
			entry["status"] = "observed"
			entry["verified"] = false
			entry["expires_at"] = nil
			entry["sha256"] = nil
			entry["measurements"] = nil
			entry["signature"] = nil
		}
		if mode == "drill" {
			entry["recipe_digest"] = contextspec.RecipeDigest(drill)
			entry["dependencies"] = dependenciesToRaw(drill.Dependencies)
		} else {
			entry["recipe_digest"] = nil
			entry["dependencies"] = nil
		}
		stampProofHost(entry)
		if signer != nil && mode == "drill" && res.Verified {
			signed := typedDrillProof(res, drill, command, now, ttl)
			sig, err := contextspec.SignProofV2(signer, signed)
			if err != nil {
				return fmt.Errorf("sign proof %q: %w", res.Proof, err)
			}
			entry["signature"] = map[string]any{
				"version":    sig.Version,
				"public_key": sig.PublicKeyHex,
				"signature":  sig.SignatureHex,
			}
		}
		entries = append(entries, entry)
	}
	return proofstore.Upsert(path, entries)
}

// buildDrillProofEntry renders one drill result as the raw proof map
// recordDrillProofs writes to YAML. Measurements are attached only when
// checks actually ran (len(res.Checks) > 0) — a hard engine failure (sandbox
// creation, an unreadable artifact) and a pin_check result both leave
// Checks empty, so neither gets a measurements: block or a signature over
// one, matching the "non-verified record drops measurements/signature" rule
// (true for both disputed and unreachable).
func buildDrillProofEntry(res drill.Result, command string, now time.Time, ttl time.Duration, signer ed25519.PrivateKey) map[string]any {
	entry := map[string]any{
		"id":          res.Proof,
		"observed_at": now.Format(time.RFC3339Nano),
		"command":     command,
	}
	if res.Verified {
		entry["status"] = "validated"
		entry["verified"] = true
		if res.PostHash != "" {
			entry["sha256"] = res.PostHash
		}
		if ttl > 0 {
			entry["expires_at"] = now.Add(ttl).Format(time.RFC3339Nano)
		}
	} else {
		// Contradicted or unproven evidence, not merely absent: say which, so
		// a guard stops clearing changes on it immediately AND the operator
		// can tell "the source was asleep" (unreachable) from "the recovery
		// ran and did not verify" (disputed) apart.
		if res.SourceUnreachable {
			entry["status"] = "unreachable"
		} else {
			entry["status"] = "disputed"
		}
		entry["verified"] = false
		if res.PostHash != "" {
			entry["sha256"] = res.PostHash
		}
	}

	var measurements *contextspec.Measurements
	if len(res.Checks) > 0 {
		measurements = &contextspec.Measurements{RTOSeconds: res.RTOSeconds, RPOSeconds: res.RPOSeconds, Checks: res.Checks}
		entry["measurements"] = map[string]any{
			"rto_seconds": measurements.RTOSeconds,
			"rpo_seconds": measurements.RPOSeconds,
			"checks":      checksToRaw(measurements.Checks),
		}
	}

	// Sign only verified proofs, and sign exactly what CheckProof verifies —
	// contextspec.SignedMessage is the one place that decides what a
	// signature covers, so drift between signing and verifying is impossible
	// by construction.
	if signer != nil && res.Verified {
		status, _ := entry["status"].(string)
		observedAt, _ := entry["observed_at"].(string)
		sha, _ := entry["sha256"].(string)
		msg := contextspec.SignedMessage(res.Proof, status, observedAt, sha, measurements)
		entry["signature"] = map[string]any{
			"public_key": hex.EncodeToString(signer.Public().(ed25519.PublicKey)),
			"signature":  hex.EncodeToString(ed25519.Sign(signer, []byte(msg))),
		}
	}

	return entry
}

// clearDrillGeneratedFields turns omitted producer-owned fields into explicit
// proofstore clears. Keeping this at the persistence call site preserves the
// small buildDrillProofEntry map contract used by unit tests and other CLI
// formatting code, while preventing stale authority from surviving a rerun.
func clearDrillGeneratedFields(entry map[string]any) {
	for _, field := range []string{"expires_at", "sha256", "measurements", "signature", "recipe_digest", "dependencies"} {
		if _, present := entry[field]; !present {
			entry[field] = nil
		}
	}
}

func dependenciesToRaw(deps contextspec.Dependencies) map[string]any {
	normalized := contextspec.NormalizeDependencies(deps)
	return map[string]any{
		"paths": normalized.Paths, "commands": normalized.Commands, "packages": normalized.Packages,
	}
}

func typedDrillProof(res drill.Result, d contextspec.Drill, command string, now time.Time, ttl time.Duration) contextspec.Proof {
	status := contextspec.ProofRecordDisputed
	if res.SourceUnreachable {
		status = contextspec.ProofRecordUnreachable
	}
	if res.Verified {
		status = contextspec.ProofRecordValidated
	}
	var expires *time.Time
	if res.Verified && ttl > 0 {
		value := now.Add(ttl)
		expires = &value
	}
	var measurements *contextspec.Measurements
	if len(res.Checks) > 0 {
		measurements = &contextspec.Measurements{RTOSeconds: res.RTOSeconds, RPOSeconds: res.RPOSeconds, Checks: res.Checks}
	}
	host := hostid.Current()
	deps := contextspec.NormalizeDependencies(d.Dependencies)
	return contextspec.Proof{
		ID: res.Proof, Status: status, ObservedAt: &now, ExpiresAt: expires,
		SHA256: res.PostHash, Verified: res.Verified, Command: command,
		Measurements: measurements, RecipeDigest: contextspec.RecipeDigest(d),
		Dependencies: &deps,
		Host:         &contextspec.ProofHost{Name: host.HostName, ID: host.HostID}, Epoch: host.Epoch,
	}
}

func checksToRaw(checks []contextspec.CheckOutcome) []any {
	out := make([]any, 0, len(checks))
	for _, c := range checks {
		out = append(out, map[string]any{"type": c.Type, "pass": c.Pass, "detail": c.Detail})
	}
	return out
}

// stampProofHost stamps the proof record with the current machine's durable
// identity: scope.host stays the human-readable hostname default it always
// was (taxonomy spec section F, never overriding a declared host), and host:
// {name, id} + epoch: record the machine-id-derived identity and epoch the
// proof was observed under (docs/SCHEMA.md §Identity & epoch) so a proof
// imported from another machine or recorded before a reinstall can be told
// apart from this machine's own fresh evidence.
func stampProofHost(entry map[string]any) {
	scope, _ := entry["scope"].(map[string]any)
	if scope == nil {
		scope = map[string]any{}
	}
	if host, _ := scope["host"].(string); host == "" {
		if hostname, err := os.Hostname(); err == nil && hostname != "" {
			scope["host"] = hostname
			entry["scope"] = scope
		}
	}
	id := hostid.Current()
	entry["host"] = map[string]any{"name": id.HostName, "id": id.HostID}
	entry["epoch"] = id.Epoch
}

// appendDrillLedgerEntries appends one telemetry entry per drill result to
// ledgerPath, in the given mode, stamped with the host/epoch/policy the run
// happened under. Recovery proof already succeeded or failed by the time
// this runs — telemetry is secondary, so an append failure prints a loud
// warning on warnOut instead of failing the command (recovery proof outranks
// its own history).
func appendDrillLedgerEntries(warnOut io.Writer, ledgerPath, contextPath, actor, mode string, results []drill.Result, drills []contextspec.Drill) {
	if ledgerPath == "" {
		return
	}
	if actor == "" {
		actor = "human/owner"
	}
	stamps := policy.StampOptions([]string{contextPath})
	budgetsByProof := map[string]contextspec.DrillBudgets{}
	for _, d := range drills {
		budgetsByProof[d.Proof] = d.Budgets
	}
	for _, res := range results {
		payload := drillLedgerPayload(res, mode, budgetsByProof[res.Proof])
		if _, err := ledger.AppendNow(ledgerPath, ledger.EntryDrill, actor, ledger.Payload{Drill: &payload}, stamps...); err != nil {
			_, _ = fmt.Fprintf(warnOut, "drill: WARNING: telemetry ledger append failed for %s: %v\n", res.Proof, err)
		}
	}
}

// drillLedgerPayload renders one drill result as ledger telemetry: proof id,
// mode, verified, RTO/RPO in integer milliseconds, budget verdicts (nil when
// that budget was not declared), and per-check type/pass.
func drillLedgerPayload(res drill.Result, mode string, budgets contextspec.DrillBudgets) ledger.DrillPayload {
	// LevelFromChecks is the same mapping the CLI's pass line and the status
	// inventory use — a failed/never-run result naturally lands on
	// "declared" (LevelFromChecks(nil) included), which is itself useful
	// telemetry: a rung REGRESSION from "serves" to "declared" between runs
	// is exactly the trend this field exists to capture.
	level := contextspec.LevelFromChecks(res.Checks)
	p := ledger.DrillPayload{ProofID: res.Proof, Mode: mode, Verified: res.Verified, Level: level.String()}
	if len(res.Checks) > 0 {
		p.RTOMs = int64(res.RTOSeconds * 1000)
	}
	if res.RPOSeconds != nil {
		ms := int64(*res.RPOSeconds * 1000)
		p.RPOMs = &ms
	}
	if budgets.RTO > 0 {
		met := res.RTOSeconds <= budgets.RTO.Seconds()
		p.BudgetRTOMet = &met
	}
	if budgets.RPO > 0 {
		met := res.RPOSeconds != nil && *res.RPOSeconds <= budgets.RPO.Seconds()
		p.BudgetRPOMet = &met
	}
	for _, c := range res.Checks {
		p.Checks = append(p.Checks, ledger.DrillCheckRecord{Type: c.Type, Pass: c.Pass})
	}
	return p
}

func init() { extraCommands = append(extraCommands, newDrillCmd) }
