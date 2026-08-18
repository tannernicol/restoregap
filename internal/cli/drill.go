// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/drill"
	"github.com/tannernicol/restoregap/internal/ledger"
)

// newDrillCmd runs every declared drill and records the outcome as a proof.
//
// A drill is the only thing here that produces verified: true, because it is the
// only one that actually performs the recovery. Everything else attests; this
// reconstructs the artifact in a sandbox and checks it against typed, measurable
// outcomes — byte-identity by default, or whatever validate: checks and RTO/RPO
// budgets the drill declares.
//
// A failure is recorded as `disputed` rather than silently left alone. A drill
// that used to pass and now does not is exactly the state that must be loud —
// leaving the old passing proof in place would mean the guard keeps clearing
// changes on evidence that has since been contradicted.
//
// --pins-only runs a cheaper, more frequent check: for each drill that declares
// pin_check, prove the pinned recovery source still exists WITHOUT performing a
// recovery. A pin failure flips the proof to disputed immediately; a pin success
// leaves the existing proof record completely untouched — a pin check is not a
// drill and must never refresh observed_at or expiry.
//
// --lint statically checks every declared drill without running or writing
// anything — see internal/drill.Lint. It is the step an agent authoring a new
// drill config runs before ever invoking a real recovery command.
func newDrillCmd() *cobra.Command {
	var contextPath, only, expiresIn, signingKey, ledgerPath, actor, sandboxDir string
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
				return runPinsOnlyCmd(cmd, contextPath, ctx.Drills, only, ledgerPath, actor)
			}
			return runFullDrillCmd(cmd, contextPath, ctx.Drills, only, expiresIn, signingKey, ledgerPath, actor, sandboxDir)
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
func runFullDrillCmd(cmd *cobra.Command, contextPath string, drills []contextspec.Drill, only, expiresIn, signingKey, ledgerPath, actor, sandboxDir string) error {
	var ttl time.Duration
	if expiresIn != "" && expiresIn != "0" {
		d, err := time.ParseDuration(expiresIn)
		if err != nil {
			return fmt.Errorf("drill: --expires-in: %w", err)
		}
		ttl = d
	}

	results, err := runDrills(cmd.OutOrStdout(), drills, only, sandboxDir)
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

	appendDrillLedgerEntries(cmd.ErrOrStderr(), ledgerPath, actor, "drill", results, drills)

	if err := checkDrillsVerified(results); err != nil {
		cmd.SilenceUsage = true
		return err
	}
	return nil
}

// runPinsOnlyCmd runs pin_check for every drill that declares one. Failing
// pins rewrite their proof to disputed (reusing recordDrillProofs); passing
// pins leave their proof untouched. Every attempted pin still gets a ledger
// telemetry entry, pass or fail.
func runPinsOnlyCmd(cmd *cobra.Command, contextPath string, drills []contextspec.Drill, only, ledgerPath, actor string) error {
	results, err := runPinChecks(cmd.OutOrStdout(), drills, only)
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
			return fmt.Errorf("drill --pins-only: recording disputed proofs: %w", err)
		}
	}

	appendDrillLedgerEntries(cmd.ErrOrStderr(), ledgerPath, actor, "pin_check", results, drills)

	if len(failed) > 0 {
		cmd.SilenceUsage = true
		return fmt.Errorf("drill --pins-only: %d pinned recovery source(s) are gone — proofs recorded as disputed", len(failed))
	}
	return nil
}

// runDrills executes each declared drill (optionally filtered to a single
// proof id via only), printing a pass/fail line per drill as it runs, and
// returns the accumulated results.
func runDrills(out io.Writer, drills []contextspec.Drill, only, sandboxDir string) ([]drill.Result, error) {
	if only != "" && !anyDrillMatches(drills, only) {
		return nil, fmt.Errorf("drill: no drill matches --proof %q", only)
	}
	runner := drill.Runner{Now: time.Now, SandboxDir: sandboxDir}
	results := make([]drill.Result, 0, len(drills))

	for _, d := range drills {
		if only != "" && d.Proof != only {
			continue
		}
		res := runner.Run(drill.Spec{
			Proof:          d.Proof,
			Artifact:       d.Artifact,
			Recover:        d.Recover,
			RecoverySource: d.RecoverySource,
			Validate:       d.Validate,
			Budgets:        d.Budgets,
			PinCheck:       d.PinCheck,
		})
		results = append(results, res)
		_, _ = fmt.Fprintln(out, formatDrillLine(res))
	}
	return results, nil
}

// formatDrillLine renders one drill's CLI-facing line. A pass names the
// recovery level it earned (contextspec.LevelFromChecks — the same mapping
// LevelOf uses for a recorded proof, so a live run and the status inventory
// never disagree) alongside its RTO/RPO measurements; a failure names the
// failing check(s) first (summarizeDetail in the drill package already
// orders them that way) so the cause is visible before anything else. A
// failed run never claims a level — LevelOf's own rule is that "verified"
// is a precondition for any rung above declared, and a failing drill isn't.
func formatDrillLine(res drill.Result) string {
	if res.Err != nil {
		return fmt.Sprintf("✗ %s — %v", res.Proof, res.Err)
	}
	rto := contextspec.FormatRTO(res.RTOSeconds)
	rpo := ""
	if res.RPOSeconds != nil {
		rpo = fmt.Sprintf(", RPO %s", contextspec.FormatRPO(*res.RPOSeconds))
	}
	if res.Verified {
		level := contextspec.LevelFromChecks(res.Checks)
		return fmt.Sprintf("✓ %s — %s (L%d) in %s%s: %s", res.Proof, level, level.Rung(), rto, rpo, res.Detail)
	}
	return fmt.Sprintf("✗ %s — NOT verified (%s%s): %s", res.Proof, rto, rpo, res.Detail)
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

// runPinChecks runs pin_check for each declared drill that has one
// (optionally filtered to a single proof id via only), printing a pass/fail
// line as it goes. Drills without a pin_check are skipped silently — not
// every drill needs the cheap check, only the recovery.
func runPinChecks(out io.Writer, drills []contextspec.Drill, only string) ([]drill.Result, error) {
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
		res := runPinCheck(d)
		results = append(results, res)
		if res.Verified {
			_, _ = fmt.Fprintf(out, "✓ %s — pin ok: %s\n", d.Proof, res.Detail)
		} else {
			_, _ = fmt.Fprintf(out, "✗ %s — pin FAILED: %s\n", d.Proof, res.Detail)
		}
	}
	return results, nil
}

// runPinCheck runs one drill's pin_check with RG_RECOVERY_SOURCE set and
// RG_SANDBOX/RG_TARGET unset — it proves the pinned source is still
// reachable, never that a recovery works. It never returns Err: a nonzero
// exit is the pin failing, not the command failing to run one, so it always
// resolves to a Verified true/false verdict.
func runPinCheck(d contextspec.Drill) drill.Result {
	res := drill.Result{Proof: d.Proof}
	c := exec.Command("sh", "-c", d.PinCheck)
	c.Env = append(os.Environ(), "RG_RECOVERY_SOURCE="+d.RecoverySource)
	out, err := c.CombinedOutput()
	if err != nil {
		res.Detail = fmt.Sprintf("pinned recovery source vanished: %s", pinCheckFirstLine(out))
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

// parseDrillSigningKey decodes a hex ed25519 seed into a signer. It returns a
// nil signer (and no error) when signingKey is empty, so verified proofs are
// simply left unsigned.
func parseDrillSigningKey(signingKey string) (ed25519.PrivateKey, error) {
	if signingKey == "" {
		return nil, nil
	}
	seed, err := hex.DecodeString(signingKey)
	if err != nil {
		return nil, fmt.Errorf("drill: --signing-key must be hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("drill: --signing-key must be a %d-byte hex seed, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// checkDrillsVerified returns an error if any drill result failed to verify.
func checkDrillsVerified(results []drill.Result) error {
	for _, r := range results {
		if !r.Verified {
			return fmt.Errorf("one or more recoveries did not verify — proofs recorded as disputed")
		}
	}
	return nil
}

// recordDrillProofs merges results back into the context document, preserving
// everything it does not own via a map round-trip. mode selects which
// declared command ("recover" for a full drill, "pin_check" for pins-only)
// is recorded as the proof's command field.
func recordDrillProofs(path string, results []drill.Result, drills []contextspec.Drill, ttl time.Duration, signer ed25519.PrivateKey, mode string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return err
	}

	commandBy := map[string]string{}
	for _, d := range drills {
		if mode == "pin_check" {
			commandBy[d.Proof] = d.PinCheck
		} else {
			commandBy[d.Proof] = d.Recover
		}
	}

	now := time.Now().UTC()
	proofs, _ := doc["proofs"].([]any)
	for _, res := range results {
		proofs = upsertProof(proofs, res.Proof, buildDrillProofEntry(res, commandBy[res.Proof], now, ttl, signer))
	}
	doc["proofs"] = proofs

	encoded, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o644)
}

// buildDrillProofEntry renders one drill result as the raw proof map
// recordDrillProofs writes to YAML. Measurements are attached only when
// checks actually ran (len(res.Checks) > 0) — a hard engine failure (sandbox
// creation, an unreadable artifact) and a pin_check result both leave
// Checks empty, so neither gets a measurements: block or a signature over
// one, matching the "disputed record drops measurements/signature" rule.
func buildDrillProofEntry(res drill.Result, command string, now time.Time, ttl time.Duration, signer ed25519.PrivateKey) map[string]any {
	entry := map[string]any{
		"id":          res.Proof,
		"observed_at": now.Format(time.RFC3339),
		"command":     command,
	}
	if res.Verified {
		entry["status"] = "validated"
		entry["verified"] = true
		entry["sha256"] = res.PostHash
		if ttl > 0 {
			entry["expires_at"] = now.Add(ttl).Format(time.RFC3339)
		}
	} else {
		// Contradicted evidence, not merely absent: say so, so a guard
		// stops clearing changes on it immediately.
		entry["status"] = "disputed"
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

func checksToRaw(checks []contextspec.CheckOutcome) []any {
	out := make([]any, 0, len(checks))
	for _, c := range checks {
		out = append(out, map[string]any{"type": c.Type, "pass": c.Pass, "detail": c.Detail})
	}
	return out
}

func upsertProof(proofs []any, id string, entry map[string]any) []any {
	for i, p := range proofs {
		if pm, ok := p.(map[string]any); ok && pm["id"] == id {
			proofs[i] = entry
			return proofs
		}
	}
	return append(proofs, entry)
}

// appendDrillLedgerEntries appends one telemetry entry per drill result to
// ledgerPath, in the given mode. Recovery proof already succeeded or failed
// by the time this runs — telemetry is secondary, so an append failure
// prints a loud warning on warnOut instead of failing the command (recovery
// proof outranks its own history).
func appendDrillLedgerEntries(warnOut io.Writer, ledgerPath, actor, mode string, results []drill.Result, drills []contextspec.Drill) {
	if ledgerPath == "" {
		return
	}
	if actor == "" {
		actor = "human/owner"
	}
	budgetsByProof := map[string]contextspec.DrillBudgets{}
	for _, d := range drills {
		budgetsByProof[d.Proof] = d.Budgets
	}
	for _, res := range results {
		payload := drillLedgerPayload(res, mode, budgetsByProof[res.Proof])
		if _, err := ledger.AppendNow(ledgerPath, ledger.EntryDrill, actor, ledger.Payload{Drill: &payload}); err != nil {
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
