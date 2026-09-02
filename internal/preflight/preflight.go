// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package preflight orchestrates a preflight run: load context (or the
// zero-config default), parse the proposed change (intent YAML or diff),
// evaluate the engine, resolve/record ledger overrides and decisions, and
// render the report. It is the only package that does I/O across
// contextspec/intent/rules/engine/ledger/report — those packages stay pure.
package preflight

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/engine"
	"github.com/tannernicol/restoregap/internal/intent"
	"github.com/tannernicol/restoregap/internal/ledger"
	"github.com/tannernicol/restoregap/internal/policy"
	"github.com/tannernicol/restoregap/internal/report"
	"github.com/tannernicol/restoregap/internal/rules"
)

// Request is the full preflight input surface, mapped 1:1 from CLI flags and
// reused by the MCP server tools.
type Request struct {
	DiffPath   string
	DiffRoot   string // repo root; makes repo-relative diff paths absolute
	IntentPath string
	// ContextPaths is repeatable: real deployments keep one context file per
	// drill (its proof-writing timer rewrites that file, so co-mingling
	// several drills in one file fights the timer that owns it) — preflight
	// needs to see all of them to gate on the whole machine's declared
	// guards, not just whichever single file happened to be passed. Zero
	// paths means the built-in default policy, same as an empty ContextPath
	// used to mean.
	ContextPaths  []string
	LedgerPath    string
	Actor         string
	IntentActor   string
	ContextWindow string
	CommitSHA     string
	Format        string
	OutPath       string
	FailOnWarn    bool
	AsOf          string // RFC3339; pins evaluation time for proof freshness (empty = now)
	// ToolVersion is the CLI version stamped into a durable decision entry.
	// It is set by internal/cli; non-CLI callers may leave it empty.
	ToolVersion string
	// Plan evaluates and renders exactly as a normal run does, but skips
	// recordDecision: nothing is appended to the ledger. A readiness probe
	// or dry run that re-evaluates the same unexecuted intent repeatedly
	// must not spam the ledger with identical warn/block entries — a real
	// deployment saw ~3,000 identical entries written in a week by a
	// 10-minute readiness timer doing exactly that.
	Plan bool
}

// Result is a rendered preflight outcome plus its process exit code.
type Result struct {
	Rendered []byte
	ExitCode int
}

// Write emits the rendered report to w (stdout unless --out was given).
func (r *Result) Write(w io.Writer) error {
	_, err := w.Write(r.Rendered)
	return err
}

// evaluationTime resolves the instant proofs are judged against: now, or the
// pinned --as-of. Split out of Run so the gate's ladder stays readable as a
// sequence of steps rather than one long function.
func evaluationTime(asOf string) (time.Time, error) {
	if asOf == "" {
		return time.Now().UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, asOf)
	if err != nil {
		return time.Time{}, fmt.Errorf("preflight: --as-of must be RFC3339 (e.g. 2026-07-16T12:00:00Z): %w", err)
	}
	return t.UTC(), nil
}

// Run executes a preflight against declared guards and the proofs backing them.
func Run(_ context.Context, req Request) (*Result, error) {
	if req.Format != "json" && req.Format != "md" && req.Format != "html" && req.Format != "text" {
		return nil, fmt.Errorf("preflight: --format must be json, md, or html, got %q", req.Format)
	}
	started := time.Now()
	var checks []ledger.DecisionCheckRecord

	checkStarted := time.Now()
	intents, err := loadIntents(req)
	if err != nil {
		return nil, err
	}
	checks = appendCheck(checks, "load_intent", "pass", checkStarted)
	if len(intents) == 0 {
		return nil, fmt.Errorf("preflight: --intent or --diff is required")
	}

	checkStarted = time.Now()
	ctxSpec, policyFindings, err := loadContext(req.ContextPaths)
	if err != nil {
		return gateBroken(req, "load_context", err, started, appendCheck(checks, "load_context", "broken", checkStarted))
	}
	checks = appendCheck(checks, "load_context", "pass", checkStarted)

	// A syntactically readable ledger can still be untrustworthy if its chain
	// is broken. Preflight must never quietly use its overrides in that state:
	// callers treat exit 3 as a block precisely because the gate did not run.
	checkStarted = time.Now()
	entries, err := loadVerifiedLedger(req.LedgerPath)
	if err != nil {
		return gateBroken(req, "verify_ledger", err, started, appendCheck(checks, "verify_ledger", "broken", checkStarted))
	}
	ledgerOutcome := "pass"
	if req.LedgerPath == "" {
		ledgerOutcome = "skip"
	}
	checks = appendCheck(checks, "verify_ledger", ledgerOutcome, checkStarted)

	now, err := evaluationTime(req.AsOf)
	if err != nil {
		return nil, err
	}
	checkStarted = time.Now()
	findings, overall, exitCode := evaluate(req, intents, ctxSpec, entries, now)
	findings, overall, exitCode = withPolicyFindings(findings, overall, exitCode, policyFindings, req.FailOnWarn)
	checks = appendCheck(checks, "evaluate_policy", outcomeFor(exitCode), checkStarted)

	if req.LedgerPath != "" && !req.Plan {
		if err := recordDecision(req, findings, overall, now, "ran", "", checks, elapsedMS(started)); err != nil {
			return gateBroken(req, "record_ledger", err, started, appendCheck(checks, "record_ledger", "broken", time.Now()))
		}
	}

	rendered, err := render(req, findings, overall, now, "ran", "", checks, elapsedMS(started))
	if err != nil {
		return nil, err
	}

	return &Result{Rendered: rendered, ExitCode: exitCode}, nil
}

// evaluate is the policy step: match the intents against the declared guards,
// downgrade anything an active override covers, and reduce to one verdict.
func evaluate(req Request, intents []intent.ChangeIntent, ctxSpec contextspec.Context, entries []ledger.Entry, now time.Time) ([]engine.Finding, engine.Verdict, int) {
	findings := rules.Evaluate(intents, ctxSpec, now)
	findings = engine.ApplyOverrides(findings, ledger.ActiveOverrides(entries, now))
	overall := engine.Overall(findings)
	return findings, overall, engine.ExitCode(overall, req.FailOnWarn)
}

// outcomeFor maps the process exit code to the check vocabulary recorded in
// the ledger.
func outcomeFor(exitCode int) string {
	if exitCode == 1 {
		return "fail"
	}
	return "pass"
}

// appendCheck records a completed stage using a wall-clock duration rounded
// down to whole milliseconds. Ledger numbers are intentionally integral so
// canonical JSON never needs floating-point normalization.
func appendCheck(checks []ledger.DecisionCheckRecord, id, outcome string, started time.Time) []ledger.DecisionCheckRecord {
	return append(checks, ledger.DecisionCheckRecord{ID: id, Outcome: outcome, DurationMS: elapsedMS(started)})
}

func elapsedMS(started time.Time) int64 {
	return time.Since(started).Milliseconds()
}

// gateBroken creates the report-and-ledger representation of a gate that
// could not be trusted to run. This is intentionally not an engine block: a
// policy block says the gate evaluated the change and rejected it, while this
// says evaluation was unavailable. Both stop callers, but operators need the
// distinction to repair the gate rather than chase a nonexistent proof gap.
func gateBroken(req Request, checkID string, cause error, started time.Time, checks []ledger.DecisionCheckRecord) (*Result, error) {
	reason := fmt.Sprintf("%s: %v", checkID, cause)
	now := time.Now().UTC()
	if req.LedgerPath != "" && !req.Plan {
		// The primary failure is still rendered even if recording it fails. A
		// broken write path cannot be made auditable by returning a generic
		// error and hiding the check that failed.
		_ = recordDecision(req, nil, engine.VerdictBlock, now, "broken", reason, checks, elapsedMS(started))
	}
	rendered, err := render(req, nil, engine.VerdictBlock, now, "broken", reason, checks, elapsedMS(started))
	if err != nil {
		return nil, err
	}
	return &Result{Rendered: rendered, ExitCode: 3}, nil
}

// loadIntents parses exactly one of --intent or --diff into normalized
// ChangeIntents, applying --intent-actor / --context-window overrides.
func loadIntents(req Request) ([]intent.ChangeIntent, error) {
	if req.IntentPath != "" && req.DiffPath != "" {
		return nil, fmt.Errorf("preflight: pass only one of --intent or --diff")
	}

	var intents []intent.ChangeIntent
	switch {
	case req.IntentPath != "":
		r, closeFn, err := openInput(req.IntentPath)
		if err != nil {
			return nil, fmt.Errorf("preflight: --intent: %w", err)
		}
		defer func() { _ = closeFn() }()
		ci, err := intent.Parse(r)
		if err != nil {
			return nil, fmt.Errorf("preflight: --intent: %w", err)
		}
		intents = []intent.ChangeIntent{ci}
	case req.DiffPath != "":
		r, closeFn, err := openInput(req.DiffPath)
		if err != nil {
			return nil, fmt.Errorf("preflight: --diff: %w", err)
		}
		defer func() { _ = closeFn() }()
		files, err := intent.ParseDiff(r)
		if err != nil {
			return nil, fmt.Errorf("preflight: --diff: %w", err)
		}
		// git emits repo-relative paths ("bin/ctx"); declared guards are
		// absolute ("/home/user/bin/ctx"). Without a root to resolve
		// against, every path guard silently fails to match and a git hook
		// reports "pass" on a change that touches a lifeline — the worst
		// failure mode a gate has, because it is indistinguishable from safe.
		files = intent.Rebase(files, req.DiffRoot)
		intents = intent.ToChangeIntents(files)
	default:
		return nil, nil
	}

	for i := range intents {
		if req.IntentActor != "" {
			intents[i].Actor = req.IntentActor
		}
		if req.ContextWindow != "" {
			intents[i].ContextWindow = req.ContextWindow
		}
	}
	return intents, nil
}

func openInput(path string) (io.Reader, func() error, error) {
	if path == "-" {
		return os.Stdin, func() error { return nil }, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

// loadContext loads and merges every declared context file via policy.Merge
// — union of facts/proofs/drills (duplicate ids across files are an error),
// tighten-only by id for guards (docs/SCHEMA.md §Layered policy: a later
// file may add a guard or make an existing one stricter, never weaker; a
// weakening attempt is ignored and reported as a Finding) — or falls back
// to the built-in zero-config default when none was supplied. Explicitly
// supplied context files — even a single empty `version: 2` document —
// REPLACE the default; it is never merged with them (docs/ARCHITECTURE.md
// §Compatibility stance, point 2).
func loadContext(paths []string) (contextspec.Context, []policy.Finding, error) {
	if len(paths) == 0 {
		return contextspec.Default(), nil, nil
	}
	ctxSpec, findings, err := policy.Merge(paths)
	if err != nil {
		return contextspec.Context{}, nil, fmt.Errorf("preflight: %w", err)
	}
	return ctxSpec, findings, nil
}

// withPolicyFindings folds policy.Merge's ignored-loosening findings (see
// policyLoosenedFindings) into an already-evaluated findings/overall/
// exitCode triple, recomputing overall and exitCode only when there are any
// — the common case (no policy layers, or none in conflict) returns its
// inputs unchanged. A later policy layer's loosening attempt is ignored,
// not applied, but it must never pass silently as though the run saw
// nothing — split out of Run to keep Run's own branching within the
// project's gocyclo cap.
func withPolicyFindings(findings []engine.Finding, overall engine.Verdict, exitCode int, policyFindings []policy.Finding, failOnWarn bool) ([]engine.Finding, engine.Verdict, int) {
	if len(policyFindings) == 0 {
		return findings, overall, exitCode
	}
	findings = append(findings, policyLoosenedFindings(policyFindings)...)
	overall = engine.Overall(findings)
	return findings, overall, engine.ExitCode(overall, failOnWarn)
}

// policyLoosenedFindings renders policy.Merge's ignored-loosening findings
// as engine.Finding so they flow through the same override/report pipeline
// as every other finding: RiskNone/ProofNotRequired because they are not
// about a resource's recovery proof, VerdictWarn because the loosening
// attempt was ignored, not applied — the run is not broken, it just needs
// an owner to fix or remove the offending declaration.
func policyLoosenedFindings(findings []policy.Finding) []engine.Finding {
	out := make([]engine.Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, engine.Finding{
			ID:               "policy/loosened:" + f.GuardID + ":" + f.File,
			GuardID:          f.GuardID,
			Kind:             "policy",
			Resource:         f.File,
			RiskClass:        engine.RiskNone,
			ProofStatus:      engine.ProofNotRequired,
			Verdict:          engine.VerdictWarn,
			Title:            "policy layer loosening ignored for guard " + f.GuardID,
			RequiredNextStep: "fix or remove the loosening attempt in " + f.File + " — the earlier (stricter) declaration is still enforced",
		})
	}
	return out
}

// applyLedgerOverrides resolves active owner overrides from ledgerPath (if
// any) and applies them to findings. An empty ledgerPath means no ledger was
// supplied, so findings are returned unchanged.
func loadVerifiedLedger(ledgerPath string) ([]ledger.Entry, error) {
	if ledgerPath == "" {
		return nil, nil
	}
	entries, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		return nil, fmt.Errorf("preflight: %w", err)
	}
	verified := ledger.VerifyEntries(entries)
	if !verified.OK {
		return nil, fmt.Errorf("preflight: ledger chain is unverifiable: %s", verified.Reason)
	}
	return entries, nil
}

func recordDecision(req Request, findings []engine.Finding, overall engine.Verdict, now time.Time, gateState, brokenReason string, checks []ledger.DecisionCheckRecord, durationMS int64) error {
	records := make([]ledger.FindingRecord, 0, len(findings))
	for _, f := range findings {
		records = append(records, ledger.FindingRecord{
			FindingID:   f.ID,
			GuardID:     f.GuardID,
			Resource:    f.Resource,
			Verdict:     string(f.Verdict),
			RiskClass:   string(f.RiskClass),
			ProofStatus: string(f.ProofStatus),
		})
	}
	payload := ledger.Payload{Decision: &ledger.DecisionPayload{
		Verdict:       string(overall),
		Findings:      records,
		Actor:         req.Actor,
		ContextWindow: req.ContextWindow,
		GateState:     gateState,
		BrokenReason:  brokenReason,
		Checks:        checks,
		DurationMS:    durationMS,
		ToolVersion:   req.ToolVersion,
	}}
	id, err := ledger.NewID()
	if err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	opts := policy.StampOptions(req.ContextPaths)
	if _, err := ledger.Append(req.LedgerPath, ledger.EntryDecision, req.Actor, payload, now, id, opts...); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	return nil
}

func render(req Request, findings []engine.Finding, overall engine.Verdict, now time.Time, gateState, brokenReason string, checks []ledger.DecisionCheckRecord, durationMS int64) ([]byte, error) {
	rep := report.FromFindings(findings, overall, now, req.Actor, req.ContextWindow)
	rep.GateState = gateState
	rep.BrokenReason = brokenReason
	rep.DurationMS = durationMS
	for _, c := range checks {
		rep.Checks = append(rep.Checks, report.Check{ID: c.ID, Outcome: c.Outcome, DurationMS: c.DurationMS})
	}
	switch req.Format {
	case "json":
		return rep.JSON()
	case "html":
		return rep.HTML()
	case "text":
		return rep.Text(), nil
	default:
		return rep.Markdown(), nil
	}
}

// runTerraformPlan runs Recovery Preflight: gate a Terraform plan that
// materially changes an RDS/Aurora resource on supplied restore evidence
// (internal/recovery, a semantic port of recovery_preflight.py). Unlike
// local mode, verdict vocabulary here is fail|pass — there is no warn
// state, so --fail-on-warn has nothing to do and is intentionally ignored.
