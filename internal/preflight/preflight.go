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

// Run executes a preflight against declared guards and the proofs backing them.
func Run(_ context.Context, req Request) (*Result, error) {
	if req.Format != "json" && req.Format != "md" && req.Format != "html" && req.Format != "text" {
		return nil, fmt.Errorf("preflight: --format must be json, md, or html, got %q", req.Format)
	}
	intents, err := loadIntents(req)
	if err != nil {
		return nil, err
	}
	if len(intents) == 0 {
		return nil, fmt.Errorf("preflight: --intent or --diff is required")
	}

	ctxSpec, err := loadContext(req.ContextPaths)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if req.AsOf != "" {
		now, err = time.Parse(time.RFC3339, req.AsOf)
		if err != nil {
			return nil, fmt.Errorf("preflight: --as-of must be RFC3339 (e.g. 2026-07-16T12:00:00Z): %w", err)
		}
		now = now.UTC()
	}
	findings := rules.Evaluate(intents, ctxSpec, now)

	findings, err = applyLedgerOverrides(req.LedgerPath, findings, now)
	if err != nil {
		return nil, err
	}

	overall := engine.Overall(findings)
	exitCode := engine.ExitCode(overall, req.FailOnWarn)

	if req.LedgerPath != "" && !req.Plan {
		if err := recordDecision(req, findings, overall, now); err != nil {
			return nil, err
		}
	}

	rendered, err := render(req, findings, overall, now)
	if err != nil {
		return nil, err
	}

	return &Result{Rendered: rendered, ExitCode: exitCode}, nil
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

// loadContext loads and merges every declared context file (contextspec.
// LoadAll — union of guards/facts/proofs/drills, duplicate ids across files
// are an error), or falls back to the built-in zero-config default when
// none was supplied. Explicitly supplied context files — even a single
// empty `version: 2` document — REPLACE the default; it is never merged
// with them (docs/ARCHITECTURE.md §Compatibility stance, point 2).
func loadContext(paths []string) (contextspec.Context, error) {
	if len(paths) == 0 {
		return contextspec.Default(), nil
	}
	ctxSpec, err := contextspec.LoadAll(paths)
	if err != nil {
		return contextspec.Context{}, fmt.Errorf("preflight: %w", err)
	}
	return ctxSpec, nil
}

// applyLedgerOverrides resolves active owner overrides from ledgerPath (if
// any) and applies them to findings. An empty ledgerPath means no ledger was
// supplied, so findings are returned unchanged.
func applyLedgerOverrides(ledgerPath string, findings []engine.Finding, now time.Time) ([]engine.Finding, error) {
	if ledgerPath == "" {
		return findings, nil
	}
	entries, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		return nil, fmt.Errorf("preflight: %w", err)
	}
	overrides := ledger.ActiveOverrides(entries, now)
	return engine.ApplyOverrides(findings, overrides), nil
}

func recordDecision(req Request, findings []engine.Finding, overall engine.Verdict, now time.Time) error {
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
	}}
	id, err := ledger.NewID()
	if err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	if _, err := ledger.Append(req.LedgerPath, ledger.EntryDecision, req.Actor, payload, now, id); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	return nil
}

func render(req Request, findings []engine.Finding, overall engine.Verdict, now time.Time) ([]byte, error) {
	rep := report.FromFindings(findings, overall, now, req.Actor, req.ContextWindow)
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
