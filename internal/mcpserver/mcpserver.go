// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package mcpserver exposes restoregap to agents over MCP (newline-delimited
// JSON-RPC 2.0 on stdio). The seven capabilities ported from the Python
// server — preflight_intent, preflight_diff, acknowledge_risk,
// explain_decision, required_proof, ledger_query, story — plus three
// Go-only additions, drill_lint, next_steps, and discover. Tools write only
// to the ledger path the caller supplies — never to system state, and NEVER
// by running a declared drill: a drill executes a user-declared shell
// command (recover, validate checks, pin_check), so letting an MCP tool
// trigger one would make this an exec service reachable by anything that
// can speak the protocol. drill_lint, next_steps, and discover are all
// static/read-only on purpose; `restoregap drill`, `restoregap accept`, and
// discover's own on-disk snapshot writes all stay CLI-only.
package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/discover"
	"github.com/tannernicol/restoregap/internal/discovery"
	"github.com/tannernicol/restoregap/internal/drill"
	"github.com/tannernicol/restoregap/internal/ledger"
	"github.com/tannernicol/restoregap/internal/policy"
	"github.com/tannernicol/restoregap/internal/preflight"
	"github.com/tannernicol/restoregap/internal/status"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type toolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema map[string]any  `json:"inputSchema"`
	Annotations toolAnnotations `json:"annotations"`
}

// Preflight tools may append decisions to the ledger, even when the proposed
// operation is only being planned. Only inspection tools advertise read-only.
type toolAnnotations struct {
	Title        string `json:"title"`
	ReadOnlyHint bool   `json:"readOnlyHint"`
}

func schema(required []string, props map[string]any) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func boolean(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

func toolDefs() []toolDef {
	common := map[string]any{
		"context_path": str("path to restoregap.yml / restoregap.local.yml (omit to discover $RESTOREGAP_CONTEXT / " +
			"./restoregap.local.yml / ./restoregap.yml, else the built-in default policy)"),
		"ledger_path":      str("append-only decision ledger (JSONL); the only path tools write to"),
		"actor":            str("acting identity (default agent/mcp)"),
		"context_window":   str("execution context, e.g. coding-agent"),
		"as_of":            str("RFC3339 evaluation time (testing)"),
		"require_coverage": boolean("strict mode: every addressed path, target, package, and command must be covered by a matching guard"),
	}
	intentProps := map[string]any{"intent": str("intent YAML content, inline"), "intent_path": str("path to an intent YAML file")}
	diffProps := map[string]any{"diff": str("unified diff content, inline"), "diff_path": str("path to a diff file")}
	for k, v := range common {
		intentProps[k] = v
		diffProps[k] = v
	}
	return []toolDef{
		{"preflight_intent", "Gate a proposed action (intent YAML) on declared recovery invariants; returns the decision JSON.", schema(nil, intentProps), toolAnnotations{"Preflight intent", false}},
		{"preflight_diff", "Gate a proposed change (unified diff) on declared recovery invariants; returns the decision JSON.", schema(nil, diffProps), toolAnnotations{"Preflight diff", false}},
		{"acknowledge_risk", "Record an owner-approved override for a blocked decision in the ledger.", schema([]string{"ledger_path", "decision_id", "acknowledgement", "owner"}, map[string]any{
			"ledger_path": str("ledger to append to"), "decision_id": str("finding/decision id being overridden"),
			"acknowledgement": str("owner statement"), "owner": str("who approves"),
			"reason":     str("test-environment | false-positive | disposable-test-data | emergency | other"),
			"actor":      str("recording actor"),
			"expires_in": str("how long the override stays active, e.g. 720h (default 30d, maximum 90d — an override is an exception with a deadline, never an amnesty)"),
		}), toolAnnotations{"Acknowledge risk", false}},
		{"explain_decision", "Explain a recorded decision from the ledger.", schema([]string{"ledger_path"}, map[string]any{
			"ledger_path": str("ledger to read"), "decision_id": str("finding/decision id"), "entry_id": str("ledger entry id")}), toolAnnotations{"Explain decision", true}},
		{"required_proof", "What proof would let a blocked decision pass.", schema([]string{"ledger_path"}, map[string]any{
			"ledger_path": str("ledger to read"), "decision_id": str("finding/decision id"), "entry_id": str("ledger entry id")}), toolAnnotations{"Required proof", true}},
		{"ledger_query", "List ledger entries, optionally filtered by resource or entry id.", schema([]string{"ledger_path"}, map[string]any{
			"ledger_path": str("ledger to read"), "resource": str("resource substring filter"), "entry_id": str("exact entry id")}), toolAnnotations{"Query ledger", true}},
		{"story", "Markdown timeline of decisions for a resource.", schema([]string{"ledger_path"}, map[string]any{
			"ledger_path": str("ledger to read"), "resource": str("resource substring filter")}), toolAnnotations{"Decision story", true}},
		// drill_lint is read-only and static: it parses context_path and reports
		// per-drill findings, the same checks as `restoregap drill --lint`.
		// Deliberately NOT a drill-execution tool — a drill runs a user-declared
		// shell command, and an MCP tool that could trigger that would turn this
		// server into a remotely-reachable exec service. Running a drill (or
		// --pins-only) stays CLI-only; author and lint here, run at the terminal.
		{"drill_lint", "Statically check every declared drill for problems — no recovery is run, nothing is written. " +
			"Same checks as `restoregap drill --lint`: an rpo budget nothing can measure is an error; a missing " +
			"pin_check or a not-yet-present artifact path is a warning.",
			schema([]string{"context_path"}, map[string]any{
				"context_path": str("v2 context file with a drills: block"),
			}), toolAnnotations{"Lint drills", true}},
		// next_steps is read-only: it reports the same not-green proofs
		// `restoregap next` does, each with its exact remediation command —
		// it never runs a drill or writes an acceptance itself.
		{"next_steps", "The path to green: every declared proof that is not green, worst first, each with its " +
			"effective layer/category, state, why, the exact command that moves it, its source context file, " +
			"and its artifact/evidence path. Same data as `restoregap next --format json`.",
			schema([]string{"context_path"}, map[string]any{
				"context_path": str("path to restoregap.yml / restoregap.local.yml (omit to discover, same as the other tools)"),
				"layer":        str("only this layer's gaps, e.g. identity-secrets (omit for every layer)"),
			}), toolAnnotations{"Next steps", true}},
		// discover is read-only in the strongest sense: unlike `restoregap
		// discover` on the CLI, this tool NEVER writes or rotates the
		// on-disk snapshot — it only reads whatever the CLI (run by a human
		// or a timer) already saved, to compute the new-since-last-scan
		// diff. It cannot mark anything covered; coverage is recomputed
		// fresh from context_path's declared drills/guards on every call.
		{"discover", "Enumerate recovery candidates on this host (containers, databases, unbacked repos, " +
			"service state, plus the machine-id/package-manifest/etc-config floor) and diff them against " +
			"declared drills/guards — same data as `restoregap discover --format json`. Never writes the " +
			"on-disk snapshot itself (the CLI does); only reads it to report what changed since the last " +
			"real scan.",
			schema(nil, map[string]any{
				"context_path": str("path to restoregap.yml / restoregap.local.yml (omit to discover, same as the other tools)"),
				"all":          boolean("include covered candidates too (default: only the gaps)"),
				"trend":        boolean("also include the last scans' coverage-trend rows, oldest first"),
				"prompt":       boolean("return the ready-to-hand agent brief (same text as `restoregap discover --prompt`) instead of JSON"),
			}), toolAnnotations{"Discover recovery gaps", true}},
	}
}

type toolArgs struct {
	Intent          string `json:"intent"`
	IntentPath      string `json:"intent_path"`
	Diff            string `json:"diff"`
	DiffPath        string `json:"diff_path"`
	ContextPath     string `json:"context_path"`
	LedgerPath      string `json:"ledger_path"`
	Actor           string `json:"actor"`
	ContextWindow   string `json:"context_window"`
	AsOf            string `json:"as_of"`
	RequireCoverage bool   `json:"require_coverage"`
	DecisionID      string `json:"decision_id"`
	EntryID         string `json:"entry_id"`
	Acknowledgement string `json:"acknowledgement"`
	Owner           string `json:"owner"`
	Reason          string `json:"reason"`
	Resource        string `json:"resource"`
	ExpiresIn       string `json:"expires_in"`
	Layer           string `json:"layer"`
	All             bool   `json:"all"`
	Trend           bool   `json:"trend"`
	Prompt          bool   `json:"prompt"`
}

// Serve runs the stdio server until EOF.
func Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	enc := json.NewEncoder(out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		resp := handle(ctx, req)
		if resp != nil { // notifications get no response
			if err := enc.Encode(resp); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

func handle(ctx context.Context, req rpcRequest) *rpcResponse {
	if req.ID == nil && strings.HasPrefix(req.Method, "notifications/") {
		return nil
	}
	resp := &rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "restoregap", "version": "0.1.0"},
		}
	case "tools/list":
		resp.Result = map[string]any{"tools": toolDefs()}
	case "tools/call":
		var params struct {
			Name      string   `json:"name"`
			Arguments toolArgs `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = &rpcError{Code: -32602, Message: "invalid params"}
			return resp
		}
		text, err := callTool(ctx, params.Name, params.Arguments)
		if err != nil {
			resp.Result = map[string]any{"content": []map[string]any{{"type": "text", "text": "error: " + err.Error()}}, "isError": true}
			return resp
		}
		resp.Result = map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
	default:
		resp.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
	return resp
}

func callTool(ctx context.Context, name string, a toolArgs) (string, error) {
	if a.Actor == "" {
		a.Actor = "agent/mcp"
	}
	switch name {
	case "preflight_intent", "preflight_diff":
		return preflightTool(ctx, name, a)
	case "acknowledge_risk":
		return acknowledgeRiskTool(a)
	case "explain_decision", "required_proof", "ledger_query", "story":
		if a.LedgerPath == "" {
			return "", fmt.Errorf("%s requires ledger_path", name)
		}
		entries, err := ledger.ReadAll(a.LedgerPath)
		if err != nil {
			return "", err
		}
		return renderLedgerTool(name, entries, a)
	case "drill_lint":
		return drillLintTool(a)
	case "next_steps":
		return nextStepsTool(a)
	case "discover":
		return discoverTool(a)
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

// nextStepsTool is callTool's next_steps case: the same not-green-proof
// data `restoregap next --format json` prints, read-only — it gathers
// status and reports; it never drills or writes an acceptance.
func nextStepsTool(a toolArgs) (string, error) {
	s, err := status.Gather(status.Request{ContextPaths: contextPathsFor(a.ContextPath)})
	if err != nil {
		return "", err
	}
	steps := s.NextSteps()
	if a.Layer != "" {
		steps = status.FilterNextSteps(steps, status.NewTreeFilter([]string{a.Layer}, nil, nil, nil, nil, nil))
	}
	if steps == nil {
		steps = []status.NextStep{}
	}
	encoded, err := json.MarshalIndent(steps, "", "  ")
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// discoverTool is callTool's discover case: runs discover.Collect with
// NoSave always true (this tool must never write to system state — see the
// package doc comment at the top of this file) and returns the resulting
// Report as JSON, filtered to only-uncovered unless a.All is set. Coverage
// comes straight from context_path's declared drills/guards via
// discover.Collect; this function has no way to override it.
func discoverTool(a toolArgs) (string, error) {
	ctx, err := loadDiscoverContext(contextPathsFor(a.ContextPath))
	if err != nil {
		return "", err
	}
	report, err := discover.Collect(discover.Options{Context: ctx, NoSave: true})
	if err != nil {
		return "", err
	}
	if a.Prompt {
		return discover.RenderPrompt(report, a.All, "all"), nil
	}
	resp := *report
	if !a.All {
		resp.Candidates = uncoveredOnly(report.Candidates)
	}
	result := struct {
		discover.Report
		Trend []discover.HistoryRow `json:"trend,omitempty"`
	}{Report: resp}
	if a.Trend {
		result.Trend = recentTrend()
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// uncoveredOnly filters candidates to the ones not yet covered AND not
// suppressed as noise — the gaps an agent asking "what am I missing"
// actually needs. A suppressed candidate (a browser profile cache, an
// archived project's leftover database) is exactly the noise that makes a
// gap list get ignored; all=true (discoverTool) bypasses this filter
// entirely, same as the CLI's --all.
func uncoveredOnly(candidates []discover.Candidate) []discover.Candidate {
	out := make([]discover.Candidate, 0, len(candidates))
	for _, c := range candidates {
		if !c.Covered && !c.Suppressed {
			out = append(out, c)
		}
	}
	return out
}

// recentTrend reads the last discover.TrendDisplayLimit rows of scan
// history, or nil when there is no state dir or no history yet — never an
// error, since trend is an optional enrichment of a successful discover
// call.
func recentTrend() []discover.HistoryRow {
	stateDir, err := discover.DefaultStateDir()
	if err != nil {
		return nil
	}
	rows, err := discover.ReadHistory(stateDir)
	if err != nil || len(rows) == 0 {
		return nil
	}
	if len(rows) > discover.TrendDisplayLimit {
		rows = rows[len(rows)-discover.TrendDisplayLimit:]
	}
	return rows
}

// loadDiscoverContext loads and merges every declared context path via
// policy.Merge (same semantics as status.Gather's own loadMerged and
// internal/cli's discover command), falling back to the built-in
// zero-config default when no context is discoverable.
func loadDiscoverContext(paths []string) (contextspec.Context, error) {
	if len(paths) == 0 {
		return contextspec.Default(), nil
	}
	ctx, _, err := policy.Merge(paths)
	if err != nil {
		return contextspec.Context{}, fmt.Errorf("discover: %w", err)
	}
	return ctx, nil
}

// preflightTool is callTool's preflight_intent/preflight_diff case, split
// out to keep callTool itself under the gocyclo threshold.
func preflightTool(ctx context.Context, name string, a toolArgs) (string, error) {
	req := preflight.Request{
		ContextPaths: contextPathsFor(a.ContextPath), LedgerPath: a.LedgerPath, Actor: a.Actor,
		ContextWindow: a.ContextWindow, AsOf: a.AsOf, Format: "json", RequireCoverage: a.RequireCoverage,
	}
	var err error
	if name == "preflight_intent" {
		req.IntentPath, err = inlineOrPath(a.Intent, a.IntentPath, "intent-*.yml")
	} else {
		req.DiffPath, err = inlineOrPath(a.Diff, a.DiffPath, "diff-*.patch")
	}
	if err != nil {
		return "", err
	}
	result, err := preflight.Run(ctx, req)
	if err != nil {
		return "", err
	}
	return string(result.Rendered), nil
}

// contextPathsFor resolves the MCP tool's single context_path argument into
// the []string preflight.Request now takes. An explicit path is used
// unchanged. An omitted one falls back to the same $RESTOREGAP_CONTEXT /
// ./restoregap.local.yml / ./restoregap.yml discovery the CLI uses
// (internal/discovery), tried BEFORE preflight.Run's own built-in
// zero-config default — without this, a tool call that omits context_path
// silently evaluates against the toy built-in policy even on a machine that
// has a real declared context sitting right next to it, gating nothing that
// context actually protects.
func contextPathsFor(explicit string) []string {
	if explicit != "" {
		return []string{explicit}
	}
	return discovery.ContextPaths()
}

// drillLintTool is callTool's drill_lint case, split out to keep callTool
// itself under the gocyclo threshold.
func drillLintTool(a toolArgs) (string, error) {
	if a.ContextPath == "" {
		return "", fmt.Errorf("drill_lint requires context_path")
	}
	ctx, err := contextspec.Load(a.ContextPath)
	if err != nil {
		return "", err
	}
	return renderDrillLint(ctx.Drills), nil
}

// renderDrillLint runs drill.Lint over every declared drill and renders one
// "error: <proof>: <message>" / "warn: <proof>: <message>" line per finding
// — the same agent-parseable shape `restoregap drill --lint` prints to
// stdout, so an agent that already knows how to read the CLI's output reads
// this identically.
func renderDrillLint(drills []contextspec.Drill) string {
	var b strings.Builder
	for _, d := range drills {
		for _, f := range drill.Lint(d) {
			fmt.Fprintf(&b, "%s: %s: %s\n", f.Severity, f.Proof, f.Message)
		}
	}
	if b.Len() == 0 {
		return fmt.Sprintf("%d drill(s) declared, no problems found", len(drills))
	}
	return b.String()
}

func renderLedgerTool(name string, entries []ledger.Entry, a toolArgs) (string, error) {
	var b strings.Builder
	found := false

	for _, e := range entries {
		if a.EntryID != "" && e.ID != a.EntryID {
			continue
		}
		if e.EntryType != ledger.EntryDecision || e.Payload.Decision == nil {
			if name == "ledger_query" && a.EntryID == e.ID {
				j, _ := json.MarshalIndent(e, "", "  ")
				return string(j), nil
			}
			continue
		}
		if renderFindings(&b, name, e, a) {
			found = true
		}
	}
	if !found {
		return "no matching ledger entries", nil
	}
	if name == "story" {
		return "# Recovery decision story\n\n" + b.String(), nil
	}
	return b.String(), nil
}

// findingMatches reports whether rec satisfies the caller's decision_id and
// resource filters (an empty filter matches everything).
func findingMatches(rec ledger.FindingRecord, a toolArgs) bool {
	if a.DecisionID != "" && rec.FindingID != a.DecisionID {
		return false
	}
	if a.Resource != "" && !strings.Contains(rec.Resource, a.Resource) {
		return false
	}
	return true
}

// renderFindings appends one rendered line per matching finding in e's
// decision payload to b, and reports whether any finding matched.
func renderFindings(b *strings.Builder, name string, e ledger.Entry, a toolArgs) bool {
	matched := false
	for _, rec := range e.Payload.Decision.Findings {
		if !findingMatches(rec, a) {
			continue
		}
		matched = true
		switch name {
		case "explain_decision":
			explainDecision(b, rec, e)
		case "required_proof":
			requiredProof(b, rec)
		case "ledger_query":
			ledgerQuery(b, e, rec)
		case "story":
			story(b, e, rec)
		}
	}
	return matched
}

func explainDecision(b *strings.Builder, rec ledger.FindingRecord, e ledger.Entry) {
	fmt.Fprintf(b, "decision %s: verdict %s — guard %s matched %s (risk %s, proof %s), recorded %s by %s\n",
		rec.FindingID, rec.Verdict, rec.GuardID, rec.Resource, rec.RiskClass, rec.ProofStatus,
		e.CreatedAt.Format("2006-01-02 15:04"), e.Actor)
}

func requiredProof(b *strings.Builder, rec ledger.FindingRecord) {
	// An agent asking "what would make this pass" must get the remedy that
	// matches WHY it blocked: an unreachable proof needs the source back and
	// a drill re-run (nothing was proven — no data loss implied), while any
	// other status needs the evidence itself satisfied.
	remedy := "satisfy the guard's declared proofs/facts in the context file, then re-run preflight; or record an owner override via acknowledge_risk"
	if rec.ProofStatus == "unreachable" {
		remedy = "the recovery source was not reachable when the drill last ran, so nothing was proven (no data loss is implied); " +
			"re-run the drill once the source is reachable, then re-run preflight; or record an owner override via acknowledge_risk"
	}
	fmt.Fprintf(b, "decision %s (guard %s): proof status %s — %s\n",
		rec.FindingID, rec.GuardID, rec.ProofStatus, remedy)
}

func ledgerQuery(b *strings.Builder, e ledger.Entry, rec ledger.FindingRecord) {
	fmt.Fprintf(b, "%s %s %s %s %s %s\n", e.ID, e.CreatedAt.Format("2006-01-02"), rec.Verdict, rec.GuardID, rec.Resource, e.Actor)
}

func story(b *strings.Builder, e ledger.Entry, rec ledger.FindingRecord) {
	fmt.Fprintf(b, "- **%s** — `%s`: %s (%s) by %s\n", e.CreatedAt.Format("2006-01-02 15:04"), rec.Resource, rec.Verdict, rec.GuardID, e.Actor)
}

func inlineOrPath(inline, path, pattern string) (string, error) {
	if inline != "" && path != "" {
		return "", fmt.Errorf("pass inline content or a path, not both")
	}
	if inline == "" {
		if path == "" {
			return "", fmt.Errorf("intent/diff content or path is required")
		}
		return path, nil
	}
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(inline); err != nil {
		_ = f.Close()
		return "", err
	}
	return f.Name(), f.Close()
}

func nonEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// acknowledgeRiskTool records an owner-approved override. Split out of
// callTool so the deadline rule (NewOverridePayload) reads as its own step
// rather than one branch of a growing switch.
func acknowledgeRiskTool(a toolArgs) (string, error) {
	if a.LedgerPath == "" || a.DecisionID == "" || a.Acknowledgement == "" || a.Owner == "" {
		return "", fmt.Errorf("acknowledge_risk requires ledger_path, decision_id, acknowledgement, owner")
	}
	// Every new override goes through NewOverridePayload so the deadline
	// rule is enforced at the WRITE path, not only in the reader: this is
	// the only place overrides are created, and building the payload here
	// by hand is exactly how "dated override" would have degraded back
	// into a permanent amnesty.
	var expiresIn time.Duration
	if a.ExpiresIn != "" {
		d, perr := time.ParseDuration(a.ExpiresIn)
		if perr != nil {
			return "", fmt.Errorf("acknowledge_risk: expires_in must be a duration like 720h: %w", perr)
		}
		expiresIn = d
	}
	payload, err := ledger.NewOverridePayload(a.DecisionID, a.Owner, nonEmpty(a.Reason, "other"), expiresIn, time.Now().UTC())
	if err != nil {
		return "", fmt.Errorf("acknowledge_risk: %w", err)
	}
	payload.Acknowledgement = a.Acknowledgement
	entry, err := ledger.AppendNow(a.LedgerPath, ledger.EntryOverride, a.Actor, ledger.Payload{Override: payload})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("override recorded: entry %s for decision %s (owner %s), expires %s",
		entry.ID, a.DecisionID, a.Owner, payload.ExpiresAt.Format(time.RFC3339)), nil
}
