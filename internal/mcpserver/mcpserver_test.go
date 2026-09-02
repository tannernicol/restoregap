// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/ledger"
)

// TestMain gives every test in this package an isolated XDG_CONFIG_HOME for
// the whole run. Context discovery reads $XDG_CONFIG_HOME/restoregap/*.yml
// as its final tier, so the "nothing discoverable" tests below would load a
// real machine's context files (this homelab's ~/.config/restoregap holds
// fifteen of them) without it. RESTOREGAP_CONTEXT is cleared so no test
// result depends on the outer shell's environment.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "restoregap-mcp-test-config-*")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("XDG_CONFIG_HOME", dir)
	_ = os.Unsetenv("RESTOREGAP_CONTEXT")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func writeContext(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "restoregap.yml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write context: %v", err)
	}
	return path
}

// TestToolDefsExposesDrillLintOnly: drill_lint is read-only and static; no
// drill-execution tool (whatever it might be named) may ever be listed —
// that would make the MCP server a remotely-reachable exec service, since a
// drill runs a user-declared shell command.
func TestToolDefsExposesDrillLintOnly(t *testing.T) {
	defs := toolDefs()
	var found *toolDef
	for i, d := range defs {
		if d.Name == "drill_lint" {
			found = &defs[i]
		}
		if strings.HasPrefix(d.Name, "drill") && d.Name != "drill_lint" {
			t.Errorf("unexpected drill-execution-shaped tool exposed over MCP: %q", d.Name)
		}
	}
	if found == nil {
		t.Fatal("drill_lint not found in toolDefs()")
	}
	req, _ := found.InputSchema["required"].([]string)
	if len(req) != 1 || req[0] != "context_path" {
		t.Errorf("drill_lint required = %v, want [context_path]", req)
	}
}

const mcpCleanDrillYAML = `version: 2
drills:
  - proof: clean
    artifact: %s
    recover: "true"
    pin_check: "true"
`

const mcpDirtyDrillYAML = `version: 2
drills:
  - proof: dirty
    artifact: /nonexistent/for/mcp/test
    recover: "true"
    budgets: { rpo: 1h }
`

func TestCallToolDrillLintClean(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact")
	if err := os.WriteFile(artifact, []byte("x"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	path := writeContext(t, fmt.Sprintf(mcpCleanDrillYAML, artifact))

	text, err := callTool(context.Background(), "drill_lint", toolArgs{ContextPath: path})
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	if !strings.Contains(text, "no problems found") {
		t.Errorf("expected a clean summary, got %q", text)
	}
}

func TestCallToolDrillLintDirty(t *testing.T) {
	path := writeContext(t, mcpDirtyDrillYAML)

	text, err := callTool(context.Background(), "drill_lint", toolArgs{ContextPath: path})
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	// no pin_check (warn) + artifact missing (warn) + rpo with no freshness source (error).
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), text)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "error: ") && !strings.HasPrefix(l, "warn: ") {
			t.Errorf("line not agent-parseable: %q", l)
		}
	}
	if !strings.Contains(text, "error: dirty:") {
		t.Errorf("expected the rpo error tagged with its proof id, got %q", text)
	}
}

func TestCallToolDrillLintRequiresContextPath(t *testing.T) {
	if _, err := callTool(context.Background(), "drill_lint", toolArgs{}); err == nil {
		t.Fatal("drill_lint with no context_path must error, not silently no-op")
	}
}

func TestCallToolDrillLintBadContextPath(t *testing.T) {
	if _, err := callTool(context.Background(), "drill_lint", toolArgs{ContextPath: "/nonexistent/restoregap.yml"}); err == nil {
		t.Fatal("a context file that fails to load must error")
	}
}

// mcpFallbackGuardYAML declares a guard on /x/app.db with no proof
// declared to satisfy it — an intent deleting /x/app.db must BLOCK when
// this file is the loaded context, and PASS under the built-in default
// policy (which knows nothing about /x/app.db at all).
const mcpFallbackGuardYAML = `version: 2
guards:
  - id: app-db-guard
    kind: guard
    match: {paths: ["/x/app.db"]}
    requires: {proofs: [app-db-recovery]}
    enforcement: block
`

func preflightVerdict(t *testing.T, text string) string {
	t.Helper()
	var out struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("unmarshal preflight_intent result: %v (raw: %s)", err, text)
	}
	return out.Verdict
}

// TestPreflightToolFallsBackToDiscoveredContextWhenOmitted is the MCP-side
// case of the bug this feature fixes: a tool call that omits context_path
// must not silently fall through to the built-in toy policy when a real
// context is discoverable in the working directory — it must find and use
// it, same as the CLI would.
func TestPreflightToolFallsBackToDiscoveredContextWhenOmitted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "restoregap.local.yml"), []byte(mcpFallbackGuardYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	text, err := callTool(context.Background(), "preflight_intent", toolArgs{
		Intent: "version: 2\naction: delete_file\npath: /x/app.db\n",
		AsOf:   "2026-08-20T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	if got := preflightVerdict(t, text); got != "block" {
		t.Errorf("verdict = %q, want block (the discovered restoregap.local.yml declares this guard) — got %s", got, text)
	}
}

// TestPreflightToolNoContextPathAndNothingDiscoverableUsesBuiltInDefault
// pins the pre-existing zero-config fallback: when context_path is omitted
// AND nothing is discoverable in the working directory, preflight still
// falls all the way back to the built-in default policy rather than
// erroring — this must be unaffected by the new discovery fallback.
func TestPreflightToolNoContextPathAndNothingDiscoverableUsesBuiltInDefault(t *testing.T) {
	t.Chdir(t.TempDir())

	text, err := callTool(context.Background(), "preflight_intent", toolArgs{
		Intent: "version: 2\naction: delete_file\npath: /x/app.db\n",
		AsOf:   "2026-08-20T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	// The built-in default policy declares nothing about /x/app.db, so this
	// passes — proving the fallback did NOT invent a block from nowhere and
	// did NOT error just because nothing was discoverable.
	if got := preflightVerdict(t, text); got != "pass" {
		t.Errorf("verdict = %q, want pass (built-in default policy has no opinion on /x/app.db) — got %s", got, text)
	}
}

// TestPreflightToolExplicitContextPathIsNeverOverriddenByDiscovery: an
// explicit context_path must win even when a different file is also
// discoverable in the working directory — discovery is a fallback for the
// omitted case only, never a replacement for what the caller asked for.
func TestPreflightToolExplicitContextPathIsNeverOverriddenByDiscovery(t *testing.T) {
	dir := t.TempDir()
	// A discoverable file that would BLOCK if (wrongly) used instead of the
	// explicit one.
	if err := os.WriteFile(filepath.Join(dir, "restoregap.local.yml"), []byte(mcpFallbackGuardYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	explicitPath := writeContext(t, "version: 2\n") // empty v2 context: no guards at all

	text, err := callTool(context.Background(), "preflight_intent", toolArgs{
		Intent:      "version: 2\naction: delete_file\npath: /x/app.db\n",
		ContextPath: explicitPath,
		AsOf:        "2026-08-20T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	if got := preflightVerdict(t, text); got != "pass" {
		t.Errorf("verdict = %q, want pass (the explicit empty context, not the discoverable blocking one) — got %s", got, text)
	}
}

// TestServeDrillLintOverJSONRPC: an end-to-end round trip through the actual
// stdio protocol (tools/list then tools/call), not just the callTool helper.
func TestServeDrillLintOverJSONRPC(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact")
	if err := os.WriteFile(artifact, []byte("x"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	path := writeContext(t, fmt.Sprintf(mcpCleanDrillYAML, artifact))

	callReq := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"drill_lint","arguments":{"context_path":%q}}}`, path)
	in := strings.NewReader(callReq + "\n")
	var out bytes.Buffer
	if err := Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	var resp rpcResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v (raw: %s)", err, out.String())
	}
	if resp.Error != nil {
		t.Fatalf("unexpected rpc error: %+v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result shape: %+v", resp.Result)
	}
	if isErr, _ := result["isError"].(bool); isErr {
		t.Fatalf("tool reported isError: %+v", result)
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("no content in result: %+v", result)
	}
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)
	if !strings.Contains(text, "no problems found") {
		t.Errorf("unexpected text: %q", text)
	}
}

// TestAcknowledgeRiskAlwaysDatesTheOverride pins the rule at the WRITE path:
// the only place overrides are created must produce a dated one (default 30d,
// max 90d, reason required), because a permanent override is the amnesty the
// deadline exists to prevent.
func TestAcknowledgeRiskAlwaysDatesTheOverride(t *testing.T) {
	dir := t.TempDir()
	lp := filepath.Join(dir, "ledger.jsonl")
	out, err := callTool(context.Background(), "acknowledge_risk", toolArgs{
		LedgerPath: lp, DecisionID: "f1", Acknowledgement: "I accept", Owner: "tanner",
	})
	if err != nil {
		t.Fatalf("acknowledge_risk: %v", err)
	}
	if !strings.Contains(out, "expires ") {
		t.Fatalf("override must report its deadline, got %q", out)
	}
	entries, err := ledger.ReadAll(lp)
	if err != nil {
		t.Fatal(err)
	}
	last := entries[len(entries)-1]
	if last.Payload.Override == nil || last.Payload.Override.ExpiresAt == nil {
		t.Fatal("a newly recorded override must carry expires_at")
	}
	if got := time.Until(*last.Payload.Override.ExpiresAt); got > ledger.DefaultOverrideExpiry+time.Minute {
		t.Errorf("default expiry = %s, want <= %s", got, ledger.DefaultOverrideExpiry)
	}
	// Beyond the maximum is refused, not silently clamped.
	if _, err := callTool(context.Background(), "acknowledge_risk", toolArgs{
		LedgerPath: lp, DecisionID: "f2", Acknowledgement: "a", Owner: "tanner", ExpiresIn: "5000h",
	}); err == nil {
		t.Error("expires_in beyond the maximum must be refused")
	}
}

// TestRequiredProofUnreachableCarriesDistinctRemedy: an agent asking why a
// decision blocked gets the remedy that matches the reason. For an
// unreachable proof that is "bring the source back and re-run the drill
// (nothing was proven, no data loss implied)" — never the generic
// satisfy-the-evidence text, and never a hint that the copy is corrupt.
func TestRequiredProofUnreachableCarriesDistinctRemedy(t *testing.T) {
	var unreach, generic strings.Builder
	requiredProof(&unreach, ledger.FindingRecord{FindingID: "f1", GuardID: "g", ProofStatus: "unreachable"})
	requiredProof(&generic, ledger.FindingRecord{FindingID: "f1", GuardID: "g", ProofStatus: "contradicted"})

	if !strings.Contains(unreach.String(), "re-run the drill once the source is reachable") {
		t.Errorf("unreachable remedy should say to re-run once reachable, got %q", unreach.String())
	}
	if !strings.Contains(unreach.String(), "no data loss is implied") {
		t.Errorf("unreachable remedy must say no data loss is implied, got %q", unreach.String())
	}
	if strings.Contains(unreach.String(), "satisfy the guard's declared proofs/facts") {
		t.Errorf("unreachable remedy must not be the generic satisfy-evidence text, got %q", unreach.String())
	}
	if !strings.Contains(generic.String(), "satisfy the guard's declared proofs/facts") {
		t.Errorf("non-unreachable statuses keep the generic remedy, got %q", generic.String())
	}
	if unreach.String() == generic.String() {
		t.Error("unreachable and contradicted must render different remedies")
	}
}
