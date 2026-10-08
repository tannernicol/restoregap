// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tannernicol/restoregap/internal/ledger"
)

// rpcResult runs one JSON-RPC request through Serve and returns the result map.
func rpcResult(t *testing.T, req string, opts ...Option) map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := Serve(context.Background(), strings.NewReader(req+"\n"), &out, opts...); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resp rpcResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (raw %s)", err, out.String())
	}
	if resp.Error != nil {
		t.Fatalf("rpc error: %+v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result: %+v", resp.Result)
	}
	return result
}

func TestInitializeReportsInjectedVersion(t *testing.T) {
	const req = `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	info := rpcResult(t, req, WithVersion("9.8.7-test"))["serverInfo"].(map[string]any)
	if info["version"] != "9.8.7-test" {
		t.Errorf("serverInfo.version = %v, want 9.8.7-test", info["version"])
	}
	info = rpcResult(t, req)["serverInfo"].(map[string]any)
	if info["version"] != DefaultVersion {
		t.Errorf("default serverInfo.version = %v, want %s", info["version"], DefaultVersion)
	}
}

func TestRequiredProofDefaultsLedgerFromEnv(t *testing.T) {
	lp := filepath.Join(t.TempDir(), "state", "ledger.jsonl")
	t.Setenv("RESTOREGAP_LEDGER", lp)
	// acknowledge_risk without ledger_path writes to the default (and creates its dir).
	if _, err := callTool(context.Background(), "acknowledge_risk", toolArgs{DecisionID: "f1", Acknowledgement: "ok", Owner: "tanner"}); err != nil {
		t.Fatalf("acknowledge_risk without ledger_path: %v", err)
	}
	if entries, err := ledger.ReadAll(lp); err != nil || len(entries) != 1 {
		t.Fatalf("default ledger entries = %d, err = %v; want 1", len(entries), err)
	}
	result := rpcResult(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"required_proof","arguments":{"decision_id":"f1"}}}`)
	if isErr, _ := result["isError"].(bool); isErr {
		t.Fatalf("required_proof without ledger_path failed: %+v", result)
	}
}

func TestExplicitLedgerPathBeatsDefault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RESTOREGAP_LEDGER", filepath.Join(dir, "env.jsonl"))
	explicit := filepath.Join(dir, "explicit.jsonl")
	if _, err := callTool(context.Background(), "acknowledge_risk", toolArgs{LedgerPath: explicit, DecisionID: "f1", Acknowledgement: "ok", Owner: "tanner"}); err != nil {
		t.Fatal(err)
	}
	if entries, _ := ledger.ReadAll(filepath.Join(dir, "env.jsonl")); len(entries) != 0 {
		t.Errorf("explicit ledger_path leaked into the default ledger")
	}
	if entries, _ := ledger.ReadAll(explicit); len(entries) != 1 {
		t.Errorf("explicit ledger has %d entries, want 1", len(entries))
	}
}

func TestResolveLedgerPathFallbackOrder(t *testing.T) {
	t.Setenv("RESTOREGAP_LEDGER", "")
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	got, err := resolveLedgerPath("", false)
	if err != nil || got != filepath.Join(state, "restoregap", "ledger.jsonl") {
		t.Errorf("XDG fallback = %q, %v", got, err)
	}
	home := t.TempDir()
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", home)
	got, err = resolveLedgerPath("", false)
	if err != nil || got != filepath.Join(home, ".local", "state", "restoregap", "ledger.jsonl") {
		t.Errorf("HOME fallback = %q, %v", got, err)
	}
}
