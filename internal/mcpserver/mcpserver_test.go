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
)

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
