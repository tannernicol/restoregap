// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tannernicol/restoregap/internal/agentconfig"
)

func TestAgentHookCursorContract(t *testing.T) {
	dir := agentTestEnv(t)
	t.Chdir(dir)
	policy := fmt.Sprintf("version: 2\nguards:\n  - id: file\n    kind: lifeline\n    match: {paths: [%q]}\n", filepath.Join(dir, "guarded"))
	if err := os.WriteFile(filepath.Join(dir, "context.yml"), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, want, reason string }{
		{`{"command":"rm guarded"}`, "deny", "BLOCK"},
		{`{"hook_event_name":"beforeShellExecution","command":"ls"}`, "allow", "unrecognized operation"},
		{`{"hook_event_name":"beforeMCPExecution","tool_name":"Write","tool_input":"{\"file_path\":\"guarded\"}","command":"server --stdio"}`, "deny", "BLOCK"},
		{`{"tool_name":"Edit","tool_input":{"file_path":"guarded"}}`, "deny", "BLOCK"},
		{`{"tool_name":"lookup","tool_input":"{}","command":"rm guarded"}`, "allow", "unrecognized operation"},
		{`{"hook_event_name":"beforeMCPExecution","command":"ls"}`, "deny", "malformed event"},
		{`{"hook_event_name":"beforeShellExecution","tool_name":"Write","tool_input":{}}`, "deny", "malformed event"},
		{`{"command":5}`, "deny", "malformed event"},
		{`{"tool_name":"Write","tool_input":"invalid"}`, "deny", "malformed event"},
		{`{"command":"ls"} {}`, "deny", "malformed event"},
		{`null`, "deny", "malformed event"},
	} {
		output := runAgent(t, tc.input, "hook", "cursor")
		var wire map[string]string
		if err := json.Unmarshal([]byte(output), &wire); err != nil {
			t.Fatal(err)
		}
		if len(wire) != 3 || wire["permission"] != tc.want || wire["user_message"] != wire["agent_message"] || !strings.Contains(wire["agent_message"], tc.reason) {
			t.Fatalf("%s: %s", tc.input, output)
		}
	}
	t.Setenv("RESTOREGAP_REQUIRE_COVERAGE", "1")
	output := runAgent(t, `{"command":"ls"}`, "hook", "cursor")
	if !strings.Contains(output, `"permission":"deny"`) {
		t.Fatal(output)
	}
	t.Setenv("RESTOREGAP_CONTEXT", filepath.Join(dir, "missing"))
	output = runAgent(t, `{"command":"rm guarded"}`, "hook", "cursor")
	if !strings.Contains(output, `"permission":"deny"`) || !strings.Contains(output, "recovery gate unavailable") {
		t.Fatal(output)
	}
}

func TestAgentInstallCursorFreshHome(t *testing.T) {
	for _, scope := range []string{"user", "project"} {
		t.Run(scope, func(t *testing.T) {
			dir := agentTestEnv(t)
			t.Chdir(dir)
			path, registry := agentconfig.Paths("cursor", filepath.Join(dir, "home"), dir, scope)
			args := []string{"install", "cursor", "--scope", scope}
			dry := runAgent(t, "", append(args, "--dry-run")...)
			if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
				t.Fatal("dry run wrote settings")
			}
			if got := runAgent(t, "", args...); got != dry {
				t.Fatal("diff differs")
			}
			if got := runAgent(t, "", args...); got != "" {
				t.Fatal("not idempotent", got)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var obj map[string]any
			if err := json.Unmarshal(data, &obj); err != nil {
				t.Fatal(err)
			}
			if obj["version"] != float64(1) || obj["mcpServers"] != nil {
				t.Fatal(obj)
			}
			exe, _ := os.Executable()
			hooks := obj["hooks"].(map[string]any)
			for _, event := range []string{"beforeShellExecution", "beforeMCPExecution"} {
				entry := hooks[event].([]any)[0].(map[string]any)
				if len(entry) != 2 || entry["command"] != shellQuote(exe)+" agent hook cursor" || entry["failClosed"] != true {
					t.Fatal(entry)
				}
			}
			data, err = os.ReadFile(registry)
			if err != nil || !strings.Contains(string(data), `"mcpServers"`) {
				t.Fatalf("%v %s", err, data)
			}
		})
	}
}
