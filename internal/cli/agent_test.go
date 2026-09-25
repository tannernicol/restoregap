// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func agentTestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	for k, v := range map[string]string{"XDG_CONFIG_HOME": filepath.Join(dir, "config"), "XDG_STATE_HOME": filepath.Join(dir, "state"), "RESTOREGAP_POLICY_DIRS": filepath.Join(dir, "policy"), "RESTOREGAP_CONTEXT": filepath.Join(dir, "context.yml"), "RESTOREGAP_LEDGER": filepath.Join(dir, "ledger.jsonl"), "RESTOREGAP_REQUIRE_COVERAGE": ""} {
		t.Setenv(k, v)
	}
	return dir
}

func TestAgentHookAllowNamesWhyItAllowed(t *testing.T) {
	dir := agentTestEnv(t)
	t.Chdir(dir)
	policy := fmt.Sprintf("version: 2\nguards:\n  - id: file\n    kind: lifeline\n    match: {paths: [%q]}\n", filepath.Join(dir, "guarded"))
	if err := os.WriteFile(filepath.Join(dir, "context.yml"), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	out := checkHook(t, "claude", hookEvent("Bash", "command", "rm "+filepath.Join(dir, "unguarded.txt"), dir), "allow", "no declared guard matched")
	if !strings.Contains(out, "no declared guard matched") {
		t.Errorf("an allow with no matched guard must say so, got: %s", out)
	}
	if strings.Contains(out, "recovery gate passed:") {
		t.Errorf("an unmatched allow must not claim a proof, got: %s", out)
	}
}

func TestAgentHookDegradedRuntimeDirAllowsUnguardedAndDeniesGuarded(t *testing.T) {
	dir := agentTestEnv(t)
	t.Chdir(dir)
	runtime := filepath.Join(dir, "runtime")
	if err := os.Mkdir(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtime, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(runtime, 0o700) })
	t.Setenv("RESTOREGAP_RUNTIME_DIR", runtime)
	policy := fmt.Sprintf("version: 2\nguards:\n  - id: lifeline\n    kind: lifeline\n    match: {paths: [%q]}\n", filepath.Join(dir, "guarded"))
	if err := os.WriteFile(filepath.Join(dir, "context.yml"), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	output, stderr := runAgentWithStderr(t, hookEvent("Bash", "command", "rm "+filepath.Join(dir, "benign"), dir), "hook", "claude")
	assertHookOutput(t, output, "claude", "allow", "degraded mode: cannot write hook intent")
	if !strings.Contains(stderr, "degraded hook mode") {
		t.Fatalf("stderr = %q, want degraded-mode note", stderr)
	}
	output, _ = runAgentWithStderr(t, hookEvent("Bash", "command", "rm "+filepath.Join(dir, "guarded"), dir), "hook", "claude")
	assertHookOutput(t, output, "claude", "deny", "cannot write hook intent")
}

func runAgent(t *testing.T, input string, args ...string) string {
	t.Helper()
	out, _ := runAgentWithStderr(t, input, args...)
	return out
}

func runAgentWithStderr(t *testing.T, input string, args ...string) (string, string) {
	t.Helper()
	cmd := newAgentCmd()
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetIn(strings.NewReader(input))
	cmd.SetOut(&out)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("agent %v: %v\nstdout: %s\nstderr: %s", args, err, out.String(), stderr.String())
	}
	return out.String(), stderr.String()
}

func hookEvent(tool, key, value, cwd string) string {
	b, _ := json.Marshal(map[string]any{"tool_name": tool, "tool_input": map[string]string{key: value}, "cwd": cwd})
	return string(b)
}

func checkHook(t *testing.T, vendor, event, want, contains string) string {
	t.Helper()
	return assertHookOutput(t, runAgent(t, event, "hook", vendor), vendor, want, contains)
}

func assertHookOutput(t *testing.T, output, vendor, want, contains string) string {
	t.Helper()
	var wire map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &wire); err != nil {
		t.Fatal(err, output)
	}
	var decision, reason string
	switch vendor {
	case "claude":
		var specific map[string]string
		if err := json.Unmarshal(wire["hookSpecificOutput"], &specific); err != nil {
			t.Fatal(err)
		}
		if specific["hookEventName"] != "PreToolUse" {
			t.Fatal(output)
		}
		decision, reason = specific["permissionDecision"], specific["permissionDecisionReason"]
	case "cursor":
		var fields map[string]string
		if err := json.Unmarshal([]byte(output), &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields) != 3 || fields["user_message"] != fields["agent_message"] {
			t.Fatalf("Cursor messages disagree or unexpected fields: %s", output)
		}
		decision, reason = fields["permission"], fields["agent_message"]
	default:
		if err := json.Unmarshal(wire["decision"], &decision); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(wire["reason"], &reason); err != nil {
			t.Fatal(err)
		}
		if _, ok := wire["hookSpecificOutput"]; ok {
			t.Fatal("Claude shape in Gemini response")
		}
	}
	if decision != want {
		t.Fatalf("%s decision = %q, want %q", vendor, decision, want)
	}
	if !strings.Contains(reason, contains) {
		t.Fatalf("%s reason = %q, want substring %q", vendor, reason, contains)
	}
	return reason
}

// Mirrors the 21 cases in docs/examples/preflight-hook.test.sh, including a
// real drill between the denied and allowed calls. Each invocation executes
// the agent hook claude command tree and requires successful (exit 0) JSON.
func TestAgentHookClaudeShellReference21Cases(t *testing.T) {
	dir := agentTestEnv(t)
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	setup := exec.Command("bash", filepath.Join(repo, "demo/setup.sh"), dir)
	if out, err := setup.CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v %s", err, out)
	}
	t.Chdir(dir)
	if err := os.WriteFile("README.md", []byte("unguarded"), 0o600); err != nil {
		t.Fatal(err)
	}
	propose := newDrillProposeCmd()
	var proposed bytes.Buffer
	propose.SetOut(&proposed)
	propose.SetArgs([]string{"proj/app.db", "--source", "backup/app.db"})
	if err := propose.Execute(); err != nil {
		t.Fatal(err)
	}
	contextPath := filepath.Join(dir, "context.yml")
	if err := os.WriteFile(contextPath, proposed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	type testCase struct {
		name, event, want, contains string
		strict, glob                bool
	}
	cases := []testCase{}
	for _, command := range []string{"rm proj/app.db", "rm -rf proj", "mv proj/app.db /tmp/rg-hook-test-dst", "mv README.md proj/app.db", "truncate -s0 proj/app.db", "dd if=/dev/zero of=proj/app.db bs=1 count=1", "shred proj/app.db"} {
		cases = append(cases, testCase{name: command, event: hookEvent("Bash", "command", command, dir), want: "deny", contains: "Required proof:"})
	}
	cases = append(cases,
		testCase{name: "file edit", event: hookEvent("Edit", "file_path", "proj/app.db", dir), want: "deny", contains: "restoregap drill --context"},
		testCase{name: "malformed event", event: "{not-json", want: "deny", contains: "malformed event"},
		testCase{name: "wildcard new file", event: hookEvent("Write", "file_path", "proj/new.db", dir), want: "deny", glob: true},
		testCase{name: "strict unknown file", event: hookEvent("Edit", "file_path", "README.md", dir), want: "deny", strict: true},
		testCase{name: "default unknown command", event: hookEvent("Bash", "command", "ls -la", dir), want: "allow"},
		testCase{name: "strict unknown command", event: hookEvent("Bash", "command", "ls -la", dir), want: "deny", strict: true, contains: "not evaluated: unrecognized operation"},
		testCase{name: "strict missing command", event: `{"tool_name":"Bash","tool_input":{}}`, want: "deny", strict: true, contains: "not evaluated: unrecognized operation"},
		testCase{name: "strict unsupported tool", event: `{"tool_name":"OtherTool","tool_input":{}}`, want: "deny", strict: true, contains: "not evaluated: unrecognized operation"},
		testCase{name: "strict malformed command", event: hookEvent("Bash", "command", "rm", dir), want: "deny", strict: true, contains: "not evaluated: unrecognized operation"},
		testCase{name: "unguarded deletion", event: hookEvent("Bash", "command", "rm README.md", dir), want: "allow"},
		testCase{name: "unmatched ls", event: hookEvent("Bash", "command", "ls -la", dir), want: "allow"},
		testCase{name: "unguarded force push", event: hookEvent("Bash", "command", "git push --force origin main", dir), want: "allow"})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.strict {
				t.Setenv("RESTOREGAP_REQUIRE_COVERAGE", "1")
			}
			if tc.glob {
				path := filepath.Join(dir, "glob.yml")
				if err := os.WriteFile(path, []byte(fmt.Sprintf("version: 2\nguards:\n  - id: wildcard\n    kind: lifeline\n    match: {paths: [%q]}\n", filepath.Join(dir, "proj/**"))), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("RESTOREGAP_CONTEXT", path)
			}
			checkHook(t, "claude", tc.event, tc.want, tc.contains)
		})
	}
	drill := newDrillCmd()
	var drillOut bytes.Buffer
	drill.SetOut(&drillOut)
	drill.SetErr(&drillOut)
	drill.SetArgs([]string{"--context", contextPath})
	if err := drill.Execute(); err != nil {
		t.Fatalf("drill: %v %s", err, drillOut.String())
	}
	t.Run("deletion after real drill", func(t *testing.T) {
		checkHook(t, "claude", hookEvent("Bash", "command", "rm proj/app.db", dir), "allow", "")
	})
	t.Run("strict edit after real drill", func(t *testing.T) {
		t.Setenv("RESTOREGAP_REQUIRE_COVERAGE", "1")
		checkHook(t, "claude", hookEvent("Edit", "file_path", "proj/app.db", dir), "allow", "")
	})
}

func TestAgentHookGeminiAndBrokenGate(t *testing.T) {
	dir := agentTestEnv(t)
	policy := fmt.Sprintf("version: 2\nguards:\n  - id: file\n    kind: lifeline\n    match: {paths: [%q]}\n", filepath.Join(dir, "guarded"))
	if err := os.WriteFile(filepath.Join(dir, "context.yml"), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"write_file", "replace"} {
		checkHook(t, "gemini", hookEvent(tool, "file_path", "guarded", dir), "deny", "")
	}
	checkHook(t, "gemini", hookEvent("run_shell_command", "command", "rm guarded", dir), "deny", "")
	checkHook(t, "gemini", hookEvent("run_shell_command", "command", "ls", dir), "allow", "")
	t.Setenv("RESTOREGAP_REQUIRE_COVERAGE", "1")
	checkHook(t, "gemini", hookEvent("other", "unused", "", dir), "deny", "unrecognized operation")
	for _, vendor := range []string{"claude", "gemini"} {
		for _, event := range []string{`null`, `{}`, `{"tool_name":"Edit","tool_input":{}}`, `{"tool_name":"Bash","tool_input":{"command":5}}`, `{"tool_name":"Bash","tool_input":{}} {}`} {
			checkHook(t, vendor, event, "deny", "malformed event")
		}
		t.Run(vendor+" broken", func(t *testing.T) {
			t.Setenv("RESTOREGAP_CONTEXT", filepath.Join(dir, "missing.yml"))
			checkHook(t, vendor, hookEvent("Edit", "file_path", "guarded", dir), "deny", "recovery gate unavailable: load_context:")
		})
		t.Run(vendor+" ledger broken", func(t *testing.T) {
			t.Setenv("RESTOREGAP_LEDGER", dir)
			checkHook(t, vendor, hookEvent("Edit", "file_path", "guarded", dir), "deny", "recovery gate unavailable:")
		})
	}
}

func TestAgentHookShellShapes(t *testing.T) {
	t.Chdir(agentTestEnv(t))
	for _, command := range []string{"> file", ": > file", "git push -f origin main", "git push --force-with-lease origin main", "git branch -D old", "terraform destroy", "dropdb db"} {
		in, err := translateAgentEvent(agentEvent{Tool: "Bash", Input: map[string]json.RawMessage{"command": json.RawMessage(fmt.Sprintf("%q", command))}}, "claude")
		if err != nil || in.Action == "" || len(in.Paths) != 1 {
			t.Fatalf("%s: %+v %v", command, in, err)
		}
	}
}

func TestAgentInstall(t *testing.T) {
	for _, vendor := range []string{"claude", "gemini"} {
		for _, scope := range []string{"user", "project"} {
			t.Run(vendor+"/"+scope, func(t *testing.T) {
				dir := agentTestEnv(t)
				t.Chdir(dir)
				base := filepath.Join(dir, "home")
				if scope == "project" {
					base = dir
				}
				path := filepath.Join(base, "."+vendor, "settings.json")
				args := []string{"install", vendor, "--scope", scope}
				dry := runAgent(t, "", append(args, "--dry-run")...)
				if !strings.Contains(dry, "@@ -0,0 +1,") {
					t.Fatal(dry)
				}
				if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
					t.Fatalf("dry run created settings directory: %v", err)
				}
				applied := runAgent(t, "", args...)
				if dry != applied {
					t.Fatal("dry-run and applied diff disagree")
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if again := runAgent(t, "", args...); again != "" {
					t.Fatal("not idempotent", again)
				}
				after, _ := os.ReadFile(path)
				if !bytes.Equal(before, after) {
					t.Fatal("repeat install changed bytes")
				}
				var obj map[string]any
				if err := json.Unmarshal(before, &obj); err != nil {
					t.Fatal(err)
				}
				exe, _ := os.Executable()
				servers := obj["mcpServers"].(map[string]any)
				server := servers["restoregap"].(map[string]any)
				if server["command"] != exe {
					t.Fatal(server)
				}
				event, matcher := "PreToolUse", "Bash|Edit|Write|MultiEdit|NotebookEdit"
				if vendor == "gemini" {
					event, matcher = "BeforeTool", "run_shell_command|write_file|replace"
				}
				entry := obj["hooks"].(map[string]any)[event].([]any)[0].(map[string]any)
				if entry["matcher"] != matcher || entry["hooks"].([]any)[0].(map[string]any)["command"] != shellQuote(exe)+" agent hook "+vendor {
					t.Fatal(entry)
				}
				if vendor == "claude" {
					registry := filepath.Join(dir, "home", ".claude.json")
					if scope == "project" {
						registry = filepath.Join(dir, ".mcp.json")
					}
					data, err := os.ReadFile(registry)
					if err != nil {
						t.Fatal(err)
					}
					assertMCPRegistry(t, data)
				}
			})
		}
	}
}

func TestAgentInstallPreservesAndRejects(t *testing.T) {
	dir := agentTestEnv(t)
	path := filepath.Join(dir, "settings.json")
	server := map[string]any{"command": "/a path/restoregap", "args": []string{"mcp", "serve"}}
	original := `{"large":9007199254740993,"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other"}]}]},"mcpServers":{"other":{"command":"keep"},"restoregap":{"env":{"KEEP":"yes"}}}}`
	if err := os.WriteFile(path, []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}
	c, err := planAgentSettings(path, "claude", "'path' agent hook claude", server, true)
	if err != nil {
		t.Fatal(err)
	}
	var merged struct {
		Large      json.Number
		Hooks      map[string][]struct{ Hooks []struct{ Command string } }
		MCPServers map[string]struct {
			Command string
			Env     map[string]string
		}
	}
	if err := json.Unmarshal(c.after, &merged); err != nil {
		t.Fatal(err)
	}
	if merged.Large.String() != "9007199254740993" {
		t.Fatalf("large = %q", merged.Large)
	}
	if got := merged.MCPServers["restoregap"].Env["KEEP"]; got != "yes" {
		t.Fatalf("restoregap env KEEP = %q", got)
	}
	if got := merged.MCPServers["other"].Command; got != "keep" {
		t.Fatalf("other MCP command = %q", got)
	}
	entries := merged.Hooks["PreToolUse"]
	if len(entries) != 2 || len(entries[0].Hooks) != 1 || entries[0].Hooks[0].Command != "other" {
		t.Fatalf("preserved hooks = %+v", entries)
	}
	if err := writeAgentSettings(c); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Fatal(info.Mode())
	}
	for _, bad := range []string{`null`, `{`, `{} {}`, `{"hooks":[]}`, `{"hooks":{"PreToolUse":{}}}`, `{"mcpServers":[]}`} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := planAgentSettings(path, "claude", "command", server, true); err == nil {
			t.Fatalf("accepted invalid settings %s", bad)
		}
		data, _ := os.ReadFile(path)
		if string(data) != bad {
			t.Fatal("damaged invalid input")
		}
	}
}

func TestAgentHookSymlinkAndEventCWD(t *testing.T) {
	dir := agentTestEnv(t)
	if err := os.Mkdir(filepath.Join(dir, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	policy := fmt.Sprintf("version: 2\nguards:\n  - id: file\n    kind: lifeline\n    match: {paths: [%q]}\n", filepath.Join(dir, "real/**"))
	if err := os.WriteFile(filepath.Join(dir, "context.yml"), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	checkHook(t, "claude", hookEvent("Write", "file_path", "alias/new.db", dir), "deny", "")
}

func assertMCPRegistry(t *testing.T, data []byte) {
	t.Helper()
	var registry struct {
		Servers map[string]struct {
			Command string
			Args    []string
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	server := registry.Servers["restoregap"]
	if server.Command != exe || !slices.Equal(server.Args, []string{"mcp", "serve"}) {
		t.Fatalf("registry restoregap = %+v, want command %q and args [mcp serve]", server, exe)
	}
}
