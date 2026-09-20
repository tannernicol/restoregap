// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tannernicol/restoregap/internal/agentconfig"
	"github.com/tannernicol/restoregap/internal/discover"
)

// Exercise the actual executable (including the path recorded by installation),
// with no vendor credentials, user policy, containers, or existing configuration.
func TestAgentAdaptersFreshHomeBinary(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	binary := filepath.Join(binDir, "restoregap")
	build := exec.Command("go", "build", "-o", binary, "./cmd/restoregap")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	for _, vendor := range []string{"claude", "gemini", "cursor"} {
		t.Run(vendor, func(t *testing.T) {
			home, project := t.TempDir(), t.TempDir()
			env := []string{"HOME=" + home, "PATH=" + binDir, "XDG_CONFIG_HOME=" + filepath.Join(home, "config"), "XDG_STATE_HOME=" + filepath.Join(home, "state"), "RESTOREGAP_POLICY_DIRS=" + filepath.Join(home, "policies")}
			run := func(input string, args ...string) string {
				t.Helper()
				cmd := exec.Command(binary, args...)
				cmd.Dir, cmd.Env, cmd.Stdin = project, env, strings.NewReader(input)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%v: %v %s", args, err, out)
				}
				return string(out)
			}
			settings, _ := agentconfig.Paths(vendor, home, project, "user")
			if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(settings, []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
			run("", "discover")
			if status := run("", "status"); !strings.Contains(status, "no recovery gate wired (run: restoregap agent install "+vendor+")") {
				t.Fatal(status)
			}
			for _, scope := range []string{"user", "project"} {
				run("", "agent", "install", vendor, "--scope", scope)
				if got := run("", "agent", "install", vendor, "--scope", scope); got != "" {
					t.Fatal("not idempotent", got)
				}
			}
			var report discover.Report
			output := run("", "discover", "--format", "json")
			if err := json.Unmarshal([]byte(output), &report); err != nil {
				t.Fatal(err, output)
			}
			found := 0
			for _, c := range report.Candidates {
				if c.Kind != discover.KindAgent {
					continue
				}
				found++
				if !c.Covered || c.Agent == nil || !c.Agent.Hook || !c.Agent.MCP {
					t.Fatalf("agent: %+v", c)
				}
			}
			if found != 1 {
				t.Fatalf("found %d agents", found)
			}
			status := run("", "status")
			if !strings.Contains(status, "recovery gate wired; MCP: wired") {
				t.Fatal(status)
			}
			input := `{"tool_name":"Bash","tool_input":{"command":"ls"}}`
			if vendor == "gemini" {
				input = `{"tool_name":"run_shell_command","tool_input":{"command":"ls"}}`
			}
			if vendor == "cursor" {
				input = `{"command":"ls"}`
			}
			if output := run(input, "agent", "hook", vendor); !strings.Contains(output, `"allow"`) {
				t.Fatal(output)
			}
			if output := run(`{broken`, "agent", "hook", vendor); !strings.Contains(output, `"deny"`) {
				t.Fatal(output)
			}
			t.Logf("fresh HOME: %s user/project install idempotent; discover/status hook+MCP wired; allow and malformed deny", vendor)
		})
	}
}

func TestClaudePluginLauncher(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	// Loading from a directory with spaces also tests plugin-root shell quoting.
	pluginRoot := filepath.Join(t.TempDir(), "plugin with spaces")
	if err := os.MkdirAll(filepath.Join(pluginRoot, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(root, "hooks", "restoregap.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginRoot, "hooks", "restoregap.sh"), script, 0o600); err != nil {
		t.Fatal(err)
	}
	var hooks struct {
		Hooks map[string][]struct {
			Matcher string
			Hooks   []struct{ Type, Command string }
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "hooks", "restoregap.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatal(err)
	}
	entry := hooks.Hooks["PreToolUse"][0]
	if entry.Matcher != "Bash|Edit|Write|MultiEdit|NotebookEdit" || entry.Hooks[0].Type != "command" {
		t.Fatal(entry)
	}
	binDir, home := t.TempDir(), t.TempDir()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sh, filepath.Join(binDir, "sh")); err != nil {
		t.Fatal(err)
	}
	run := func(command string) ([]byte, error) {
		cmd := exec.Command(sh, "-c", command)
		cmd.Dir = home
		cmd.Env = []string{"HOME=" + home, "PATH=" + binDir, "CLAUDE_PLUGIN_ROOT=" + pluginRoot}
		cmd.Stdin = strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`)
		return cmd.CombinedOutput()
	}
	command := entry.Hooks[0].Command
	output, err := run(command)
	if err != nil || !strings.Contains(string(output), `"permissionDecision":"deny"`) || !strings.Contains(string(output), "restoregap not installed") {
		t.Fatalf("%v %s", err, output)
	}
	binary := filepath.Join(binDir, "restoregap")
	stub := "#!/bin/sh\n[ \"$*\" = 'agent hook claude' ] || exit 1\nIFS= read -r event\n[ -n \"$event\" ] || exit 1\nprintf '%s\\n' '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\",\"permissionDecisionReason\":\"stub invoked\"}}'\n"
	if err := os.WriteFile(binary, []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	output, err = run(command)
	if err != nil || !strings.Contains(string(output), "stub invoked") {
		t.Fatalf("%v %s", err, output)
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	output, err = run(command)
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 2 || !strings.Contains(string(output), "gate unavailable") {
		t.Fatalf("%v %s", err, output)
	}
	var mcp struct {
		Servers map[string]struct {
			Command string
			Args    []string
		} `json:"mcpServers"`
	}
	data, err = os.ReadFile(filepath.Join(root, "hooks", "restoregap-mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &mcp); err != nil {
		t.Fatal(err)
	}
	server := mcp.Servers["restoregap"]
	if server.Command != "sh" || len(server.Args) != 2 || server.Args[1] != "mcp" {
		t.Fatal(server)
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n[ \"$*\" = 'mcp serve' ] || exit 1\nprintf 'mcp invoked\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	output, err = run(server.Command + " \"" + server.Args[0] + "\" " + server.Args[1])
	if err != nil || string(output) != "mcp invoked\n" {
		t.Fatalf("%v %s", err, output)
	}
	t.Log("fresh HOME: plugin denies absent binary, forwards hook stdin and MCP arguments from PATH, exits 2 for crashed gate")
}
