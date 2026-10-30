// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tannernicol/restoregap/internal/agentconfig"
	"github.com/tannernicol/restoregap/internal/contextspec"
)

func TestAgentCoverageFreshHome(t *testing.T) {
	for _, vendor := range []string{"claude", "gemini", "cursor"} {
		for _, scope := range []string{"user", "project"} {
			t.Run(vendor+"/"+scope, func(t *testing.T) {
				home, cwd := t.TempDir(), t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
				if got := collectAgents(home, cwd); len(got) != 0 {
					t.Fatal(got)
				}
				path, registry := agentconfig.Paths(vendor, home, cwd, scope)
				write := func(path, data string) {
					t.Helper()
					if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				write(path, `{}`)
				got := collectAgents(home, cwd)
				if len(got) != 1 || got[0].Covered || got[0].Agent.Hook || got[0].Agent.MCP {
					t.Fatal(got)
				}
				if !strings.Contains(AgentCoverageLine(got[0]), "no recovery gate wired (run: restoregap agent install "+vendor+")") {
					t.Fatal(got)
				}
				// A declared guard on settings cannot substitute for installed enforcement.
				ctx := contextspec.Default()
				if _, _, err := annotateCandidates(got, ctx, cwd); err != nil {
					t.Fatal(err)
				}
				if got[0].Covered {
					t.Fatal("unwired agent marked covered")
				}
				settings := `{"hooks":{"PreToolUse":[{"matcher":"Bash|Edit|Write|MultiEdit|NotebookEdit","hooks":[{"type":"command","command":"'restoregap' agent hook claude"}]}]}}`
				if vendor == "gemini" {
					settings = `{"hooks":{"BeforeTool":[{"matcher":"run_shell_command|write_file|replace","hooks":[{"type":"command","command":"restoregap agent hook gemini"}]}]},"mcpServers":{"restoregap":{"command":"restoregap","args":["mcp","serve"]}}}`
				}
				if vendor == "cursor" {
					settings = `{"version":1,"hooks":{"beforeShellExecution":[{"command":"restoregap agent hook cursor"}],"beforeMCPExecution":[{"command":"restoregap agent hook cursor"}]}}`
				}
				write(path, settings)
				if registry != path {
					write(registry, `{"mcpServers":{"restoregap":{"command":"restoregap","args":["mcp","serve"]}}}`)
				}
				got = collectAgents(home, cwd)
				if len(got) != 1 || !got[0].Covered || !got[0].Agent.Hook || !got[0].Agent.MCP {
					t.Fatalf("%+v", got)
				}
				covered, _, err := annotateCandidates(got, ctx, cwd)
				if err != nil || covered != 1 || !got[0].Covered {
					t.Fatalf("%+v %v", got, err)
				}
				if !strings.Contains(string(RenderText(&Report{Candidates: got}, true)), "recovery gate wired; MCP: wired") {
					t.Fatal(got)
				}
				write(path, `{broken`)
				got = collectAgents(home, cwd)
				if got[0].Covered || len(got[0].Agent.Errors) == 0 {
					t.Fatal(got)
				}
			})
		}
	}
}

func TestAgentHookDetectionRejectsPartialAndUnrelated(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	path, _ := agentconfig.Paths("claude", home, cwd, "user")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, settings := range []string{
		`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"restoregap agent hook claude"}]}]}}`,
		`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo restoregap agent hook claude"}]}]}}`,
		`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo /usr/bin/restoregap agent hook claude"}]}]}}`,
		`{"disableAllHooks":true,"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"restoregap agent hook claude"}]}]}}`,
	} {
		if err := os.WriteFile(path, []byte(settings), 0o600); err != nil {
			t.Fatal(err)
		}
		got := collectAgents(home, cwd)
		if len(got) != 1 || got[0].Agent.Hook {
			t.Fatalf("accepted %s", settings)
		}
	}
}
