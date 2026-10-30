// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tannernicol/restoregap/internal/agentconfig"
)

func TestAgentCoverageSettingsErrors(t *testing.T) {
	for _, vendor := range []string{"claude", "gemini", "cursor"} {
		for _, tc := range []struct {
			name, data, want string
			unreadable       bool
		}{
			{name: "unreadable", data: `{}`, unreadable: true},
			{name: "array", data: `[]`, want: "json: cannot unmarshal array into Go value of type map[string]interface {}"},
			{name: "string", data: `"settings"`, want: "json: cannot unmarshal string into Go value of type map[string]interface {}"},
			{name: "truncated", data: `{`, want: "unexpected end of JSON input"},
			{name: "null", data: `null`, want: "expected settings object"},
		} {
			t.Run(vendor+"/"+tc.name, func(t *testing.T) {
				home, cwd := t.TempDir(), t.TempDir()
				path, _ := agentconfig.Paths(vendor, home, cwd, "user")
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
					t.Fatal(err)
				}
				want := fmt.Sprintf("%s: %s", path, tc.want)
				if tc.unreadable {
					if err := os.Chmod(path, 0); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := os.Chmod(path, 0o600); err != nil {
							t.Error(err)
						}
					})
					want = "open " + path + ": permission denied"
				}
				got := collectAgents(home, cwd)
				if len(got) != 1 {
					t.Fatalf("candidate count = %d, want 1", len(got))
				}
				c := got[0]
				if c.Covered || c.CoveredBy != "" || c.Agent.Hook || c.Agent.MCP {
					t.Fatalf("invalid settings reported wired: %+v, %+v", c, c.Agent)
				}
				if c.Path != path || c.Agent.Vendor != vendor {
					t.Fatalf("wrong source: %+v, %+v", c, c.Agent)
				}
				if !reflect.DeepEqual(c.Agent.Errors, []string{want}) {
					t.Fatalf("errors = %#v, want [%q]", c.Agent.Errors, want)
				}
			})
		}
	}
}

func TestAgentCoverageRegistryErrors(t *testing.T) {
	for _, tc := range []struct{ vendor, settings string }{
		{"claude", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"restoregap agent hook claude"}]}]}}`},
		{"cursor", `{"version":1,"hooks":{"beforeShellExecution":[{"command":"restoregap agent hook cursor"}],"beforeMCPExecution":[{"command":"restoregap agent hook cursor"}]}}`},
	} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/missing=%v", tc.vendor, missing), func(t *testing.T) {
				home, cwd := t.TempDir(), t.TempDir()
				settings, registry := agentconfig.Paths(tc.vendor, home, cwd, "user")
				if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(settings, []byte(tc.settings), 0o600); err != nil {
					t.Fatal(err)
				}
				var wantErrors []string
				if !missing {
					if err := os.WriteFile(registry, []byte(`{`), 0o600); err != nil {
						t.Fatal(err)
					}
					wantErrors = []string{registry + ": unexpected end of JSON input"}
				}
				got := collectAgents(home, cwd)
				if len(got) != 1 {
					t.Fatalf("candidate count = %d, want 1", len(got))
				}
				c := got[0]
				if c.Covered || c.CoveredBy != "" || !c.Agent.Hook || c.Agent.MCP {
					t.Fatalf("wrong incomplete-registry coverage: %+v, %+v", c, c.Agent)
				}
				if !reflect.DeepEqual(c.Agent.Errors, wantErrors) {
					t.Fatalf("errors = %#v, want %#v", c.Agent.Errors, wantErrors)
				}
			})
		}
	}
}
