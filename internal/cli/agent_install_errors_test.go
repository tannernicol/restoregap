// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAgentInstallSettingsErrors(t *testing.T) {
	for _, tc := range []struct {
		name, data, vendor, want string
		unreadable               bool
	}{
		{name: "unreadable", data: `{}`, vendor: "claude", unreadable: true},
		{name: "array", data: `[]`, vendor: "claude", want: "json: cannot unmarshal array into Go value of type map[string]interface {}"},
		{name: "string", data: `"settings"`, vendor: "claude", want: "json: cannot unmarshal string into Go value of type map[string]interface {}"},
		{name: "truncated", data: `{`, vendor: "claude", want: "unexpected EOF"},
		{name: "null", data: `null`, vendor: "claude", want: "must contain one JSON object"},
		{name: "multiple objects", data: `{} {}`, vendor: "claude", want: "must contain one JSON object"},
		{name: "hooks not object", data: `{"hooks":[]}`, vendor: "claude", want: "settings hooks must be an object"},
		{name: "hook event not array", data: `{"hooks":{"PreToolUse":{}}}`, vendor: "claude", want: "settings hooks.PreToolUse must be an array"},
		{name: "servers not object", data: `{"mcpServers":[]}`, vendor: "claude", want: "settings mcpServers must be an object"},
		{name: "server not object", data: `{"mcpServers":{"restoregap":[]}}`, vendor: "claude", want: "settings restoregap must be an object"},
		{name: "cursor version", data: `{"version":2}`, vendor: "cursor", want: "cursor hooks version must be 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := agentTestEnv(t)
			path := filepath.Join(dir, "settings.json")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			want := tc.want
			switch tc.name {
			case "array", "string", "truncated":
				want = fmt.Sprintf("settings %s: %s", path, want)
			case "null", "multiple objects":
				want = fmt.Sprintf("settings %s %s", path, want)
			}
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
			_, err := planAgentSettings(path, tc.vendor, "restoregap agent hook "+tc.vendor, map[string]any{"command": "restoregap"}, true)
			if err == nil || err.Error() != want {
				t.Fatalf("error = %v, want %q", err, want)
			}
			if tc.unreadable {
				if err := os.Chmod(path, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != tc.data {
				t.Fatalf("settings changed on failure: %s", after)
			}
		})
	}
}

func TestAgentInstallPreservesHookArrays(t *testing.T) {
	for _, tc := range []struct{ vendor, event string }{
		{"claude", "PreToolUse"}, {"gemini", "BeforeTool"}, {"cursor", "beforeShellExecution"}, {"cursor", "beforeMCPExecution"},
	} {
		t.Run(tc.vendor+"/"+tc.event, func(t *testing.T) {
			dir := agentTestEnv(t)
			path := filepath.Join(dir, "settings.json")
			existing := []any{map[string]any{"command": "first", "custom": true}, map[string]any{"command": "second", "hooks": []any{map[string]any{"type": "command", "command": "keep"}}}}
			original := map[string]any{"hooks": map[string]any{tc.event: existing, "unrelated": []any{map[string]any{"command": "unrelated"}}}}
			before, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, before, 0o600); err != nil {
				t.Fatal(err)
			}
			command := "restoregap agent hook " + tc.vendor
			change, err := planAgentSettings(path, tc.vendor, command, map[string]any{"command": "restoregap"}, true)
			if err != nil {
				t.Fatal(err)
			}
			var obj map[string]any
			if err := json.Unmarshal(change.after, &obj); err != nil {
				t.Fatal(err)
			}
			hooks := obj["hooks"].(map[string]any)
			entries := hooks[tc.event].([]any)
			if len(entries) != 3 {
				t.Fatalf("hook count = %d, want 3", len(entries))
			}
			if !reflect.DeepEqual(entries[:2], existing) {
				t.Fatalf("existing hooks changed: %#v", entries[:2])
			}
			if !reflect.DeepEqual(hooks["unrelated"], original["hooks"].(map[string]any)["unrelated"]) {
				t.Fatalf("unrelated hooks changed: %#v", hooks["unrelated"])
			}
			expected := map[string]any{"command": command, "failClosed": true}
			if tc.vendor != "cursor" {
				matcher := "Bash|Edit|Write|MultiEdit|NotebookEdit"
				if tc.vendor == "gemini" {
					matcher = "run_shell_command|write_file|replace"
				}
				expected = map[string]any{"matcher": matcher, "hooks": []any{map[string]any{"type": "command", "command": command}}}
			}
			if !reflect.DeepEqual(entries[2], expected) {
				t.Fatalf("new hook = %#v, want %#v", entries[2], expected)
			}
			if err := writeAgentSettings(change); err != nil {
				t.Fatal(err)
			}
			again, err := planAgentSettings(path, tc.vendor, command, map[string]any{"command": "restoregap"}, true)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again.before, again.after) {
				t.Fatal("repeat merge changed settings")
			}
		})
	}
}
