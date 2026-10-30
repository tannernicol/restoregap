// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAgentHookFailureReasons(t *testing.T) {
	for _, vendor := range []string{"claude", "gemini", "cursor"} {
		for _, name := range []string{"malformed", "truncated", "missing tool", "strict unknown", "missing context", "unwritable ledger"} {
			t.Run(vendor+"/"+name, func(t *testing.T) {
				dir := agentTestEnv(t)
				t.Chdir(dir)
				contextPath := filepath.Join(dir, "context.yml")
				if err := os.WriteFile(contextPath, []byte("version: 2\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				tool := "Write"
				if vendor == "gemini" {
					tool = "write_file"
				}
				event := hookEvent(tool, "file_path", "guarded", dir)
				var want string
				switch name {
				case "malformed":
					event, want = `{broken`, "malformed event: invalid character 'b' looking for beginning of object key string"
				case "truncated":
					event, want = `{"tool_name":`, "malformed event: unexpected EOF"
				case "missing tool":
					event, want = `{"tool_input":{}}`, "malformed event: expected one tool event with tool_name and tool_input"
				case "strict unknown":
					t.Setenv("RESTOREGAP_REQUIRE_COVERAGE", "1")
					event, want = hookEvent("UnknownTool", "unused", "", dir), "not evaluated: unrecognized operation"
				case "missing context":
					if err := os.Remove(contextPath); err != nil {
						t.Fatal(err)
					}
					want = fmt.Sprintf("recovery gate unavailable: load_context: preflight: contextspec: cannot read %s: %s", contextPath, (&os.PathError{Op: "open", Path: contextPath, Err: syscall.ENOENT}).Error())
				case "unwritable ledger":
					ledgerPath := filepath.Join(dir, "ledger.jsonl")
					if err := os.WriteFile(ledgerPath, nil, 0o400); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := os.Chmod(ledgerPath, 0o600); err != nil {
							t.Error(err)
						}
					})
					want = fmt.Sprintf("recovery gate unavailable: record_ledger: preflight: ledger: cannot open %s: %s", ledgerPath, (&os.PathError{Op: "open", Path: ledgerPath, Err: syscall.EACCES}).Error())
				}
				reason := checkHook(t, vendor, event, "deny", "")
				if reason != want {
					t.Fatalf("reason = %q, want %q", reason, want)
				}
			})
		}
	}
}
