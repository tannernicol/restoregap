// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/discovery"
	"github.com/tannernicol/restoregap/internal/intent"
	"github.com/tannernicol/restoregap/internal/policy"
	"github.com/tannernicol/restoregap/internal/preflight"
	"github.com/tannernicol/restoregap/internal/report"
	"gopkg.in/yaml.v3"
)

type agentEvent struct {
	Tool  string                     `json:"tool_name"`
	Input map[string]json.RawMessage `json:"tool_input"`
	CWD   string                     `json:"cwd"`
}

type hookIntent struct {
	Version       int      `yaml:"version"`
	Action        string   `yaml:"action"`
	Paths         []string `yaml:"paths"`
	Targets       []string `yaml:"target_paths,omitempty"`
	Command       string   `yaml:"command,omitempty"`
	Actor         string   `yaml:"actor"`
	ContextWindow string   `yaml:"context_window"`
	Description   string   `yaml:"description"`
}

var hookDegradedModeOnce sync.Once

func agentHook(cmd *cobra.Command, vendor string) (string, string) {
	var raw json.RawMessage
	dec := json.NewDecoder(cmd.InOrStdin())
	if err := dec.Decode(&raw); err != nil {
		return "deny", "malformed event: " + err.Error()
	}
	var extra any
	event, err := decodeAgentEvent(raw, vendor)
	if dec.Decode(&extra) != io.EOF || err != nil || strings.TrimSpace(event.Tool) == "" || event.Input == nil {
		return "deny", "malformed event: expected one tool event with tool_name and tool_input"
	}
	if event.CWD != "" {
		if !filepath.IsAbs(event.CWD) {
			return "deny", "malformed event: cwd must be absolute"
		}
		cwd, err := os.Getwd()
		if err != nil {
			return "deny", "recovery gate unavailable: " + err.Error()
		}
		if err := os.Chdir(event.CWD); err != nil {
			return "deny", "recovery gate unavailable: " + err.Error()
		}
		defer func() { _ = os.Chdir(cwd) }()
	}
	in, err := translateAgentEvent(event, vendor)
	if err != nil {
		return "deny", "malformed event: " + err.Error()
	}
	if in.Action == "" || len(in.Paths) == 0 {
		if os.Getenv("RESTOREGAP_REQUIRE_COVERAGE") == "1" {
			return "deny", "not evaluated: unrecognized operation"
		}
		return "allow", "not evaluated: unrecognized operation"
	}
	return evaluateAgentHook(cmd, in)
}

func eventString(e agentEvent, key string) (string, error) {
	val, ok := e.Input[key]
	if !ok || string(val) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(val, &s); err != nil {
		return "", fmt.Errorf("tool_input.%s must be a string", key)
	}
	return s, nil
}

func translateAgentEvent(e agentEvent, vendor string) (hookIntent, error) {
	in := hookIntent{Version: 2, Actor: "agent/" + vendor, ContextWindow: "coding-agent", Description: "tool call intercepted by recovery hook"}
	tool := e.Tool
	if vendor == "gemini" {
		switch tool {
		case "run_shell_command":
			tool = "Bash"
		case "write_file", "replace":
			tool = "Write"
		}
	}
	switch tool {
	case "Edit", "Write", "MultiEdit", "NotebookEdit":
		path, err := eventString(e, "file_path")
		if err != nil {
			return in, err
		}
		if path == "" {
			path, err = eventString(e, "notebook_path")
			if err != nil {
				return in, err
			}
		}
		if strings.TrimSpace(path) == "" {
			return in, fmt.Errorf("%s requires a file path", e.Tool)
		}
		in.Action, in.Paths = "modify_file", []string{path}
	case "Bash":
		command, err := eventString(e, "command")
		if err != nil {
			return in, err
		}
		in.Command = command
		parseHookShell(&in)
	}
	for i, p := range in.Paths {
		abs, err := hookAbsolutePath(p)
		if err != nil {
			return in, err
		}
		in.Paths[i] = abs
	}
	for i, p := range in.Targets {
		abs, err := hookAbsolutePath(p)
		if err != nil {
			return in, err
		}
		in.Targets[i] = abs
	}
	return in, nil
}

var hookRedirect = regexp.MustCompile(`^(:\s*)?>\s*([^\s]+)`)

// This intentionally mirrors the reference shell hook's narrow word parser.
// It does not execute, expand, or claim to interpret arbitrary shell syntax.
func parseHookShell(in *hookIntent) {
	words := strings.Fields(strings.SplitN(in.Command, "\n", 2)[0])
	if len(words) == 0 {
		return
	}
	if match := hookRedirect.FindStringSubmatch(in.Command); match != nil {
		in.Action, in.Paths = "modify_file", []string{match[2]}
		return
	}
	args := hookNonflags(words[1:])
	switch words[0] {
	case "rm", "shred":
		in.Action, in.Paths = "delete_file", args
	case "mv":
		if len(args) > 1 {
			in.Action, in.Paths, in.Targets = "move_file", args[:len(args)-1], args[len(args)-1:]
		}
	case "truncate":
		in.Action, in.Paths = "modify_file", args
	case "dd":
		for _, word := range words[1:] {
			if strings.HasPrefix(word, "of=") && len(word) > 3 {
				in.Action, in.Paths = "modify_file", []string{strings.TrimPrefix(word, "of=")}
			}
		}
	default:
		if hookRunShape(words) {
			root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
			path := strings.TrimSpace(string(root))
			if err != nil || path == "" {
				path = "."
			}
			in.Action, in.Paths = "run_command", []string{path}
		}
	}
}

func hookRunShape(w []string) bool {
	if w[0] == "dropdb" {
		return true
	}
	if len(w) < 2 {
		return false
	}
	if w[0] == "terraform" {
		return w[1] == "destroy"
	}
	if w[0] != "git" {
		return false
	}
	rest := " " + strings.Join(w[1:], " ") + " "
	return (w[1] == "push" && (strings.Contains(rest, "--force") || strings.Contains(rest, " -f "))) || (w[1] == "branch" && strings.Contains(rest, " -D "))
}

func evaluateAgentHook(cmd *cobra.Command, in hookIntent) (string, string) {
	broken := func(err error) (string, string) { return "deny", "recovery gate unavailable: " + err.Error() }
	ledgerPath, err := defaultLedgerPath()
	if err != nil {
		return broken(err)
	}
	data, err := yaml.Marshal(in)
	if err != nil {
		return broken(err)
	}
	intentPath, err := writeHookIntent(data)
	if err != nil {
		return evaluateAgentHookDegraded(cmd, in, data, ledgerPath, err)
	}
	defer func() { _ = os.Remove(intentPath) }()
	paths := discovery.ContextPaths()
	result, err := preflight.Run(cmd.Context(), preflight.Request{IntentPath: intentPath, ContextPaths: paths, LedgerPath: ledgerPath, Actor: in.Actor, ContextWindow: in.ContextWindow, Format: "json", RequireCoverage: os.Getenv("RESTOREGAP_REQUIRE_COVERAGE") == "1", ToolVersion: Version})
	if err != nil {
		return broken(err)
	}
	var rep report.Report
	if err := json.Unmarshal(result.Rendered, &rep); err != nil {
		return broken(err)
	}
	if rep.GateState == "broken" {
		return "deny", "recovery gate unavailable: " + rep.BrokenReason
	}
	if result.ExitCode == 0 {
		return "allow", hookAllowReason(rep)
	}
	return "deny", hookDenyReason(rep, paths)
}

// hookRuntimeDir chooses a private, durable-enough place for the short-lived
// intent file. A configured directory is deliberately not skipped when it is
// broken: falling through to an unexpected filesystem can hide an operator's
// runtime-dir failure and turn a full /tmp into an unrecoverable hook outage.
func hookRuntimeDir() string {
	if dir := os.Getenv("RESTOREGAP_RUNTIME_DIR"); dir != "" {
		return dir
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "restoregap")
	}
	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			stateHome = filepath.Join(home, ".local", "state")
		}
	}
	if stateHome != "" {
		return filepath.Join(stateHome, "restoregap", "run")
	}
	return os.TempDir()
}

func writeHookIntent(data []byte) (string, error) {
	dir := hookRuntimeDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create hook runtime directory %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, "restoregap-hook-*.yml")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func evaluateAgentHookDegraded(cmd *cobra.Command, in hookIntent, data []byte, ledgerPath string, writeErr error) (string, string) {
	hookDegradedModeOnce.Do(func() {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "restoregap: degraded hook mode: cannot write intent file: %v\n", writeErr)
	})
	ci, err := intent.Parse(bytes.NewReader(data))
	if err != nil {
		return "deny", "recovery gate unavailable: " + err.Error()
	}
	paths := discovery.ContextPaths()
	result, err := preflight.Run(cmd.Context(), preflight.Request{Intents: []intent.ChangeIntent{ci}, ContextPaths: paths, LedgerPath: ledgerPath, Actor: in.Actor, ContextWindow: in.ContextWindow, Format: "json", RequireCoverage: os.Getenv("RESTOREGAP_REQUIRE_COVERAGE") == "1", ToolVersion: Version})
	if err != nil {
		return "deny", "recovery gate unavailable: " + err.Error()
	}
	var rep report.Report
	if err := json.Unmarshal(result.Rendered, &rep); err != nil {
		return "deny", "recovery gate unavailable: " + err.Error()
	}
	for _, finding := range rep.Findings {
		if finding.GuardID != "" {
			return "deny", fmt.Sprintf("recovery gate unavailable: cannot write hook intent: %v; declared guard %s matched", writeErr, finding.GuardID)
		}
	}
	return "allow", fmt.Sprintf("degraded mode: cannot write hook intent: %v; no declared guard matched this proposal; allowed on declared coverage, not on a drill proof", writeErr)
}

// hookAllowReason distinguishes a proposal a declared guard cleared on the
// strength of a proof from one no guard matched at all. Both are allowed, and
// only the first is evidence, so an agent must never read them as the same
// answer.
func hookAllowReason(rep report.Report) string {
	var proofs []string
	for _, finding := range rep.Findings {
		if finding.Proof != "" {
			proofs = append(proofs, finding.Proof)
		}
	}
	if len(proofs) == 0 {
		return "no declared guard matched this proposal; allowed on declared coverage, not on a drill proof"
	}
	return "recovery gate passed: " + strings.Join(proofs, "; ")
}

func hookDenyReason(rep report.Report, paths []string) string {
	ctx := contextspec.Default()
	if len(paths) > 0 {
		loaded, _, err := policy.Merge(paths)
		if err == nil {
			ctx = loaded
		}
	}
	commands := hookDrillCommands(paths)
	var reasons []string
	for _, finding := range rep.Findings {
		if finding.Verdict != "block" {
			continue
		}
		reason := "BLOCK"
		if len(finding.Actions) > 0 {
			reason += " " + strings.Join(finding.Actions, ",")
		}
		if finding.Resource != "" {
			reason += " " + filepath.Base(finding.Resource)
		}
		reason += ": " + strings.TrimSuffix(finding.Title, ".") + ". " + finding.RequiredNextStep
		for _, guard := range ctx.Guards {
			if guard.ID != finding.GuardID {
				continue
			}
			for _, proof := range guard.Requires.Proofs {
				reason += " Required proof: " + proof + "."
				if command := commands[proof]; command != "" {
					reason += " Run: " + command
				} else {
					reason += " No declared drill; author a recovery drill before retrying."
				}
			}
		}
		reasons = append(reasons, reason)
	}
	if len(reasons) == 0 {
		return "recovery gate blocked the operation"
	}
	return strings.Join(reasons, "\n")
}

// Same context/proof selection as next_steps, including proofs whose own TTL
// is still green but no longer meets a stricter guard's max_age requirement.
func hookDrillCommands(paths []string) map[string]string {
	commands := map[string]string{}
	for _, path := range paths {
		ctx, err := contextspec.Load(path)
		if err != nil {
			continue
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		for _, d := range ctx.Drills {
			commands[d.Proof] = "restoregap drill --context " + shellQuote(abs) + " --proof " + shellQuote(d.Proof)
		}
	}
	return commands
}

func hookNonflags(words []string) []string {
	var args []string
	for _, word := range words {
		if !strings.HasPrefix(word, "-") {
			args = append(args, word)
		}
	}
	return args
}

// Resolve existing symlinks, including a parent of a not-yet-created file,
// just as the reference's realpath -m does. A symlink alias must not hide a guard.
func hookAbsolutePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return abs, nil
	}
	resolved, err = hookAbsolutePath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(abs)), nil
}

// Cursor MCP's top-level command launches the server; it is never the proposed
// shell command. Only beforeShellExecution maps that field to Bash input.
func decodeAgentEvent(raw json.RawMessage, vendor string) (agentEvent, error) {
	var event agentEvent
	if vendor != "cursor" {
		err := json.Unmarshal(raw, &event)
		return event, err
	}
	var wire struct {
		Event   string          `json:"hook_event_name"`
		Tool    string          `json:"tool_name"`
		Input   json.RawMessage `json:"tool_input"`
		Command *string         `json:"command"`
		CWD     string          `json:"cwd"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return event, err
	}
	event.CWD = wire.CWD
	switch wire.Event {
	case "", "beforeShellExecution", "beforeMCPExecution":
	default:
		return event, fmt.Errorf("unsupported Cursor event")
	}
	mcp := wire.Event == "beforeMCPExecution" || wire.Tool != "" || wire.Input != nil
	if mcp {
		if wire.Event == "beforeShellExecution" {
			return event, fmt.Errorf("conflicting Cursor event")
		}
		event.Tool = wire.Tool
		input := wire.Input
		// Cursor documents tool_input as JSON params serialized into a string.
		// Accept object-form params too, without ever executing either form.
		if len(input) > 0 && input[0] == '"' {
			var serialized string
			if err := json.Unmarshal(input, &serialized); err != nil {
				return event, err
			}
			input = []byte(serialized)
		}
		err := json.Unmarshal(input, &event.Input)
		return event, err
	}
	if wire.Command == nil {
		return event, fmt.Errorf("missing Cursor command")
	}
	event.Tool = "Bash"
	command, _ := json.Marshal(*wire.Command)
	event.Input = map[string]json.RawMessage{"command": command}
	return event, nil
}
