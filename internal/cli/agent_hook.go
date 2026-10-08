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
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/discovery"
	"github.com/tannernicol/restoregap/internal/intent"
	"github.com/tannernicol/restoregap/internal/policy"
	"github.com/tannernicol/restoregap/internal/preflight"
	"github.com/tannernicol/restoregap/internal/report"
	"github.com/tannernicol/restoregap/internal/shellintent"
	"gopkg.in/yaml.v3"
)

type agentEvent struct {
	Tool  string                     `json:"tool_name"`
	Input map[string]json.RawMessage `json:"tool_input"`
	CWD   string                     `json:"cwd"`
}

type hookIntent struct {
	Version int      `yaml:"version"`
	Action  string   `yaml:"action"`
	Paths   []string `yaml:"paths"`
	Targets []string `yaml:"target_paths,omitempty"`
	// LexicalPaths and LexicalTargets are the pre-symlink-resolution forms
	// of Paths/Targets (filepath.Abs only, index-aligned 1:1), carried
	// alongside so guard matching can catch a symlink at or after a guard
	// pattern's wildcard that would otherwise resolve the canonical path
	// outside a pattern that plainly matched the path as typed. See
	// intent.ChangeIntent.LexicalPaths.
	LexicalPaths   []string `yaml:"lexical_paths,omitempty"`
	LexicalTargets []string `yaml:"lexical_target_paths,omitempty"`
	Command        string   `yaml:"command,omitempty"`
	Actor          string   `yaml:"actor"`
	ContextWindow  string   `yaml:"context_window"`
	Description    string   `yaml:"description"`
}

var (
	hookDegradedModeOnce sync.Once
	hookParseNoteOnce    sync.Once
)

// hookPlan is what one tool event translates to. Intents holds every
// recognized operation in order; the first is embedded so single-operation
// callers read Action and Paths directly. A compound shell command yields
// several, and Unrecognized counts the pieces that were seen but not
// classified, so strict mode can refuse a line it only partly understood.
type hookPlan struct {
	hookIntent
	Intents      []hookIntent
	Unrecognized int
	// ParseFailure is why the shell command could not be parsed at all
	// (heredoc, unbalanced quote, ...); Intents is empty when it is set.
	ParseFailure string
}

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
	plan, err := translateAgentEvent(event, vendor)
	if err != nil {
		return "deny", "malformed event: " + err.Error()
	}
	strict := os.Getenv("RESTOREGAP_REQUIRE_COVERAGE") == "1"
	if plan.ParseFailure != "" {
		reason := "not evaluated: could not parse command (" + plan.ParseFailure + ")"
		hookParseNoteOnce.Do(func() {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "restoregap: hook %s\n", reason)
		})
		if strict {
			return "deny", reason
		}
		return "allow", reason
	}
	if len(plan.Intents) == 0 {
		if strict {
			return "deny", "not evaluated: unrecognized operation"
		}
		return "allow", "not evaluated: unrecognized operation"
	}
	decision, reason := evaluateAgentHook(cmd, plan.Intents)
	// Strict mode promises every piece was evaluated. A recognized operation
	// that passed does not excuse a sibling the parser could not classify, but
	// a real block is the more useful answer, so it wins.
	if decision == "allow" && strict && plan.Unrecognized > 0 {
		return "deny", "not evaluated: unrecognized operation in compound command"
	}
	return decision, reason
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

func translateAgentEvent(e agentEvent, vendor string) (hookPlan, error) {
	base := hookIntent{Version: 2, Actor: "agent/" + vendor, ContextWindow: "coding-agent", Description: "tool call intercepted by recovery hook"}
	plan := hookPlan{hookIntent: base}
	tool := e.Tool
	if vendor == "gemini" {
		switch tool {
		case "run_shell_command":
			tool = "Bash"
		case "write_file", "replace":
			tool = "Write"
		}
	}
	var proposed []hookIntent
	switch tool {
	case "Edit", "Write", "MultiEdit", "NotebookEdit":
		path, err := eventString(e, "file_path")
		if err != nil {
			return plan, err
		}
		if path == "" {
			path, err = eventString(e, "notebook_path")
			if err != nil {
				return plan, err
			}
		}
		if strings.TrimSpace(path) == "" {
			return plan, fmt.Errorf("%s requires a file path", e.Tool)
		}
		in := base
		in.Action, in.Paths = "modify_file", []string{path}
		proposed = append(proposed, in)
	case "Bash":
		command, err := eventString(e, "command")
		if err != nil {
			return plan, err
		}
		parsed := shellintent.Parse(command)
		if parsed.Unparseable {
			plan.ParseFailure = parsed.Reason
			return plan, nil
		}
		repoRoots := map[string]string{}
		for _, op := range parsed.Ops {
			if op.Action == "" {
				if !op.Benign {
					plan.Unrecognized++
				}
				continue
			}
			in := base
			in.Action, in.Command = op.Action, op.Command
			in.Paths, in.Targets = anchorHookPaths(op.Dir, op.Paths), anchorHookPaths(op.Dir, op.Targets)
			if op.Remote != "" {
				in.Description += "; runs through " + strings.Fields(op.Command)[0] + " on " + op.Remote
			}
			if op.RepoScoped {
				root, ok := repoRoots[op.Dir]
				if !ok {
					root = hookRepoRoot(op.Dir)
					repoRoots[op.Dir] = root
				}
				in.Paths = []string{root}
			}
			proposed = append(proposed, in)
		}
	}
	for i := range proposed {
		var err error
		proposed[i].Paths, proposed[i].LexicalPaths, err = resolveHookPaths(proposed[i].Paths)
		if err != nil {
			return plan, err
		}
		proposed[i].Targets, proposed[i].LexicalTargets, err = resolveHookPaths(proposed[i].Targets)
		if err != nil {
			return plan, err
		}
	}
	plan.Intents = proposed
	if len(proposed) > 0 {
		plan.hookIntent = proposed[0]
	}
	return plan, nil
}

// expandHookTilde expands a leading ~ the way the shell would have, so that
// "rm ~/Backups/x" names the home directory and not a directory called "~".
func expandHookTilde(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	return home + p[1:]
}

// anchorHookPaths resolves a shell command's paths against the directory an
// earlier `cd` in the same line moved to. An empty dir means the hook's own
// directory, which later path resolution already uses.
func anchorHookPaths(dir string, paths []string) []string {
	if len(paths) == 0 {
		return paths
	}
	dir = expandHookTilde(dir)
	out := make([]string, len(paths))
	for i, p := range paths {
		p = expandHookTilde(p)
		if dir != "" && !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		out[i] = p
	}
	return out
}

// hookRepoRoot anchors a command whose effect is scoped to the working
// repository (git, terraform, dropdb) to a path a guard can match. Outside a
// repository it falls back to the working directory, or to the directory an
// earlier `cd` in the same line moved to.
func hookRepoRoot(dir string) string {
	dir = expandHookTilde(dir)
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = dir
	root, err := cmd.Output()
	path := strings.TrimSpace(string(root))
	if err != nil || path == "" {
		if dir != "" {
			return dir
		}
		return "."
	}
	return path
}

// resolveHookPaths resolves each path to its canonical (symlink-resolved)
// form and, alongside it, records the lexical absolute form (filepath.Abs,
// no symlink resolution) it was resolved from — so guard matching can still
// catch a symlink at or after a guard pattern's wildcard that would
// otherwise resolve the canonical path outside a pattern that plainly
// matched the path as typed. See intent.ChangeIntent.LexicalPaths.
func resolveHookPaths(paths []string) (canonical, lexical []string, err error) {
	for _, p := range paths {
		lex, err := filepath.Abs(p)
		if err != nil {
			return nil, nil, err
		}
		abs, err := preflight.ResolveLocalPath(p)
		if err != nil {
			return nil, nil, err
		}
		canonical = append(canonical, abs)
		lexical = append(lexical, lex)
	}
	return canonical, lexical, nil
}

// evaluateAgentHook runs every proposed operation of one tool call through a
// single preflight, so the ledger records the whole call and one blocked piece
// of a compound command denies all of it.
//
// A lone operation still travels through a short-lived intent file (and the
// degraded path when that cannot be written), exactly as before. Several cannot:
// an intent file holds one document, and preflight takes the others in memory
// without losing anything in the ledger record.
func evaluateAgentHook(cmd *cobra.Command, ins []hookIntent) (string, string) {
	broken := func(err error) (string, string) { return "deny", "recovery gate unavailable: " + err.Error() }
	in := ins[0]
	ledgerPath, err := defaultLedgerPath()
	if err != nil {
		return broken(err)
	}
	paths := discovery.ContextPaths()
	req := preflight.Request{ContextPaths: paths, LedgerPath: ledgerPath, Actor: in.Actor, ContextWindow: in.ContextWindow, Format: "json", RequireCoverage: os.Getenv("RESTOREGAP_REQUIRE_COVERAGE") == "1", ToolVersion: Version, ResolveLocalPaths: true}
	if len(ins) == 1 {
		data, err := yaml.Marshal(in)
		if err != nil {
			return broken(err)
		}
		intentPath, err := writeHookIntent(data)
		if err != nil {
			return evaluateAgentHookDegraded(cmd, in, data, ledgerPath, err)
		}
		defer func() { _ = os.Remove(intentPath) }()
		req.IntentPath = intentPath
	} else {
		for _, op := range ins {
			data, err := yaml.Marshal(op)
			if err != nil {
				return broken(err)
			}
			ci, err := intent.Parse(bytes.NewReader(data))
			if err != nil {
				return broken(err)
			}
			req.Intents = append(req.Intents, ci)
		}
	}
	result, err := preflight.Run(cmd.Context(), req)
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
	reason := hookDenyReason(rep, paths)
	if len(ins) > 1 {
		reason += fmt.Sprintf(" (%d operations evaluated)", len(ins))
	}
	return "deny", reason
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
	result, err := preflight.Run(cmd.Context(), preflight.Request{Intents: []intent.ChangeIntent{ci}, ContextPaths: paths, LedgerPath: ledgerPath, Actor: in.Actor, ContextWindow: in.ContextWindow, Format: "json", RequireCoverage: os.Getenv("RESTOREGAP_REQUIRE_COVERAGE") == "1", ToolVersion: Version, ResolveLocalPaths: true})
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
