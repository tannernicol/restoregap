// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tannernicol/restoregap/internal/agentconfig"
)

// AgentWiring reports configuration, not proof that an agent loaded the hook or
// that the recovery policy covers every operation.
type AgentWiring struct {
	Vendor string   `json:"vendor"`
	Hook   bool     `json:"hook"`
	MCP    bool     `json:"mcp"`
	Errors []string `json:"errors,omitempty"`
}

func collectAgents(home, cwd string) []Candidate {
	var out []Candidate
	for _, vendor := range []string{"claude", "gemini", "cursor"} {
		wiring := &AgentWiring{Vendor: vendor}
		c := Candidate{Kind: KindAgent, Name: vendor, Weight: weightFor(KindAgent), Agent: wiring}
		if vendor == "claude" {
			c.Name = "claude-code"
		}
		seen := map[string]bool{}
		for _, scope := range []string{"user", "project"} {
			settings, registry := agentconfig.Paths(vendor, home, cwd, scope)
			if seen[settings] {
				continue
			}
			seen[settings] = true
			inspectAgentScope(&c, wiring, vendor, settings, registry)
		}
		if c.Path == "" {
			continue
		}
		c.Covered = wiring.Hook && wiring.MCP && len(wiring.Errors) == 0
		if c.Covered {
			c.CoveredBy = "agent:hook+mcp"
		}
		out = append(out, c)
	}
	return out
}

func inspectAgentScope(c *Candidate, wiring *AgentWiring, vendor, settings, registry string) {
	obj, found, err := readAgentConfig(settings)
	if !found {
		return
	}
	if c.Path == "" {
		c.Path = settings
	} else {
		c.AlternatePaths = append(c.AlternatePaths, settings)
	}
	if err != nil {
		wiring.Errors = append(wiring.Errors, err.Error())
		return
	}
	wiring.Hook = wiring.Hook || agentHookWired(obj, vendor)
	if registry != settings {
		obj, _, err = readAgentConfig(registry)
		if err != nil {
			wiring.Errors = append(wiring.Errors, err.Error())
			return
		}
	}
	servers, _ := obj["mcpServers"].(map[string]any)
	server, _ := servers["restoregap"].(map[string]any)
	command, _ := server["command"].(string)
	args, _ := server["args"].([]any)
	wiring.MCP = wiring.MCP || (command != "" && len(args) == 2 && args[0] == "mcp" && args[1] == "serve")
}

func readAgentConfig(path string) (map[string]any, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, true, fmt.Errorf("%s: %w", path, err)
	}
	if obj == nil {
		return nil, true, fmt.Errorf("%s: expected settings object", path)
	}
	return obj, true, nil
}

func agentHookWired(obj map[string]any, vendor string) bool {
	if obj["disableAllHooks"] == true {
		return false
	}
	hooks, _ := obj["hooks"].(map[string]any)
	if vendor == "cursor" {
		return cursorHookWired(obj, hooks)
	}
	event, tools := "PreToolUse", []string{"Bash", "Edit", "Write", "MultiEdit", "NotebookEdit"}
	if vendor == "gemini" {
		if hooks["enabled"] == false {
			return false
		}
		event, tools = "BeforeTool", []string{"run_shell_command", "write_file", "replace"}
	}
	entries, _ := hooks[event].([]any)
	for _, tool := range tools {
		found := false
		for _, raw := range entries {
			entry, _ := raw.(map[string]any)
			matcher, _ := entry["matcher"].(string)
			if matcher != "" && matcher != "*" {
				matched, err := regexp.MatchString("^(?:"+matcher+")$", tool)
				if err != nil || !matched {
					continue
				}
			}
			commands, _ := entry["hooks"].([]any)
			for _, rawCommand := range commands {
				command, _ := rawCommand.(map[string]any)
				found = found || (command["type"] == "command" && isAgentCommand(command["command"], vendor))
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func cursorHookWired(obj, hooks map[string]any) bool {
	if obj["version"] != float64(1) {
		return false
	}
	for _, event := range []string{"beforeShellExecution", "beforeMCPExecution"} {
		found := false
		entries, _ := hooks[event].([]any)
		for _, raw := range entries {
			entry, _ := raw.(map[string]any)
			// A matcher restricting execution is not full gate wiring.
			if entry["matcher"] != nil && entry["matcher"] != "" {
				continue
			}
			found = found || isAgentCommand(entry["command"], "cursor")
		}
		if !found {
			return false
		}
	}
	return true
}

func isAgentCommand(value any, vendor string) bool {
	command, _ := value.(string)
	suffix := " agent hook " + vendor
	if !strings.HasSuffix(command, suffix) {
		return false
	}
	binary := strings.TrimSuffix(command, suffix)
	if len(binary) > 1 && (binary[0] == '\'' || binary[0] == '"') && binary[len(binary)-1] == binary[0] {
		quote := binary[0]
		binary = binary[1 : len(binary)-1]
		if strings.ContainsRune(binary, rune(quote)) {
			return false
		}
	} else if strings.ContainsAny(binary, " \t\r\n\"'") {
		return false
	}
	return filepath.Base(binary) == "restoregap" || filepath.Base(binary) == "restoregap.exe"
}

// AgentCoverageLine is shared by discover and status's saved coverage summary.
func AgentCoverageLine(c Candidate) string {
	if c.Agent == nil {
		return ""
	}
	state := "recovery gate wired"
	if !c.Agent.Hook {
		state = "no recovery gate wired (run: restoregap agent install " + c.Agent.Vendor + ")"
	}
	mcp := "wired"
	if !c.Agent.MCP {
		mcp = "missing (run: restoregap agent install " + c.Agent.Vendor + ")"
	}
	line := fmt.Sprintf("%s: %s; MCP: %s", c.Name, state, mcp)
	if len(c.Agent.Errors) > 0 {
		line += "; settings unreadable: " + strings.Join(c.Agent.Errors, "; ")
	}
	return line
}
