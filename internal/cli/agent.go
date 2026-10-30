// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

func init() { extraCommands = append(extraCommands, newAgentCmd) }

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "agent", Short: "Install and run recovery gates for coding agents"}
	var scope string
	var dry bool
	install := &cobra.Command{Use: "install <claude|gemini|cursor>", Short: "Install the recovery hook and MCP server; print the settings diff", Args: agentVendorArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return installAgent(cmd, args[0], scope, dry) }}
	install.Flags().StringVar(&scope, "scope", "user", "settings scope: user or project")
	install.Flags().BoolVar(&dry, "dry-run", false, "print the diff without writing settings")
	hook := &cobra.Command{Use: "hook <claude|gemini|cursor>", Short: "Evaluate one tool event from stdin and return a structured decision", Args: agentVendorArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			decision, reason := agentHook(cmd, args[0])
			var out any = map[string]any{"decision": decision, "reason": reason}
			if args[0] == "claude" {
				out = map[string]any{"hookSpecificOutput": map[string]string{"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}}
			}
			if args[0] == "cursor" {
				out = map[string]string{"permission": decision, "user_message": reason, "agent_message": reason}
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
		}}
	cmd.AddCommand(install, hook)
	return cmd
}

func agentVendorArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.ExactArgs(1)(cmd, args); err != nil {
		return err
	}
	if args[0] != "claude" && args[0] != "gemini" && args[0] != "cursor" {
		return fmt.Errorf("unknown agent %q: expected claude, gemini or cursor", args[0])
	}
	return nil
}

func mcpConfig() (map[string]any, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return map[string]any{"mcpServers": map[string]any{"restoregap": map[string]any{"command": exe, "args": []string{"mcp", "serve"}}}}, nil
}
