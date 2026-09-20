// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tannernicol/restoregap/internal/agentconfig"
)

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

type settingsChange struct {
	path          string
	before, after []byte
	mode          os.FileMode
}

func installAgent(cmd *cobra.Command, vendor, scope string, dry bool) error {
	if scope != "user" && scope != "project" {
		return fmt.Errorf("scope must be user or project")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	base := home
	if scope == "project" {
		base, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	cfg, err := mcpConfig()
	if err != nil {
		return err
	}
	server := cfg["mcpServers"].(map[string]any)["restoregap"].(map[string]any)
	command := shellQuote(server["command"].(string)) + " agent hook " + vendor
	settings, registry := agentconfig.Paths(vendor, home, base, scope)
	paths := []string{settings}
	if registry != settings {
		paths = append(paths, registry)
	}
	changes := make([]settingsChange, 0, len(paths))
	for i, path := range paths {
		change, err := planAgentSettings(path, vendor, command, server, i == 0)
		if err != nil {
			return err
		}
		changes = append(changes, change)
	}
	return applyAgentSettings(cmd, changes, dry)
}

func applyAgentSettings(cmd *cobra.Command, changes []settingsChange, dry bool) error {
	for _, change := range changes {
		if bytes.Equal(change.before, change.after) {
			continue
		}
		if !dry {
			if err := writeAgentSettings(change); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(cmd.OutOrStdout(), settingsDiff(change)); err != nil {
			return err
		}
	}
	return nil
}

func readSettings(path string) (map[string]any, []byte, os.FileMode, error) {
	mode := os.FileMode(0o600)
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return nil, nil, mode, fmt.Errorf("settings %s is not a regular file", path)
		}
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return nil, nil, mode, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil, mode, nil
	}
	if err != nil {
		return nil, nil, mode, err
	}
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err = dec.Decode(&obj); err != nil {
		return nil, nil, mode, fmt.Errorf("settings %s: %w", path, err)
	}
	var extra any
	if obj == nil || dec.Decode(&extra) != io.EOF {
		return nil, nil, mode, fmt.Errorf("settings %s must contain one JSON object", path)
	}
	return obj, data, mode, nil
}

func settingsObject(parent map[string]any, key string) (map[string]any, error) {
	if val, ok := parent[key]; ok {
		obj, ok := val.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("settings %s must be an object", key)
		}
		return obj, nil
	}
	obj := map[string]any{}
	parent[key] = obj
	return obj, nil
}

func planAgentSettings(path, vendor, command string, server map[string]any, hook bool) (settingsChange, error) {
	obj, before, mode, err := readSettings(path)
	change := settingsChange{path: path, before: before, mode: mode}
	if err != nil {
		return change, err
	}
	original, _ := json.Marshal(obj)
	if vendor != "cursor" || !hook {
		servers, err := settingsObject(obj, "mcpServers")
		if err != nil {
			return change, err
		}
		// Retain server-specific options (env, timeout, etc.), replacing only our launch command.
		entry, err := settingsObject(servers, "restoregap")
		if err != nil {
			return change, err
		}
		for k, v := range server {
			entry[k] = v
		}
	}
	if hook {
		if err := addAgentHook(obj, vendor, command); err != nil {
			return change, err
		}
	}
	after, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return change, err
	}
	compact, _ := json.Marshal(obj)
	if bytes.Equal(original, compact) {
		change.after = before
	} else {
		change.after = append(after, '\n')
	}
	return change, nil
}

func addAgentHook(obj map[string]any, vendor, command string) error {
	hooks, err := settingsObject(obj, "hooks")
	if err != nil {
		return err
	}
	if vendor == "cursor" {
		if version, exists := obj["version"]; exists && version != json.Number("1") {
			return fmt.Errorf("cursor hooks version must be 1")
		}
		obj["version"] = json.Number("1")
		for _, event := range []string{"beforeShellExecution", "beforeMCPExecution"} {
			if err := appendAgentHook(hooks, event, map[string]any{"command": command, "failClosed": true}); err != nil {
				return err
			}
		}
		return nil
	}
	event, matcher := "PreToolUse", "Bash|Edit|Write|MultiEdit|NotebookEdit"
	if vendor == "gemini" {
		event, matcher = "BeforeTool", "run_shell_command|write_file|replace"
	}
	entry := map[string]any{"matcher": matcher, "hooks": []any{map[string]any{"type": "command", "command": command}}}
	return appendAgentHook(hooks, event, entry)
}

func appendAgentHook(hooks map[string]any, event string, entry map[string]any) error {
	var entries []any
	if val, ok := hooks[event]; ok {
		var valid bool
		entries, valid = val.([]any)
		if !valid {
			return fmt.Errorf("settings hooks.%s must be an array", event)
		}
	}
	for _, existing := range entries {
		if reflect.DeepEqual(existing, entry) {
			return nil
		}
	}
	hooks[event] = append(entries, entry)
	return nil
}

func writeAgentSettings(c settingsChange) error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(c.path), ".restoregap-settings-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err = f.Chmod(c.mode); err == nil {
		_, err = f.Write(c.after)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), c.path)
}

// A whole-file unified hunk is deliberately simple and applies even when the
// original settings were compact JSON. No external diff executable is needed.
func settingsDiff(c settingsChange) string {
	lines := func(b []byte) []string {
		if len(b) == 0 {
			return nil
		}
		return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	}
	old, newLines := lines(c.before), lines(c.after)
	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ %s\n@@ -%d,%d +1,%d @@\n", c.path, c.path, min(1, len(old)), len(old), len(newLines))
	for _, line := range old {
		fmt.Fprintln(&b, "-"+line)
	}
	if len(c.before) > 0 && c.before[len(c.before)-1] != '\n' {
		b.WriteString("\\ No newline at end of file\n")
	}
	for _, line := range newLines {
		fmt.Fprintln(&b, "+"+line)
	}
	return b.String()
}
