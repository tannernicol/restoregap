// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestNextStepsToolReturnsSameShapeAsCLI: next_steps is read-only and
// mirrors `restoregap next --format json` — id/layer/category/state/why/
// command/context_file/artifact/scope per not-green proof.
func TestNextStepsToolReturnsSameShapeAsCLI(t *testing.T) {
	path := writeContext(t, `version: 2
guards:
- id: ssh-guard
  kind: lifeline
  match: {paths: ["~/.ssh/id_ed25519"]}
  layer: identity-secrets
  requires: {proofs: [ssh-key-recovery]}
proofs:
- id: ssh-key-recovery
  status: observed
  observed_at: "2026-01-01T00:00:00Z"
`)
	text, err := callTool(context.Background(), "next_steps", toolArgs{ContextPath: path})
	if err != nil {
		t.Fatal(err)
	}
	var steps []struct {
		ID, Layer, Category, State, Why, Command, ContextFile, Artifact string
	}
	if err := json.Unmarshal([]byte(text), &steps); err != nil {
		t.Fatalf("json.Unmarshal: %v (%s)", err, text)
	}
	if len(steps) != 1 || steps[0].ID != "ssh-key-recovery" || steps[0].Layer != "identity-secrets" {
		t.Fatalf("steps = %+v, want one ssh-key-recovery/identity-secrets step", steps)
	}
}

// TestNextStepsToolLayerFilter: the optional layer argument narrows results
// the same way `restoregap next --layer` does.
func TestNextStepsToolLayerFilter(t *testing.T) {
	path := writeContext(t, `version: 2
guards:
- id: ssh-guard
  kind: lifeline
  match: {paths: ["~/.ssh/id_ed25519"]}
  layer: identity-secrets
  requires: {proofs: [ssh-key-recovery]}
- id: git-guard
  kind: guard
  match: {paths: ["/repo/**"]}
  layer: git-code
  requires: {proofs: [git-estate-recovery]}
proofs:
- id: ssh-key-recovery
  status: observed
  observed_at: "2026-01-01T00:00:00Z"
- id: git-estate-recovery
  status: observed
  observed_at: "2026-01-01T00:00:00Z"
`)
	text, err := callTool(context.Background(), "next_steps", toolArgs{ContextPath: path, Layer: "git-code"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "ssh-key-recovery") {
		t.Errorf("layer=git-code must exclude the identity-secrets proof, got %s", text)
	}
	if !strings.Contains(text, "git-estate-recovery") {
		t.Errorf("expected git-estate-recovery in layer=git-code results, got %s", text)
	}
}

// TestToolDefsIncludesNextSteps ensures next_steps is registered alongside
// the other tools and requires context_path.
func TestToolDefsIncludesNextSteps(t *testing.T) {
	defs := toolDefs()
	for _, d := range defs {
		if d.Name != "next_steps" {
			continue
		}
		req, _ := d.InputSchema["required"].([]string)
		if len(req) != 1 || req[0] != "context_path" {
			t.Errorf("next_steps required = %v, want [context_path]", req)
		}
		return
	}
	t.Fatal("next_steps not found in toolDefs()")
}
