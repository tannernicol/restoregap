// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// Assert the wire contract used by clients to distinguish inspection from
// ledger mutations. Decode pointers so omission is not mistaken for false.
func TestToolsListAnnotations(t *testing.T) {
	var out bytes.Buffer
	if err := Serve(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Annotations *struct {
					Title        string `json:"title"`
					ReadOnlyHint *bool  `json:"readOnlyHint"`
				} `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"preflight_intent": false,
		"preflight_diff":   false,
		"acknowledge_risk": false,
		"explain_decision": true,
		"required_proof":   true,
		"ledger_query":     true,
		"story":            true,
		"drill_lint":       true,
		"next_steps":       true,
		"discover":         true,
	}
	for _, tool := range response.Result.Tools {
		readOnly, exists := want[tool.Name]
		if !exists {
			t.Errorf("unclassified or duplicate tool %q", tool.Name)
			continue
		}
		delete(want, tool.Name)
		if tool.Annotations == nil || tool.Annotations.ReadOnlyHint == nil {
			t.Errorf("%s: annotations.readOnlyHint omitted", tool.Name)
			continue
		}
		if *tool.Annotations.ReadOnlyHint != readOnly {
			t.Errorf("%s: readOnlyHint = %v, want %v", tool.Name, *tool.Annotations.ReadOnlyHint, readOnly)
		}
		if strings.TrimSpace(tool.Annotations.Title) == "" {
			t.Errorf("%s: annotation title omitted", tool.Name)
		}
	}
	for name := range want {
		t.Errorf("tool %s missing from tools/list", name)
	}
}
