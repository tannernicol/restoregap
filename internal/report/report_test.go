package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/engine"
)

var fixedTime = time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)

func sampleFindings() []engine.Finding {
	return []engine.Finding{
		{
			ID: "finding_1", GuardID: "default-ssh-private-keys", Kind: "lifeline", Resource: "~/.ssh/id_ed25519",
			Actions: []string{"delete_file"}, RiskClass: engine.RiskCannotProveSafe, ProofStatus: engine.ProofMissing,
			Verdict: engine.VerdictBlock, Title: "cannot prove safe", Proof: "no proof vocabulary",
			RequiredNextStep: "declare a guard",
		},
	}
}

func TestFromFindings(t *testing.T) {
	rep := FromFindings(sampleFindings(), engine.VerdictBlock, fixedTime, "agent/claude", "local-shell")
	if rep.Schema != Schema {
		t.Errorf("schema = %d, want %d", rep.Schema, Schema)
	}
	if rep.Verdict != "block" {
		t.Errorf("verdict = %s, want block", rep.Verdict)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].GuardID != "default-ssh-private-keys" {
		t.Fatalf("unexpected findings: %+v", rep.Findings)
	}
	if rep.Actor != "agent/claude" || rep.ContextWindow != "local-shell" {
		t.Errorf("unexpected actor/context_window: %+v", rep)
	}
}

func TestJSONRoundTrips(t *testing.T) {
	rep := FromFindings(sampleFindings(), engine.VerdictBlock, fixedTime, "agent/claude", "")
	data, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Verdict != rep.Verdict || len(decoded.Findings) != len(rep.Findings) {
		t.Errorf("round-trip mismatch: got %+v, want %+v", decoded, rep)
	}
	if strings.Contains(string(data), `"context_window"`) {
		t.Error("empty context_window should be omitted from JSON")
	}
}

func TestMarkdownBannerFirst(t *testing.T) {
	rep := FromFindings(sampleFindings(), engine.VerdictBlock, fixedTime, "agent/claude", "")
	md := string(rep.Markdown())
	if !strings.HasPrefix(md, "# BLOCK\n") {
		t.Fatalf("markdown must start with the verdict banner, got:\n%s", md)
	}
	bannerEnd := strings.Index(md, "| Verdict |")
	detailStart := strings.Index(md, "## Detail")
	if bannerEnd == -1 || detailStart == -1 || detailStart < bannerEnd {
		t.Errorf("expected banner, then table, then detail section; got:\n%s", md)
	}
	if !strings.Contains(md, "declare a guard") {
		t.Error("required_next_step should appear in the banner's action list")
	}
}

func TestMarkdownNoFindings(t *testing.T) {
	rep := FromFindings(nil, engine.VerdictPass, fixedTime, "agent/claude", "")
	md := string(rep.Markdown())
	if !strings.Contains(md, "PASS") || !strings.Contains(md, "No findings.") {
		t.Errorf("expected PASS banner and 'No findings.', got:\n%s", md)
	}
}

// TestTextHasNoMarkdownSyntax: the whole point of Text is that it is not
// markdown — no pipe tables, no #/** — so a human at a terminal isn't
// handed source for a renderer nobody is piping it to.
func TestTextHasNoMarkdownSyntax(t *testing.T) {
	rep := FromFindings(sampleFindings(), engine.VerdictBlock, fixedTime, "agent/claude", "")
	text := string(rep.Text())
	if strings.Contains(text, "|") {
		t.Errorf("Text must not contain a pipe table, got:\n%s", text)
	}
	if strings.Contains(text, "#") || strings.Contains(text, "**") {
		t.Errorf("Text must not contain markdown headers/bold, got:\n%s", text)
	}
}

// TestTextStartsWithHeadlineThenSummary: verdict headline first, then the
// summary sentence — same order Markdown's banner uses.
func TestTextStartsWithHeadlineThenSummary(t *testing.T) {
	rep := FromFindings(sampleFindings(), engine.VerdictBlock, fixedTime, "agent/claude", "")
	text := string(rep.Text())
	if !strings.HasPrefix(text, "BLOCK\n"+summarySentence("block")+"\n") {
		t.Fatalf("Text must start with the verdict headline then the summary sentence, got:\n%s", text)
	}
}

// TestTextNamesGuardResourceProofPerFinding: each finding gets one line
// naming its guard, resource, and proof status — the information a human
// needs without a table.
func TestTextNamesGuardResourceProofPerFinding(t *testing.T) {
	rep := FromFindings(sampleFindings(), engine.VerdictBlock, fixedTime, "agent/claude", "")
	text := string(rep.Text())
	if !strings.Contains(text, "guard") || !strings.Contains(text, "default-ssh-private-keys") {
		t.Errorf("expected the guard id in the finding line, got:\n%s", text)
	}
	if !strings.Contains(text, "resource") || !strings.Contains(text, "~/.ssh/id_ed25519") {
		t.Errorf("expected the resource in the finding line, got:\n%s", text)
	}
	if !strings.Contains(text, "proof") || !strings.Contains(text, "missing") {
		t.Errorf("expected the proof status in the finding line, got:\n%s", text)
	}
	if !strings.Contains(text, "next: declare a guard") {
		t.Errorf("expected a next: line for the required next step, got:\n%s", text)
	}
}

func TestTextNoFindings(t *testing.T) {
	rep := FromFindings(nil, engine.VerdictPass, fixedTime, "agent/claude", "")
	text := string(rep.Text())
	if !strings.HasPrefix(text, "PASS\n") || !strings.Contains(text, "No findings.") {
		t.Errorf("expected PASS headline and 'No findings.', got:\n%s", text)
	}
}
