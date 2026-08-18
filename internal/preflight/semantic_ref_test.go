package preflight

// Semantic reference tests: replay the cases captured from the Python
// implementation (testdata/golden, commit 170062f) through the Go engine and
// assert Go is never MORE PERMISSIVE than Python was on the same input.
// Byte-exact output parity is explicitly not a goal (clean-slate decision,
// docs/ARCHITECTURE.md §Compatibility stance); verdict semantics are.
//
// The captured inputs use the Python v1 context schema; convertV1Context is a
// test-only translation onto the v2 unified guard model.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const goldenDir = "../../testdata/golden"

type manifest struct {
	Cases []struct {
		Name         string `json:"name"`
		Description  string `json:"description"`
		ExpectedExit int    `json:"expected_exit"`
	} `json:"cases"`
}

func verdictRank(t *testing.T, v string) int {
	t.Helper()
	switch v {
	case "pass":
		return 0
	case "warn":
		return 1
	case "block", "fail": // recovery mode says "fail" where local mode says "block"
		return 2
	}
	t.Fatalf("unknown verdict %q", v)
	return -1
}

func TestSemanticReferenceCases(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(goldenDir, "manifest.json"))
	if os.IsNotExist(err) {
		t.Skip("golden manifest not present; semantic reference cases not captured")
	}
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}

	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) {
			dir := filepath.Join(goldenDir, "cases", c.Name)
			cmdTxt, err := os.ReadFile(filepath.Join(dir, "cmd.txt"))
			if err != nil {
				t.Fatal(err)
			}
			cmd := string(cmdTxt)

			req := Request{Format: "json", Actor: flagValue(cmd, "--actor")}

			if p := filepath.Join(dir, "intent.yml"); fileExists(p) {
				req.IntentPath = p
			}
			if p := filepath.Join(dir, "diff.patch"); fileExists(p) {
				req.DiffPath = p
			}
			req.FailOnWarn = strings.Contains(cmd, "--fail-on-warn")
			req.IntentActor = flagValue(cmd, "--intent-actor")
			req.ContextWindow = flagValue(cmd, "--context-window")
			req.AsOf = flagValue(cmd, "--as-of")
			if strings.Contains(cmd, "--context ") {
				req.ContextPaths = []string{convertV1Context(t, filepath.Join(dir, "restoregap.local.yml"))}
			}

			result, err := Run(context.Background(), req)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			var out struct {
				Verdict string `json:"verdict"`
			}
			if err := json.Unmarshal(result.Rendered, &out); err != nil {
				t.Fatalf("rendered JSON: %v", err)
			}

			pyVerdict := pythonVerdict(t, dir)
			goRank, pyRank := verdictRank(t, out.Verdict), verdictRank(t, pyVerdict)
			if goRank < pyRank {
				t.Errorf("Go verdict %q is more permissive than Python %q", out.Verdict, pyVerdict)
			}
			if pyRank == 0 && goRank != 0 {
				t.Errorf("Python passed but Go said %q — overstrict on a known-good change", out.Verdict)
			}
			// Exit codes must agree except where Go legitimately tightened
			// warn -> block (allowed by the strictness rule above).
			if out.Verdict == pyVerdict && result.ExitCode != c.ExpectedExit {
				t.Errorf("exit code %d, Python exited %d (verdicts agree: %q)", result.ExitCode, c.ExpectedExit, out.Verdict)
			}
		})
	}
}

func pythonVerdict(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "out.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out.Verdict
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// flagValue extracts the first "--flag value" occurrence from a captured
// command line (cmd.txt embeds the exact invocation used for the capture).
func flagValue(cmd, flag string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(flag) + `\s+(\S+)`)
	m := re.FindStringSubmatch(cmd)
	if m == nil {
		return ""
	}
	return strings.Trim(m[1], "'\"")
}

// ---- v1 -> v2 context conversion (test-only) --------------------------------

type v1Context struct {
	LifelineArtifacts []struct {
		ID             string   `yaml:"id"`
		Paths          []string `yaml:"paths"`
		PathPatterns   []string `yaml:"path_patterns"`
		RequiredFor    []string `yaml:"required_for"`
		RecoveryCopy   string   `yaml:"recovery_copy"`
		AlternatePaths []string `yaml:"alternate_paths"`
	} `yaml:"lifeline_artifacts"`
	AdminRoutes []struct {
		ID    string   `yaml:"id"`
		Files []string `yaml:"files"`
	} `yaml:"admin_routes"`
	RecoveryKit struct {
		Artifacts []string `yaml:"artifacts"`
	} `yaml:"recovery_kit"`
	UpdateGuards  []v1Guard `yaml:"update_guards"`
	CommandGuards []v1Guard `yaml:"command_guards"`
	ChangeGuards  []v1Guard `yaml:"change_guards"`
	Facts         []struct {
		FactID    string `yaml:"fact_id"`
		Statement string `yaml:"statement"`
		Source    string `yaml:"source"`
		ExpiresAt string `yaml:"expires_at"`
	} `yaml:"facts"`
	Proofs []struct {
		ID          string `yaml:"id"`
		ProofID     string `yaml:"proof_id"`
		Status      string `yaml:"status"`
		ObservedAt  string `yaml:"observed_at"`
		ExpiresAt   string `yaml:"expires_at"`
		SHA256      string `yaml:"sha256"`
		EvidenceURL string `yaml:"evidence_url"`
	} `yaml:"proofs"`
}

type v1Guard struct {
	ID                string   `yaml:"id"`
	Paths             []string `yaml:"paths"`
	PathPatterns      []string `yaml:"path_patterns"`
	Packages          []string `yaml:"packages"`
	Commands          []string `yaml:"commands"`
	Actions           []string `yaml:"actions"`
	RecoveryArtifacts []string `yaml:"recovery_artifacts"`
}

// convertV1Context translates a captured Python v1 context document onto the
// v2 unified guard model and writes it to a temp file, returning its path.
// Assurance contracts are intentionally not translated: the lifeline/guard
// mappings already carry the verdict-relevant semantics for the captured
// cases (contracts only narrowed WHO a requirement applied to).
func convertV1Context(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v1 v1Context
	if err := yaml.Unmarshal(raw, &v1); err != nil {
		t.Fatalf("v1 context %s: %v", path, err)
	}

	type match map[string]any
	type guard map[string]any
	var guards []guard

	lifeline := func(id string, paths []string) {
		if len(paths) == 0 {
			return
		}
		guards = append(guards, guard{
			"id": id, "kind": "lifeline", "enforcement": "block",
			"match": match{"paths": paths},
		})
	}
	for _, l := range v1.LifelineArtifacts {
		lifeline(l.ID, append(append([]string{}, l.Paths...), l.PathPatterns...))
	}
	for _, r := range v1.AdminRoutes {
		var paths []string
		for _, f := range r.Files {
			paths = append(paths, f, "**/"+f)
		}
		lifeline("admin-route-"+r.ID, paths)
	}
	{
		var paths []string
		for _, a := range v1.RecoveryKit.Artifacts {
			paths = append(paths, a, "**/"+a)
		}
		lifeline("recovery-kit", paths)
	}

	proofGuard := func(id string, m match, requires []string, actions []string) {
		g := guard{"id": id, "kind": "guard", "enforcement": "block", "match": m}
		if len(actions) > 0 {
			m["actions"] = actions
		}
		if len(requires) > 0 {
			g["requires"] = map[string]any{"proofs": requires}
		}
		guards = append(guards, g)
	}
	for _, u := range v1.UpdateGuards {
		if len(u.Packages) == 0 {
			continue
		}
		proofGuard(u.ID, match{"packages": u.Packages}, u.RecoveryArtifacts,
			[]string{"package_update", "system_update"})
	}
	for _, cg := range v1.CommandGuards {
		if len(cg.Commands) == 0 {
			continue
		}
		proofGuard(cg.ID, match{"commands": cg.Commands}, cg.RecoveryArtifacts, nil)
	}
	for _, cg := range v1.ChangeGuards {
		paths := append(append([]string{}, cg.Paths...), cg.PathPatterns...)
		if len(paths) == 0 {
			continue
		}
		proofGuard(cg.ID, match{"paths": paths}, cg.RecoveryArtifacts, cg.Actions)
	}

	doc := map[string]any{"version": 2, "guards": guards}

	var facts []map[string]any
	for _, f := range v1.Facts {
		fact := map[string]any{"id": f.FactID, "statement": f.Statement, "provenance": f.Source}
		if f.ExpiresAt != "" {
			fact["expires_at"] = f.ExpiresAt
		}
		facts = append(facts, fact)
	}
	if len(facts) > 0 {
		doc["facts"] = facts
	}

	statusMap := map[string]string{
		"attested": "observed", "failed": "disputed",
		"observed": "observed", "validated": "validated", "stale": "stale",
	}
	var proofs []map[string]any
	for _, p := range v1.Proofs {
		id := p.ID
		if id == "" {
			id = p.ProofID
		}
		proof := map[string]any{"id": id, "status": statusMap[p.Status]}
		for k, v := range map[string]string{
			"observed_at": p.ObservedAt, "expires_at": p.ExpiresAt,
			"sha256": p.SHA256, "evidence_url": p.EvidenceURL,
		} {
			if v != "" {
				proof[k] = v
			}
		}
		proofs = append(proofs, proof)
	}
	if len(proofs) > 0 {
		doc["proofs"] = proofs
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "restoregap.v2.yml")
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}
