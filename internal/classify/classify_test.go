// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package classify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRuleTableExactOrder pins the taxonomy spec's revised literal keyword
// table (section B, proof-first classification refresh) so a future edit
// that reorders or drops a keyword is caught here rather than silently
// changing production classifications. Two cases changed deliberately from
// the previous table: "vault" alone no longer triggers identity-secrets
// (only the more specific "vaultwarden" does — see
// TestVaultwardenBeatsGenericVault / TestGenericVaultFallsToDataApps), and
// "assistant" is now a real agents-context keyword (see
// TestAssistantKeywordMatchesAgentsContext).
func TestRuleTableExactOrder(t *testing.T) {
	cases := []struct {
		search string
		layer  string
	}{
		{"ssh-key-recovery", "identity-secrets"},
		{"secret-store-recovery", "identity-secrets"},
		{"password-store", "identity-secrets"},
		{"vaultwarden-recovery", "identity-secrets"},
		{"nas-breakglass-access", "identity-secrets"}, // credential keyword beats generic "nas"
		{"some-credential-thing", "identity-secrets"},
		{"recovery-usb-bootstrap", "recovery-kit"},
		{"restoregap-policy-backup", "recovery-kit"},
		{"phone-reprovision-path", "recovery-kit"},
		{"os-snapshot-recovery", "system-os"},
		{"kernel-boot-args-change", "system-os"},
		{"etc-fstab-recovery", "system-os"},
		{"off-machine-os-snapshot", "system-os"},
		{"deliberate-machine-crash-test", "system-os"},
		{"nas-outofband-access", "infra-network"},
		{"tailnet-dns-firewall", "infra-network"},
		{"private-app-caddy-surface", "infra-network"},
		{"homelab-spine", "infra-network"},
		{"restic-latest-snapshot-observed", "backups-offsite"},
		{"offsite-recovery", "backups-offsite"},
		{"restic-repository-health", "backups-offsite"},
		{"rclone-mirror", "backups-offsite"},
		{"git-estate-recovery", "git-code"},
		{"gitea-mirror", "git-code"},
		{"context-plane-recovery", "agents-context"},
		{"codex-state-recovery", "agents-context"},
		{"claude-launch-wrappers", "agents-context"},
		{"agent-launcher-loadability", "agents-context"},
		{"assistant-conversations-recovery", "agents-context"},
		{"money-db-recovery", "data-apps"},
		{"obsidian-vault-recovery", "data-apps"},
	}
	for _, c := range cases {
		got, reason := suggestLayer(c.search)
		if got != c.layer {
			t.Errorf("suggestLayer(%q) = %q (%s), want %q", c.search, got, reason, c.layer)
		}
	}
}

// TestVaultwardenBeatsGenericVault: "vaultwarden" is its own rule 1,
// checked before anything else, so it always resolves to identity-secrets
// regardless of what else the id contains.
func TestVaultwardenBeatsGenericVault(t *testing.T) {
	got, _ := suggestLayer("vaultwarden-recovery")
	if got != "identity-secrets" {
		t.Fatalf("suggestLayer(vaultwarden-recovery) = %q, want identity-secrets", got)
	}
}

// TestGenericVaultFallsToDataApps documents the deliberate, revised
// behavior: unlike the old table, bare "vault" (as in "obsidian-vault") is
// NOT an identity-secrets keyword — only "vaultwarden" is — so an
// Obsidian-vault-shaped id correctly falls through to the data-apps
// default instead of being misclassified as a credential store.
func TestGenericVaultFallsToDataApps(t *testing.T) {
	got, _ := suggestLayer("obsidian-vault-recovery")
	if got != "data-apps" {
		t.Fatalf("suggestLayer(obsidian-vault-recovery) = %q, want data-apps (generic \"vault\" must not match identity-secrets)", got)
	}
}

// TestAssistantKeywordMatchesAgentsContext documents the revised table's
// addition of "assistant" to the agents-context keyword list.
func TestAssistantKeywordMatchesAgentsContext(t *testing.T) {
	got, _ := suggestLayer("assistant-conversations-recovery")
	if got != "agents-context" {
		t.Fatalf("suggestLayer(assistant-conversations-recovery) = %q, want agents-context", got)
	}
}

// TestCredentialKeywordBeatsGenericInfraKeyword: identity-secrets'
// ssh|secret|password|breakglass|credential rule is checked before
// infra-network's broader nas|tailscale|dns|... rule, so a credential-
// shaped id wins even though it also contains a generic infra keyword.
func TestCredentialKeywordBeatsGenericInfraKeyword(t *testing.T) {
	got, _ := suggestLayer("nas-breakglass-access-observed")
	if got != "identity-secrets" {
		t.Fatalf("suggestLayer(nas-breakglash-access-observed) = %q, want identity-secrets (breakglass beats generic nas)", got)
	}
}

// TestBackupsOffsiteBeatsSSH: restic|offsite|rclone is checked before
// identity-secrets' own ssh rule (taxonomy spec: "before ssh").
func TestBackupsOffsiteBeatsSSH(t *testing.T) {
	got, _ := suggestLayer("restic-over-ssh-mirror")
	if got != "backups-offsite" {
		t.Fatalf("suggestLayer(restic-over-ssh-mirror) = %q, want backups-offsite (restic must beat ssh)", got)
	}
}

func TestSuggestListsGuardsAndOnlyUnattachedProofs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "restoregap.local.yml")
	writeFile(t, path, `version: 2
guards:
- id: money-guard
  kind: guard
  match: {paths: ["/data/money.db"]}
  requires: {proofs: [money-db-recovery]}
proofs:
- id: money-db-recovery
  status: observed
  observed_at: "2026-01-01T00:00:00Z"
- id: orphan-ssh-proof
  status: observed
  observed_at: "2026-01-01T00:00:00Z"
`)
	suggestions, err := Suggest([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range suggestions {
		ids = append(ids, string(s.Kind)+":"+s.ID)
	}
	joined := strings.Join(ids, ",")
	if !strings.Contains(joined, "guard:money-guard") {
		t.Errorf("expected money-guard in table, got %v", ids)
	}
	if strings.Contains(joined, "proof:money-db-recovery") {
		t.Errorf("money-db-recovery is attached (required by money-guard) and must NOT get its own row, got %v", ids)
	}
	if !strings.Contains(joined, "proof:orphan-ssh-proof") {
		t.Errorf("orphan-ssh-proof is unattached and must get its own row, got %v", ids)
	}
}

func TestAnyUnfiledAndApplyNeverOverridesExplicitLayer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "restoregap.local.yml")
	writeFile(t, path, `version: 2
guards:
- id: ssh-guard
  kind: lifeline
  match: {paths: ["/home/.ssh/id_ed25519"]}
  layer: data-apps
  requires: {proofs: [ssh-key-recovery]}
proofs:
- id: ssh-key-recovery
  status: observed
  observed_at: "2026-01-01T00:00:00Z"
- id: git-estate-recovery
  status: observed
  observed_at: "2026-01-01T00:00:00Z"
`)
	suggestions, err := Suggest([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if !AnyUnfiled(suggestions) {
		t.Fatal("AnyUnfiled = false, want true — git-estate-recovery has no layer yet")
	}

	applied, err := Apply(suggestions)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range applied {
		if a.ID == "ssh-guard" {
			t.Fatalf("ssh-guard already had an explicit layer (data-apps) — apply must never touch it, got %+v", a)
		}
	}
	var gitApplied bool
	for _, a := range applied {
		if a.ID == "git-estate-recovery" {
			gitApplied = true
			if a.Layer != "git-code" {
				t.Errorf("git-estate-recovery applied layer = %q, want git-code", a.Layer)
			}
		}
	}
	if !gitApplied {
		t.Fatal("git-estate-recovery was not applied")
	}

	// Re-read the file: ssh-guard's explicit layer must be byte-identical
	// (never overridden), git-estate-recovery must now carry layer: git-code,
	// and re-running Suggest must show ssh-guard's current is still data-apps.
	suggestions2, err := Suggest([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range suggestions2 {
		if s.ID == "ssh-guard" && s.Current != "data-apps" {
			t.Errorf("after apply, ssh-guard current = %q, want unchanged data-apps", s.Current)
		}
		if s.ID == "git-estate-recovery" && s.Current != "git-code" {
			t.Errorf("after apply, git-estate-recovery current = %q, want git-code", s.Current)
		}
	}
	if AnyUnfiled(suggestions2) {
		t.Error("AnyUnfiled = true after applying every unfiled entry, want false")
	}

	// A backup must exist.
	matches, _ := filepath.Glob(path + ".bak.*")
	if len(matches) == 0 {
		t.Error("expected a .bak.<timestamp> backup file, found none")
	}
}

// TestSuggestCategoryLeadingStem exercises the fixed leading-stem list
// (section B): the first stem an id has as a prefix becomes its suggested
// category.
func TestSuggestCategoryLeadingStem(t *testing.T) {
	cases := map[string]string{
		"ssh-key-recovery":                 "ssh-key",
		"ssh-key-recovery-copy-observed":   "ssh-key",
		"secret-store-recovery":            "secret-store",
		"vaultwarden-recovery":             "vaultwarden",
		"nas-breakglass-access-observed":   "nas",
		"private-app-caddy-surface":        "private-app",
		"tailnet-dns-firewall":             "tailnet",
		"os-snapshot-recovery":             "os",
		"context-plane-recovery":           "context",
		"codex-state-recovery":             "codex",
		"claude-launch-wrappers":           "claude",
		"agent-launcher-loadability":       "agent",
		"money-db-recovery":                "money",
		"obsidian-vault-recovery":          "obsidian",
		"assistant-conversations-recovery": "assistant",
		"recovery-bootstrap-usb":           "recovery-bootstrap",
		"recovery-usb-bootstrap":           "recovery-usb",
		"phone-reprovision-path":           "phone",
		"restic-repository-health":         "restic",
		"offsite-recovery":                 "offsite",
		"git-estate-recovery":              "git-estate",
	}
	for id, want := range cases {
		got, ok := suggestCategory(id)
		if !ok || got != want {
			t.Errorf("suggestCategory(%q) = (%q, %v), want (%q, true)", id, got, ok, want)
		}
	}
	if _, ok := suggestCategory("totally-unrelated-id"); ok {
		t.Error("suggestCategory(totally-unrelated-id) matched, want no match")
	}
}

// TestSuggestGuardLayerCrossCuttingWhenRequiredProofsSpanLayers: a guard
// requiring proofs whose own-classified layers span two or more distinct
// layers is suggested cross-cutting rather than an arbitrary keyword-based
// pick.
func TestSuggestGuardLayerCrossCuttingWhenRequiredProofsSpanLayers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "restoregap.local.yml")
	writeFile(t, path, `version: 2
guards:
- id: contract-graphics-boot-test
  kind: guard
  match: {paths: ["/dev/dri"]}
  requires: {proofs: [ssh-key-recovery, restic-repository-health]}
proofs:
- id: ssh-key-recovery
  status: observed
  observed_at: "2026-01-01T00:00:00Z"
- id: restic-repository-health
  status: observed
  observed_at: "2026-01-01T00:00:00Z"
`)
	suggestions, err := Suggest([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range suggestions {
		if s.ID != "contract-graphics-boot-test" {
			continue
		}
		if s.Suggested != "cross-cutting" {
			t.Errorf("Suggested = %q, want cross-cutting, got %+v", s.Suggested, s)
		}
		return
	}
	t.Fatal("contract-graphics-boot-test not found in suggestions")
}

// TestApplyWritesCategoryWithoutOverridingExplicit mirrors
// TestAnyUnfiledAndApplyNeverOverridesExplicitLayer for the category axis:
// Apply fills a missing category but never touches one already declared.
func TestApplyWritesCategoryWithoutOverridingExplicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "restoregap.local.yml")
	writeFile(t, path, `version: 2
proofs:
- id: ssh-key-recovery
  status: observed
  observed_at: "2026-01-01T00:00:00Z"
  category: hand-picked
- id: git-estate-recovery
  status: observed
  observed_at: "2026-01-01T00:00:00Z"
`)
	suggestions, err := Suggest([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := Apply(suggestions)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Applied{}
	for _, a := range applied {
		byID[a.ID] = a
	}
	if a, ok := byID["ssh-key-recovery"]; ok && a.Category != "" {
		t.Errorf("ssh-key-recovery already had an explicit category — apply must never touch it, got %+v", a)
	}
	git, ok := byID["git-estate-recovery"]
	if !ok || git.Category != "git-estate" {
		t.Errorf("git-estate-recovery category = %+v, want git-estate applied", git)
	}

	suggestions2, err := Suggest([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range suggestions2 {
		if s.ID == "ssh-key-recovery" && s.CurrentCategory != "hand-picked" {
			t.Errorf("ssh-key-recovery current category = %q, want unchanged hand-picked", s.CurrentCategory)
		}
		if s.ID == "git-estate-recovery" && s.CurrentCategory != "git-estate" {
			t.Errorf("git-estate-recovery current category = %q, want git-estate", s.CurrentCategory)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
