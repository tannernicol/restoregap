// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package contextspec

import (
	"fmt"
	"path/filepath"
	"strings"
)

// keywordRule is one ordered keyword/prefix -> layer mapping in the
// taxonomy spec's fixed rule table (section B). Rules are tried in slice
// order; the FIRST rule whose prefix or keyword matches wins.
type keywordRule struct {
	layer    string
	prefixes []string
	keywords []string
}

// keywordRules is the taxonomy spec's exact ordered rule table, most
// specific first. This is the ONE copy: `classify`'s suggestion table and
// EffectiveProofLayer's own-classification step both read it through
// KeywordLayer, so a proof's own classification never disagrees between
// `restoregap classify` and `restoregap status`/`next`.
//
// Ordering notes (the parts not obvious from "most specific first" alone):
//   - vaultwarden is its own rule, deliberately NOT the generic substring
//     "vault" — "obsidian-vault-recovery" must fall through to the
//     data-apps default, not identity-secrets.
//   - backups-offsite (restic|offsite|rclone) is checked before identity-
//     secrets' own ssh|secret|... rule, so e.g. a restic-over-ssh id lands
//     in backups-offsite.
//   - identity-secrets' ssh|secret|password|breakglash|credential rule is
//     checked before infra-network's broader nas|tailscale|dns|... rule:
//     a credential-shaped keyword is more specific than a generic
//     infra-adjacent one, so "nas-breakglass-access" is identity-secrets,
//     not infra-network, even though it also contains "nas".
var keywordRules = []keywordRule{
	{layer: LayerIdentitySecrets, keywords: []string{"vaultwarden"}},
	{layer: LayerBackupsOffsite, keywords: []string{"restic", "offsite", "rclone"}},
	{layer: LayerIdentitySecrets, keywords: []string{"ssh", "secret", "password", "breakglass", "credential"}},
	{layer: LayerInfraNetwork, keywords: []string{
		"nas", "outofband", "tailscale", "tailnet", "dns", "caddy", "route", "firewall",
		"private-app", "private-access", "homelab-spine",
	}},
	{layer: LayerRecoveryKit, keywords: []string{
		"bootstrap", "recovery-usb", "recovery-kit", "phone-reprov", "restoregap-policy", "policy-backup",
	}},
	{layer: LayerSystemOS, prefixes: []string{"os-"}, keywords: []string{
		"boot", "kernel", "fstab", "off-machine-os", "crash", "kdump", "mount", "storage",
	}},
	{layer: LayerGitCode, keywords: []string{"git", "gitea", "repo"}},
	{layer: LayerAgentsContext, keywords: []string{"context", "codex", "claude", "agent", "launcher", "assistant"}},
}

// KeywordLayer runs the fixed rule table over search (already the id +
// artifact/evidence surface for the entry being classified) and returns
// the first matching layer plus a human reason. matched is false when
// nothing in the table fired — the caller decides what a non-match means
// (classify's suggestion table falls back to a data-apps default;
// EffectiveProofLayer instead falls through to guard inheritance, then
// LayerUnfiled, so an unmatched proof with no requiring guard still lands
// in the computed-only unfiled bucket rather than being force-fed
// data-apps).
func KeywordLayer(search string) (layer, reason string, matched bool) {
	s := strings.ToLower(search)
	for _, r := range keywordRules {
		for _, p := range r.prefixes {
			if strings.HasPrefix(s, p) {
				return r.layer, fmt.Sprintf("prefix %q → %s", p, r.layer), true
			}
		}
		for _, kw := range r.keywords {
			if strings.Contains(s, kw) {
				return r.layer, fmt.Sprintf("keyword %q → %s", kw, r.layer), true
			}
		}
	}
	return "", "", false
}

// ProofKeywordSearchText is a proof's classify surface, literally "id +
// artifact/evidence path": the proof's own id, its drill's declared
// artifact (if any), and the BASENAME of its evidence_url (a full evidence
// URL/path routinely carries hostnames or directory segments that are not
// this proof's own vocabulary — only the filename is).
func ProofKeywordSearchText(ctx Context, p Proof) string {
	artifact := ""
	for _, d := range ctx.Drills {
		if d.Proof == p.ID {
			artifact = d.Artifact
			break
		}
	}
	evidence := ""
	if p.EvidenceURL != "" {
		evidence = filepath.Base(p.EvidenceURL)
	}
	return strings.Join([]string{p.ID, artifact, evidence}, " ")
}

// GuardKeywordSearchText is a guard's classify surface: its id alone (see
// internal/classify's guardSearchText doc comment for why a guard's
// Match/RecoveryCopy fields are deliberately excluded).
func GuardKeywordSearchText(g Guard) string {
	return g.ID
}
