// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package rules

import (
	"fmt"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/engine"
	"github.com/tannernicol/restoregap/internal/globmatch"
	"github.com/tannernicol/restoregap/internal/intent"
)

// riskyPackagePatterns are package classes whose updates can sever recovery
// access (graphics/boot/kernel/network/remote-access stacks). Mirrors the
// Python heuristic warn on update intents no declared guard covers.
var riskyPackagePatterns = []string{
	"nvidia*", "akmod*", "kmod-nvidia*", "kernel*", "grub*", "shim*",
	"dracut*", "systemd*", "openssh*", "tailscale*", "wireguard*",
	"cloudflared*", "NetworkManager*", "caddy*", "nginx*", "traefik*",
	"mesa*", "xorg*", "wayland*", "gdm*", "sddm*",
}

// sensitivePathPatterns are file paths whose modification is recovery-relevant
// even when the caller declared no guard for them.
var sensitivePathPatterns = []string{
	"**/Caddyfile", "**/Caddyfile.*", "**/sshd_config", "**/sshd_config.d/**",
	"/etc/systemd/**", "**/.config/systemd/**", "/etc/NetworkManager/**",
	"/etc/resolv.conf", "/etc/fstab", "/boot/**", "/etc/crypttab",
	"**/authelia/**", "**/acme.json",
}

// HeuristicRule is the built-in advisory layer: when NO declared guard matched
// a change intent, it warns on changes that look recovery-relevant (risky
// package classes, sensitive config paths, whole-system updates) instead of
// passing silently. It never blocks — declared guards own blocking — so an
// explicit context can only tighten, not loosen, what heuristics report.
type HeuristicRule struct{}

// Match reports which heuristic concerns apply to the given change intent.
func (HeuristicRule) Match(ci intent.ChangeIntent, _ contextspec.Context) []MatchResult {
	if reason, resource, ok := heuristicConcern(ci); ok {
		return []MatchResult{{
			GuardID:     "heuristic/" + reason,
			Kind:        contextspec.GuardKindGuard,
			Resource:    resource,
			Actions:     []string{string(ci.Action)},
			Enforcement: contextspec.EnforcementWarn,
		}}
	}
	return nil
}

func heuristicConcern(ci intent.ChangeIntent) (reason, resource string, ok bool) {
	for _, pkg := range ci.Packages {
		if globmatch.MatchAny(riskyPackagePatterns, pkg) {
			return "risky-package-update", pkg, true
		}
	}
	if pathHit, found := firstMatch(sensitivePathPatterns, ci.AllPaths(), globmatch.MatchPathAny); found {
		return "sensitive-path-change", pathHit, true
	}
	if ci.Action == intent.ActionSystemUpdate {
		return "whole-system-update", primaryResource(ci), true
	}
	return "", "", false
}

// heuristicFinding renders a heuristic match as a warn finding directly: it
// has no proof vocabulary to check, and its risk is a proof gap by definition.
func heuristicFinding(m MatchResult) engine.Finding {
	return engine.Finding{
		ID:          findingID(m),
		GuardID:     m.GuardID,
		Kind:        string(m.Kind),
		Resource:    m.Resource,
		Actions:     m.Actions,
		Verdict:     engine.VerdictWarn,
		RiskClass:   engine.RiskRecoveryProofGap,
		ProofStatus: engine.ProofUnknown,
		Title:       fmt.Sprintf("recovery-relevant change to %q has no declared guard", m.Resource),
		Proof:       "no declared guard covers this change; restoregap cannot check recovery proof for it",
		RequiredNextStep: fmt.Sprintf(
			"Declare a guard for %q in restoregap.local.yml (with proofs/facts it can check), or record an owner override.",
			m.Resource),
	}
}
