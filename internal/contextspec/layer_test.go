// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package contextspec

import "testing"

func TestValidLayer(t *testing.T) {
	for _, l := range []string{LayerRecoveryKit, LayerIdentitySecrets, LayerSystemOS, LayerInfraNetwork,
		LayerBackupsOffsite, LayerGitCode, LayerDataApps, LayerAgentsContext} {
		if !ValidLayer(l) {
			t.Errorf("ValidLayer(%q) = false, want true", l)
		}
	}
	if ValidLayer(LayerUnfiled) {
		t.Error("ValidLayer(unfiled) = true, want false — unfiled is computed only, never declarable")
	}
	if ValidLayer("bogus") {
		t.Error("ValidLayer(bogus) = true, want false")
	}
}

func TestValidGuardLayerAcceptsCrossCuttingProofDoesNot(t *testing.T) {
	if !ValidGuardLayer(LayerCrossCutting) {
		t.Error("ValidGuardLayer(cross-cutting) = false, want true — a guard may declare it")
	}
	if ValidLayer(LayerCrossCutting) {
		t.Error("ValidLayer(cross-cutting) = true, want false — a proof may not declare it")
	}
	for _, l := range LayerOrder {
		if l == LayerUnfiled {
			continue
		}
		if !ValidGuardLayer(l) {
			t.Errorf("ValidGuardLayer(%q) = false, want true", l)
		}
	}
}

func TestKeywordLayerMatchesAndOrdering(t *testing.T) {
	cases := []struct {
		search string
		layer  string
	}{
		{"vaultwarden-recovery", LayerIdentitySecrets},
		{"obsidian-vault-recovery", ""}, // generic "vault" must NOT match identity-secrets
		{"restic-latest-snapshot-observed", LayerBackupsOffsite},
		{"nas-breakglass-access-observed", LayerIdentitySecrets}, // credential keyword beats generic "nas"
		{"nas-outofband-tailscale", LayerInfraNetwork},
		{"recovery-usb-bootstrap", LayerRecoveryKit},
		{"os-snapshot-recovery", LayerSystemOS},
		{"git-estate-recovery", LayerGitCode},
		{"context-plane-recovery", LayerAgentsContext},
		{"totally-unrelated-id", ""},
	}
	for _, c := range cases {
		layer, _, matched := KeywordLayer(c.search)
		if c.layer == "" {
			if matched {
				t.Errorf("KeywordLayer(%q) matched %q, want no match", c.search, layer)
			}
			continue
		}
		if !matched || layer != c.layer {
			t.Errorf("KeywordLayer(%q) = (%q, matched=%v), want %q", c.search, layer, matched, c.layer)
		}
	}
}

func TestEffectiveProofLayerOwnKeywordMatchBeatsGuardInheritance(t *testing.T) {
	ctx := Context{
		Guards: []Guard{{ID: "g1", Requires: Requirement{Proofs: []string{"ssh-key-recovery"}}, Layer: LayerDataApps}},
	}
	res := EffectiveProofLayer(ctx, Proof{ID: "ssh-key-recovery"})
	if res.Layer != LayerIdentitySecrets {
		t.Errorf("Layer = %q, want %q (the proof's own keyword match must beat the requiring guard's layer)", res.Layer, LayerIdentitySecrets)
	}
	if res.Conflict {
		t.Error("Conflict = true, want false — a proof with its own classification never reaches the guard tie-break")
	}
}

func TestEffectiveProofLayerCrossCuttingGuardNeverPropagates(t *testing.T) {
	ctx := Context{
		Guards: []Guard{{ID: "boot-test-guard", Requires: Requirement{Proofs: []string{"orphan-widget"}}, Layer: LayerCrossCutting}},
	}
	res := EffectiveProofLayer(ctx, Proof{ID: "orphan-widget"})
	if res.Layer != LayerUnfiled {
		t.Errorf("Layer = %q, want %q — a cross-cutting guard must never propagate its layer", res.Layer, LayerUnfiled)
	}
}

func TestLayerRankOrder(t *testing.T) {
	if LayerRank(LayerRecoveryKit) >= LayerRank(LayerIdentitySecrets) {
		t.Error("recovery-kit must rank before identity-secrets")
	}
	if LayerRank(LayerDataApps) >= LayerRank(LayerAgentsContext) {
		t.Error("data-apps must rank before agents-context")
	}
	if LayerRank(LayerUnfiled) != len(LayerOrder)-1 {
		t.Error("unfiled must rank last")
	}
	if LayerRank("bogus") != LayerRank(LayerUnfiled) {
		t.Error("an unrecognized layer must rank the same as unfiled")
	}
}

func TestEffectiveProofLayerOwnLayerWins(t *testing.T) {
	ctx := Context{
		Guards: []Guard{{ID: "g1", Requires: Requirement{Proofs: []string{"p1"}}, Layer: LayerDataApps}},
	}
	p := Proof{ID: "p1", Layer: LayerIdentitySecrets}
	res := EffectiveProofLayer(ctx, p)
	if res.Layer != LayerIdentitySecrets {
		t.Errorf("Layer = %q, want %q (proof's own layer must win over any guard)", res.Layer, LayerIdentitySecrets)
	}
	if res.Conflict {
		t.Error("Conflict = true, want false — an explicit own layer never conflicts")
	}
}

func TestEffectiveProofLayerInheritsFromSingleGuard(t *testing.T) {
	ctx := Context{
		Guards: []Guard{{ID: "g1", Requires: Requirement{Proofs: []string{"p1"}}, Layer: LayerBackupsOffsite, Category: "restic"}},
	}
	p := Proof{ID: "p1"}
	res := EffectiveProofLayer(ctx, p)
	if res.Layer != LayerBackupsOffsite {
		t.Errorf("Layer = %q, want %q", res.Layer, LayerBackupsOffsite)
	}
	if res.Category != "restic" {
		t.Errorf("Category = %q, want %q (inherited from the requiring guard)", res.Category, "restic")
	}
}

func TestEffectiveProofLayerUnfiled(t *testing.T) {
	res := EffectiveProofLayer(Context{}, Proof{ID: "orphan"})
	if res.Layer != LayerUnfiled {
		t.Errorf("Layer = %q, want %q (no own layer, no requiring guard)", res.Layer, LayerUnfiled)
	}
}

func TestEffectiveProofLayerConflictEarliestWins(t *testing.T) {
	ctx := Context{
		Guards: []Guard{
			{ID: "gA", Requires: Requirement{Proofs: []string{"p1"}}, Layer: LayerDataApps},
			{ID: "gB", Requires: Requirement{Proofs: []string{"p1"}}, Layer: LayerIdentitySecrets},
		},
	}
	res := EffectiveProofLayer(ctx, Proof{ID: "p1"})
	if res.Layer != LayerIdentitySecrets {
		t.Errorf("Layer = %q, want %q (earliest in vocabulary order must win)", res.Layer, LayerIdentitySecrets)
	}
	if !res.Conflict {
		t.Error("Conflict = false, want true — two guards disagreed")
	}
	if res.ConflictDetail == "" {
		t.Error("ConflictDetail is empty, want a one-line explanation")
	}
}

func TestEffectiveProofLayerNoConflictWhenGuardsAgree(t *testing.T) {
	ctx := Context{
		Guards: []Guard{
			{ID: "gA", Requires: Requirement{Proofs: []string{"p1"}}, Layer: LayerGitCode},
			{ID: "gB", Requires: Requirement{Proofs: []string{"p1"}}, Layer: LayerGitCode},
		},
	}
	res := EffectiveProofLayer(ctx, Proof{ID: "p1"})
	if res.Conflict {
		t.Error("Conflict = true, want false — both guards agree")
	}
}

func TestMergeScopeFieldByField(t *testing.T) {
	base := Scope{Environment: "prod", System: "money", Host: "nas", Owner: "tanner", Tags: []string{"a"}}
	override := Scope{System: "obsidian"}
	got := mergeScope(base, override)
	want := Scope{Environment: "prod", System: "obsidian", Host: "nas", Owner: "tanner", Tags: []string{"a"}}
	if got.Environment != want.Environment || got.System != want.System || got.Host != want.Host || got.Owner != want.Owner {
		t.Errorf("mergeScope = %+v, want %+v", got, want)
	}
}

func TestEnvironmentOrdering(t *testing.T) {
	cases := []struct{ a, b string }{
		{"prod", "staging"},
		{"staging", "dev"},
		{"dev", "lab"},
		{"lab", ""},
		{"", "zzz-unknown"},
		{"aaa-unknown", "zzz-unknown"},
	}
	for _, c := range cases {
		if !EnvironmentLess(c.a, c.b) {
			t.Errorf("EnvironmentLess(%q, %q) = false, want true", c.a, c.b)
		}
		if EnvironmentLess(c.b, c.a) {
			t.Errorf("EnvironmentLess(%q, %q) = true, want false", c.b, c.a)
		}
	}
}
