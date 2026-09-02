// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
)

// buildFleetFilterCSS extends buildFilterCSS (taxonomy_html.go) with one
// more `:has()` rule per host chip — fleet.html's one filter axis the
// single-host dashboard has no need for. Reusing buildFilterCSS for the
// other four axes keeps the generated selector shape (and its safety
// argument: every id is either a fixed vocabulary word or slug()-escaped)
// identical between the two pages rather than re-implemented a second time.
func buildFleetFilterCSS(layerChips, stateChips, envChips, systemChips, hostChips []FilterChip) template.CSS {
	var b strings.Builder
	b.WriteString(string(buildFilterCSS(layerChips, stateChips, envChips, systemChips)))
	for _, c := range hostChips {
		fmt.Fprintf(&b, `body:has(#f-host-%s:not(:checked)) [data-hostslug="%s"]{display:none}`+"\n", c.ID, c.ID)
	}
	return template.CSS(b.String())
}

// RenderHTML renders fleet.html: a self-contained, forced-dark page reusing
// status.html's own CSS (statusCSS) and class names — fleetExtraCSS only
// overrides the color tokens to force dark (statusCSS itself only goes dark
// under prefers-color-scheme) and adds the handful of classes the fleet
// shape needs (a host column, the bundle list) that the single-host page
// has no equivalent for.
func (f Fleet) RenderHTML() ([]byte, error) {
	data := buildFleetPageData(f)
	var buf bytes.Buffer
	if err := fleetPageTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("bundle merge: render fleet.html: %w", err)
	}
	return buf.Bytes(), nil
}

// fleetExtraCSS forces the dark palette (statusCSS's :root only goes dark
// under @media prefers-color-scheme; a later same-specificity :root rule
// wins, so this unconditionally overrides it) and adds the small number of
// classes fleet.html needs beyond the taxonomy section it otherwise reuses
// verbatim: a per-row host column and a "bundles merged" summary list.
const fleetExtraCSS = `
:root {
  --surface: #17181b; --surface-2: #1f2024; --text-1: #f5f5f2; --text-2: #a9a9a2;
  --line: #33343a; --accent: #4c93e8; --aqua: #22b483;
  --good: #3fcf5a; --warning: #f5b342; --serious: #ef8a63; --critical: #f0544f;
}
.rgs-taxhost { color: var(--text-2); font-size: 0.78rem; min-width: 6rem; }
.rgs-bundles { margin: 1rem 0; padding-top: 1rem; border-top: 1px solid var(--line); }
.rgs-bundles summary { cursor: pointer; color: var(--text-2); font-size: 0.85rem; list-style: none; }
.rgs-bundles summary::-webkit-details-marker { display: none; }
.rgs-bundles ul { margin: 0.6rem 0 0; padding-left: 1.2rem; font-size: 0.82rem; color: var(--text-2); }
.rgs-bundles code { color: var(--text-1); }
`

// fleetPageTemplate is fleet.html's whole page: statusCSS + fleetExtraCSS
// for styling, then a header, an optional conflict banner, the bundles-
// merged list, the env×system roll-up, and the layer→category→proof tree
// with its five-plus-host chip filter bar — the same zero-JavaScript
// `:has()` mechanism status.html's taxonomy section uses.
var fleetPageTemplate = template.Must(template.New("fleet").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>restoregap fleet</title>
<style>` + statusCSS + fleetExtraCSS + `</style>
</head>
<body>
<div class="rgs-shell">
  <header class="rgs-header">
    <span class="rgs-wordmark">restore<b>gap</b></span>
    <span class="rgs-tagline">Fleet recovery status</span>
    <span class="rgs-spacer"></span>
    <span class="rgs-meta">generated {{.GeneratedAt}} · {{len .Bundles}} bundle(s)</span>
  </header>

  {{- if .Conflicts}}
  <section class="rgs-gap" data-status="warning">
    <span aria-hidden="true">⚠</span>
    <span>{{len .Conflicts}} merge conflict(s) — later generated_at won</span>
  </section>
  <details class="rgs-bundles">
    <summary>conflict detail</summary>
    <ul>
      {{- range .Conflicts}}
      <li>{{.}}</li>
      {{- end}}
    </ul>
  </details>
  {{- end}}

  <details class="rgs-bundles">
    <summary>{{len .Bundles}} bundle(s) merged</summary>
    <ul>
      {{- range .Bundles}}
      <li><code>{{.Host}}</code> · epoch {{.Epoch}} · generated {{.GeneratedAt}} · {{.Path}}</li>
      {{- end}}
    </ul>
  </details>

  {{- if .HasAny}}
  <section class="rgs-tax">
    <style>{{.FilterCSS}}</style>
    {{- if .Rollup}}
    <h2>Environment &times; system roll-up</h2>
    <div class="rgs-rollup-wrap">
      <table class="rgs-rollup">
        <thead><tr><th>Environment</th><th>System</th><th>Restored</th><th>Observed</th><th>Accepted</th><th>Unreviewed</th><th>Expired/lapsed</th></tr></thead>
        <tbody>
          {{- range .Rollup}}
          <tr><td>{{.Env}}</td><td>{{.System}}</td><td>{{.Restored}}</td><td>{{.Observed}}</td><td>{{.Accepted}}</td><td>{{.Unreviewed}}</td><td>{{.Expired}}</td></tr>
          {{- end}}
        </tbody>
      </table>
    </div>
    {{- end}}

    <h2>Recovery taxonomy — layer &rarr; category &rarr; proof</h2>
    <div class="rgs-filterbar">
      {{- range .LayerChips}}
      <label class="rgs-chip-toggle"><input type="checkbox" id="f-layer-{{.ID}}" checked> {{.Label}}</label>
      {{- end}}
      {{- range .StateChips}}
      <label class="rgs-chip-toggle"><input type="checkbox" id="f-state-{{.ID}}" checked> {{.Label}}</label>
      {{- end}}
      {{- range .EnvChips}}
      <label class="rgs-chip-toggle"><input type="checkbox" id="f-env-{{.ID}}" checked> env: {{.Label}}</label>
      {{- end}}
      {{- range .SystemChips}}
      <label class="rgs-chip-toggle"><input type="checkbox" id="f-system-{{.ID}}" checked> system: {{.Label}}</label>
      {{- end}}
      {{- range .HostChips}}
      <label class="rgs-chip-toggle"><input type="checkbox" id="f-host-{{.ID}}" checked> host: {{.Label}}</label>
      {{- end}}
    </div>

    {{- range .Layers}}
    <details class="rgs-taxlayer" data-layer="{{.LayerID}}"{{if .Open}} open{{end}}>
      <summary>{{.Header}}</summary>
      {{- $showCat := .ShowCategoryHeaders}}
      {{- range .Categories}}
      {{- if $showCat}}
      <h4 class="rgs-taxcat">{{.Category}}</h4>
      {{- end}}
      {{- range .Rows}}
      <div class="rgs-taxrow" data-state="{{.State}}" data-bucket="{{.Bucket}}" data-envslug="{{.EnvSlug}}" data-systemslug="{{.SystemSlug}}" data-hostslug="{{.HostSlug}}">
        <span class="rgs-taxproof"><code>{{.Proof}}</code><span class="rgs-taxsub">{{.Artifact}}</span></span>
        <span class="rgs-taxhost">{{.Host}}</span>
        <span class="rgs-taxstate" data-bucket="{{.Bucket}}">{{.State}}</span>
        <span class="rgs-taxlevel">{{.Level}}</span>
        <span class="rgs-taxwhy">{{.Why}}</span>
      </div>
      {{- end}}
      {{- end}}
    </details>
    {{- end}}
  </section>
  {{- else}}
  <p class="rgs-muted">No proofs in this fleet.</p>
  {{- end}}
</div>
</body>
</html>
`))
