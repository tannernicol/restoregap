// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/tannernicol/restoregap/ui"
)

// KVRow is one row of a key-value section on an artifact page. Value is
// escaped by the template; ValueHTML (when set) renders as-is and must only
// ever be built from explicitly escaped parts (see vendorlimits citations).
type KVRow struct {
	Key       string
	Value     string
	ValueHTML template.HTML
}

// KVSection is a titled key-value block (framework evidence, status
// overview, …) rendered through the shared page shell.
type KVSection struct {
	Title string
	Note  string
	Rows  []KVRow
}

type htmlPage struct {
	Title      string
	ThemeBoot  template.JS
	CSS        template.CSS
	JS         template.JS
	Subtitle   string
	Verdict    string
	Summary    string
	Operation  string
	Proposed   []ProposedChange
	NextSteps  []string
	Findings   []htmlFinding
	NoFindings string
	Sections   []KVSection
	FooterNote string
}

type htmlFinding struct {
	Finding
	Headline string
}

// pageTemplate is THE shell: every restoregap HTML artifact renders through
// it, so no surface can ship outside the design system.
var pageTemplate = template.Must(template.New("page").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<script>{{.ThemeBoot}}</script>
<style>{{.CSS}}</style>
<script type="module">{{.JS}}</script>
</head>
<body>
<div class="rg-shell">
  <header class="rg-topbar">
    <span class="rg-brand">restore<b>gap</b></span>
    <span class="rg-meta">{{.Subtitle}}</span>
    <span class="rg-spacer"></span>
    <button class="rg-theme-toggle" data-rg-theme-toggle>theme</button>
  </header>

  {{if .Verdict}}
  <section class="rg-banner" data-verdict="{{.Verdict}}">
    <span class="rg-verdict">{{.Verdict | printf "%s" | upper}}</span>
    <span>{{.Summary}}</span>
    {{range .NextSteps}}<span class="rg-next"><b>To proceed:</b> {{.}}</span>{{end}}
  </section>

  {{if .Operation}}
  <section class="rg-decision" aria-labelledby="decision-title">
    <h2 id="decision-title">Decision: {{.Verdict | upper}}</h2>
    <p>Restore Gap did not execute the change.</p>
    <h3>Proposed change</h3>
    {{if .Proposed}}<ul>{{range .Proposed}}<li><code>{{.Action}}{{if .Command}} · command: {{.Command}}{{end}}{{if .Packages}} · packages: {{range $i, $p := .Packages}}{{if $i}}, {{end}}{{$p}}{{end}}{{end}}{{if .TargetPaths}} · from: {{range $i, $p := .Paths}}{{if $i}}, {{end}}{{$p}}{{end}} · to: {{range $i, $p := .TargetPaths}}{{if $i}}, {{end}}{{$p}}{{end}}{{else if .Paths}} · paths: {{range $i, $p := .Paths}}{{if $i}}, {{end}}{{$p}}{{end}}{{end}}{{if .Description}} — {{.Description}}{{end}}</code></li>{{end}}</ul>{{else}}<p>Not recorded in this report.</p>{{end}}
  </section>
  {{end}}
  {{end}}

  {{if .Findings}}
  <div data-rg-tableset>
    <input class="rg-filter" type="search" placeholder="Filter findings…" aria-label="Filter findings">
    <div class="rg-tablewrap">
      <table class="rg-table">
        <thead><tr>
          <th data-sortable>Verdict</th><th data-sortable>Risk class</th>
          <th data-sortable>Proof</th><th data-sortable>Guard</th><th data-sortable>Resource</th>
        </tr></thead>
        <tbody>
        {{range .Findings}}
          <tr>
            <td><span class="rg-chip" data-verdict="{{.Verdict}}">{{.Verdict | upper}}</span></td>
            <td>{{.RiskClass}}</td><td>{{.ProofStatus}}</td>
            <td>{{.GuardID}}</td><td><code>{{.Resource}}</code></td>
          </tr>
        {{end}}
        </tbody>
      </table>
    </div>
  </div>
  {{range .Findings}}
  <details class="rg-fold">
    <summary>{{.Headline}}</summary>
    <div class="rg-fold-body">
      <dl class="rg-kv">
        <dt>Why</dt><dd>{{.Title}}</dd>
        <dt>Proof state</dt><dd>{{.Proof}}</dd>
        <dt>Required next step</dt><dd>{{.RequiredNextStep}}</dd>
        <dt>Actions</dt><dd>{{range .Actions}}<code>{{.}}</code> {{end}}</dd>
        <dt>Guard</dt><dd>{{.GuardID}}</dd>
        <dt>Finding ID</dt><dd>{{.ID}}</dd>
      </dl>
    </div>
  </details>
  {{end}}
  {{else if .NoFindings}}
  <div class="rg-empty">{{.NoFindings}}</div>
  {{end}}

  {{range .Sections}}
  <h2>{{.Title}}</h2>
  {{if .Note}}<p style="color:var(--rg-text-muted);font-size:var(--rg-text-sm)">{{.Note}}</p>{{end}}
  <dl class="rg-kv">
    {{range .Rows}}<dt>{{.Key}}</dt><dd>{{if .ValueHTML}}{{.ValueHTML}}{{else}}{{.Value}}{{end}}</dd>{{end}}
  </dl>
  {{end}}

  <footer class="rg-footer">{{.FooterNote}}</footer>
</div>
</body>
</html>
`))

// HTML renders the report as a self-contained artifact page: design system
// inlined, no external requests, readable offline and with JS stripped.
func (r Report) HTML() ([]byte, error) {

	var next []string
	for _, f := range r.Findings {
		if f.Verdict == "block" && f.RequiredNextStep != "" {
			next = append(next, f.RequiredNextStep)
			break // banner carries the first blocking step; the rest are in folds
		}
	}

	blocks, warns := 0, 0
	for _, f := range r.Findings {
		switch f.Verdict {
		case "block":
			blocks++
		case "warn":
			warns++
		}
	}
	summary := fmt.Sprintf("%d finding(s) block · %d warning(s) · evaluated %s",
		blocks, warns, r.EvaluatedAt.Format("2006-01-02T15:04:05Z"))
	if r.Actor != "" {
		summary += " · actor " + r.Actor
	}

	var sections []KVSection
	htmlFindings := make([]htmlFinding, 0, len(r.Findings))
	for _, finding := range r.Findings {
		htmlFindings = append(htmlFindings, htmlFinding{Finding: finding, Headline: findingHeadline(finding)})
	}
	page := htmlPage{
		Title:      "restoregap preflight — " + strings.ToUpper(r.Verdict),
		ThemeBoot:  template.JS(ui.ThemeBoot),
		CSS:        template.CSS(ui.CSS),
		JS:         template.JS(ui.JS),
		Subtitle:   "Change preflight report",
		Verdict:    r.Verdict,
		Summary:    summary,
		Operation:  r.Operation,
		Proposed:   r.Proposed,
		NextSteps:  next,
		Findings:   htmlFindings,
		NoFindings: "No findings — every declared guard has current proof.",
		Sections:   sections,
		FooterNote: "Generated by restoregap · self-contained evidence artifact",
	}
	return renderPage(page)
}

// renderPage runs the shared shell template — the single exit for every
// restoregap HTML artifact.
func renderPage(page htmlPage) ([]byte, error) {
	var buf bytes.Buffer
	if err := pageTemplate.ExecuteTemplate(&buf, "page", page); err != nil {
		return nil, fmt.Errorf("report: render html: %w", err)
	}
	return buf.Bytes(), nil
}

// StatusHTML renders a status overview page through the shared shell.
func StatusHTML(verdict, summary string, sections []KVSection) ([]byte, error) {
	return renderPage(htmlPage{
		Title:      "restoregap status",
		ThemeBoot:  template.JS(ui.ThemeBoot),
		CSS:        template.CSS(ui.CSS),
		JS:         template.JS(ui.JS),
		Subtitle:   "Recovery-chain status",
		Verdict:    verdict,
		Summary:    summary,
		Sections:   sections,
		FooterNote: "Generated by restoregap · self-contained evidence artifact",
	})
}
