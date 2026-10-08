// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

// appCSS is everything the service adds to the design system, appended after
// status.StyleSheet(). Two jobs:
//
//  1. Re-point the status page's color aliases (--surface, --text-1, ...) at
//     the rg- tokens. The status stylesheet derives them from the dark-only
//     --ui-* palette, which would leave the fleet tree dark-on-light under the
//     light theme toggle; the rg- tokens follow data-theme.
//  2. The few layout rules the app pages need that the design system has no
//     component for (nav, forms, key/hash blocks). Tokens only, no colors, no
//     fixed widths, nothing that moves: pages must read at 320px.
const appCSS = `
:root {
  --surface: var(--rg-bg); --surface-2: var(--rg-surface); --text-1: var(--rg-text); --text-2: var(--rg-text-muted);
  --line: var(--rg-border); --accent: var(--rg-accent); --good: var(--rg-pass); --warning: var(--rg-warn);
  --serious: var(--rg-high); --critical: var(--rg-block);
}
:root[data-theme="light"] { color-scheme: light; }
body { background: var(--rg-bg); color: var(--rg-text); font-family: var(--rg-font); line-height: var(--rg-leading); }
.rg-shell { min-width: 0; }
.rg-topbar .rg-brand { color: var(--rg-text); }
.rg-kv { grid-template-columns: minmax(0, max-content) minmax(0, 1fr); }
.rg-topbar { flex-wrap: wrap; row-gap: var(--rg-sp-2); }
.cl-mark { width: 22px; height: 22px; vertical-align: -5px; margin-right: var(--rg-sp-2); }
.cl-nav { display: flex; flex-wrap: wrap; gap: var(--rg-sp-1) var(--rg-sp-3); font-size: var(--rg-text-sm); }
.cl-nav a { color: var(--rg-text-muted); padding: var(--rg-sp-1) 0; }
.cl-nav a[aria-current="page"] { color: var(--rg-text); font-weight: 600; }
.cl-inline { display: inline; margin: 0; }
.cl-link-button { background: none; border: 0; padding: var(--rg-sp-1) 0; font: inherit; color: var(--rg-text-muted); cursor: pointer; font-size: var(--rg-text-sm); }
.cl-link-button:hover { color: var(--rg-text); text-decoration: underline; }
.rg-shell p, .rg-shell li, .rg-shell dd { overflow-wrap: anywhere; }
.cl-lede { color: var(--rg-text-muted); max-width: 44rem; }
.cl-narrow { max-width: 34rem; }
.cl-stats { color: var(--rg-text-muted); font-size: var(--rg-text-sm); margin: 0 0 var(--rg-sp-4); }
.cl-flash { border: 1px solid var(--rg-border); border-left: 4px solid var(--rg-pass); border-radius: var(--rg-radius); padding: var(--rg-sp-3) var(--rg-sp-4); margin-bottom: var(--rg-sp-4); background: var(--rg-surface); }
.cl-secret { display: block; margin: var(--rg-sp-2) 0 0; font-family: var(--rg-mono); font-size: var(--rg-text-sm); white-space: normal; overflow-wrap: anywhere; user-select: all; }
.cl-hex { font-family: var(--rg-mono); font-size: var(--rg-text-sm); overflow-wrap: anywhere; word-break: break-all; }
.cl-form { display: grid; gap: var(--rg-sp-3); margin: var(--rg-sp-3) 0 var(--rg-sp-6); max-width: 34rem; }
.cl-form .ui-kit-field label { font-size: var(--rg-text-sm); color: var(--rg-text-muted); }
.cl-form .cl-hint { font-size: var(--rg-text-xs); color: var(--rg-text-faint); margin: 0; }
.cl-check { display: flex; gap: var(--rg-sp-2); align-items: center; font-size: var(--rg-text-sm); }
.ui-kit-field input, .ui-kit-field select, .ui-kit-field textarea { background: var(--rg-bg); color: var(--rg-text); border-color: var(--rg-border); }
.ui-kit-button { background: var(--rg-surface); color: var(--rg-text); border-color: var(--rg-border); }
.ui-kit-button.is-primary { background: var(--rg-surface-2); color: var(--rg-accent); border-color: var(--rg-accent); }
.ui-kit-button:disabled { opacity: .55; cursor: not-allowed; }
.cl-actions { display: flex; flex-wrap: wrap; gap: var(--rg-sp-2); align-items: center; }
.cl-row-form { display: inline; margin: 0; }
.cl-badge { display: inline-block; border: 1px solid var(--rg-border); border-radius: 999px; padding: 0 var(--rg-sp-2); font-size: var(--rg-text-xs); color: var(--rg-text-muted); white-space: nowrap; }
.cl-badge[data-kind="lapsed"], .cl-badge[data-kind="proof_regressed"], .cl-badge[data-kind="revoked"], .cl-badge[data-kind="expired"] { color: var(--rg-warn); border-color: var(--rg-warn); }
.cl-badge[data-kind="recovered"], .cl-badge[data-kind="active"] { color: var(--rg-pass); border-color: var(--rg-pass); }
.cl-state[data-bucket="attention"], .cl-state[data-bucket="unreviewed"] { color: var(--rg-warn); }
.cl-state[data-bucket="restored"] { color: var(--rg-pass); }
.cl-state[data-bucket="observed"], .cl-state[data-bucket="accepted"] { color: var(--rg-accent); }
.rg-tablewrap { margin-bottom: var(--rg-sp-4); }
.rg-table th, .rg-table td { text-align: left; vertical-align: top; }
.rg-table td.cl-wrap { min-width: 10rem; overflow-wrap: anywhere; }
.cl-plans { display: grid; gap: var(--rg-sp-3); grid-template-columns: repeat(auto-fit, minmax(min(100%, 14rem), 1fr)); margin: var(--rg-sp-3) 0 var(--rg-sp-6); }
.cl-plans .rg-card[data-current="true"] { border-color: var(--rg-accent); }
.cl-price { font-size: var(--rg-text-lg); font-weight: 650; }
.cl-section { margin-top: var(--rg-sp-8); }
.cl-section > h2:first-child { margin-top: 0; }
.cl-verify { border: 1px solid var(--rg-border); border-radius: var(--rg-radius); padding: var(--rg-sp-3); margin-bottom: var(--rg-sp-3); background: var(--rg-surface); }
.cl-verify h3 { margin: 0 0 var(--rg-sp-2); font-size: var(--rg-text-md); color: var(--rg-text); }
.rgs-tax { margin-top: var(--rg-sp-4); padding-top: var(--rg-sp-3); }
.rgs-taxrow a { color: var(--rg-accent); }
.rgs-taxlayer, .rgs-gap { min-width: 0; }
.rgs-taxhost { min-width: 0; }
.rg-code { max-width: 100%; }
@media (max-width: 480px) {
  .rg-kv { grid-template-columns: minmax(0, 1fr); }
  .rg-kv dt { margin-top: var(--rg-sp-2); }
  .rg-shell { padding-left: var(--rg-sp-3); padding-right: var(--rg-sp-3); }
  .cl-form { max-width: none; }
}
`
