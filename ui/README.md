# restoregap UI design system

One design system for every HTML artifact restoregap emits (reports, status,
evidence packets). Go inlines the built assets via `go:embed`
of `dist/`, so artifacts stay **self-contained single files** — offline,
emailable, archivable.

## Build

```
npm install
npm run build     # → dist/restoregap.css, dist/restoregap.js, dist/restoregap-graph.js
npm run check     # size budgets + gallery/component/calm-contract assertions
```

Review surface: open `gallery.html` after a build — every component with
realistic sample data.

## Contract with internal/report

- Inline `THEME_BOOT_SNIPPET` (see `src/index.ts`) as the FIRST `<script>` in
  `<head>`, then `<style>{restoregap.css}</style>`, then
  `<script type="module">{restoregap.js}</script>`.
- `restoregap-graph.js` is inlined only on graph-bearing pages (it defines
  `RestoreGapGraph.mount`, ported byte-identical from the Python scanner's
  `report/assets/recovery_graph.js` — the marketing site syncs from that file,
  so behavior changes need a coordinated sync). One deliberate CSS deviation:
  the source-indicator's infinite pulse animation was replaced with a static
  ring (calm contract); sync that change back to the site when the repos
  reconcile.
- Every page uses the shell: `.rg-topbar` → content → `.rg-footer`, and every
  report leads with `.rg-banner[data-verdict]`. Dense detail goes inside
  `.rg-fold`, never as bare walls of text.

## Rules

- **Dark-first**: dark is the default; light serves print/evidence recipients.
  Explicit `data-theme` (localStorage `rg-theme`) beats the OS preference.
- **Calm contract**: no flashing, shimmer, autoplay, or motion. The only
  transitions are color/border hovers ≤150ms; `check.mjs` enforces this and
  rejects any `@keyframes` in the bundle.
- **Tokens only**: components consume `--rg-*` custom properties from
  `src/tokens.css`; no hardcoded colors in components or page templates.
- JS is progressive enhancement — artifacts must read fine with JS stripped.
