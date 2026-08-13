// Package ui exposes the built design-system assets for go:embed inlining
// into self-contained artifact pages. dist/ is committed so `go build`
// never requires a Node toolchain; rebuild with `npm run build` + commit
// when src/ changes (ui/scripts/check.mjs is the gate).
package ui

import _ "embed"

// CSS is the embedded stylesheet served with the report UI.
//
//go:embed dist/restoregap.css
var CSS string

// JS is the embedded script for the report UI.
//
//go:embed dist/restoregap.js
var JS string

// GraphJS is the embedded script for the dependency-graph view.
//
//go:embed dist/restoregap-graph.js
var GraphJS string

// ThemeBoot is inlined FIRST in <head> so pages never flash the wrong
// theme. Mirrors THEME_BOOT_SNIPPET in src/index.ts.
const ThemeBoot = `(function(){try{var t=localStorage.getItem("rg-theme");if(t)document.documentElement.setAttribute("data-theme",t)}catch(e){}})()`

// Mark is the restoregap brand mark: a 32x32 stroke-drawn shield with a
// broken line across it (the "gap"). Its stroke is a fixed brand teal
// (#7fa891) baked into the source rather than currentColor or a CSS
// variable, so it renders identically in light and dark pages. It is
// decorative wherever wordmark text sits beside it — inline copies should
// carry aria-hidden="true".
//
//go:embed mark.svg
var Mark string
