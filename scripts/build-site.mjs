// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol
// Embed the pinned shared design and approved mark. No visitor-side fetch or JS.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(resolve(root, p), 'utf8');
const version = `v${read('VERSION').trim()}`;
const css = read('ui/dist/restoregap.css');
const logo = read('site/assets/logo.svg');
let html = read('site/index.html');
html = html.replace(/\/\* shared-ui:start \*\/[\s\S]*?\/\* shared-ui:end \*\//, `/* shared-ui:start */\n${css}\n/* shared-ui:end */`);
html = html.replace(/<!-- brand:start -->[\s\S]*?<!-- brand:end -->/, `<!-- brand:start -->${logo.replace('role="img" aria-label="Restore Gap"', 'aria-hidden="true"')}<!-- brand:end -->`);
html = html.replaceAll('{{version}}', version).replace(/restoregap\/v\d+\.\d+\.\d+\/scripts/g, `restoregap/${version}/scripts`).replace(/RESTOREGAP_VERSION=v\d+\.\d+\.\d+/g, `RESTOREGAP_VERSION=${version}`).replace(/--branch v\d+\.\d+\.\d+/g, `--branch ${version}`);
const mark = logo.replace('stroke="currentColor"', 'stroke="#b9c1cc"');
const outputs = { 'site/index.html': html, 'ui/mark.svg': mark };
let stale = false;
for (const [p, expected] of Object.entries(outputs)) {
  if (process.argv.includes('--check')) { if (read(p) !== expected) { console.error(`stale generated content: ${p}`); stale = true; } }
  else writeFileSync(resolve(root, p), expected);
}
if (stale) process.exit(1);
console.log(`site assets ${process.argv.includes('--check') ? 'verified' : 'built'} (${version})`);
