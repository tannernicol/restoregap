// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Post-build verification: the dist contract internal/report embeds.
import { readFileSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fail = (msg) => {
  console.error("ui check FAIL:", msg);
  process.exit(1);
};

const artifacts = {
  "dist/restoregap.css": 60_000,
  "dist/restoregap.js": 15_000,
  "dist/restoregap-graph.js": 60_000,
};

let total = 0;
for (const [rel, budget] of Object.entries(artifacts)) {
  let size;
  try {
    size = statSync(resolve(root, rel)).size;
  } catch {
    fail(`${rel} missing — run npm run build`);
  }
  if (size > budget) fail(`${rel} is ${size}B, over its ${budget}B budget`);
  total += size;
  console.log(`ok ${rel} ${size}B`);
}
console.log(`ok total ${total}B`);

const gallery = readFileSync(resolve(root, "gallery.html"), "utf8");
for (const ref of ["dist/restoregap.css", "dist/restoregap.js"]) {
  if (!gallery.includes(ref)) fail(`gallery.html does not reference ${ref}`);
}
for (const cls of ["rg-banner", "rg-table", "rg-chip", "rg-fold", "rg-kv", "rg-cards", "rg-empty", "rg-theme-toggle"]) {
  if (!gallery.includes(cls)) fail(`gallery.html missing component ${cls}`);
}
const css = readFileSync(resolve(root, "dist/restoregap.css"), "utf8");
for (const needle of ["--rg-bg", "data-verdict", "prefers-reduced-motion"]) {
  if (!css.includes(needle)) fail(`restoregap.css missing ${needle}`);
}
// Calm contract: no keyframe animations may enter the bundle, and no
// transition may exceed 150ms.
if (css.includes("@keyframes")) fail("restoregap.css contains @keyframes — calm contract violation");
const slow = css.match(/transition[^;]*?(\d{3,})ms/g)?.filter((m) => Number(m.match(/(\d+)ms/)[1]) > 150);
if (slow?.length) fail(`transitions over 150ms: ${slow.join(", ")}`);

console.log("ui check PASS");
