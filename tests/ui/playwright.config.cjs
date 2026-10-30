// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol
const path = require('node:path');
const { createRequire } = require('node:module');
const fromKit = createRequire(path.join(process.env.HOMELAB_UI_ROOT, 'package.json'));
const { defineConfig } = fromKit('@playwright/test');
module.exports = defineConfig({
  testDir: __dirname,
  testMatch: '*.spec.cjs',
  workers: 1,
  retries: 0,
  forbidOnly: true,
  outputDir: path.join(process.env.UI_KIT_RESULTS_DIR, 'runs'),
  reporter: [['line'], ['json', { outputFile: path.join(process.env.UI_KIT_RESULTS_DIR, 'results.json') }]],
  use: {
    baseURL: process.env.RESTOREGAP_UI_URL,
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE } : {},
  },
  projects: [320, 390, 430, 1440].map(width => ({ name: `${width}px`, use: { viewport: { width, height: width === 1440 ? 1000 : 844 } } })),
});
