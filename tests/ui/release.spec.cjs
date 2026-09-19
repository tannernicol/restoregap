// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol
const path = require('node:path');
const { createRequire } = require('node:module');
const { pathToFileURL } = require('node:url');
const fromKit = createRequire(path.join(process.env.HOMELAB_UI_ROOT, 'package.json'));
const { test, expect } = fromKit('@playwright/test');
const AxeBuilder = fromKit('@axe-core/playwright').default;

test('launch has working in-page navigation, accessible content and no runtime requests', async ({ page }) => {
  const requests = [];
  page.on('request', req => requests.push(req.url()));
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Prove your recovery works');
  await expect(page.locator('script, iframe, video, img[src$=".gif"]')).toHaveCount(0);
  for (const id of ['how', 'install', 'hosted']) {
    await page.locator(`.site-nav a[href="#${id}"]`).click();
    await expect(page.locator(`#${id}`)).toBeInViewport();
  }
  expect(requests.filter(url => !url.startsWith(process.env.RESTOREGAP_UI_URL))).toEqual([]);
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(result.violations).toEqual([]);
});

test('status filters and grouping compose without moving controls or losing focus', async ({ page }) => {
  const { expectStableInteraction } = await import(pathToFileURL(path.join(process.env.HOMELAB_UI_ROOT, 'scripts/layout-stability.mjs')).href);
  const errors = [];
  page.on('pageerror', err => errors.push(err.message));
  await page.goto('/status.html');
  await expect(page.locator('script, link[rel="stylesheet"]')).toHaveCount(0);
  const decision = page.getByRole('region', { name: 'Decision ledger · latest' });
  await expect(decision).toContainText('BLOCK');
  await expect(decision).toContainText('delete_file');
  await expect(decision).toContainText('no fresh recovery proof');
  await expect(decision).toContainText('run restoregap drill');
  await expect(decision).toContainText('Restore Gap did not execute the change.');
  await expect(page.locator('#rgs-view-attention')).toBeChecked();
  const controls = page.locator('.rgs-viewswitch');
  await controls.scrollIntoViewIfNeeded();
  const action = async (id) => {
    const input = page.locator(id);
    await expectStableInteraction(page, {
      anchors: ['.rgs-viewswitch', '.rgs-estate'],
      action: () => input.click(),
      settled: () => expect(input).toBeChecked(),
    });
    await expect(input).toBeFocused();
  };
  await action('#rgs-view-all');
  await action('#rgs-view-system');
  await expect(page.locator('#rgs-view-all')).toBeChecked();
  await page.locator('[data-panel="system"] details').evaluateAll(items => items.forEach(item => item.open = true));
  await expect(page.locator('[data-panel="system"] .rgs-row:visible')).toHaveCount(2);
  await action('#rgs-view-attention');
  await expect(page.locator('#rgs-view-system')).toBeChecked();
  await expect(page.locator('[data-panel="system"] .rgs-row:visible')).toHaveCount(1);
  await action('#rgs-view-layer');
  await expect(page.locator('#rgs-view-attention')).toBeChecked();
  await expect(page.locator('[data-panel="layer"] .rgs-row:visible')).toHaveCount(1);
  expect(errors).toEqual([]);
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(result.violations).toEqual([]);
});

test('empty status remains readable with JavaScript disabled', async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  await page.goto(`${process.env.RESTOREGAP_UI_URL}/empty.html`);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Is there a way back?');
  await expect(page.locator('body')).not.toContainText('undefined');
  await context.close();
});
