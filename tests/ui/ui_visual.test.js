// Visual Regression Tests using Playwright
// Smoke tests: Verify pages load correctly on desktop and mobile viewports.
// This is the foundation for visual regression testing.
// To capture baselines: npx playwright test --project=chromium ui_visual.test.js --update-snapshots
//
// Note: Full visual regression with baseline comparison is prepared but not enabled by default
// in CI to avoid blocking on first run. Enable via --update-snapshots and review diffs before merging.
const { test, expect } = require('@playwright/test');

const pages = [
    { name: 'Dashboard', path: 'dashboard.html' },
    { name: 'AllowList', path: 'allowlist.html' },
    { name: 'Audit Log', path: 'audit_log.html' },
    { name: 'Settings Environments', path: 'settings_environments.html' },
    { name: 'Scans', path: 'scans.html' },
];

// Viewport is provided by Playwright projects (desktop/mobile); tests do not override it.
test.describe('Visual Smoke Tests - Page Loading (per project viewport)', () => {
    for (const pageDef of pages) {
        test(`${pageDef.name} loads`, async ({ page }) => {
            await page.goto(pageDef.path, { waitUntil: 'load' });
            await page.waitForTimeout(300);
            await expect(page.locator('.nav')).toBeVisible();
        });
    }
});
