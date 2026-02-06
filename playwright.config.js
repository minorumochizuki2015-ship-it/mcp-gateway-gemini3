// Playwright Visual Regression Configuration for MCP Gateway Suite UI
const { defineConfig, devices } = require('@playwright/test');

module.exports = defineConfig({
    testDir: './tests/ui',
    testMatch: '**/ui_visual.test.js',
    fullyParallel: false,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: process.env.CI ? 1 : 1,
    reporter: [
        ['list'],
        ['json', { outputFile: 'artifacts/ui_preview/playwright-results.json' }],
        ['html', { outputFolder: 'artifacts/ui_preview/playwright-report' }],
    ],
    use: {
        baseURL: 'file://' + process.cwd() + '/docs/ui_poc/',
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
    },
    projects: [
        {
            name: 'desktop',
            use: {
                ...devices['Desktop Chrome'],
                viewport: { width: 1440, height: 900 },
            },
        },
        {
            name: 'mobile',
            use: {
                ...devices['Pixel 5'],
                viewport: { width: 480, height: 800 },
            },
        },
    ],
    webServer: null, // Static HTML, no server needed
    globalSetup: require.resolve('./tests/ui/global-setup.js'),
});
