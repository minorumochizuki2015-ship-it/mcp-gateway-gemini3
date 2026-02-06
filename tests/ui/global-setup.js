// Global setup for Playwright visual regression tests
const fs = require('fs');
const path = require('path');

async function globalSetup() {
    // Ensure baseline and artifacts directories exist
    const dirs = [
        'tests/ui/__screenshots__',
        'tests/ui/__screenshots__/dashboard',
        'tests/ui/__screenshots__/allowlist',
        'tests/ui/__screenshots__/audit_log',
        'tests/ui/__screenshots__/settings_environments',
        'tests/ui/__screenshots__/scans',
        'artifacts/ui_preview',
    ];

    dirs.forEach((dir) => {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    });

    console.log('Visual regression baseline directories created.');
}

module.exports = globalSetup;
