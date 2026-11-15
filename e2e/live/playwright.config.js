const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
    testDir: './tests',
    // Exchange is slow, and one sign-in goes through three hosts.
    timeout: 240_000,
    expect: { timeout: 30_000 },
    // One Exchange VM and one rate limit for each client address: no parallel runs.
    workers: 1,
    fullyParallel: false,
    retries: 0,
    reporter: [['list'], ['html', { outputFolder: 'report', open: 'never' }]],
    use: {
        // every host in the lab has a self-signed certificate
        ignoreHTTPSErrors: true,
        screenshot: 'only-on-failure',
        trace: 'retain-on-failure',
        actionTimeout: 30_000,
        navigationTimeout: 90_000,
    },
    projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
