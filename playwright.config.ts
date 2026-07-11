import { defineConfig, devices } from "@playwright/test";

declare const process: {
  env: Record<string, string | undefined>;
};

/**
 * E2E accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Run `npm run build` first (the test:a11y script does).
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "list" : [["list"], ["html", { open: "never" }]],
  webServer: {
    command: "npm run preview -- --port 4215 --strictPort",
    url: "http://localhost:4215/crypto-lab-iron-letter/",
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
  use: {
    baseURL: "http://localhost:4215/crypto-lab-iron-letter/",
    colorScheme: "dark",
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
