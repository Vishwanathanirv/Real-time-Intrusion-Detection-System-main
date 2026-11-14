import { defineConfig } from "@playwright/test";

/** End-to-end checks run against the static demo build, the same thing Vercel serves. */
export default defineConfig({
  testDir: "e2e",
  timeout: 90_000,
  use: { baseURL: "http://localhost:4311" },
  webServer: { command: "npx vite preview --port 4311 --strictPort", cwd: "apps/web", url: "http://localhost:4311", reuseExistingServer: !process.env.CI },
});
