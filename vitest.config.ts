import path from "node:path";
import { defineConfig } from "vitest/config";
export default defineConfig({
  resolve: { alias: { "@packeteye/core": path.resolve(__dirname, "packages/core/src/index.ts") } },
  test: { include: ["packages/*/test/**/*.test.ts", "apps/api/test/**/*.test.ts"], testTimeout: 60_000 },
});
