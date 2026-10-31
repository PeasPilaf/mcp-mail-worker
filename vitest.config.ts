import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      {
        // Runs inside workerd with the real KV / Durable Object bindings.
        plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" } })],
        test: { name: "worker", include: ["test/worker/**/*.test.ts"] },
      },
      {
        // Repository files and the deploy workflow.
        test: { name: "node", include: ["test/node/**/*.test.ts"], environment: "node" },
      },
    ],
  },
});
