import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// Two-project setup: Node pool for existing fast unit tests (DNS and fetch
// are mocked), Workers pool for runtime tests that must exercise the real
// Cloudflare Workers fetch stack. The workers pool exists specifically to
// catch regressions like PR #58/#92 where `redirect: "error"` throws inside
// workerd but works fine in Node's global fetch — a class of bug that has
// slipped past the mocked unit tests twice.
//
// `cloudflareTest()` is the idiomatic plugin form exported by
// `@cloudflare/vitest-pool-workers`; it wires up vitest's pool runner,
// transforms vite config with the workerd module conditions, and inherits
// compatibility flags / bindings from wrangler.toml.
export default defineConfig({
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: "node",
          globals: true,
          include: ["test/**/*.test.ts", "scripts/**/__tests__/*.test.ts"],
          exclude: ["test/integration/**", "node_modules/**"],
        },
      },
      // stripe-lifecycle lives in test/integration/ but uses vi.mock and
      // vi.stubGlobal (Node-only APIs). It gets its own project entry so the
      // Workers pool exclude and the Node pool exclude don't fight each other.
      {
        extends: true,
        test: {
          name: "node-integration",
          globals: true,
          include: ["test/integration/stripe-lifecycle.test.ts"],
        },
      },
      {
        extends: true,
        plugins: [
          cloudflareTest({
            wrangler: { configPath: "./wrangler.toml" },
          }),
        ],
        test: {
          name: "workers",
          include: ["test/integration/**/*.test.ts"],
          // stripe-lifecycle uses vi.mock/vi.stubGlobal — Node pool only.
          exclude: ["test/integration/stripe-lifecycle.test.ts"],
        },
      },
    ],
  },
});
