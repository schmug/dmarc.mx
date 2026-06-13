import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  checkRateLimit,
  type RateLimitConfig,
  rateLimitHeaders,
} from "../../src/rate-limit.js";
import type { RateLimiterDO } from "../../src/rate-limit-do.js";

// These tests run inside the real Cloudflare Workers runtime via
// `@cloudflare/vitest-pool-workers`, which is the only place the
// `RATE_LIMITER` Durable Object binding exists. They are the complete fix for
// GHSA-v7qc-7qh8-h69g: the prior Cache-API counter was a non-atomic
// read-modify-write, so a concurrent burst under one identity could each read
// the same stale count and collectively exceed the configured ceiling. A
// Durable Object serializes increments per identity, closing that window
// across isolates and colos — something the Node-pool tests (single isolate,
// synchronous JS) cannot exercise.

declare module "cloudflare:test" {
  interface ProvidedEnv {
    RATE_LIMITER: DurableObjectNamespace<RateLimiterDO>;
  }
}

const FREE: RateLimitConfig = { limit: 10, windowSec: 60 };
const PRO: RateLimitConfig = { limit: 60, windowSec: 3600 };

describe("RateLimiterDO (runs inside real workerd runtime)", () => {
  it("exposes the RATE_LIMITER binding", () => {
    expect(env.RATE_LIMITER).toBeDefined();
  });

  it("serializes N concurrent increments to one identity — no lost updates, no burst bypass", async () => {
    // The core GHSA-v7qc-7qh8-h69g assertion. Fire N simultaneous RPCs at one
    // DO instance; because the DO is single-threaded the stored count must
    // reach exactly N (each increment observes the previous one) and exactly
    // `limit` of them are allowed. A non-atomic counter would lose updates
    // (count < N) and allow more than `limit`.
    const N = 30;
    const stub = env.RATE_LIMITER.getByName("ip:atomic-burst");
    const results = await Promise.all(
      Array.from({ length: N }, () =>
        stub.increment(FREE.limit, FREE.windowSec),
      ),
    );

    const counts = results.map((r) => r.count).sort((a, b) => a - b);
    expect(counts).toEqual(Array.from({ length: N }, (_, i) => i + 1));
    expect(Math.max(...counts)).toBe(N);
    expect(results.filter((r) => r.allowed).length).toBe(FREE.limit);
  });

  it("checkRateLimit() routed through the DO blocks a concurrent burst at the limit", async () => {
    const N = 30;
    const results = await Promise.all(
      Array.from({ length: N }, () =>
        checkRateLimit("ip:wired-burst", FREE, env.RATE_LIMITER),
      ),
    );
    expect(results.filter((r) => r.allowed).length).toBe(FREE.limit);
    expect(results.filter((r) => !r.allowed).length).toBe(N - FREE.limit);
    expect(Math.max(...results.map((r) => r.count))).toBe(N);
  });

  it("free tier: allows 10 sequential requests, blocks the 11th, with correct headers", async () => {
    for (let i = 1; i <= FREE.limit; i++) {
      const r = await checkRateLimit("ip:free-seq", FREE, env.RATE_LIMITER);
      expect(r.allowed).toBe(true);
      expect(r.remaining).toBe(FREE.limit - i);
      expect(r.limit).toBe(FREE.limit);
      expect(r.windowSec).toBe(FREE.windowSec);
    }
    const blocked = await checkRateLimit("ip:free-seq", FREE, env.RATE_LIMITER);
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);

    const headers = rateLimitHeaders(blocked);
    expect(headers["X-RateLimit-Limit"]).toBe("10");
    expect(headers["X-RateLimit-Remaining"]).toBe("0");
    expect(headers["X-RateLimit-Window"]).toBe("60s");
    expect(Number(headers["X-RateLimit-Reset"])).toBeGreaterThan(
      Math.floor(Date.now() / 1000),
    );
  });

  it("pro tier: allows 60 sequential requests and blocks the 61st", async () => {
    for (let i = 1; i <= PRO.limit; i++) {
      const r = await checkRateLimit("user:pro-seq", PRO, env.RATE_LIMITER);
      expect(r.allowed).toBe(true);
      expect(r.limit).toBe(60);
      expect(r.windowSec).toBe(3600);
    }
    const blocked = await checkRateLimit("user:pro-seq", PRO, env.RATE_LIMITER);
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
    const headers = rateLimitHeaders(blocked);
    expect(headers["X-RateLimit-Limit"]).toBe("60");
    expect(headers["X-RateLimit-Window"]).toBe("3600s");
  });

  it("keeps resetAt stable within a single window", async () => {
    const first = await checkRateLimit("ip:stable", FREE, env.RATE_LIMITER);
    const second = await checkRateLimit("ip:stable", FREE, env.RATE_LIMITER);
    expect(second.resetAt).toBe(first.resetAt);
    expect(first.resetAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("keeps `ip:X` and `user:X` in separate buckets and tracks identities independently", async () => {
    for (let i = 0; i < FREE.limit; i++) {
      await checkRateLimit("ip:iso", FREE, env.RATE_LIMITER);
    }
    const ipBlocked = await checkRateLimit("ip:iso", FREE, env.RATE_LIMITER);
    expect(ipBlocked.allowed).toBe(false);

    // Same suffix, different prefix — must be an independent bucket.
    const userFresh = await checkRateLimit("user:iso", FREE, env.RATE_LIMITER);
    expect(userFresh.allowed).toBe(true);
    expect(userFresh.remaining).toBe(FREE.limit - 1);

    // A different IP is also independent.
    const otherIp = await checkRateLimit("ip:other", FREE, env.RATE_LIMITER);
    expect(otherIp.allowed).toBe(true);
    expect(otherIp.remaining).toBe(FREE.limit - 1);
  });

  it("rolls the window: an expired bucket resets to count 1 on the next increment", async () => {
    // Time travel is not available inside workerd, so seed an already-expired
    // window directly via runInDurableObject and assert the reset branch.
    const stub = env.RATE_LIMITER.getByName("ip:expired");
    await runInDurableObject(stub, (instance, state) => {
      const nowSec = Math.floor(Date.now() / 1000);
      state.storage.sql.exec(
        `INSERT INTO bucket (id, count, reset_at) VALUES (1, ?, ?)
         ON CONFLICT(id) DO UPDATE SET count = excluded.count, reset_at = excluded.reset_at`,
        9,
        nowSec - 1,
      );

      const r = instance.increment(FREE.limit, FREE.windowSec);
      expect(r.count).toBe(1);
      expect(r.allowed).toBe(true);
      expect(r.remaining).toBe(FREE.limit - 1);
      expect(r.resetAt).toBeGreaterThan(nowSec);
    });
  });
});
