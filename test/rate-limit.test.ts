import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  _FREE_CONFIG,
  _memoryStore,
  _PRO_CONFIG,
  _resetCallCount,
  _SWEEP_INTERVAL,
  checkRateLimit,
  getRateLimitConfig,
  rateLimitHeaders,
} from "../src/rate-limit.js";

const FREE = _FREE_CONFIG;
const PRO = _PRO_CONFIG;

describe("rate-limit", () => {
  beforeEach(() => {
    _memoryStore.clear();
    _resetCallCount();
    vi.stubGlobal("caches", undefined);
  });

  describe("getRateLimitConfig", () => {
    it("returns the anon bucket for free", () => {
      expect(getRateLimitConfig("free")).toEqual({ limit: 10, windowSec: 60 });
    });

    it("returns the pro bucket", () => {
      expect(getRateLimitConfig("pro")).toEqual({ limit: 60, windowSec: 3600 });
    });
  });

  describe("in-memory fallback — free config (anon path, unchanged)", () => {
    it("allows first request and returns correct remaining count", async () => {
      const result = await checkRateLimit("ip:1.2.3.4", FREE);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(FREE.limit - 1);
      expect(result.limit).toBe(FREE.limit);
      expect(result.windowSec).toBe(FREE.windowSec);
    });

    it("allows up to the limit", async () => {
      for (let i = 1; i <= FREE.limit; i++) {
        const result = await checkRateLimit("ip:1.2.3.4", FREE);
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(FREE.limit - i);
      }
    });

    it("blocks the limit+1 request", async () => {
      for (let i = 0; i < FREE.limit; i++) {
        await checkRateLimit("ip:1.2.3.4", FREE);
      }
      const result = await checkRateLimit("ip:1.2.3.4", FREE);
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });

    it("tracks identities independently", async () => {
      for (let i = 0; i < FREE.limit; i++) {
        await checkRateLimit("ip:1.2.3.4", FREE);
      }
      const blocked = await checkRateLimit("ip:1.2.3.4", FREE);
      expect(blocked.allowed).toBe(false);

      const different = await checkRateLimit("ip:5.6.7.8", FREE);
      expect(different.allowed).toBe(true);
      expect(different.remaining).toBe(FREE.limit - 1);
    });

    it("keeps `user:X` and `ip:X` in separate buckets", async () => {
      // Pathological: a user id that collides with an IP string must not share
      // a counter with that IP. The prefix makes the keys globally distinct.
      for (let i = 0; i < FREE.limit; i++) {
        await checkRateLimit("ip:abc", FREE);
      }
      const ipBlocked = await checkRateLimit("ip:abc", FREE);
      expect(ipBlocked.allowed).toBe(false);

      const userFresh = await checkRateLimit("user:abc", FREE);
      expect(userFresh.allowed).toBe(true);
      expect(userFresh.remaining).toBe(FREE.limit - 1);
    });

    it("resets count after window expires", async () => {
      vi.useFakeTimers();

      for (let i = 0; i < FREE.limit; i++) {
        await checkRateLimit("ip:1.2.3.4", FREE);
      }
      const blocked = await checkRateLimit("ip:1.2.3.4", FREE);
      expect(blocked.allowed).toBe(false);

      vi.advanceTimersByTime(FREE.windowSec * 1000 + 1);

      const afterExpiry = await checkRateLimit("ip:1.2.3.4", FREE);
      expect(afterExpiry.allowed).toBe(true);
      expect(afterExpiry.remaining).toBe(FREE.limit - 1);

      vi.useRealTimers();
    });
  });

  describe("in-memory fallback — pro config", () => {
    it("allows 60 requests and blocks the 61st", async () => {
      for (let i = 1; i <= PRO.limit; i++) {
        const result = await checkRateLimit("user:u1", PRO);
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(PRO.limit - i);
      }
      const blocked = await checkRateLimit("user:u1", PRO);
      expect(blocked.allowed).toBe(false);
      expect(blocked.remaining).toBe(0);
      expect(blocked.limit).toBe(60);
      expect(blocked.windowSec).toBe(3600);
    });

    it("rolls the window at 3600s", async () => {
      vi.useFakeTimers();
      for (let i = 0; i < PRO.limit; i++) {
        await checkRateLimit("user:u1", PRO);
      }
      const blocked = await checkRateLimit("user:u1", PRO);
      expect(blocked.allowed).toBe(false);

      vi.advanceTimersByTime(PRO.windowSec * 1000 + 1);

      const afterExpiry = await checkRateLimit("user:u1", PRO);
      expect(afterExpiry.allowed).toBe(true);
      expect(afterExpiry.remaining).toBe(PRO.limit - 1);
      vi.useRealTimers();
    });

    it("returns a resetAt in the future", async () => {
      const before = Math.floor(Date.now() / 1000);
      const result = await checkRateLimit("user:u1", PRO);
      expect(result.resetAt).toBeGreaterThanOrEqual(before + PRO.windowSec - 1);
      expect(result.resetAt).toBeLessThanOrEqual(before + PRO.windowSec + 1);
    });

    it("keeps resetAt stable within a single window", async () => {
      const first = await checkRateLimit("user:u1", PRO);
      const second = await checkRateLimit("user:u1", PRO);
      expect(second.resetAt).toBe(first.resetAt);
    });
  });

  describe("expired entry eviction", () => {
    it("removes expired entries after SWEEP_INTERVAL calls", async () => {
      vi.useFakeTimers();

      const past = Date.now() - 1;
      _memoryStore.set("stale-1", { count: 5, expires: past, resetAt: 0 });
      _memoryStore.set("stale-2", { count: 3, expires: past, resetAt: 0 });

      for (let i = 0; i < _SWEEP_INTERVAL; i++) {
        await checkRateLimit(`ip:10.0.0.${i % 256}`, FREE);
      }

      expect(_memoryStore.has("stale-1")).toBe(false);
      expect(_memoryStore.has("stale-2")).toBe(false);

      vi.useRealTimers();
    });

    it("preserves non-expired entries during sweep", async () => {
      vi.useFakeTimers();

      const past = Date.now() - 1;
      const future = Date.now() + 60_000;
      _memoryStore.set("stale", { count: 5, expires: past, resetAt: 0 });
      _memoryStore.set("active", {
        count: 2,
        expires: future,
        resetAt: Math.floor(future / 1000),
      });

      for (let i = 0; i < _SWEEP_INTERVAL; i++) {
        await checkRateLimit(`ip:10.0.0.${i % 256}`, FREE);
      }

      expect(_memoryStore.has("stale")).toBe(false);
      expect(_memoryStore.has("active")).toBe(true);
      expect(_memoryStore.get("active")?.count).toBe(2);

      vi.useRealTimers();
    });

    it("does not sweep before SWEEP_INTERVAL calls", async () => {
      vi.useFakeTimers();

      const past = Date.now() - 1;
      _memoryStore.set("stale", { count: 5, expires: past, resetAt: 0 });

      for (let i = 0; i < _SWEEP_INTERVAL - 1; i++) {
        await checkRateLimit(`ip:10.0.0.${i % 256}`, FREE);
      }

      expect(_memoryStore.has("stale")).toBe(true);

      vi.useRealTimers();
    });
  });

  describe("rateLimitHeaders", () => {
    it("returns all four headers including X-RateLimit-Reset", async () => {
      const result = await checkRateLimit("ip:1.2.3.4", FREE);
      const headers = rateLimitHeaders(result);
      expect(headers["X-RateLimit-Limit"]).toBe(String(FREE.limit));
      expect(headers["X-RateLimit-Remaining"]).toBe(String(FREE.limit - 1));
      expect(headers["X-RateLimit-Window"]).toBe(`${FREE.windowSec}s`);
      expect(Number(headers["X-RateLimit-Reset"])).toBe(result.resetAt);
      expect(Number(headers["X-RateLimit-Reset"])).toBeGreaterThan(
        Math.floor(Date.now() / 1000),
      );
    });

    it("reports the pro window for pro results", async () => {
      const result = await checkRateLimit("user:u1", PRO);
      const headers = rateLimitHeaders(result);
      expect(headers["X-RateLimit-Limit"]).toBe("60");
      expect(headers["X-RateLimit-Window"]).toBe("3600s");
    });

    it("returns 0 remaining when exhausted", async () => {
      for (let i = 0; i < FREE.limit + 1; i++) {
        await checkRateLimit("ip:1.2.3.4", FREE);
      }
      const result = await checkRateLimit("ip:1.2.3.4", FREE);
      expect(result.remaining).toBe(0);
      const headers = rateLimitHeaders(result);
      expect(headers["X-RateLimit-Remaining"]).toBe("0");
    });
  });
});
