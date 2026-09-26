import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  __resetApiKeyTouchCache,
  generateApiKey,
} from "../src/auth/api-key.js";
import { _memoryStore, _resetCallCount } from "../src/rate-limit.js";

// Small Hono test rig around the real rateLimitMiddleware.
interface Fixture {
  apiKeyRaw: string;
  apiKeyHash: string;
  subscriptionStatus: string | null; // null = no row
  keyRevoked?: boolean;
}

function makeMockDb(fixture: Fixture): D1Database {
  const prepare = (sql: string) => ({
    bind: (...params: unknown[]) => ({
      first: async <T>(): Promise<T | null> => {
        if (sql.includes("FROM api_keys WHERE hash")) {
          const hash = params[0] as string;
          if (hash === fixture.apiKeyHash && !fixture.keyRevoked) {
            return { id: "k1", user_id: "u42" } as T;
          }
          return null;
        }
        if (sql.includes("FROM subscriptions WHERE user_id")) {
          if (fixture.subscriptionStatus === null) return null;
          return { status: fixture.subscriptionStatus } as T;
        }
        return null;
      },
      run: async () => ({ success: true, meta: { changes: 0 } }),
    }),
  });
  return { prepare } as unknown as D1Database;
}

async function buildApp() {
  // Import inside the helper so module-level state can be reset per test.
  const { rateLimitMiddleware } = await import(
    "../src/security/rate-limit-middleware.js"
  );
  const app = new Hono();
  app.use(
    "/ping",
    rateLimitMiddleware((c, result, headers) =>
      c.json({ error: "limited", resetAt: result.resetAt }, 429, headers),
    ),
  );
  app.get("/ping", (c) => {
    const bearer = c.get("bearer" as never) as { userId: string } | undefined;
    return c.json({ ok: true, bearerUser: bearer?.userId ?? null });
  });
  return app;
}

interface Dispatch {
  ip: string;
  bearer?: string;
}

async function dispatch(
  app: Hono,
  db: D1Database,
  { ip, bearer }: Dispatch,
): Promise<Response> {
  const headers: Record<string, string> = { "CF-Connecting-IP": ip };
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  const req = new Request("http://local/ping", { headers });
  return app.fetch(
    req,
    { DB: db } as unknown as Record<string, unknown>,
    {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as ExecutionContext,
  );
}

describe("rateLimitMiddleware", () => {
  beforeEach(() => {
    _memoryStore.clear();
    _resetCallCount();
    __resetApiKeyTouchCache();
    vi.stubGlobal("caches", undefined);
  });

  it("anon IP bucket blocks after 10 requests", async () => {
    const app = await buildApp();
    const db = makeMockDb({
      apiKeyRaw: "",
      apiKeyHash: "",
      subscriptionStatus: null,
    });

    for (let i = 0; i < 10; i++) {
      const res = await dispatch(app, db, { ip: "1.2.3.4" });
      expect(res.status).toBe(200);
    }
    const blocked = await dispatch(app, db, { ip: "1.2.3.4" });
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("X-RateLimit-Limit")).toBe("10");
    expect(blocked.headers.get("X-RateLimit-Window")).toBe("60s");
    const resetAt = Number(blocked.headers.get("X-RateLimit-Reset"));
    expect(resetAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("pro bearer allows 60 and blocks the 61st", async () => {
    const { raw, hash } = await generateApiKey();
    const app = await buildApp();
    const db = makeMockDb({
      apiKeyRaw: raw,
      apiKeyHash: hash,
      subscriptionStatus: "active",
    });

    for (let i = 0; i < 60; i++) {
      const res = await dispatch(app, db, { ip: "1.2.3.4", bearer: raw });
      expect(res.status).toBe(200);
      expect(res.headers.get("X-RateLimit-Limit")).toBe("60");
      expect(res.headers.get("X-RateLimit-Window")).toBe("3600s");
    }
    const blocked = await dispatch(app, db, { ip: "1.2.3.4", bearer: raw });
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("X-RateLimit-Remaining")).toBe("0");
    expect(Number(blocked.headers.get("X-RateLimit-Reset"))).toBeGreaterThan(
      Math.floor(Date.now() / 1000),
    );
  });

  it("trialing and past_due statuses are also treated as pro", async () => {
    const { raw, hash } = await generateApiKey();
    const app = await buildApp();

    for (const status of ["trialing", "past_due"]) {
      _memoryStore.clear();
      const db = makeMockDb({
        apiKeyRaw: raw,
        apiKeyHash: hash,
        subscriptionStatus: status,
      });
      const res = await dispatch(app, db, { ip: "1.2.3.4", bearer: raw });
      expect(res.status).toBe(200);
      expect(res.headers.get("X-RateLimit-Limit")).toBe("60");
    }
  });

  it("canceled subscription drops back to anon (10) limit", async () => {
    const { raw, hash } = await generateApiKey();
    const app = await buildApp();
    const db = makeMockDb({
      apiKeyRaw: raw,
      apiKeyHash: hash,
      subscriptionStatus: "canceled",
    });

    for (let i = 0; i < 10; i++) {
      const res = await dispatch(app, db, { ip: "1.2.3.4", bearer: raw });
      expect(res.status).toBe(200);
      expect(res.headers.get("X-RateLimit-Limit")).toBe("10");
    }
    const blocked = await dispatch(app, db, { ip: "1.2.3.4", bearer: raw });
    expect(blocked.status).toBe(429);
  });

  it("free-plan bearer (no subscription row) uses per-IP bucket, so a second IP gets its own quota", async () => {
    const { raw, hash } = await generateApiKey();
    const app = await buildApp();
    const db = makeMockDb({
      apiKeyRaw: raw,
      apiKeyHash: hash,
      subscriptionStatus: null,
    });

    for (let i = 0; i < 10; i++) {
      const res = await dispatch(app, db, { ip: "1.1.1.1", bearer: raw });
      expect(res.status).toBe(200);
    }
    const blockedFromIp1 = await dispatch(app, db, {
      ip: "1.1.1.1",
      bearer: raw,
    });
    expect(blockedFromIp1.status).toBe(429);

    // Same free bearer from a different IP starts fresh — documented semantics.
    const freshFromIp2 = await dispatch(app, db, {
      ip: "2.2.2.2",
      bearer: raw,
    });
    expect(freshFromIp2.status).toBe(200);
    expect(freshFromIp2.headers.get("X-RateLimit-Limit")).toBe("10");
  });

  it("revoked key falls through to anon per-IP bucket and leaves bearer unset", async () => {
    const { raw, hash } = await generateApiKey();
    const app = await buildApp();
    const db = makeMockDb({
      apiKeyRaw: raw,
      apiKeyHash: hash,
      subscriptionStatus: "active",
      keyRevoked: true,
    });

    const res = await dispatch(app, db, { ip: "9.9.9.9", bearer: raw });
    expect(res.status).toBe(200);
    expect(res.headers.get("X-RateLimit-Limit")).toBe("10");
    const body = (await res.json()) as { bearerUser: string | null };
    expect(body.bearerUser).toBeNull();
  });

  it("pro bearer populates c.get('bearer') for downstream handlers", async () => {
    const { raw, hash } = await generateApiKey();
    const app = await buildApp();
    const db = makeMockDb({
      apiKeyRaw: raw,
      apiKeyHash: hash,
      subscriptionStatus: "active",
    });

    const res = await dispatch(app, db, { ip: "1.2.3.4", bearer: raw });
    const body = (await res.json()) as { bearerUser: string | null };
    expect(body.bearerUser).toBe("u42");
  });

  it("malformed bearer is ignored and request falls through to anon", async () => {
    const app = await buildApp();
    const db = makeMockDb({
      apiKeyRaw: "",
      apiKeyHash: "",
      subscriptionStatus: null,
    });

    const res = await dispatch(app, db, {
      ip: "1.2.3.4",
      bearer: "not-a-dmk-key",
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("X-RateLimit-Limit")).toBe("10");
  });
});
