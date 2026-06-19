import { Hono } from "hono";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createReauthProof, extractReauthJti } from "../src/auth/reauth.js";
import { authRoutes } from "../src/auth/routes.js";
import { createSessionToken } from "../src/auth/session.js";
import { dashboardRoutes } from "../src/dashboard/routes.js";

const SECRET = "test-session-secret";

interface UserRow {
  id: string;
  email: string;
  email_domain: string;
  stripe_customer_id: string | null;
  email_alerts_enabled: number;
  notify_on_change_only: number;
  api_key_retirement_acknowledged_at: number | null;
  max_domains_override: number | null;
  created_at: number;
}

function user(id: string, email: string): UserRow {
  return {
    id,
    email,
    email_domain: email.split("@")[1] ?? "",
    stripe_customer_id: null,
    email_alerts_enabled: 1,
    notify_on_change_only: 0,
    api_key_retirement_acknowledged_at: 1700000000,
    max_domains_override: null,
    created_at: 1700000000,
  };
}

// Minimal D1 mock: resolves user lookups, records every write, and applies the
// DELETE FROM users so we can assert the row is (or is not) gone. Everything
// else returns empty so unrelated dashboard queries don't throw.
function makeDB(opts: {
  users: UserRow[];
  writes: Array<{ sql: string; bindings: unknown[] }>;
}) {
  const { users, writes } = opts;
  const make = (sql: string, bindings: unknown[]) => ({
    bind: (...args: unknown[]) => make(sql, args),
    first: async <T>() => {
      if (/SELECT \* FROM users WHERE id = \?/i.test(sql)) {
        return (users.find((u) => u.id === bindings[0]) ?? null) as T | null;
      }
      return null as T | null;
    },
    all: async <T>() => ({ results: [] as T[] }),
    run: async () => {
      writes.push({ sql, bindings });
      if (/^DELETE FROM users WHERE id = \?/i.test(sql)) {
        const idx = users.findIndex((u) => u.id === bindings[0]);
        if (idx >= 0) users.splice(idx, 1);
      }
      return { success: true, meta: { changes: 1 } };
    },
  });
  return {
    prepare: (sql: string) => make(sql, []),
  } as unknown as D1Database;
}

function makeApp(db: D1Database, env: Record<string, unknown> = {}) {
  const app = new Hono();
  app.route("/auth", authRoutes);
  app.route("/dashboard", dashboardRoutes);
  return {
    request: (url: string, init?: RequestInit) =>
      app.request(url, init, { SESSION_SECRET: SECRET, DB: db, ...env }, {
        waitUntil: () => {},
        passThroughOnException: () => {},
      } as ExecutionContext),
  };
}

async function sessionCookie(sub: string, email: string): Promise<string> {
  return `session=${await createSessionToken({ sub, email }, SECRET)}`;
}

const form = (data: Record<string, string>): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(data).toString(),
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("account deletion — step-up re-auth start", () => {
  it("POST /dashboard/account/delete/reauth redirects to WorkOS with prompt=login + delete state", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const db = makeDB({ users: [user("user_1", "a@b.com")], writes });
    const app = makeApp(db, {
      WORKOS_CLIENT_ID: "client_x",
      WORKOS_REDIRECT_URI: "https://dmarc.mx/auth/callback",
    });
    const res = await app.request("/dashboard/account/delete/reauth", {
      ...form({}),
      headers: {
        ...((form({}).headers as Record<string, string>) ?? {}),
        Cookie: await sessionCookie("user_1", "a@b.com"),
      },
    });
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location") as string);
    expect(loc.origin + loc.pathname).toBe(
      "https://api.workos.com/user_management/authorize",
    );
    expect(loc.searchParams.get("prompt")).toBe("login");
    expect(loc.searchParams.get("state")?.startsWith("delete:")).toBe(true);
    // Sets an oauth_state cookie matching the delete state (CSRF for the leg).
    expect(res.headers.get("Set-Cookie")).toMatch(/oauth_state=delete%3A/);
  });
});

describe("account deletion — settings Danger Zone", () => {
  it("GET /dashboard/settings renders the Danger Zone delete control", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const db = makeDB({ users: [user("user_1", "a@b.com")], writes });
    const app = makeApp(db);
    const res = await app.request("/dashboard/settings", {
      headers: { Cookie: await sessionCookie("user_1", "a@b.com") },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("Danger Zone");
    expect(body).toContain('action="/dashboard/account/delete/reauth"');
  });
});

describe("account deletion — WorkOS callback mints the proof", () => {
  it("mints a delete_proof cookie when the re-authed user matches the session", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const db = makeDB({ users: [user("user_1", "a@b.com")], writes });
    const app = makeApp(db, {
      WORKOS_CLIENT_ID: "client_x",
      WORKOS_CLIENT_SECRET: "secret_x",
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({ user: { id: "user_1", email: "a@b.com" } }),
        { status: 200 },
      ),
    );
    const cookie = `${await sessionCookie("user_1", "a@b.com")}; oauth_state=delete:nonce123`;
    const res = await app.request(
      "/auth/callback?code=abc&state=delete:nonce123",
      {
        headers: { Cookie: cookie },
      },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/dashboard/account/delete");
    expect(res.headers.get("Set-Cookie")).toMatch(/delete_proof=/);
  });

  it("refuses to mint a proof when the re-authed user differs from the session", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const db = makeDB({ users: [user("user_1", "a@b.com")], writes });
    const app = makeApp(db, {
      WORKOS_CLIENT_ID: "client_x",
      WORKOS_CLIENT_SECRET: "secret_x",
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({ user: { id: "attacker", email: "x@y.com" } }),
        { status: 200 },
      ),
    );
    const cookie = `${await sessionCookie("user_1", "a@b.com")}; oauth_state=delete:nonce123`;
    const res = await app.request(
      "/auth/callback?code=abc&state=delete:nonce123",
      {
        headers: { Cookie: cookie },
      },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/dashboard/settings");
    expect(res.headers.get("Set-Cookie") ?? "").not.toMatch(/delete_proof=/);
  });
});

describe("account deletion — confirmation page gating", () => {
  it("GET /dashboard/account/delete redirects to settings without a proof", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const db = makeDB({ users: [user("user_1", "a@b.com")], writes });
    const app = makeApp(db);
    const res = await app.request("/dashboard/account/delete", {
      headers: { Cookie: await sessionCookie("user_1", "a@b.com") },
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/dashboard/settings");
  });

  it("GET /dashboard/account/delete renders the typed-confirm form with a valid proof", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const db = makeDB({ users: [user("user_1", "a@b.com")], writes });
    const app = makeApp(db);
    const proof = await createReauthProof("user_1", SECRET);
    const res = await app.request("/dashboard/account/delete", {
      headers: {
        Cookie: `${await sessionCookie("user_1", "a@b.com")}; delete_proof=${proof}`,
      },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('name="confirm"');
    expect(body).toContain("a@b.com");
  });
});

describe("account deletion — execute (POST /dashboard/account/delete)", () => {
  it("is rejected without a valid fresh re-auth proof (no rows deleted)", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const users = [user("user_1", "a@b.com")];
    const db = makeDB({ users, writes });
    const app = makeApp(db);
    const res = await app.request("/dashboard/account/delete", {
      ...form({ confirm: "DELETE" }),
      headers: {
        ...(form({}).headers as Record<string, string>),
        Cookie: await sessionCookie("user_1", "a@b.com"),
      },
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/dashboard/settings");
    expect(writes.some((w) => /DELETE FROM users/i.test(w.sql))).toBe(false);
    expect(users).toHaveLength(1);
  });

  it("is rejected with a proof minted for a different subject", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const users = [user("user_1", "a@b.com")];
    const db = makeDB({ users, writes });
    const app = makeApp(db);
    const proofForOther = await createReauthProof("user_2", SECRET);
    const res = await app.request("/dashboard/account/delete", {
      ...form({ confirm: "DELETE" }),
      headers: {
        ...(form({}).headers as Record<string, string>),
        Cookie: `${await sessionCookie("user_1", "a@b.com")}; delete_proof=${proofForOther}`,
      },
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/dashboard/settings");
    expect(users).toHaveLength(1);
  });

  it("rejects an incorrect typed confirmation (account not deleted)", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const users = [user("user_1", "a@b.com")];
    const db = makeDB({ users, writes });
    const app = makeApp(db);
    const proof = await createReauthProof("user_1", SECRET);
    const res = await app.request("/dashboard/account/delete", {
      ...form({ confirm: "totally-wrong" }),
      headers: {
        ...(form({}).headers as Record<string, string>),
        Cookie: `${await sessionCookie("user_1", "a@b.com")}; delete_proof=${proof}`,
      },
    });
    expect(res.status).toBe(400);
    expect(writes.some((w) => /DELETE FROM users/i.test(w.sql))).toBe(false);
    expect(users).toHaveLength(1);
  });

  it("deletes the account with a valid proof + literal DELETE, clearing cookies", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const users = [user("user_1", "a@b.com")];
    const db = makeDB({ users, writes });
    const app = makeApp(db);
    const proof = await createReauthProof("user_1", SECRET);
    const res = await app.request("/dashboard/account/delete", {
      ...form({ confirm: "DELETE" }),
      headers: {
        ...(form({}).headers as Record<string, string>),
        Cookie: `${await sessionCookie("user_1", "a@b.com")}; delete_proof=${proof}`,
      },
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/");
    const del = writes.find((w) =>
      /DELETE FROM users WHERE id = \?/i.test(w.sql),
    );
    expect(del?.bindings).toEqual(["user_1"]);
    expect(users).toHaveLength(0);
    // Session + proof cookies are cleared.
    const setCookie = res.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toMatch(/session=;|session=deleted|Max-Age=0/);
  });

  it("accepts the account email as the typed confirmation", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const users = [user("user_1", "a@b.com")];
    const db = makeDB({ users, writes });
    const app = makeApp(db);
    const proof = await createReauthProof("user_1", SECRET);
    const res = await app.request("/dashboard/account/delete", {
      ...form({ confirm: "A@B.com" }), // case-insensitive
      headers: {
        ...(form({}).headers as Record<string, string>),
        Cookie: `${await sessionCookie("user_1", "a@b.com")}; delete_proof=${proof}`,
      },
    });
    expect(res.status).toBe(302);
    expect(users).toHaveLength(0);
  });

  it("derives the target from session.sub only — a user_id in the body is ignored (IDOR guard)", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const users = [user("user_1", "a@b.com"), user("victim", "v@b.com")];
    const db = makeDB({ users, writes });
    const app = makeApp(db);
    const proof = await createReauthProof("user_1", SECRET);
    const res = await app.request("/dashboard/account/delete", {
      ...form({
        confirm: "DELETE",
        user_id: "victim",
        id: "victim",
        sub: "victim",
      }),
      headers: {
        ...(form({}).headers as Record<string, string>),
        Cookie: `${await sessionCookie("user_1", "a@b.com")}; delete_proof=${proof}`,
      },
    });
    expect(res.status).toBe(302);
    const del = writes.find((w) =>
      /DELETE FROM users WHERE id = \?/i.test(w.sql),
    );
    expect(del?.bindings).toEqual(["user_1"]);
    // The victim's row is untouched; only the session subject was deleted.
    expect(users.map((u) => u.id)).toEqual(["victim"]);
  });
});

// Minimal mock for DurableObjectNamespace<RateLimiterDO> used by nonce tests.
function makeNonceStore() {
  const consumed = new Set<string>();
  return {
    idFromName: (_name: string) =>
      ({ toString: () => _name }) as DurableObjectId,
    get: (_id: DurableObjectId) =>
      ({
        tryConsumeNonce: async (jti: string, _expiresAt: number) => {
          if (consumed.has(jti)) return false;
          consumed.add(jti);
          return true;
        },
      }) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

describe("account deletion — server-side single-use nonce (#553)", () => {
  it("replayed proof is rejected after nonce is consumed on first use", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const users = [user("user_1", "a@b.com")];
    const db = makeDB({ users, writes });
    const rateLimiter = makeNonceStore();
    const app = makeApp(db, { RATE_LIMITER: rateLimiter });
    const proof = await createReauthProof("user_1", SECRET);

    // First POST — succeeds; nonce is consumed.
    const first = await app.request("/dashboard/account/delete", {
      ...form({ confirm: "DELETE" }),
      headers: {
        ...(form({}).headers as Record<string, string>),
        Cookie: `${await sessionCookie("user_1", "a@b.com")}; delete_proof=${proof}`,
      },
    });
    expect(first.status).toBe(302);
    expect(first.headers.get("Location")).toBe("/");

    // Restore user row so the replay isn't deflected by the missing-row path.
    users.push(user("user_1", "a@b.com"));

    // Second POST with the same proof — nonce already consumed, must be rejected.
    const replay = await app.request("/dashboard/account/delete", {
      ...form({ confirm: "DELETE" }),
      headers: {
        ...(form({}).headers as Record<string, string>),
        Cookie: `${await sessionCookie("user_1", "a@b.com")}; delete_proof=${proof}`,
      },
    });
    expect(replay.status).toBe(302);
    expect(replay.headers.get("Location")).toBe("/dashboard/settings");
  });

  it("deletion succeeds when RATE_LIMITER is absent (graceful fallback)", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const users = [user("user_1", "a@b.com")];
    const db = makeDB({ users, writes });
    // No RATE_LIMITER in env — nonce check must be skipped, not block deletion.
    const app = makeApp(db);
    const proof = await createReauthProof("user_1", SECRET);
    const res = await app.request("/dashboard/account/delete", {
      ...form({ confirm: "DELETE" }),
      headers: {
        ...(form({}).headers as Record<string, string>),
        Cookie: `${await sessionCookie("user_1", "a@b.com")}; delete_proof=${proof}`,
      },
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/");
    expect(users).toHaveLength(0);
  });

  it("extractReauthJti is consistent: the jti in the proof matches what the store sees", async () => {
    const consumed: string[] = [];
    const rateLimiter = {
      idFromName: (_n: string) => ({}) as DurableObjectId,
      get: (_id: DurableObjectId) =>
        ({
          tryConsumeNonce: async (jti: string, _exp: number) => {
            consumed.push(jti);
            return true;
          },
        }) as unknown as DurableObjectStub,
    } as unknown as DurableObjectNamespace;

    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const users = [user("user_1", "a@b.com")];
    const db = makeDB({ users, writes });
    const app = makeApp(db, { RATE_LIMITER: rateLimiter });
    const proof = await createReauthProof("user_1", SECRET);
    const expectedJti = extractReauthJti(proof);

    await app.request("/dashboard/account/delete", {
      ...form({ confirm: "DELETE" }),
      headers: {
        ...(form({}).headers as Record<string, string>),
        Cookie: `${await sessionCookie("user_1", "a@b.com")}; delete_proof=${proof}`,
      },
    });
    expect(consumed).toHaveLength(1);
    expect(consumed[0]).toBe(expectedJti);
  });
});

describe("account deletion — stale session after deletion", () => {
  it("a retained valid cookie for a deleted user does not 500 on /dashboard", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const db = makeDB({ users: [], writes }); // user row already gone
    const app = makeApp(db);
    const res = await app.request("/dashboard", {
      headers: { Cookie: await sessionCookie("ghost", "ghost@b.com") },
    });
    expect(res.status).toBe(200);
  });

  it("a retained valid cookie for a deleted user is bounced to logout on /dashboard/settings", async () => {
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const db = makeDB({ users: [], writes });
    const app = makeApp(db);
    const res = await app.request("/dashboard/settings", {
      headers: { Cookie: await sessionCookie("ghost", "ghost@b.com") },
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/auth/logout");
  });
});
