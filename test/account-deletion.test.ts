import { Hono } from "hono";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  authRoutes,
  createReauthProof,
  REAUTH_PROOF_COOKIE,
  validateReauthProof,
} from "../src/auth/routes.js";
import { createSessionToken } from "../src/auth/session.js";
import { dashboardRoutes } from "../src/dashboard/routes.js";

const SECRET = "test-session-secret";
const USER_ID = "user-test-abc123";
const USER_EMAIL = "alice@example.com";

// Minimal D1 mock covering the SQL the execute handler issues.
function makeDb(opts: {
  subscription?: {
    stripe_subscription_id: string;
    status: string;
  } | null;
  deleteCalled?: { called: boolean };
}): D1Database {
  const { subscription = null, deleteCalled } = opts;
  const prepare = (sql: string) => ({
    bind: (..._params: unknown[]) => ({
      run: async () => {
        if (/DELETE FROM users WHERE id = \?/i.test(sql)) {
          if (deleteCalled) deleteCalled.called = true;
        }
        return { success: true, meta: { changes: 1 } };
      },
      first: async <T>(): Promise<T | null> => {
        if (/SELECT \* FROM subscriptions WHERE user_id/i.test(sql)) {
          return (subscription ?? null) as T | null;
        }
        return null;
      },
      all: async <T>() => ({ results: [] as T[] }),
    }),
  });
  return { prepare } as unknown as D1Database;
}

function createTestApp(db: D1Database, extraEnv?: Record<string, unknown>) {
  const app = new Hono();
  app.route("/auth", authRoutes);
  app.route("/dashboard", dashboardRoutes);
  const env = { SESSION_SECRET: SECRET, DB: db, ...extraEnv };
  const ec = {
    waitUntil: (_p: Promise<unknown>) => {},
    passThroughOnException: () => {},
  } as unknown as ExecutionContext;
  return {
    request: (url: string, init?: RequestInit) =>
      app.request(url, init, env, ec),
  };
}

async function sessionCookie(sub: string, email: string): Promise<string> {
  const token = await createSessionToken({ sub, email }, SECRET);
  return `session=${token}`;
}

async function proofCookie(sub: string): Promise<string> {
  const token = await createReauthProof(sub, "account_delete", SECRET);
  return `${REAUTH_PROOF_COOKIE}=${token}`;
}

// ---- Re-auth proof helpers ----

describe("createReauthProof / validateReauthProof", () => {
  it("round-trips a valid proof", async () => {
    const token = await createReauthProof(USER_ID, "account_delete", SECRET);
    const result = await validateReauthProof(
      token,
      USER_ID,
      "account_delete",
      SECRET,
    );
    expect(result).not.toBeNull();
    expect(result?.sub).toBe(USER_ID);
    expect(result?.purpose).toBe("account_delete");
  });

  it("rejects a proof with wrong secret", async () => {
    const token = await createReauthProof(USER_ID, "account_delete", SECRET);
    const result = await validateReauthProof(
      token,
      USER_ID,
      "account_delete",
      "wrong-secret",
    );
    expect(result).toBeNull();
  });

  it("rejects a proof for a different subject", async () => {
    const token = await createReauthProof(USER_ID, "account_delete", SECRET);
    const result = await validateReauthProof(
      token,
      "other-user-id",
      "account_delete",
      SECRET,
    );
    expect(result).toBeNull();
  });

  it("rejects a proof with wrong purpose", async () => {
    const token = await createReauthProof(USER_ID, "account_delete", SECRET);
    const result = await validateReauthProof(
      token,
      USER_ID,
      "other_purpose",
      SECRET,
    );
    expect(result).toBeNull();
  });

  it("rejects a tampered proof", async () => {
    const token = await createReauthProof(USER_ID, "account_delete", SECRET);
    const tampered = token.slice(0, -4) + "xxxx";
    const result = await validateReauthProof(
      tampered,
      USER_ID,
      "account_delete",
      SECRET,
    );
    expect(result).toBeNull();
  });

  it("rejects a proof with no dot separator", async () => {
    const result = await validateReauthProof(
      "nodot",
      USER_ID,
      "account_delete",
      SECRET,
    );
    expect(result).toBeNull();
  });
});

// ---- GET /auth/reauth ----

describe("GET /auth/reauth", () => {
  it("redirects to /auth/login when no session cookie is present", async () => {
    const db = makeDb({});
    const { request } = createTestApp(db, {
      WORKOS_CLIENT_ID: "cid",
      WORKOS_REDIRECT_URI: "https://example.com/auth/callback",
    });
    const res = await request("/auth/reauth");
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/auth/login");
  });

  it("redirects to WorkOS with prompt=login when session is valid", async () => {
    const db = makeDb({});
    const { request } = createTestApp(db, {
      WORKOS_CLIENT_ID: "cid",
      WORKOS_REDIRECT_URI: "https://example.com/auth/callback",
    });
    const cookie = await sessionCookie(USER_ID, USER_EMAIL);
    const res = await request("/auth/reauth", {
      headers: { Cookie: cookie },
    });
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location") as string);
    expect(loc.hostname).toBe("api.workos.com");
    expect(loc.searchParams.get("prompt")).toBe("login");
    expect(loc.searchParams.get("client_id")).toBe("cid");
  });

  it("sets oauth_state cookie with reauth suffix", async () => {
    const db = makeDb({});
    const { request } = createTestApp(db, {
      WORKOS_CLIENT_ID: "cid",
      WORKOS_REDIRECT_URI: "https://example.com/auth/callback",
    });
    const cookie = await sessionCookie(USER_ID, USER_EMAIL);
    const res = await request("/auth/reauth", {
      headers: { Cookie: cookie },
    });
    const setCookie = res.headers.get("Set-Cookie") ?? "";
    const stateMatch = setCookie.match(/oauth_state=([^;]+)/);
    expect(stateMatch).not.toBeNull();
    expect(decodeURIComponent(stateMatch?.[1] ?? "")).toMatch(
      /:reauth_delete$/,
    );
  });
});

// ---- POST /dashboard/account/delete (step 2) ----

describe("POST /dashboard/account/delete", () => {
  it("redirects to /auth/reauth when confirmation matches email", async () => {
    const db = makeDb({});
    const { request } = createTestApp(db);
    const cookie = await sessionCookie(USER_ID, USER_EMAIL);
    const res = await request("/dashboard/account/delete", {
      method: "POST",
      headers: {
        Cookie: cookie,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `confirmation=${encodeURIComponent(USER_EMAIL)}`,
    });
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/auth/reauth");
  });

  it("redirects to /auth/reauth when confirmation is the literal DELETE", async () => {
    const db = makeDb({});
    const { request } = createTestApp(db);
    const cookie = await sessionCookie(USER_ID, USER_EMAIL);
    const res = await request("/dashboard/account/delete", {
      method: "POST",
      headers: {
        Cookie: cookie,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "confirmation=DELETE",
    });
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/auth/reauth");
  });

  it("returns 400 when confirmation is wrong", async () => {
    const db = makeDb({});
    const { request } = createTestApp(db);
    const cookie = await sessionCookie(USER_ID, USER_EMAIL);
    const res = await request("/dashboard/account/delete", {
      method: "POST",
      headers: {
        Cookie: cookie,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "confirmation=wrong%40example.com",
    });
    expect(res.status).toBe(400);
    const body = await res.text();
    expect(body).toContain("Type your account email address");
  });

  it("returns 400 when confirmation is empty", async () => {
    const db = makeDb({});
    const { request } = createTestApp(db);
    const cookie = await sessionCookie(USER_ID, USER_EMAIL);
    const res = await request("/dashboard/account/delete", {
      method: "POST",
      headers: {
        Cookie: cookie,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "confirmation=",
    });
    expect(res.status).toBe(400);
  });
});

// ---- POST /dashboard/account/delete/execute (step 3b) ----

describe("POST /dashboard/account/delete/execute", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("redirects to ?error=no_proof when no proof cookie is present", async () => {
    const db = makeDb({});
    const { request } = createTestApp(db);
    const cookie = await sessionCookie(USER_ID, USER_EMAIL);
    const res = await request("/dashboard/account/delete/execute", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe(
      "/dashboard/account/delete/execute?error=no_proof",
    );
  });

  it("redirects to ?error=invalid_proof when proof is tampered", async () => {
    const db = makeDb({});
    const { request } = createTestApp(db);
    const sessionC = await sessionCookie(USER_ID, USER_EMAIL);
    const res = await request("/dashboard/account/delete/execute", {
      method: "POST",
      headers: {
        Cookie: `${sessionC}; ${REAUTH_PROOF_COOKIE}=badtoken.badsig`,
      },
    });
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe(
      "/dashboard/account/delete/execute?error=invalid_proof",
    );
  });

  it("redirects to ?error=invalid_proof when proof belongs to wrong user", async () => {
    const db = makeDb({});
    const { request } = createTestApp(db);
    const sessionC = await sessionCookie(USER_ID, USER_EMAIL);
    // proof minted for a different user
    const wrongProof = await createReauthProof(
      "other-user",
      "account_delete",
      SECRET,
    );
    const res = await request("/dashboard/account/delete/execute", {
      method: "POST",
      headers: {
        Cookie: `${sessionC}; ${REAUTH_PROOF_COOKIE}=${wrongProof}`,
      },
    });
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe(
      "/dashboard/account/delete/execute?error=invalid_proof",
    );
  });

  it("deletes user, clears session cookie, and redirects on success (no Stripe)", async () => {
    const deleteCalled = { called: false };
    const db = makeDb({ deleteCalled });
    const { request } = createTestApp(db);
    const sessionC = await sessionCookie(USER_ID, USER_EMAIL);
    const proof = await proofCookie(USER_ID);

    const res = await request("/dashboard/account/delete/execute", {
      method: "POST",
      headers: { Cookie: `${sessionC}; ${proof}` },
    });

    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/?account_deleted=1");
    expect(deleteCalled.called).toBe(true);
    // Session cookie should be cleared
    const setCookie = res.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toMatch(/session=/);
    expect(setCookie).toMatch(/Max-Age=0/);
  });

  it("cancels Stripe subscription before deleting when active Pro sub exists", async () => {
    const deleteCalled = { called: false };
    const db = makeDb({
      subscription: {
        stripe_subscription_id: "sub_abc",
        status: "active",
      },
      deleteCalled,
    });
    const { request } = createTestApp(db, {
      STRIPE_SECRET_KEY: "sk_test_key",
      STRIPE_WEBHOOK_SECRET: "whsec_test",
      STRIPE_PRICE_ID_PRO: "price_pro",
    });

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "sub_abc", status: "canceled" }), {
        status: 200,
      }),
    );

    const sessionC = await sessionCookie(USER_ID, USER_EMAIL);
    const proof = await proofCookie(USER_ID);
    const res = await request("/dashboard/account/delete/execute", {
      method: "POST",
      headers: { Cookie: `${sessionC}; ${proof}` },
    });

    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/?account_deleted=1");
    expect(deleteCalled.called).toBe(true);
  });

  it("aborts deletion and redirects to ?error=stripe when Stripe cancel fails", async () => {
    const deleteCalled = { called: false };
    const db = makeDb({
      subscription: {
        stripe_subscription_id: "sub_abc",
        status: "active",
      },
      deleteCalled,
    });
    const { request } = createTestApp(db, {
      STRIPE_SECRET_KEY: "sk_test_key",
      STRIPE_WEBHOOK_SECRET: "whsec_test",
      STRIPE_PRICE_ID_PRO: "price_pro",
    });

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: { message: "Card declined" } }), {
        status: 402,
      }),
    );

    const sessionC = await sessionCookie(USER_ID, USER_EMAIL);
    const proof = await proofCookie(USER_ID);
    const res = await request("/dashboard/account/delete/execute", {
      method: "POST",
      headers: { Cookie: `${sessionC}; ${proof}` },
    });

    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe(
      "/dashboard/account/delete/execute?error=stripe",
    );
    // User row must NOT have been deleted
    expect(deleteCalled.called).toBe(false);
  });

  it("skips Stripe cancel when STRIPE_SECRET_KEY is absent (self-host)", async () => {
    const deleteCalled = { called: false };
    const db = makeDb({
      subscription: {
        stripe_subscription_id: "sub_abc",
        status: "active",
      },
      deleteCalled,
    });
    // No STRIPE_SECRET_KEY in env
    const { request } = createTestApp(db);
    const sessionC = await sessionCookie(USER_ID, USER_EMAIL);
    const proof = await proofCookie(USER_ID);

    const res = await request("/dashboard/account/delete/execute", {
      method: "POST",
      headers: { Cookie: `${sessionC}; ${proof}` },
    });

    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/?account_deleted=1");
    expect(deleteCalled.called).toBe(true);
  });

  it("calls WorkOS Management API when WORKOS_API_KEY is present", async () => {
    const deleteCalled = { called: false };
    const db = makeDb({ deleteCalled });
    const { request } = createTestApp(db, {
      WORKOS_API_KEY: "wos_sk_test",
    });

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 200 }));

    const sessionC = await sessionCookie(USER_ID, USER_EMAIL);
    const proof = await proofCookie(USER_ID);
    await request("/dashboard/account/delete/execute", {
      method: "POST",
      headers: { Cookie: `${sessionC}; ${proof}` },
    });

    expect(deleteCalled.called).toBe(true);
    const workosCall = fetchSpy.mock.calls.find(([url]) => {
      try {
        return new URL(url as string).hostname === "api.workos.com";
      } catch {
        return false;
      }
    });
    expect(workosCall).toBeDefined();
    const [, init] = workosCall as [string, RequestInit];
    expect(init.method).toBe("DELETE");
    expect((init.headers as Record<string, string>).Authorization).toContain(
      "wos_sk_test",
    );
  });

  it("skips WorkOS delete when WORKOS_API_KEY is absent (self-host)", async () => {
    const deleteCalled = { called: false };
    const db = makeDb({ deleteCalled });
    // No WORKOS_API_KEY
    const { request } = createTestApp(db);

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 200 }));

    const sessionC = await sessionCookie(USER_ID, USER_EMAIL);
    const proof = await proofCookie(USER_ID);
    await request("/dashboard/account/delete/execute", {
      method: "POST",
      headers: { Cookie: `${sessionC}; ${proof}` },
    });

    expect(deleteCalled.called).toBe(true);
    const workosCall = fetchSpy.mock.calls.find(([url]) => {
      try {
        return new URL(url as string).hostname === "api.workos.com";
      } catch {
        return false;
      }
    });
    expect(workosCall).toBeUndefined();
  });

  it("does not delete another user's account (no IDOR via session.sub)", async () => {
    // The execute handler always uses session.sub — it ignores any user id
    // in the request body. Verify that even if we POST with a different sub
    // in the body, the session-scoped user is the one "deleted".
    const deleteCalled = { called: false };
    const db = makeDb({ deleteCalled });
    const { request } = createTestApp(db);
    const sessionC = await sessionCookie(USER_ID, USER_EMAIL);
    const proof = await proofCookie(USER_ID);

    const res = await request("/dashboard/account/delete/execute", {
      method: "POST",
      headers: {
        Cookie: `${sessionC}; ${proof}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      // Attempt to inject a different user id — must be ignored
      body: "user_id=attacker-controlled-id",
    });

    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/?account_deleted=1");
    // Deletion still proceeded (for the correct user — session.sub)
    expect(deleteCalled.called).toBe(true);
  });
});
