import { Hono } from "hono";
import { csrf } from "hono/csrf";
import { describe, expect, it, vi } from "vitest";
import { authRoutes } from "../src/auth/routes.js";

function createTestApp() {
  const app = new Hono();
  app.use("/auth/logout", csrf());
  app.route("/auth", authRoutes);
  return app;
}

const ENV = {
  WORKOS_CLIENT_ID: "test-client-id",
  WORKOS_REDIRECT_URI: "https://example.com/auth/callback",
  SESSION_SECRET: "test-session-secret",
};

describe("auth/routes", () => {
  describe("GET /auth/login", () => {
    it("redirects to WorkOS authorization URL", async () => {
      const app = createTestApp();
      const res = await app.request("/auth/login", {}, ENV);
      expect(res.status).toBe(302);
      const location = res.headers.get("Location");
      expect(location).not.toBeNull();
      const url = new URL(location as string);
      expect(url.origin + url.pathname).toBe(
        "https://api.workos.com/user_management/authorize",
      );
    });

    it("includes client_id in the authorization URL", async () => {
      const app = createTestApp();
      const res = await app.request("/auth/login", {}, ENV);
      const location = res.headers.get("Location") as string;
      const url = new URL(location);
      expect(url.searchParams.get("client_id")).toBe(ENV.WORKOS_CLIENT_ID);
    });

    it("includes redirect_uri in the authorization URL", async () => {
      const app = createTestApp();
      const res = await app.request("/auth/login", {}, ENV);
      const location = res.headers.get("Location") as string;
      const url = new URL(location);
      expect(url.searchParams.get("redirect_uri")).toBe(
        ENV.WORKOS_REDIRECT_URI,
      );
    });

    it("includes response_type=code in the authorization URL", async () => {
      const app = createTestApp();
      const res = await app.request("/auth/login", {}, ENV);
      const location = res.headers.get("Location") as string;
      const url = new URL(location);
      expect(url.searchParams.get("response_type")).toBe("code");
    });

    it("includes provider=authkit in the authorization URL", async () => {
      const app = createTestApp();
      const res = await app.request("/auth/login", {}, ENV);
      const location = res.headers.get("Location") as string;
      const url = new URL(location);
      expect(url.searchParams.get("provider")).toBe("authkit");
    });

    it("sets oauth_state cookie and includes state in authorization URL", async () => {
      const app = createTestApp();
      const res = await app.request("/auth/login", {}, ENV);

      const setCookieHeader = res.headers.get("Set-Cookie");
      expect(setCookieHeader).not.toBeNull();
      expect(setCookieHeader).toMatch(/oauth_state=[a-f0-9-]+;/);

      const cookieMatch = setCookieHeader?.match(/oauth_state=([a-f0-9-]+);/);
      const cookieState = cookieMatch?.[1];
      expect(cookieState).toBeDefined();

      const location = res.headers.get("Location") as string;
      const url = new URL(location);
      const urlState = url.searchParams.get("state");
      expect(urlState).toBeDefined();
      expect(urlState).toBe(cookieState);
    });
  });

  describe("GET /auth/callback", () => {
    it("returns 400 when code query param is missing", async () => {
      const app = createTestApp();
      const res = await app.request("/auth/callback", {}, ENV);
      expect(res.status).toBe(400);
      const body = await res.text();
      expect(body).toBe("Missing authorization code");
    });

    it("offers a retry page when state query param is missing", async () => {
      const app = createTestApp();
      const req = new Request("http://localhost/auth/callback?code=test-code");
      req.headers.set("Cookie", "oauth_state=test-state");
      const res = await app.request(req, ENV);
      expect(res.status).toBe(400);
      expect(await res.text()).toContain('href="/auth/login"');
    });

    it("offers a retry page when the oauth_state cookie has expired", async () => {
      const app = createTestApp();
      const req = new Request(
        "http://localhost/auth/callback?code=test-code&state=test-state",
      );
      const res = await app.request(req, ENV);
      expect(res.status).toBe(400);
      const body = await res.text();
      expect(body).toContain("Your sign-in timed out");
      expect(body).toContain('href="/auth/login"');
      expect(res.headers.get("Location")).toBeNull();
    });

    it("rejects mismatched state without exchanging the code", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch");
      const app = createTestApp();
      const req = new Request(
        "http://localhost/auth/callback?code=test-code&state=query-state",
      );
      req.headers.set("Cookie", "oauth_state=cookie-state");
      const res = await app.request(req, ENV);
      expect(res.status).toBe(400);
      expect(res.headers.get("Set-Cookie") ?? "").not.toContain("session=");
      expect(fetchSpy).not.toHaveBeenCalled();
      fetchSpy.mockRestore();
    });

    it("keeps the monitor intent in the retry link", async () => {
      const app = createTestApp();
      const req = new Request(
        "http://localhost/auth/callback?code=test-code&state=test-state",
      );
      req.headers.set("Cookie", "monitor_intent=example.com");
      const res = await app.request(req, ENV);
      expect(await res.text()).toContain(
        'href="/auth/login?next=/dashboard&amp;prompt=monitor:example.com"',
      );
    });

    it("drops a tampered monitor intent from the retry link", async () => {
      const app = createTestApp();
      const req = new Request(
        "http://localhost/auth/callback?code=test-code&state=test-state",
      );
      req.headers.set("Cookie", 'monitor_intent="><script>x</script>');
      const body = await (await app.request(req, ENV)).text();
      expect(body).not.toContain("<script>x");
      expect(body).toContain('href="/auth/login"');
    });

    it("gives the sign-up round-trip 30 minutes", async () => {
      const res = await createTestApp().request(
        "/auth/login?prompt=monitor:example.com",
        {},
        ENV,
      );
      const cookies = res.headers.get("Set-Cookie") ?? "";
      expect(cookies.match(/Max-Age=1800/g)).toHaveLength(2);
    });
  });

  describe("GET /auth/logout", () => {
    it("rejects with 405 and does not clear the session cookie", async () => {
      const app = createTestApp();
      const res = await app.request("/auth/logout", {}, ENV);
      expect(res.status).toBe(405);
      expect(res.headers.get("Set-Cookie")).toBeNull();
    });
  });

  describe("POST /auth/logout", () => {
    it("clears the session cookie on a same-origin request", async () => {
      const app = createTestApp();
      const req = new Request("http://localhost/auth/logout", {
        method: "POST",
        headers: { Origin: "http://localhost" },
      });
      const res = await app.request(req, ENV);
      const setCookieHeader = res.headers.get("Set-Cookie");
      expect(setCookieHeader).not.toBeNull();
      // Cookie should be cleared (Max-Age=0 or expires in the past)
      expect(setCookieHeader).toMatch(/session=/);
      expect(setCookieHeader).toMatch(/Max-Age=0/);
    });

    it("redirects to / on a same-origin request", async () => {
      const app = createTestApp();
      const req = new Request("http://localhost/auth/logout", {
        method: "POST",
        headers: { Origin: "http://localhost" },
      });
      const res = await app.request(req, ENV);
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/");
    });

    it("rejects a cross-site form POST and does not clear the session", async () => {
      const app = createTestApp();
      const req = new Request("http://localhost/auth/logout", {
        method: "POST",
        headers: {
          Origin: "https://evil.example",
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });
      const res = await app.request(req, ENV);
      expect(res.status).toBe(403);
      expect(res.headers.get("Set-Cookie")).toBeNull();
    });
  });
});

describe("auth/routes delete re-auth with migrated WorkOS id (#913)", () => {
  function makeDb(user: {
    id: string;
    email: string;
    workos_user_id: string | null;
  }) {
    const prepare = () => ({
      bind: () => ({
        first: async () => user,
        run: async () => ({ success: true, meta: { changes: 1 } }),
      }),
    });
    return { prepare } as unknown as D1Database;
  }

  async function reauth(
    user: { id: string; email: string; workos_user_id: string | null },
    freshWorkosId: string,
  ) {
    const { createSessionToken } = await import("../src/auth/session.js");
    const session = await createSessionToken(
      { sub: user.id, email: user.email },
      ENV.SESSION_SECRET,
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({ user: { id: freshWorkosId, email: user.email } }),
          ),
      ),
    );
    const app = createTestApp();
    const req = new Request(
      "http://localhost/auth/callback?code=c&state=delete:nonce",
      { headers: { Cookie: `oauth_state=delete:nonce; session=${session}` } },
    );
    const res = await app.request(req, undefined, {
      ...ENV,
      WORKOS_CLIENT_SECRET: "x",
      DB: makeDb(user),
    });
    vi.unstubAllGlobals();
    return res;
  }

  it("mints a proof when the fresh WorkOS id matches stored workos_user_id", async () => {
    const res = await reauth(
      {
        id: "user_staging",
        email: "a@example.com",
        workos_user_id: "user_prod",
      },
      "user_prod",
    );
    expect(res.headers.get("Location")).toBe("/dashboard/account/delete");
    expect(res.headers.get("Set-Cookie")).toContain("delete_proof=");
  });

  it("falls back to users.id when workos_user_id is null", async () => {
    const res = await reauth(
      { id: "user_1", email: "a@example.com", workos_user_id: null },
      "user_1",
    );
    expect(res.headers.get("Location")).toBe("/dashboard/account/delete");
  });

  it("refuses a proof when the WorkOS identity does not match", async () => {
    const res = await reauth(
      {
        id: "user_staging",
        email: "a@example.com",
        workos_user_id: "user_prod",
      },
      "user_other",
    );
    expect(res.headers.get("Location")).toBe("/dashboard/settings");
    expect(res.headers.get("Set-Cookie") ?? "").not.toContain("delete_proof=");
  });

  it("refuses the stale staging id once workos_user_id is set", async () => {
    const res = await reauth(
      {
        id: "user_staging",
        email: "a@example.com",
        workos_user_id: "user_prod",
      },
      "user_staging",
    );
    expect(res.headers.get("Location")).toBe("/dashboard/settings");
  });
});

describe("auth/routes monitor intent", () => {
  const user = { id: "u1", email: "a@corp.example", workos_user_id: "u1" };
  const db = {
    prepare: () => ({
      bind: () => ({
        first: async () => user,
        run: async () => ({ success: true, meta: { changes: 1 } }),
      }),
    }),
  } as unknown as D1Database;

  async function callback(cookie: string) {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ user }))),
    );
    const req = new Request("http://localhost/auth/callback?code=c&state=s", {
      headers: { Cookie: `oauth_state=s; ${cookie}` },
    });
    const res = await createTestApp().request(req, undefined, {
      ...ENV,
      WORKOS_CLIENT_SECRET: "x",
      DB: db,
    });
    vi.unstubAllGlobals();
    return res;
  }

  it("carries a monitor prompt to sign-up and stores the domain", async () => {
    const res = await createTestApp().request(
      "/auth/login?next=/dashboard&prompt=monitor:Example.COM",
      {},
      ENV,
    );
    const url = new URL(res.headers.get("Location") as string);
    expect(url.searchParams.get("screen_hint")).toBe("sign-up");
    expect(res.headers.get("Set-Cookie")).toContain(
      "monitor_intent=example.com",
    );
  });

  it("ignores prompts that are not a valid monitor domain", async () => {
    for (const q of ["", "?prompt=other", "?prompt=monitor:not%20a%20domain"]) {
      const res = await createTestApp().request(`/auth/login${q}`, {}, ENV);
      const url = new URL(res.headers.get("Location") as string);
      expect(url.searchParams.has("screen_hint")).toBe(false);
      expect(res.headers.get("Set-Cookie") ?? "").not.toContain(
        "monitor_intent=",
      );
    }
  });

  it("lands on a prefilled add-domain form after login", async () => {
    const res = await callback("monitor_intent=example.com");
    expect(res.headers.get("Location")).toBe(
      "/dashboard/domain/add?domain=example.com",
    );
    expect(res.headers.get("Set-Cookie")).toContain("monitor_intent=;");
  });

  it("goes to the dashboard when the intent is the auto-added email domain", async () => {
    const res = await callback("monitor_intent=corp.example");
    expect(res.headers.get("Location")).toBe("/dashboard");
  });

  it("sets the intent cookie httpOnly, Secure, Lax and short-lived", async () => {
    const res = await createTestApp().request(
      "/auth/login?prompt=monitor:example.com",
      {},
      ENV,
    );
    const cookie = (res.headers.get("Set-Cookie") ?? "")
      .split(/,(?=\s*\w+=)/)
      .find((c) => c.includes("monitor_intent=")) as string;
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Max-Age=1800");
  });

  it("reduces redirect-shaped prompts to a bare hostname", async () => {
    for (const p of ["//evil.com", "https://evil.com/x"]) {
      const res = await createTestApp().request(
        `/auth/login?prompt=monitor:${encodeURIComponent(p)}`,
        {},
        ENV,
      );
      expect(res.headers.get("Set-Cookie")).toContain(
        "monitor_intent=evil.com;",
      );
    }
  });

  it("re-validates a tampered cookie and only redirects in-app", async () => {
    const res = await callback("monitor_intent=//evil.com");
    expect(res.headers.get("Location")).toBe(
      "/dashboard/domain/add?domain=evil.com",
    );
    const bad = await callback("monitor_intent=%3Cb%3E.com");
    expect(bad.headers.get("Location")).toBe("/dashboard");
  });

  it("goes to the dashboard without an intent", async () => {
    const res = await callback("");
    expect(res.headers.get("Location")).toBe("/dashboard");
  });
});
