// POST /dashboard/domain/:id/selector-from-inbox (issue #867): saves the DKIM
// selector detected by an inbound test email (/check/email) onto a
// session-owned domain. The route re-reads the verdict from KV by token —
// never trusting a selector value from the request body — and only saves
// when DKIM passed and the signing domain aligns with the domain being saved
// to.
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createSessionToken } from "../src/auth/session.js";
import { dashboardRoutes } from "../src/dashboard/routes.js";
import type { Domain } from "../src/db/domains.js";
import { putVerdict, type VerdictRecord } from "../src/inbox/store.js";
import { FakeKV } from "./helpers/fake-kv.js";

const SECRET = "test-session-secret";
const TOKEN = "0123456789abcdef0123456789abcdef";

function makeDomain(overrides: Partial<Domain> = {}): Domain {
  return {
    id: 1,
    user_id: "user-1",
    domain: "example.com",
    is_free: 0,
    scan_frequency: "weekly",
    last_scanned_at: null,
    last_grade: null,
    created_at: 1700000000,
    dkim_selectors: null,
    ...overrides,
  };
}

/** Minimal D1 mock covering only what this route's DB calls need. */
function makeDb(initial: Domain[]) {
  const store = new Map<number, Domain>(initial.map((d) => [d.id, d]));
  const updates: Array<{ sql: string; bindings: unknown[] }> = [];

  const prepare = (sql: string) => ({
    bind: (...bindings: unknown[]) => ({
      first: async <T>(): Promise<T | null> => {
        if (
          /SELECT \* FROM domains WHERE id = \? AND user_id = \?/i.test(sql)
        ) {
          const [id, userId] = bindings as [number, string];
          const row = store.get(id);
          return (row && row.user_id === userId ? row : null) as T | null;
        }
        if (
          /SELECT dkim_selectors FROM domains WHERE id = \? AND user_id = \?/i.test(
            sql,
          )
        ) {
          const [id, userId] = bindings as [number, string];
          const row = store.get(id);
          return (
            row && row.user_id === userId
              ? { dkim_selectors: row.dkim_selectors }
              : null
          ) as T | null;
        }
        return null;
      },
      run: async () => {
        updates.push({ sql, bindings });
        if (/^UPDATE domains SET dkim_selectors/i.test(sql)) {
          const [next, id, userId] = bindings as [string, number, string];
          const row = store.get(id);
          if (row && row.user_id === userId) {
            store.set(id, { ...row, dkim_selectors: next });
          }
        }
        return { success: true, meta: { changes: 1 } };
      },
    }),
  });

  return { db: { prepare } as unknown as D1Database, store, updates };
}

function createTestApp(db: D1Database, kv: FakeKV) {
  const app = new Hono();
  app.route("/dashboard", dashboardRoutes);
  return {
    request: (url: string, init?: RequestInit) =>
      app.request(url, init, {
        SESSION_SECRET: SECRET,
        DB: db,
        INBOX_TOKENS: kv.asKv(),
      }),
  };
}

async function sessionCookie(sub: string): Promise<string> {
  const token = await createSessionToken(
    { sub, email: `${sub}@example.com` },
    SECRET,
  );
  return `session=${token}`;
}

function postForm(cookie: string, body: Record<string, string>) {
  return {
    method: "POST",
    headers: {
      Cookie: cookie,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(body).toString(),
  };
}

const passingVerdict: VerdictRecord = {
  status: "received",
  spf: "pass",
  dkim: "pass",
  dmarc: "pass",
  alignment: "pass",
  from: "sender@example.com",
  dkim_selector: "selector1",
  dkim_domain: "example.com",
  auth_results: "mx; dkim=pass",
  size_bytes: 10,
  received_at: "2026-06-28T00:00:00.000Z",
};

describe("POST /dashboard/domain/:id/selector-from-inbox", () => {
  it("redirects to /auth/login without a session cookie", async () => {
    const { db } = makeDb([makeDomain()]);
    const kv = new FakeKV();
    const app = createTestApp(db, kv);
    const res = await app.request("/dashboard/domain/1/selector-from-inbox", {
      method: "POST",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/auth/login");
  });

  it("saves the selector and redirects to the domain page on the happy path", async () => {
    const { db, store } = makeDb([makeDomain()]);
    const kv = new FakeKV();
    await putVerdict(kv.asKv(), TOKEN, passingVerdict);
    const app = createTestApp(db, kv);
    const cookie = await sessionCookie("user-1");

    const res = await app.request(
      "/dashboard/domain/1/selector-from-inbox",
      postForm(cookie, { token: TOKEN }),
    );

    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe(
      "/dashboard/domain/example.com?selector=saved",
    );
    expect(store.get(1)?.dkim_selectors).toBe("selector1");
  });

  it("never trusts a selector value sent in the request body", async () => {
    const { db, store } = makeDb([makeDomain()]);
    const kv = new FakeKV();
    await putVerdict(kv.asKv(), TOKEN, passingVerdict);
    const app = createTestApp(db, kv);
    const cookie = await sessionCookie("user-1");

    await app.request(
      "/dashboard/domain/1/selector-from-inbox",
      postForm(cookie, { token: TOKEN, selector: "evil-selector" }),
    );

    expect(store.get(1)?.dkim_selectors).toBe("selector1");
  });

  it("rejects with 400 when DKIM did not pass", async () => {
    const { db, store } = makeDb([makeDomain()]);
    const kv = new FakeKV();
    await putVerdict(kv.asKv(), TOKEN, { ...passingVerdict, dkim: "fail" });
    const app = createTestApp(db, kv);
    const cookie = await sessionCookie("user-1");

    const res = await app.request(
      "/dashboard/domain/1/selector-from-inbox",
      postForm(cookie, { token: TOKEN }),
    );

    expect(res.status).toBe(400);
    expect(await res.text()).toBe("DKIM fail");
    expect(store.get(1)?.dkim_selectors).toBeNull();
  });

  it("rejects with 400 when the DKIM signing domain does not align (d= mismatch)", async () => {
    const { db, store } = makeDb([makeDomain()]);
    const kv = new FakeKV();
    await putVerdict(kv.asKv(), TOKEN, {
      ...passingVerdict,
      dkim_domain: "unrelated.com",
    });
    const app = createTestApp(db, kv);
    const cookie = await sessionCookie("user-1");

    const res = await app.request(
      "/dashboard/domain/1/selector-from-inbox",
      postForm(cookie, { token: TOKEN }),
    );

    expect(res.status).toBe(400);
    expect(await res.text()).toBe("d= mismatch");
    expect(store.get(1)?.dkim_selectors).toBeNull();
  });

  it("rejects with 400 when the domain belongs to a different user", async () => {
    const { db, store } = makeDb([makeDomain({ user_id: "someone-else" })]);
    const kv = new FakeKV();
    await putVerdict(kv.asKv(), TOKEN, passingVerdict);
    const app = createTestApp(db, kv);
    const cookie = await sessionCookie("user-1");

    const res = await app.request(
      "/dashboard/domain/1/selector-from-inbox",
      postForm(cookie, { token: TOKEN }),
    );

    expect(res.status).toBe(400);
    expect(await res.text()).toBe("not your domain");
    expect(store.get(1)?.dkim_selectors).toBeNull();
  });

  it("rejects with 400 for an unknown/expired token (no signature)", async () => {
    const { db, store } = makeDb([makeDomain()]);
    const kv = new FakeKV();
    const app = createTestApp(db, kv);
    const cookie = await sessionCookie("user-1");

    const res = await app.request(
      "/dashboard/domain/1/selector-from-inbox",
      postForm(cookie, { token: TOKEN }),
    );

    expect(res.status).toBe(400);
    expect(await res.text()).toBe("no signature");
    expect(store.get(1)?.dkim_selectors).toBeNull();
  });

  it("rejects with 400 for a duplicate selector and saves nothing new", async () => {
    const { db, store } = makeDb([makeDomain({ dkim_selectors: "selector1" })]);
    const kv = new FakeKV();
    await putVerdict(kv.asKv(), TOKEN, passingVerdict);
    const app = createTestApp(db, kv);
    const cookie = await sessionCookie("user-1");

    const res = await app.request(
      "/dashboard/domain/1/selector-from-inbox",
      postForm(cookie, { token: TOKEN }),
    );

    expect(res.status).toBe(400);
    expect(await res.text()).toBe("selector already saved");
    expect(store.get(1)?.dkim_selectors).toBe("selector1");
  });

  it("rejects with 400 once the domain is at MAX_SELECTORS (over-cap)", async () => {
    const atCap = Array.from({ length: 16 }, (_, i) => `sel${i}`).join(",");
    const { db, store } = makeDb([makeDomain({ dkim_selectors: atCap })]);
    const kv = new FakeKV();
    await putVerdict(kv.asKv(), TOKEN, passingVerdict);
    const app = createTestApp(db, kv);
    const cookie = await sessionCookie("user-1");

    const res = await app.request(
      "/dashboard/domain/1/selector-from-inbox",
      postForm(cookie, { token: TOKEN }),
    );

    expect(res.status).toBe(400);
    expect(await res.text()).toBe("selector limit reached");
    expect(store.get(1)?.dkim_selectors).toBe(atCap);
  });
});
