import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// resolveBearer is stubbed before importing app to keep the route's bearer
// signal independent of api-key cryptography in this test file.
let bearerStub: { userId: string; keyId: string } | null = null;

vi.mock("../src/auth/api-key.js", async () => {
  const actual = await vi.importActual<typeof import("../src/auth/api-key.js")>(
    "../src/auth/api-key.js",
  );
  return {
    ...actual,
    resolveBearer: vi.fn(async () => bearerStub),
  };
});

// scan() calls real DNS otherwise — stub it so tests don't depend on the
// network or the orchestrator's compatibility flags.
vi.mock("../src/orchestrator.js", async () => {
  const actual = await vi.importActual<typeof import("../src/orchestrator.js")>(
    "../src/orchestrator.js",
  );
  return {
    ...actual,
    scan: vi.fn(async (domain: string) => ({
      domain,
      timestamp: "2026-04-19T00:00:00.000Z",
      grade: "B",
      breakdown: {
        grade: "B",
        tier: "B",
        tierReason: "test",
        modifier: 0,
        modifierLabel: "",
        factors: [{ name: "dmarc", status: "pass", weight: 1 }],
        recommendations: [],
        protocolSummaries: {},
      },
      summary: {
        mx_records: 0,
        mx_providers: [],
        dmarc_policy: "none",
      },
      protocols: {
        mx: { status: "info" },
        dmarc: { status: "pass" },
        spf: { status: "pass" },
        dkim: { status: "pass" },
        bimi: { status: "pass" },
        mta_sts: { status: "pass" },
      },
    })),
  };
});

const { app } = await import("../src/index.js");

interface FakeDomain {
  id: number;
  user_id: string;
  domain: string;
  is_free: number;
  scan_frequency: string;
  last_scanned_at: number | null;
  last_grade: string | null;
}

interface FakeSubscription {
  user_id: string;
  status: string;
}

let domainStore: FakeDomain[];
let subStore: FakeSubscription[];
let overrideStore: Map<string, number | null>;
let nextId: number;

// Minimal D1 mock supporting subscriptions lookup, domain CRUD, and the
// recordScan batch (INSERT scan_history + UPDATE domains).
function makeDb(): D1Database {
  type Bound = {
    sql: string;
    params: unknown[];
    run: () => Promise<{ success: true; meta: { changes: number } }>;
    first: <T>() => Promise<T | null>;
    all: <T>() => Promise<{ results: T[] }>;
  };

  const applyWrite = async (sql: string, params: unknown[]) => {
    if (/^INSERT INTO domains/i.test(sql)) {
      const [userId, domain, isFree, frequency] = params as [
        string,
        string,
        number,
        string,
      ];
      domainStore.push({
        id: nextId++,
        user_id: userId,
        domain,
        is_free: isFree,
        scan_frequency: frequency,
        last_scanned_at: null,
        last_grade: null,
      });
    } else if (/^UPDATE domains SET last_grade/i.test(sql)) {
      const [grade, scannedAt, domainId] = params as [string, number, number];
      const row = domainStore.find((d) => d.id === domainId);
      if (row) {
        row.last_grade = grade;
        row.last_scanned_at = scannedAt;
      }
    }
    return { success: true as const, meta: { changes: 1 } };
  };

  const makeBound = (sql: string, params: unknown[]): Bound => ({
    sql,
    params,
    run: () => applyWrite(sql, params),
    first: async <T>() => {
      if (sql.includes("SELECT status FROM subscriptions")) {
        const sub = subStore.find((s) => s.user_id === params[0]);
        return (sub ? { status: sub.status } : null) as T | null;
      }
      if (sql.includes("SELECT COUNT(*) AS n FROM domains")) {
        const userId = params[0] as string;
        const n = domainStore.filter((d) => d.user_id === userId).length;
        return { n } as T;
      }
      if (sql.includes("SELECT max_domains_override FROM users")) {
        const userId = params[0] as string;
        const override = overrideStore.get(userId) ?? null;
        return { max_domains_override: override } as T;
      }
      if (/SELECT \* FROM domains WHERE user_id = \? AND domain/i.test(sql)) {
        return (domainStore.find(
          (d) => d.user_id === params[0] && d.domain === params[1],
        ) ?? null) as T | null;
      }
      return null as T | null;
    },
    all: async <T>() => {
      if (
        /SELECT domain FROM domains WHERE user_id = \? AND domain IN/i.test(sql)
      ) {
        const userId = params[0] as string;
        const names = params.slice(1) as string[];
        const results = domainStore
          .filter((d) => d.user_id === userId && names.includes(d.domain))
          .map((d) => ({ domain: d.domain }));
        return { results: results as T[] };
      }
      return { results: [] as T[] };
    },
  });

  return {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => makeBound(sql, params),
    }),
    batch: async (stmts: Bound[]) => {
      const out = [];
      for (const stmt of stmts) {
        out.push(await stmt.run());
      }
      return out;
    },
  } as unknown as D1Database;
}

function fetchBulk(body: unknown, init: RequestInit = {}) {
  return app.request(
    "/api/bulk-scan",
    {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
      body: typeof body === "string" ? body : JSON.stringify(body),
      ...init,
    },
    {
      DB: makeDb(),
      RATE_LIMIT_KV: undefined,
    } as unknown as Record<string, unknown>,
    {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as ExecutionContext,
  );
}

beforeEach(() => {
  domainStore = [];
  subStore = [];
  overrideStore = new Map();
  nextId = 1;
  bearerStub = null;
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("POST /api/bulk-scan", () => {
  it("returns 401 when no bearer is presented", async () => {
    const res = await fetchBulk({ domains: ["example.com"] });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/bearer/i);
  });

  it("returns 402 for a free-plan bearer (Pro gate)", async () => {
    bearerStub = { userId: "user_free", keyId: "k1" };
    // No subscription row → free plan.
    const res = await fetchBulk({ domains: ["example.com"] });
    expect(res.status).toBe(402);
    const body = (await res.json()) as { error: string; upgrade?: string };
    expect(body.error).toMatch(/Pro/i);
    expect(body.upgrade).toContain("/dashboard/billing/subscribe");
  });

  it("returns 200 with results for a Pro bearer (happy path)", async () => {
    bearerStub = { userId: "user_pro", keyId: "k1" };
    subStore.push({ user_id: "user_pro", status: "active" });
    const res = await fetchBulk({ domains: ["a.example", "b.example"] });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      accepted: number;
      rejected: number;
      results: Array<{ domain: string; status: string; grade?: string }>;
    };
    expect(body.accepted).toBe(2);
    expect(body.rejected).toBe(0);
    expect(body.results.map((r) => r.status).sort()).toEqual([
      "scanned",
      "scanned",
    ]);
    expect(body.results.every((r) => r.grade === "B")).toBe(true);
  });

  it("returns 400 for invalid JSON body", async () => {
    bearerStub = { userId: "user_pro", keyId: "k1" };
    subStore.push({ user_id: "user_pro", status: "active" });
    const res = await fetchBulk("not json", {});
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/Invalid JSON/i);
  });

  it("returns 400 when body lacks a `domains` array", async () => {
    bearerStub = { userId: "user_pro", keyId: "k1" };
    subStore.push({ user_id: "user_pro", status: "active" });
    const res = await fetchBulk({ wrong: "shape" });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/domains/i);
  });

  it("returns 400 when entries are not strings", async () => {
    bearerStub = { userId: "user_pro", keyId: "k1" };
    subStore.push({ user_id: "user_pro", status: "active" });
    const res = await fetchBulk({ domains: ["ok.example", 123] });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/strings/i);
  });

  it("returns 400 with cap details when domains.length > 100", async () => {
    bearerStub = { userId: "user_pro", keyId: "k1" };
    subStore.push({ user_id: "user_pro", status: "active" });
    const tooMany = Array.from({ length: 101 }, (_, i) => `d${i}.example`);
    const res = await fetchBulk({ domains: tooMany });
    expect(res.status).toBe(400);
    const body = (await res.json()) as {
      error: string;
      cap: number;
      in_band_cap: number;
    };
    expect(body.cap).toBe(100);
    expect(body.in_band_cap).toBe(30);
    expect(body.error).toMatch(/101.*100/);
  });

  it("treats a cancelled subscription as free (returns 402)", async () => {
    bearerStub = { userId: "user_was_pro", keyId: "k1" };
    subStore.push({ user_id: "user_was_pro", status: "canceled" });
    const res = await fetchBulk({ domains: ["example.com"] });
    expect(res.status).toBe(402);
  });

  it("respects max_domains_override when the default Pro cap is exhausted", async () => {
    bearerStub = { userId: "user_pro", keyId: "k1" };
    subStore.push({ user_id: "user_pro", status: "active" });
    overrideStore.set("user_pro", 50);
    for (let i = 0; i < 25; i++) {
      domainStore.push({
        id: nextId++,
        user_id: "user_pro",
        domain: `d${i}.example`,
        is_free: 0,
        scan_frequency: "weekly",
        last_scanned_at: 1700000000,
        last_grade: "A",
      });
    }
    const res = await fetchBulk({ domains: ["new26.example"] });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      accepted: number;
      results: Array<{ domain: string; status: string; error?: string }>;
    };
    expect(body.accepted).toBe(1);
    expect(body.results).toEqual([
      { domain: "new26.example", status: "scanned", grade: "B" },
    ]);
  });
});
