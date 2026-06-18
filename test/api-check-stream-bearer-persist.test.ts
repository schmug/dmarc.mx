/**
 * Regression: GET /api/check/stream must persist bearer-authed scans on cache
 * hits, matching GET /api/check. Without this, a watched domain rescanned via
 * the SSE endpoint within the cache TTL never updates scan_history or
 * domains.last_* — dashboard grades stay stale up to 5 minutes.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { drainSSE } from "./helpers/drain-sse.js";

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

vi.mock("../src/cache.js", () => ({
  getCachedScan: vi.fn(),
  setCachedScan: vi.fn().mockReturnValue(undefined),
}));

vi.mock("../src/orchestrator.js", async () => {
  const actual = await vi.importActual<typeof import("../src/orchestrator.js")>(
    "../src/orchestrator.js",
  );
  return {
    ...actual,
    scanStreaming: vi.fn(),
  };
});

const CACHED_SCAN = {
  domain: "watched.example.com",
  timestamp: "2026-01-01T00:00:00.000Z",
  grade: "B",
  breakdown: {
    grade: "B",
    tier: "B",
    tierReason: "test",
    modifier: 0,
    modifierLabel: "",
    factors: [],
    recommendations: [],
    protocolSummaries: {},
  },
  summary: {
    mx_records: 1,
    mx_providers: ["Example"],
    dmarc_policy: "reject",
    spf_result: "pass",
    spf_lookups: "1/10",
    dkim_selectors_found: 1,
    bimi_enabled: false,
    mta_sts_mode: null,
  },
  protocols: {
    mx: { status: "info", records: [], providers: [], validations: [] },
    dmarc: { status: "pass", record: null, tags: null, validations: [] },
    spf: {
      status: "pass",
      record: null,
      lookups_used: 1,
      lookup_limit: 10,
      include_tree: null,
      validations: [],
    },
    dkim: { status: "pass", selectors: {}, validations: [] },
    bimi: { status: "fail", record: null, tags: null, validations: [] },
    mta_sts: {
      status: "fail",
      dns_record: null,
      policy: null,
      validations: [],
    },
    security_txt: {
      status: "info",
      source_url: null,
      signed: false,
      fields: null,
      validations: [],
    },
    tls_rpt: { status: "info", record: null, tags: null, validations: [] },
    dnssec: {
      status: "info",
      signed: false,
      validated: false,
      validations: [],
    },
    dane: { status: "info", hosts: [], validations: [] },
  },
};

function makeDb(
  writes: Array<{ sql: string; bindings: unknown[] }>,
): D1Database {
  type BoundStmt = {
    sql: string;
    params: unknown[];
    run: () => Promise<{ success: true; meta: { changes: number } }>;
    first: <T>() => Promise<T | null>;
    all: <T>() => Promise<{ results: T[] }>;
  };

  const applyWrite = async (sql: string, params: unknown[]) => {
    writes.push({ sql, bindings: params });
    return { success: true as const, meta: { changes: 1 } };
  };

  const makeBound = (sql: string, params: unknown[]): BoundStmt => ({
    sql,
    params,
    run: () => applyWrite(sql, params),
    first: async <T>() => {
      if (
        /SELECT \* FROM domains WHERE user_id = \? AND domain = \?/i.test(sql)
      ) {
        const userId = params[0] as string;
        const domain = params[1] as string;
        if (userId === "user_pro" && domain === "watched.example.com") {
          return {
            id: 42,
            user_id: userId,
            domain,
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: 1,
            last_grade: "C",
            created_at: 1,
          } as T;
        }
        return null;
      }
      if (/FROM subscriptions WHERE user_id = \?/i.test(sql)) {
        return { status: "active" } as T;
      }
      return null;
    },
    all: async () => ({ results: [] }),
  });

  return {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => makeBound(sql, params),
    }),
    batch: async (stmts: BoundStmt[]) => {
      for (const stmt of stmts) {
        await stmt.run();
      }
    },
  } as unknown as D1Database;
}

describe("GET /api/check/stream — bearer scan persistence on cache hit", () => {
  beforeEach(async () => {
    bearerStub = null;
    vi.clearAllMocks();
    const { getCachedScan } = await import("../src/cache.js");
    vi.mocked(getCachedScan).mockResolvedValue(CACHED_SCAN as never);
    const { _memoryStore } = await import("../src/rate-limit.js");
    _memoryStore.clear();
  });

  it("persists scan_history for a watched domain when replaying a cache hit", async () => {
    bearerStub = { userId: "user_pro", keyId: "k1" };
    const writes: Array<{ sql: string; bindings: unknown[] }> = [];
    const waitUntilTasks: Promise<unknown>[] = [];
    const { app } = await import("../src/index.js");

    const res = await app.fetch(
      new Request("http://local/api/check/stream?domain=watched.example.com", {
        headers: { "CF-Connecting-IP": "1.2.3.4" },
      }),
      { DB: makeDb(writes) },
      {
        waitUntil: (p: Promise<unknown>) => {
          waitUntilTasks.push(p);
        },
        passThroughOnException: () => {},
      } as ExecutionContext,
    );

    expect(res.status).toBe(200);
    await drainSSE(res);
    await Promise.all(waitUntilTasks);

    const historyWrites = writes.filter((w) =>
      /^INSERT INTO scan_history/i.test(w.sql),
    );
    expect(historyWrites.length).toBe(1);
    expect(historyWrites[0].bindings).toContain("B");
    expect(historyWrites[0].bindings).toContain(42);
  });
});
