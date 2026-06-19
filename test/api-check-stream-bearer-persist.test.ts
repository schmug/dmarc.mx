/**
 * Regression: bearer-authenticated /api/check/stream must persist scan_history
 * on cache hits, matching GET /api/check. Without this, a Pro user's watched
 * domain stays stale when the stream endpoint replays a cached result.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

const CACHED_SCAN = {
  domain: "watched.example.com",
  timestamp: "2026-01-01T00:00:00.000Z",
  grade: "F" as const,
  breakdown: {
    grade: "F" as const,
    tier: "F" as const,
    tierReason: "No DMARC record",
    modifier: 0,
    modifierLabel: "",
    score: 0,
    maxScore: 100,
    factors: [{ name: "dmarc", status: "fail", weight: 1 }],
    recommendations: [],
    protocolSummaries: {
      dmarc: { status: "fail" as const, summary: "No record" },
      spf: { status: "fail" as const, summary: "No record" },
      dkim: { status: "fail" as const, summary: "No selectors" },
      bimi: { status: "fail" as const, summary: "No record" },
      mta_sts: { status: "fail" as const, summary: "Not configured" },
    },
  },
  summary: {
    mx_records: 0,
    mx_providers: [] as string[],
    dmarc_policy: null,
    spf_result: "fail" as const,
    spf_lookups: "0/10",
    dkim_selectors_found: 0,
    bimi_enabled: false,
    mta_sts_mode: null,
  },
  protocols: {
    mx: {
      status: "info" as const,
      records: [],
      providers: [],
      validations: [],
    },
    dmarc: {
      status: "fail" as const,
      record: null,
      tags: null,
      validations: [],
    },
    spf: {
      status: "fail" as const,
      record: null,
      lookups_used: 0,
      lookup_limit: 10,
      include_tree: null,
      validations: [],
    },
    dkim: { status: "fail" as const, selectors: {}, validations: [] },
    bimi: {
      status: "fail" as const,
      record: null,
      tags: null,
      validations: [],
    },
    mta_sts: {
      status: "fail" as const,
      dns_record: null,
      policy: null,
      validations: [],
    },
    security_txt: {
      status: "info" as const,
      source_url: null,
      signed: false,
      fields: null,
      validations: [],
    },
    tls_rpt: {
      status: "info" as const,
      record: null,
      tags: null,
      validations: [],
    },
    dnssec: {
      status: "info" as const,
      signed: false,
      validated: false,
      validations: [],
    },
    dane: {
      status: "info" as const,
      hosts: [],
      validations: [],
    },
  },
};

interface FakeDomain {
  id: number;
  user_id: string;
  domain: string;
}

let domainStore: FakeDomain[];
let batchCalls: number;
const waitUntilTasks: Array<Promise<unknown>> = [];

function makeDb(): D1Database {
  type Bound = {
    sql: string;
    params: unknown[];
    run: () => Promise<{ success: true }>;
    first: <T>() => Promise<T | null>;
  };

  const makeBound = (sql: string, params: unknown[]): Bound => ({
    sql,
    params,
    run: async () => ({ success: true }),
    first: async <T>() => {
      if (/SELECT \* FROM domains WHERE user_id = \? AND domain/i.test(sql)) {
        const row = domainStore.find(
          (d) => d.user_id === params[0] && d.domain === params[1],
        );
        return (row ?? null) as T | null;
      }
      return null as T | null;
    },
  });

  return {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => makeBound(sql, params),
    }),
    batch: async (stmts: Bound[]) => {
      batchCalls += 1;
      for (const stmt of stmts) {
        await stmt.run();
      }
      return stmts.map(() => ({ success: true }));
    },
  } as unknown as D1Database;
}

const { app } = await import("../src/index.js");
const { drainSSE } = await import("./helpers/drain-sse.js");

function fetchStream(domain: string) {
  const req = new Request(
    `http://local/api/check/stream?domain=${encodeURIComponent(domain)}`,
    { headers: { Authorization: "Bearer dmk_test" } },
  );
  return app.fetch(
    req,
    { DB: makeDb() } as never,
    {
      waitUntil: (p: Promise<unknown>) => {
        waitUntilTasks.push(p);
      },
      passThroughOnException: () => {},
    } as ExecutionContext,
  );
}

beforeEach(async () => {
  bearerStub = { userId: "user-1", keyId: "key-1" };
  domainStore = [{ id: 42, user_id: "user-1", domain: "watched.example.com" }];
  batchCalls = 0;
  waitUntilTasks.length = 0;
  vi.clearAllMocks();
  const { getCachedScan } = await import("../src/cache.js");
  vi.mocked(getCachedScan).mockResolvedValue(CACHED_SCAN as never);
});

afterEach(async () => {
  await Promise.allSettled(waitUntilTasks);
});

describe("GET /api/check/stream bearer persistence on cache hit", () => {
  it("records scan_history for a watched domain when replaying cache", async () => {
    const res = await fetchStream("watched.example.com");
    await drainSSE(res);
    await Promise.allSettled(waitUntilTasks);
    expect(batchCalls).toBe(1);
  });

  it("does not record when the domain is not on the user's watchlist", async () => {
    domainStore = [];
    const res = await fetchStream("watched.example.com");
    await drainSSE(res);
    await Promise.allSettled(waitUntilTasks);
    expect(batchCalls).toBe(0);
  });
});
