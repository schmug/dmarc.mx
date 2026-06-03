/**
 * Tests for the /api/check/stream SSE endpoint.
 *
 * The endpoint streams protocol analysis results as Server-Sent Events.
 * Each event has one of these names:
 *   - "protocol" — one event per protocol, emitted as soon as each analyzer
 *                  completes. Data is { id: ProtocolId, html: string }.
 *   - "done"     — final event with grade and rendered header/footer HTML.
 *                  Data is { grade: string, headerHtml: string, footerHtml: string }.
 *
 * Implementation note — cache-hit vs live paths:
 * Hono's streamSSE() returns the response before the stream callback finishes.
 * The live scan path must `await` every `stream.writeSSE()` (protocol + done)
 * before the handler returns, or the Hono test client can drain an empty body.
 * Cache-hit replay has always awaited each write; live-path coverage lives in
 * the "live scan path (cache miss)" describe block via a mocked scanStreaming.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { app } from "../src/index.js";
import { PROTOCOL_LABEL, scanStreaming } from "../src/orchestrator.js";
import { _memoryStore } from "../src/rate-limit.js";
import { drainSSE } from "./helpers/drain-sse.js";

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock("../src/cache.js", () => ({
  getCachedScan: vi.fn().mockResolvedValue(null),
  setCachedScan: vi.fn().mockReturnValue(undefined),
}));

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn().mockResolvedValue(null),
  queryMx: vi.fn().mockResolvedValue(null),
}));

vi.mock("../src/orchestrator.js", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("../src/orchestrator.js")>();
  return {
    ...original,
    scanStreaming: vi.fn(original.scanStreaming),
  };
});

vi.stubGlobal(
  "fetch",
  vi.fn().mockResolvedValue({ ok: false, text: async () => "" } as Response),
);

// ---------------------------------------------------------------------------
// Shared fixture — a minimal ScanResult for cache-hit path tests.
// The cache-hit replay path uses `await stream.writeSSE()` throughout, so
// drainSSE() reliably captures all events including `done`.
// ---------------------------------------------------------------------------
const CACHED_SCAN = {
  domain: "test.example.com",
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
    factors: [],
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

// ---------------------------------------------------------------------------
// Known protocol IDs the route must emit.
//
// Derived from `PROTOCOL_LABEL` (a `Record<ProtocolId, string>` — the canonical
// exhaustive id source, also used by the #454 skeleton guard) rather than a
// hand-listed set. Adding a protocol to the `ProtocolId` union forces a new
// `PROTOCOL_LABEL` key, which flows into this set, which makes the
// "emits a protocol event for every known protocol" assertions exercise it.
// This is what the stale 8-entry literal failed to do for dnssec/dane (#451).
// ---------------------------------------------------------------------------
const KNOWN_PROTOCOL_IDS = new Set<string>(Object.keys(PROTOCOL_LABEL));

// ---------------------------------------------------------------------------
// Per-test setup
// ---------------------------------------------------------------------------
beforeEach(async () => {
  _memoryStore.clear();
  vi.clearAllMocks();

  // Default: cache miss — requestWithCacheHit() overrides this per-call.
  const { getCachedScan } = await import("../src/cache.js");
  vi.mocked(getCachedScan).mockResolvedValue(null);

  // Restore setCachedScan to return undefined so the route's
  // `if (pendingCacheWrite)` guard skips executionCtx.waitUntil().
  const { setCachedScan } = await import("../src/cache.js");
  vi.mocked(setCachedScan).mockReturnValue(undefined);

  // Restore DNS mocks to null (NXDOMAIN) after clearAllMocks resets them.
  const { queryTxt, queryMx } = await import("../src/dns/client.js");
  vi.mocked(queryTxt).mockResolvedValue(null);
  vi.mocked(queryMx).mockResolvedValue(null);

  // Restore fetch stub.
  vi.mocked(fetch).mockResolvedValue({
    ok: false,
    text: async () => "",
  } as Response);
});

// ---------------------------------------------------------------------------
// Helper: return a cache-hit response for test.example.com
// ---------------------------------------------------------------------------
async function requestWithCacheHit(url: string): Promise<Response> {
  const { getCachedScan } = await import("../src/cache.js");
  vi.mocked(getCachedScan).mockResolvedValueOnce(CACHED_SCAN as never);
  return app.request(url);
}

// ---------------------------------------------------------------------------
// 1. Happy path — verified via the cache-hit replay branch, which uses
//    `await stream.writeSSE()` throughout and reliably flushes all events.
// ---------------------------------------------------------------------------
describe("GET /api/check/stream — happy path (cache-hit replay)", () => {
  it("returns 200 with text/event-stream content type", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com",
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/event-stream");
  });

  it("emits only events with recognized names", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com",
    );
    const frames = await drainSSE(res);
    const validNames = new Set(["protocol", "done", "error"]);
    for (const { event } of frames) {
      expect(validNames.has(event), `unexpected event name: ${event}`).toBe(
        true,
      );
    }
  });

  it("emits a data payload that parses as JSON for every event", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com",
    );
    const frames = await drainSSE(res);
    expect(frames.length).toBeGreaterThan(0);
    for (const { data } of frames) {
      expect(
        () => JSON.parse(data),
        `data is not valid JSON: ${data}`,
      ).not.toThrow();
    }
  });

  it("emits a 'protocol' event for every known protocol", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com",
    );
    const frames = await drainSSE(res);
    const protocolIds = frames
      .filter((f) => f.event === "protocol")
      .map((f) => (JSON.parse(f.data) as { id: string }).id);

    for (const id of KNOWN_PROTOCOL_IDS) {
      expect(protocolIds, `missing protocol event for: ${id}`).toContain(id);
    }
  });

  it("does not emit duplicate protocol events for the same protocol", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com",
    );
    const frames = await drainSSE(res);
    const protocolIds = frames
      .filter((f) => f.event === "protocol")
      .map((f) => (JSON.parse(f.data) as { id: string }).id);

    const seen = new Set<string>();
    for (const id of protocolIds) {
      expect(seen.has(id), `duplicate protocol event for: ${id}`).toBe(false);
      seen.add(id);
    }
  });

  it("emits protocol events with an 'id' and 'html' field in the data", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com",
    );
    const frames = await drainSSE(res);
    const protocolFrames = frames.filter((f) => f.event === "protocol");
    expect(protocolFrames.length).toBeGreaterThan(0);
    for (const { data } of protocolFrames) {
      const parsed = JSON.parse(data) as { id?: unknown; html?: unknown };
      expect(typeof parsed.id).toBe("string");
      expect(typeof parsed.html).toBe("string");
    }
  });

  it("emits protocol events only for known protocol IDs", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com",
    );
    const frames = await drainSSE(res);
    const protocolIds = frames
      .filter((f) => f.event === "protocol")
      .map((f) => (JSON.parse(f.data) as { id: string }).id);

    for (const id of protocolIds) {
      expect(
        KNOWN_PROTOCOL_IDS.has(id),
        `unknown protocol id in event: ${id}`,
      ).toBe(true);
    }
  });

  it("emits a final 'done' event with grade, headerHtml, and footerHtml", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com",
    );
    const frames = await drainSSE(res);
    const doneFrames = frames.filter((f) => f.event === "done");
    expect(doneFrames).toHaveLength(1);

    const doneData = JSON.parse(doneFrames[0].data) as {
      grade?: unknown;
      headerHtml?: unknown;
      footerHtml?: unknown;
    };
    expect(typeof doneData.grade).toBe("string");
    expect(typeof doneData.headerHtml).toBe("string");
    expect(typeof doneData.footerHtml).toBe("string");
  });

  it("emits 'done' as the last event in the stream", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com",
    );
    const frames = await drainSSE(res);
    expect(frames.length).toBeGreaterThan(0);
    expect(frames[frames.length - 1].event).toBe("done");
  });

  it("done event grade matches the cached scan grade", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com",
    );
    const frames = await drainSSE(res);
    const doneFrame = frames.find((f) => f.event === "done");
    expect(doneFrame).toBeDefined();
    const doneData = JSON.parse(doneFrame?.data) as { grade: string };
    expect(doneData.grade).toBe(CACHED_SCAN.grade);
  });
});

// ---------------------------------------------------------------------------
// 1b. Cache-hit replay parity guard (#455)
//
// Mirrors the #454 skeleton guard (`test/streaming-skeleton.test.ts`): the
// cache-hit replay path must emit a `protocol` event for *every* ProtocolId the
// orchestrator can produce. `PROTOCOL_LABEL` is the canonical exhaustive id
// source, so adding a protocol to the `ProtocolId` union forces a new key here
// — and unless that protocol is wired into both the replay iteration
// (`src/index.ts`) and the `CACHED_SCAN` fixture, this test fails. That is the
// failure that the stale 8-entry fixture/list silently swallowed for
// dnssec/dane (#451).
// ---------------------------------------------------------------------------
describe("GET /api/check/stream — cache-hit replay protocol parity", () => {
  for (const id of Object.keys(PROTOCOL_LABEL)) {
    it(`emits a 'protocol' event for the ${id} protocol on a cache hit`, async () => {
      const res = await requestWithCacheHit(
        "/api/check/stream?domain=test.example.com",
      );
      const frames = await drainSSE(res);
      const emittedIds = frames
        .filter((f) => f.event === "protocol")
        .map((f) => (JSON.parse(f.data) as { id: string }).id);
      expect(
        emittedIds,
        `cache-hit replay dropped protocol "${id}" — it is in PROTOCOL_LABEL but not emitted (check the replay loop in src/index.ts and the CACHED_SCAN fixture)`,
      ).toContain(id);
    });
  }
});

// ---------------------------------------------------------------------------
// 2. Live scan path — cache miss; protocol writes are awaited before `done`
// ---------------------------------------------------------------------------
describe("GET /api/check/stream — live scan path (cache miss)", () => {
  beforeEach(() => {
    vi.mocked(scanStreaming).mockImplementation(
      async (_domain, _selectors, onResult) => {
        for (const [id, result] of Object.entries(CACHED_SCAN.protocols)) {
          onResult(id as never, result as never);
        }
        return CACHED_SCAN as never;
      },
    );
  });

  it("emits every protocol event and a terminal done event", async () => {
    const res = await app.request("/api/check/stream?domain=test.example.com");
    expect(res.status).toBe(200);
    const frames = await drainSSE(res);
    const protocolIds = frames
      .filter((f) => f.event === "protocol")
      .map((f) => (JSON.parse(f.data) as { id: string }).id);

    for (const id of KNOWN_PROTOCOL_IDS) {
      expect(protocolIds, `missing protocol event for: ${id}`).toContain(id);
    }
    expect(frames.length).toBeGreaterThan(0);
    expect(frames[frames.length - 1].event).toBe("done");
  });
});

// ---------------------------------------------------------------------------
// 3. Invalid domain — route returns 400 before starting the SSE stream
// ---------------------------------------------------------------------------
describe("GET /api/check/stream — invalid domain", () => {
  it("returns 400 for a domain that fails normalization", async () => {
    const res = await app.request(
      "/api/check/stream?domain=not_a_valid_domain!!",
    );
    expect(res.status).toBe(400);
  });

  it("returns a JSON error body for an invalid domain", async () => {
    const res = await app.request(
      "/api/check/stream?domain=not_a_valid_domain!!",
    );
    const body = (await res.json()) as { error?: string };
    expect(typeof body.error).toBe("string");
    expect(body.error.length).toBeGreaterThan(0);
  });

  it("returns 400 when domain parameter is omitted", async () => {
    const res = await app.request("/api/check/stream");
    expect(res.status).toBe(400);
  });

  it("returns 400 for an empty domain parameter", async () => {
    const res = await app.request("/api/check/stream?domain=");
    expect(res.status).toBe(400);
  });

  it("does not return text/event-stream for an invalid domain", async () => {
    const res = await app.request(
      "/api/check/stream?domain=not_a_valid_domain!!",
    );
    const ct = res.headers.get("Content-Type") ?? "";
    expect(ct).not.toContain("text/event-stream");
  });
});

// ---------------------------------------------------------------------------
// 4. Custom DKIM selectors — forwarded to scanStreaming
// ---------------------------------------------------------------------------
describe("GET /api/check/stream — custom selectors", () => {
  it("returns 200 for a valid domain with custom selectors", async () => {
    const res = await app.request(
      "/api/check/stream?domain=test.example.com&selectors=google,microsoft",
    );
    expect(res.status).toBe(200);
  });

  it("passes the parsed selector list to scanStreaming", async () => {
    await app.request(
      "/api/check/stream?domain=test.example.com&selectors=google,microsoft",
    );
    // Give the async SSE callback a chance to run before inspecting the mock.
    await new Promise((r) => setTimeout(r, 50));
    expect(vi.mocked(scanStreaming)).toHaveBeenCalledWith(
      "test.example.com",
      ["google", "microsoft"],
      expect.any(Function),
      {},
    );
  });

  it("returns 200 and cache-hit stream includes dkim event with selectors param", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com&selectors=google,microsoft",
    );
    expect(res.status).toBe(200);
    const frames = await drainSSE(res);
    const protocolIds = frames
      .filter((f) => f.event === "protocol")
      .map((f) => (JSON.parse(f.data) as { id: string }).id);
    expect(protocolIds).toContain("dkim");
  });

  it("emits no duplicate protocol events when custom selectors are supplied", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com&selectors=google,microsoft",
    );
    const frames = await drainSSE(res);
    const protocolIds = frames
      .filter((f) => f.event === "protocol")
      .map((f) => (JSON.parse(f.data) as { id: string }).id);
    const unique = new Set(protocolIds);
    expect(unique.size).toBe(protocolIds.length);
  });

  it("all data payloads are valid JSON with custom selectors", async () => {
    const res = await requestWithCacheHit(
      "/api/check/stream?domain=test.example.com&selectors=google,microsoft",
    );
    const frames = await drainSSE(res);
    for (const { data } of frames) {
      expect(() => JSON.parse(data)).not.toThrow();
    }
  });
});
