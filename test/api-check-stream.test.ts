/**
 * Tests for GET /api/check/stream — SSE event-stream contract.
 *
 * The route streams per-protocol scan results as Server-Sent Events and
 * terminates with a `done` event carrying the final grade and rendered HTML.
 * The SSE framing layer (event boundaries, `event:`/`data:` headers, terminal
 * event shape) is what these tests exercise.
 *
 * SSE event shape emitted by this route:
 *   - event: "protocol" — per-protocol card (data: { id: ProtocolId, html: string })
 *   - event: "done"     — final grade + HTML (data: { grade, headerHtml, footerHtml })
 *
 * Error path: invalid/missing domain → 400 JSON response (stream never opened).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { app } from "../src/index.js";
import { _memoryStore } from "../src/rate-limit.js";
import { drainSSE } from "./helpers/drain-sse.js";

// ─── Module mocks ────────────────────────────────────────────────────────────

vi.mock("../src/cache.js", () => ({
  getCachedScan: vi.fn().mockResolvedValue(null),
  setCachedScan: vi.fn().mockReturnValue(undefined),
}));

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn().mockResolvedValue(null),
  queryMx: vi.fn().mockResolvedValue(null),
}));

// Re-export the real scanStreaming wrapped in a vi.fn() spy so tests can
// introspect calls without changing behaviour.
vi.mock("../src/orchestrator.js", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("../src/orchestrator.js")>();
  return {
    ...original,
    scanStreaming: vi.fn(original.scanStreaming),
  };
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Protocol IDs the route knows about and must stream. */
const PROTOCOL_IDS = new Set([
  "mx",
  "dmarc",
  "spf",
  "dkim",
  "bimi",
  "mta_sts",
  "security_txt",
]);

/** SSE event names the route emits. */
const VALID_SSE_EVENT_NAMES = new Set(["protocol", "done"]);

/**
 * Dispatch a request to the Hono app with a minimal executionCtx so that
 * `c.executionCtx.waitUntil(...)` calls inside route handlers don't throw.
 */
function fetchApp(path: string): Promise<Response> {
  const req = new Request(`http://localhost${path}`);
  const mockCtx = {
    waitUntil: (_p: Promise<unknown>) => {},
    passThroughOnException: () => {},
  } as ExecutionContext;
  return app.fetch(req, {}, mockCtx);
}

/** Wipe the rate-limit bucket between tests (all share the "unknown" IP). */
beforeEach(() => {
  _memoryStore.clear();
});

// ─── Happy-path tests ─────────────────────────────────────────────────────────

describe("GET /api/check/stream — happy path", () => {
  it("returns 200 with content-type text/event-stream", async () => {
    const res = await fetchApp("/api/check/stream?domain=example.com");
    expect(res.status).toBe(200);
    const ct = res.headers.get("content-type") ?? "";
    expect(ct).toContain("text/event-stream");
  });

  it("each SSE event has a known event name", async () => {
    const res = await fetchApp("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    expect(events.length).toBeGreaterThan(0);
    for (const evt of events) {
      expect(
        VALID_SSE_EVENT_NAMES,
        `unexpected event name "${evt.event}"`,
      ).toContain(evt.event);
    }
  });

  it("each event data parses as valid JSON", async () => {
    const res = await fetchApp("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    for (const evt of events) {
      expect(
        () => JSON.parse(evt.data),
        `data for event "${evt.event}" must be JSON`,
      ).not.toThrow();
    }
  });

  it("protocol events carry a valid protocol id and html string", async () => {
    const res = await fetchApp("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    const protocolEvents = events.filter((e) => e.event === "protocol");
    expect(protocolEvents.length).toBeGreaterThan(0);
    for (const evt of protocolEvents) {
      const payload = JSON.parse(evt.data) as { id: string; html: string };
      expect(PROTOCOL_IDS, `unknown protocol id "${payload.id}"`).toContain(
        payload.id,
      );
      expect(typeof payload.html).toBe("string");
      expect(payload.html.length).toBeGreaterThan(0);
    }
  });

  it("done event arrives last in the stream", async () => {
    const res = await fetchApp("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    const last = events[events.length - 1];
    expect(last?.event).toBe("done");
  });

  it("done event carries grade, headerHtml, footerHtml", async () => {
    const res = await fetchApp("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    const doneEvt = events.find((e) => e.event === "done");
    expect(doneEvt).toBeDefined();
    // biome-ignore lint/style/noNonNullAssertion: guarded by toBeDefined() above
    const payload = JSON.parse(doneEvt!.data) as {
      grade: string;
      headerHtml: string;
      footerHtml: string;
    };
    expect(typeof payload.grade).toBe("string");
    expect(payload.grade.length).toBeGreaterThan(0);
    expect(typeof payload.headerHtml).toBe("string");
    expect(typeof payload.footerHtml).toBe("string");
  });

  it("stream contains exactly one done event", async () => {
    const res = await fetchApp("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    const doneEvents = events.filter((e) => e.event === "done");
    expect(doneEvents).toHaveLength(1);
  });

  it("no duplicate protocol events for the same protocol id", async () => {
    const res = await fetchApp("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    const protocolEvents = events.filter((e) => e.event === "protocol");
    const seen = new Set<string>();
    for (const evt of protocolEvents) {
      const { id } = JSON.parse(evt.data) as { id: string };
      expect(seen.has(id), `duplicate protocol event for id "${id}"`).toBe(
        false,
      );
      seen.add(id);
    }
  });

  it("every expected protocol id appears in the stream", async () => {
    const res = await fetchApp("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    const received = new Set(
      events
        .filter((e) => e.event === "protocol")
        .map((e) => (JSON.parse(e.data) as { id: string }).id),
    );
    for (const id of PROTOCOL_IDS) {
      expect(received, `expected protocol id "${id}" in stream`).toContain(id);
    }
  });
});

// ─── Error-path tests ─────────────────────────────────────────────────────────

describe("GET /api/check/stream — error path", () => {
  it("returns 400 JSON for missing domain — stream never opens", async () => {
    const res = await fetchApp("/api/check/stream");
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(typeof body.error).toBe("string");
    expect(body.error.length).toBeGreaterThan(0);
  });

  it("returns 400 JSON for invalid domain (no dot)", async () => {
    const res = await fetchApp("/api/check/stream?domain=notadomain");
    // normalizeDomain rejects strings without a dot
    expect(res.status).toBe(400);
  });

  it("returns 400 JSON for XSS domain payload — no payload reflection", async () => {
    const res = await fetchApp(
      "/api/check/stream?domain=example.com%27%3Balert(1)%3B%27",
    );
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).not.toContain("alert(1)");
  });
});

// ─── DKIM custom selectors ────────────────────────────────────────────────────

describe("GET /api/check/stream — DKIM custom selectors", () => {
  it("honors the selectors query param — more selectors checked when custom ones are passed", async () => {
    // queryTxt is mocked to return null for all lookups.
    // The DKIM card renders the selector count; adding custom selectors
    // increases the total above the 36 defaults, visible in the "+N more" count.
    const resDefault = await fetchApp("/api/check/stream?domain=example.com");
    const eventsDefault = await drainSSE(resDefault);
    const dkimDefault = eventsDefault.find(
      (e) =>
        e.event === "protocol" &&
        (JSON.parse(e.data) as { id: string }).id === "dkim",
    );
    // biome-ignore lint/style/noNonNullAssertion: find result checked by toBeDefined guard below
    const htmlDefault = JSON.parse(dkimDefault!.data).html as string;
    // Extract "+N more" count from default scan (36 common selectors - 6 shown = 30 more)
    const defaultMatch = htmlDefault.match(/\+(\d+) more not found/);
    const defaultMore = defaultMatch ? Number(defaultMatch[1]) : 0;

    _memoryStore.clear(); // reset rate limit

    const resCustom = await fetchApp(
      "/api/check/stream?domain=example.com&selectors=custom1,custom2",
    );
    const eventsCustom = await drainSSE(resCustom);
    const dkimCustom = eventsCustom.find(
      (e) =>
        e.event === "protocol" &&
        (JSON.parse(e.data) as { id: string }).id === "dkim",
    );
    expect(dkimCustom).toBeDefined();
    // biome-ignore lint/style/noNonNullAssertion: guarded by toBeDefined() above
    const htmlCustom = JSON.parse(dkimCustom!.data).html as string;
    const customMatch = htmlCustom.match(/\+(\d+) more not found/);
    const customMore = customMatch ? Number(customMatch[1]) : 0;

    // 2 custom selectors added → 2 more in the "+N more" count
    expect(customMore).toBe(defaultMore + 2);
  });

  it("with default selectors — dkim protocol event is present", async () => {
    const res = await fetchApp("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    const dkimEvt = events.find(
      (e) =>
        e.event === "protocol" &&
        (JSON.parse(e.data) as { id: string }).id === "dkim",
    );
    expect(dkimEvt).toBeDefined();
  });

  it("invalid selectors stripped — stream completes without XSS reflection", async () => {
    // "x';alert(1);'" has a single quote — parseSelectors drops it.
    // The stream must still complete, and the payload must not appear in any html.
    const res = await fetchApp(
      "/api/check/stream?domain=example.com&selectors=good,x%27%3Balert(1)%3B%27",
    );
    expect(res.status).toBe(200);
    const events = await drainSSE(res);
    expect(events.find((e) => e.event === "done")).toBeDefined();

    const allHtml = events
      .filter((e) => e.event === "protocol")
      .map((e) => (JSON.parse(e.data) as { id: string; html: string }).html)
      .join("");
    expect(allHtml).not.toContain("alert(1)");
  });
});

// ─── Stream structure integrity ───────────────────────────────────────────────

describe("GET /api/check/stream — stream structure", () => {
  it("all protocol events precede the done event", async () => {
    const res = await fetchApp("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    const doneIdx = events.findIndex((e) => e.event === "done");
    expect(doneIdx).toBeGreaterThan(0); // done is not first

    for (const evt of events.filter((e) => e.event === "protocol")) {
      const idx = events.indexOf(evt);
      expect(
        idx,
        `protocol event at index ${idx} must precede done at ${doneIdx}`,
      ).toBeLessThan(doneIdx);
    }
  });

  it("two sequential scans both produce complete streams", async () => {
    const res1 = await fetchApp("/api/check/stream?domain=example.com");
    const events1 = await drainSSE(res1);
    expect(events1.find((e) => e.event === "done")).toBeDefined();

    const res2 = await fetchApp("/api/check/stream?domain=other.example");
    const events2 = await drainSSE(res2);
    expect(events2.find((e) => e.event === "done")).toBeDefined();
  });
});
