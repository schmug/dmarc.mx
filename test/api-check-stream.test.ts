import { beforeEach, describe, expect, it, vi } from "vitest";
import { app } from "../src/index.js";
import { _memoryStore } from "../src/rate-limit.js";
import { drainSSE } from "./helpers/drain-sse.js";

vi.mock("../src/cache.js", () => ({
  getCachedScan: vi.fn().mockResolvedValue(null),
  setCachedScan: vi.fn(),
}));

vi.mock("../src/orchestrator.js", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("../src/orchestrator.js")>();
  return {
    ...original,
    scanStreaming: vi.fn(original.scanStreaming),
  };
});

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn().mockResolvedValue(null),
  queryMx: vi.fn().mockResolvedValue(null),
}));

// clearAllMocks resets call history but preserves mock implementations,
// so getCachedScan still returns null and scanStreaming wraps the original.
beforeEach(() => {
  _memoryStore.clear();
  vi.clearAllMocks();
});

const PROTOCOL_IDS = [
  "mx",
  "dmarc",
  "spf",
  "dkim",
  "bimi",
  "mta_sts",
  "security_txt",
] as const;

describe("GET /api/check/stream — happy path", () => {
  it("returns 200 with text/event-stream content-type", async () => {
    const res = await app.request("/api/check/stream?domain=example.com");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/event-stream");
  });

  it("emits one protocol event per analyzer", async () => {
    const res = await app.request("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    const protocolEvents = events.filter((e) => e.event === "protocol");
    expect(protocolEvents).toHaveLength(PROTOCOL_IDS.length);
  });

  it("emits exactly one done event", async () => {
    const res = await app.request("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    expect(events.filter((e) => e.event === "done")).toHaveLength(1);
  });

  it("done event is the last event in the stream", async () => {
    const res = await app.request("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    expect(events.at(-1)?.event).toBe("done");
  });

  it("done event data contains a grade field", async () => {
    const res = await app.request("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    const done = events.find((e) => e.event === "done");
    expect(done).toBeDefined();
    if (!done) return;
    const data = JSON.parse(done.data) as { grade: unknown };
    expect(typeof data.grade).toBe("string");
    expect((data.grade as string).length).toBeGreaterThan(0);
  });

  it("each protocol event parses as JSON with a valid id and non-empty html", async () => {
    const res = await app.request("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    for (const e of events.filter((ev) => ev.event === "protocol")) {
      const data = JSON.parse(e.data) as { id: string; html: string };
      expect(PROTOCOL_IDS as readonly string[]).toContain(data.id);
      expect(typeof data.html).toBe("string");
      expect(data.html.length).toBeGreaterThan(0);
    }
  });

  it("no duplicate protocol ids in the stream", async () => {
    const res = await app.request("/api/check/stream?domain=example.com");
    const events = await drainSSE(res);
    const ids = events
      .filter((e) => e.event === "protocol")
      .map((e) => (JSON.parse(e.data) as { id: string }).id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("GET /api/check/stream — invalid domain (before stream starts)", () => {
  it("returns 400 JSON for missing domain", async () => {
    const res = await app.request("/api/check/stream");
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(typeof body.error).toBe("string");
  });

  it("returns 400 JSON for a domain that fails normalization", async () => {
    const res = await app.request("/api/check/stream?domain=not_valid");
    expect(res.status).toBe(400);
  });
});

describe("GET /api/check/stream — error within stream", () => {
  it("emits a single error event when scanStreaming throws", async () => {
    const { scanStreaming } = await import("../src/orchestrator.js");
    vi.mocked(scanStreaming).mockRejectedValueOnce(
      new Error("DNS resolver failure"),
    );

    const res = await app.request("/api/check/stream?domain=example.com");
    expect(res.status).toBe(200); // stream already opened; HTTP status is fixed
    const events = await drainSSE(res);
    const errorEvents = events.filter((e) => e.event === "error");
    expect(errorEvents).toHaveLength(1);
    const data = JSON.parse(errorEvents[0].data) as { error: string };
    expect(typeof data.error).toBe("string");
  });
});

describe("GET /api/check/stream — DKIM custom selectors", () => {
  it("passes the selector list from the query string to scanStreaming", async () => {
    const { scanStreaming } = await import("../src/orchestrator.js");

    await app.request(
      "/api/check/stream?domain=example.com&selectors=google,s1",
    );

    expect(vi.mocked(scanStreaming)).toHaveBeenCalledWith(
      "example.com",
      ["google", "s1"],
      expect.any(Function),
    );
  });
});

describe("GET /api/check/stream — cancellation (best-effort)", () => {
  it("invokes scanStreaming exactly once per request", async () => {
    const { scanStreaming } = await import("../src/orchestrator.js");

    await app.request("/api/check/stream?domain=example.com");

    expect(vi.mocked(scanStreaming)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(scanStreaming)).toHaveBeenCalledWith(
      "example.com",
      [],
      expect.any(Function),
    );
  });
});
