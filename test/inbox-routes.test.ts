import { beforeEach, describe, expect, it } from "vitest";
import {
  putPending,
  putVerdict,
  type VerdictRecord,
} from "../src/inbox/store.js";
import { app } from "../src/index.js";
import { _memoryStore } from "../src/rate-limit.js";
import { drainSSE } from "./helpers/drain-sse.js";
import { FakeKV } from "./helpers/fake-kv.js";

const TOKEN = "0123456789abcdef0123456789abcdef";
const FIXED_IP = { "CF-Connecting-IP": "203.0.113.7" };

beforeEach(() => {
  _memoryStore.clear();
});

function envWith(kv: FakeKV) {
  return { INBOX_TOKENS: kv.asKv() } as unknown as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// GET /check/email — issuance
// ---------------------------------------------------------------------------
describe("GET /check/email", () => {
  it("mints a token-addressed inbox.dmarc.mx address and stores a pending record", async () => {
    const kv = new FakeKV();
    const res = await app.request("/check/email", {}, envWith(kv));
    expect(res.status).toBe(200);
    const html = await res.text();

    const match = html.match(/data-inbox-token="([0-9a-f]{32})"/);
    expect(match).not.toBeNull();
    const token = match?.[1] as string;
    expect(html).toContain(`${token}@inbox.dmarc.mx`);

    // A pending record landed in KV under the minted token.
    const stored = kv.store.get(`tok:${token}`);
    expect(stored).toBeDefined();
    expect(JSON.parse(stored as string).status).toBe("pending");
    expect(
      kv.puts.some((p) => p.key === `tok:${token}` && p.ttl === 1800),
    ).toBe(true);
  });

  it("renders a noindexed page (inbound content must never be indexed)", async () => {
    const kv = new FakeKV();
    const res = await app.request("/check/email", {}, envWith(kv));
    const html = await res.text();
    expect(html).toContain('name="robots"');
    expect(html).toContain("noindex");
  });

  it("does not interpolate the token into the inline <script> block", async () => {
    const kv = new FakeKV();
    const res = await app.request("/check/email", {}, envWith(kv));
    const html = await res.text();
    const token = html.match(
      /data-inbox-token="([0-9a-f]{32})"/,
    )?.[1] as string;
    // The stream bootstrap reads the token from the DOM, never as a JS literal.
    const scriptStart = html.indexOf(
      "new EventSource('/api/check/email/stream",
    );
    expect(scriptStart).toBeGreaterThan(-1);
    const scriptBlock = html.slice(
      scriptStart,
      html.indexOf("</script>", scriptStart),
    );
    expect(scriptBlock).not.toContain(token);
  });

  it("returns 503 when KV is not configured", async () => {
    const res = await app.request("/check/email", {}, {});
    expect(res.status).toBe(503);
  });

  it("caps simultaneous live tokens per identity (6th request blocked)", async () => {
    const kv = new FakeKV();
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      const res = await app.request(
        "/check/email",
        { headers: FIXED_IP },
        envWith(kv),
      );
      statuses.push(res.status);
    }
    // First five mint addresses; the sixth exceeds the per-identity cap.
    expect(statuses.slice(0, 5)).toEqual([200, 200, 200, 200, 200]);
    expect(statuses[5]).toBe(429);
  });
});

// ---------------------------------------------------------------------------
// GET /api/check/email/stream — SSE result stream
// ---------------------------------------------------------------------------
describe("GET /api/check/email/stream", () => {
  it("returns 400 for a missing token", async () => {
    const kv = new FakeKV();
    const res = await app.request("/api/check/email/stream", {}, envWith(kv));
    expect(res.status).toBe(400);
  });

  it("returns 400 for an invalid-charset token", async () => {
    const kv = new FakeKV();
    const res = await app.request(
      "/api/check/email/stream?token=not-valid",
      {},
      envWith(kv),
    );
    expect(res.status).toBe(400);
  });

  it("streams a clean 'closed' state for an unknown token (never 500)", async () => {
    const kv = new FakeKV();
    const res = await app.request(
      `/api/check/email/stream?token=${TOKEN}`,
      {},
      envWith(kv),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/event-stream");
    const frames = await drainSSE(res);
    expect(frames).toHaveLength(1);
    expect(frames[0].event).toBe("closed");
    expect(JSON.parse(frames[0].data).status).toBe("expired");
  });

  it("streams the parsed verdict when one is already stored, then closes", async () => {
    const kv = new FakeKV();
    await putPending(kv.asKv(), TOKEN);
    const verdict: VerdictRecord = {
      status: "received",
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      alignment: "pass",
      from: "sender@example.com",
      dkim_selector: "selector1",
      dkim_domain: "example.com",
      auth_results: "mx; spf=pass; dkim=pass; dmarc=pass",
      size_bytes: 100,
      received_at: "2026-06-28T00:00:00.000Z",
    };
    await putVerdict(kv.asKv(), TOKEN, verdict);

    const res = await app.request(
      `/api/check/email/stream?token=${TOKEN}`,
      {},
      envWith(kv),
    );
    expect(res.status).toBe(200);
    const frames = await drainSSE(res);
    expect(frames).toHaveLength(1);
    expect(frames[0].event).toBe("result");
    const payload = JSON.parse(frames[0].data);
    expect(payload).toMatchObject({
      status: "received",
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      received_at: "2026-06-28T00:00:00.000Z",
    });
    expect(payload.html).toContain("selector1");
  });

  it("escapes a crafted Authentication-Results value in the streamed html", async () => {
    const kv = new FakeKV();
    await putVerdict(kv.asKv(), TOKEN, {
      status: "received",
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      alignment: "pass",
      from: "x@y.com",
      dkim_selector: null,
      dkim_domain: null,
      auth_results: "mx; spf=pass <script>alert(1)</script>",
      size_bytes: 1,
      received_at: "2026-06-28T00:00:00.000Z",
    });
    const res = await app.request(
      `/api/check/email/stream?token=${TOKEN}`,
      {},
      envWith(kv),
    );
    const frames = await drainSSE(res);
    const payload = JSON.parse(frames[0].data);
    expect(payload.html).toContain("&lt;script&gt;");
    expect(payload.html).not.toContain("<script>alert(1)</script>");
  });

  it("streams a clean 'closed' state when KV is unbound (never 500)", async () => {
    const res = await app.request(
      `/api/check/email/stream?token=${TOKEN}`,
      {},
      {},
    );
    expect(res.status).toBe(200);
    const frames = await drainSSE(res);
    expect(frames[0].event).toBe("closed");
    expect(JSON.parse(frames[0].data).status).toBe("unavailable");
  });
});
