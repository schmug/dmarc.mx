import { describe, expect, it, vi } from "vitest";
import {
  buildResultPayload,
  getRecord,
  handleInboundEmail,
  MAX_LIVE_TOKENS_PER_IDENTITY,
  parseVerdict,
  putPending,
  putVerdict,
  reserveLiveToken,
  streamInboxResult,
  TOKEN_TTL_SECONDS,
  type VerdictRecord,
} from "../src/inbox/store.js";
import { renderInboxVerdict } from "../src/views/inbox.js";
import { FakeKV } from "./helpers/fake-kv.js";

const TOKEN = "0123456789abcdef0123456789abcdef";

function mockMessage(
  to: string,
  headers: Record<string, string>,
  from = "sender@example.com",
  rawSize = 2048,
): ForwardableEmailMessage {
  return {
    to,
    from,
    rawSize,
    headers: new Headers(headers),
    raw: new ReadableStream(),
    setReject() {},
    forward: async () => undefined,
    reply: async () => undefined,
  } as unknown as ForwardableEmailMessage;
}

// ---------------------------------------------------------------------------
// Token record store
// ---------------------------------------------------------------------------
describe("inbox store — pending / verdict roundtrip", () => {
  it("stores and reads back a pending record with a 30-min TTL", async () => {
    const kv = new FakeKV();
    await putPending(kv.asKv(), TOKEN);
    const rec = await getRecord(kv.asKv(), TOKEN);
    expect(rec?.status).toBe("pending");
    expect(kv.puts[0].ttl).toBe(TOKEN_TTL_SECONDS);
    expect(TOKEN_TTL_SECONDS).toBe(30 * 60);
  });

  it("overwrites pending with a verdict record (30-min TTL)", async () => {
    const kv = new FakeKV();
    await putPending(kv.asKv(), TOKEN);
    const verdict: VerdictRecord = {
      status: "received",
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      alignment: "pass",
      from: "a@example.com",
      dkim_selector: "s1",
      dkim_domain: "example.com",
      auth_results: "spf=pass dkim=pass dmarc=pass",
      size_bytes: 100,
      received_at: new Date().toISOString(),
    };
    await putVerdict(kv.asKv(), TOKEN, verdict);
    const rec = await getRecord(kv.asKv(), TOKEN);
    expect(rec?.status).toBe("received");
    expect(kv.puts.at(-1)?.ttl).toBe(TOKEN_TTL_SECONDS);
  });

  it("returns null for an unknown token", async () => {
    const kv = new FakeKV();
    expect(await getRecord(kv.asKv(), TOKEN)).toBeNull();
  });

  it("returns null for an invalid-charset token without hitting KV", async () => {
    const kv = new FakeKV();
    const spy = vi.spyOn(kv, "get");
    expect(await getRecord(kv.asKv(), "not-a-valid-token")).toBeNull();
    expect(spy).not.toHaveBeenCalled();
  });

  it("returns null for corrupt JSON", async () => {
    const kv = new FakeKV();
    kv.store.set(`tok:${TOKEN}`, "{not json");
    expect(await getRecord(kv.asKv(), TOKEN)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Per-identity live-token cap
// ---------------------------------------------------------------------------
describe("inbox store — reserveLiveToken cap", () => {
  it("allows up to the cap then rejects further reservations", async () => {
    const kv = new FakeKV();
    const id = "ip:1.2.3.4";
    for (let i = 0; i < MAX_LIVE_TOKENS_PER_IDENTITY; i++) {
      expect(await reserveLiveToken(kv.asKv(), id, `t${i}`)).toBe(true);
    }
    expect(await reserveLiveToken(kv.asKv(), id, "overflow")).toBe(false);
  });

  it("scopes the cap per identity", async () => {
    const kv = new FakeKV();
    for (let i = 0; i < MAX_LIVE_TOKENS_PER_IDENTITY; i++) {
      await reserveLiveToken(kv.asKv(), "ip:a", `t${i}`);
    }
    // A different identity is unaffected.
    expect(await reserveLiveToken(kv.asKv(), "ip:b", "fresh")).toBe(true);
  });

  it("prunes expired entries, freeing slots", async () => {
    const kv = new FakeKV();
    const id = "ip:9.9.9.9";
    const t0 = 1_000_000;
    for (let i = 0; i < MAX_LIVE_TOKENS_PER_IDENTITY; i++) {
      expect(await reserveLiveToken(kv.asKv(), id, `t${i}`, t0)).toBe(true);
    }
    expect(await reserveLiveToken(kv.asKv(), id, "x", t0)).toBe(false);
    // Well past the 30-min TTL — old entries prune away.
    const later = t0 + (TOKEN_TTL_SECONDS + 60) * 1000;
    expect(await reserveLiveToken(kv.asKv(), id, "later", later)).toBe(true);
  });

  it("treats a corrupt index as empty rather than locking out", async () => {
    const kv = new FakeKV();
    // Pre-seed a corrupt index under the hashed identity key. We can't know the
    // hash, so just assert a fresh identity with garbage still reserves.
    const id = "ip:corrupt";
    // Force a corrupt value by reserving once then clobbering the index.
    await reserveLiveToken(kv.asKv(), id, "t0");
    for (const key of kv.store.keys()) {
      if (key.startsWith("live:")) kv.store.set(key, "@@@");
    }
    expect(await reserveLiveToken(kv.asKv(), id, "t1")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Header → verdict parsing
// ---------------------------------------------------------------------------
describe("inbox store — parseVerdict", () => {
  it("extracts spf/dkim/dmarc + alignment from Authentication-Results", () => {
    const headers = new Headers({
      "Authentication-Results":
        "mx.cloudflare.net; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
      "DKIM-Signature":
        "v=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to",
    });
    const v = parseVerdict(headers, "sender@example.com", 1234);
    expect(v.spf).toBe("pass");
    expect(v.dkim).toBe("pass");
    expect(v.dmarc).toBe("pass");
    expect(v.alignment).toBe("pass");
    expect(v.dkim_selector).toBe("selector1");
    expect(v.dkim_domain).toBe("example.com");
    expect(v.from).toBe("sender@example.com");
    expect(v.size_bytes).toBe(1234);
  });

  it("picks the DMARC-relevant SPF (mailfrom) and From-aligned DKIM from a multi-result header", () => {
    // Real shape: a forwarding relay's results plus the author domain's. The
    // first spf= is the HELO check (none); the mailfrom check (pass) is what
    // DMARC used. The first dkim= is the relay (cloudflare-smtp.net); the
    // From-aligned signature is the author domain (cortech.online).
    const headers = new Headers({
      "Authentication-Results":
        "mx.cloudflare.net; dkim=pass header.d=cloudflare-smtp.net header.s=cf2024-1 header.b=haR8eT2T; dkim=pass header.d=cortech.online header.s=cf-bounce header.b=TkrLHPRk; dmarc=pass header.from=cortech.online policy.dmarc=reject; spf=none (mx.cloudflare.net: no SPF records found for postmaster@bg-he.cloudflare-smtp.net) smtp.helo=bg-he.cloudflare-smtp.net; spf=pass (mx.cloudflare.net: domain of bounces@cf-bounce.cortech.online designates 104.30.16.74 as permitted sender) smtp.mailfrom=bounces@cf-bounce.cortech.online; arc=none smtp.remote-ip=104.30.16.74",
    });
    const v = parseVerdict(headers, "bounces@cf-bounce.cortech.online", 4096);
    expect(v.spf).toBe("pass"); // mailfrom, not the HELO "none"
    expect(v.dkim).toBe("pass");
    expect(v.dmarc).toBe("pass");
    expect(v.alignment).toBe("pass");
    // The user's own signature, not the Cloudflare relay's cf2024-1.
    expect(v.dkim_selector).toBe("cf-bounce");
    expect(v.dkim_domain).toBe("cortech.online");
  });

  it("falls back to the first DKIM result when none aligns with the From domain", () => {
    const headers = new Headers({
      "Authentication-Results":
        "mx; dkim=pass header.d=relay.example header.s=r1; dmarc=fail header.from=victim.example; spf=fail smtp.mailfrom=relay.example",
    });
    const v = parseVerdict(headers, "x@relay.example", 1);
    expect(v.dkim).toBe("pass");
    expect(v.dkim_selector).toBe("r1");
    expect(v.dkim_domain).toBe("relay.example");
    expect(v.spf).toBe("fail");
    expect(v.dmarc).toBe("fail");
  });

  it("derives alignment=fail when dmarc fails", () => {
    const headers = new Headers({
      "Authentication-Results": "mx; spf=fail; dkim=fail; dmarc=fail",
    });
    const v = parseVerdict(headers, "x@y.com", 1);
    expect(v.dmarc).toBe("fail");
    expect(v.alignment).toBe("fail");
  });

  it("falls back to Received-SPF when Authentication-Results lacks spf", () => {
    const headers = new Headers({
      "Authentication-Results": "mx; dkim=pass; dmarc=none",
      "Received-SPF": "softfail (mx: domain of x does not designate ...)",
    });
    const v = parseVerdict(headers, "x@y.com", 1);
    expect(v.spf).toBe("softfail");
  });

  it("returns null fields when no auth headers are present", () => {
    const v = parseVerdict(new Headers(), "", 0);
    expect(v.spf).toBeNull();
    expect(v.dkim).toBeNull();
    expect(v.dmarc).toBeNull();
    expect(v.alignment).toBeNull();
    expect(v.from).toBeNull();
    expect(v.auth_results).toBeNull();
  });

  it("rejects a DKIM selector with an illegal charset", () => {
    const headers = new Headers({
      "DKIM-Signature": "v=1; s=bad selector!; d=ok-domain.com",
    });
    const v = parseVerdict(headers, "x@y.com", 1);
    expect(v.dkim_selector).toBeNull();
    expect(v.dkim_domain).toBe("ok-domain.com");
  });

  it("does not let a crafted Authentication-Results smuggle markup into scalar fields", () => {
    const headers = new Headers({
      "Authentication-Results":
        "mx; spf=pass <script>alert(1)</script> dmarc=pass",
    });
    const v = parseVerdict(headers, "x@y.com", 1);
    // The parsed keyword is clean; the raw header is retained (escaped at render).
    expect(v.spf).toBe("pass");
    expect(v.dmarc).toBe("pass");
    expect(v.auth_results).toContain("<script>");
  });
});

// ---------------------------------------------------------------------------
// Email Worker entry point
// ---------------------------------------------------------------------------
describe("inbox store — handleInboundEmail", () => {
  it("writes a verdict for a known (pending) token", async () => {
    const kv = new FakeKV();
    await putPending(kv.asKv(), TOKEN);
    await handleInboundEmail(
      mockMessage(`inbox+${TOKEN}@dmarc.mx`, {
        "Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass",
      }),
      kv.asKv(),
    );
    const rec = await getRecord(kv.asKv(), TOKEN);
    expect(rec?.status).toBe("received");
    if (rec?.status === "received") {
      expect(rec.spf).toBe("pass");
      expect(rec.dkim).toBe("pass");
      expect(rec.dmarc).toBe("pass");
      expect(rec.alignment).toBe("pass");
      expect(typeof rec.received_at).toBe("string");
    }
  });

  it("is a no-op (no write) for an unknown token", async () => {
    const kv = new FakeKV();
    const putSpy = vi.spyOn(kv, "put");
    await handleInboundEmail(
      mockMessage(`inbox+${TOKEN}@dmarc.mx`, {
        "Authentication-Results": "mx; spf=pass",
      }),
      kv.asKv(),
    );
    expect(putSpy).not.toHaveBeenCalled();
    expect(await getRecord(kv.asKv(), TOKEN)).toBeNull();
  });

  it("is a no-op for an address without the inbox+ prefix (catch-all space)", async () => {
    const kv = new FakeKV();
    await putPending(kv.asKv(), TOKEN);
    const putSpy = vi.spyOn(kv, "put");
    await handleInboundEmail(
      mockMessage(`${TOKEN}@dmarc.mx`, {
        "Authentication-Results": "mx; spf=pass",
      }),
      kv.asKv(),
    );
    expect(putSpy).not.toHaveBeenCalled();
  });

  it("does not throw when KV is unbound", async () => {
    await expect(
      handleInboundEmail(mockMessage(`inbox+${TOKEN}@dmarc.mx`, {}), undefined),
    ).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// renderInboxVerdict — XSS escaping (the render boundary)
// ---------------------------------------------------------------------------
describe("inbox views — renderInboxVerdict escaping", () => {
  it("escapes a crafted Authentication-Results value", () => {
    const rec: VerdictRecord = {
      status: "received",
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      alignment: "pass",
      from: '"><img src=x onerror=alert(1)>@evil.com',
      dkim_selector: null,
      dkim_domain: null,
      auth_results: "mx; spf=pass <script>alert(1)</script>",
      size_bytes: 1,
      received_at: "2026-06-28T00:00:00.000Z",
    };
    const html = renderInboxVerdict(rec);
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<img src=x onerror=alert(1)>");
    expect(html).toContain("&lt;img");
  });
});

// ---------------------------------------------------------------------------
// streamInboxResult — SSE state machine
// ---------------------------------------------------------------------------
interface CapturedEvent {
  event: string;
  data: string;
}

function fakeStream() {
  const events: CapturedEvent[] = [];
  return {
    events,
    writeSSE(msg: { event: string; data: string }) {
      events.push(msg);
    },
  };
}

const renderCard = (r: VerdictRecord) => renderInboxVerdict(r);

describe("inbox store — streamInboxResult", () => {
  it("emits a clean 'closed' for an unknown token (never throws)", async () => {
    const kv = new FakeKV();
    const stream = fakeStream();
    await streamInboxResult(stream, kv.asKv(), TOKEN, { renderCard });
    expect(stream.events).toHaveLength(1);
    expect(stream.events[0].event).toBe("closed");
    expect(JSON.parse(stream.events[0].data).status).toBe("expired");
  });

  it("emits 'result' immediately when the verdict is already stored", async () => {
    const kv = new FakeKV();
    await putPending(kv.asKv(), TOKEN);
    await putVerdict(kv.asKv(), TOKEN, {
      status: "received",
      spf: "pass",
      dkim: "fail",
      dmarc: "fail",
      alignment: "fail",
      from: "x@y.com",
      dkim_selector: "sel",
      dkim_domain: "y.com",
      auth_results: "mx; spf=pass; dkim=fail; dmarc=fail",
      size_bytes: 10,
      received_at: "2026-06-28T00:00:00.000Z",
    });
    const stream = fakeStream();
    await streamInboxResult(stream, kv.asKv(), TOKEN, { renderCard });
    expect(stream.events).toHaveLength(1);
    expect(stream.events[0].event).toBe("result");
    const payload = JSON.parse(stream.events[0].data);
    expect(payload).toMatchObject({
      status: "received",
      spf: "pass",
      dkim: "fail",
      dmarc: "fail",
      received_at: "2026-06-28T00:00:00.000Z",
    });
    expect(typeof payload.html).toBe("string");
  });

  it("emits 'waiting' then 'result' once the verdict lands during polling", async () => {
    const kv = new FakeKV();
    await putPending(kv.asKv(), TOKEN);
    const stream = fakeStream();
    let polls = 0;
    const sleep = async () => {
      polls++;
      if (polls === 2) {
        // Verdict arrives between the 1st and 2nd poll.
        await putVerdict(kv.asKv(), TOKEN, {
          status: "received",
          spf: "pass",
          dkim: "pass",
          dmarc: "pass",
          alignment: "pass",
          from: "x@y.com",
          dkim_selector: null,
          dkim_domain: null,
          auth_results: "mx; spf=pass",
          size_bytes: 1,
          received_at: "2026-06-28T00:00:00.000Z",
        });
      }
    };
    await streamInboxResult(stream, kv.asKv(), TOKEN, {
      renderCard,
      pollIntervalMs: 1,
      maxWaitMs: 10_000,
      sleep,
    });
    expect(stream.events.map((e) => e.event)).toEqual(["waiting", "result"]);
  });

  it("emits 'waiting' then 'closed:timeout' when nothing arrives in budget", async () => {
    const kv = new FakeKV();
    await putPending(kv.asKv(), TOKEN);
    const stream = fakeStream();
    let clock = 0;
    await streamInboxResult(stream, kv.asKv(), TOKEN, {
      renderCard,
      pollIntervalMs: 1,
      maxWaitMs: 5,
      sleep: async () => {
        clock += 10; // each sleep advances past the budget
      },
      nowMs: () => clock,
    });
    expect(stream.events.map((e) => e.event)).toEqual(["waiting", "closed"]);
    expect(JSON.parse(stream.events[1].data).status).toBe("timeout");
  });

  it("emits 'closed:expired' if the pending record vanishes mid-poll", async () => {
    const kv = new FakeKV();
    await putPending(kv.asKv(), TOKEN);
    const stream = fakeStream();
    await streamInboxResult(stream, kv.asKv(), TOKEN, {
      renderCard,
      pollIntervalMs: 1,
      maxWaitMs: 10_000,
      sleep: async () => {
        await kv.delete(`tok:${TOKEN}`);
      },
    });
    expect(stream.events.map((e) => e.event)).toEqual(["waiting", "closed"]);
    expect(JSON.parse(stream.events[1].data).status).toBe("expired");
  });
});

describe("inbox store — buildResultPayload", () => {
  it("carries the spec scalar fields + an html card", () => {
    const rec: VerdictRecord = {
      status: "received",
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      alignment: "pass",
      from: "x@y.com",
      dkim_selector: null,
      dkim_domain: null,
      auth_results: "mx; spf=pass",
      size_bytes: 1,
      received_at: "2026-06-28T00:00:00.000Z",
    };
    const payload = buildResultPayload(rec, renderCard);
    expect(payload).toMatchObject({
      status: "received",
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      alignment: "pass",
      received_at: "2026-06-28T00:00:00.000Z",
    });
    expect(payload.html).toContain("Message received");
  });
});
