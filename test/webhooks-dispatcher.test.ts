import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hmacSha256Hex } from "../src/shared/hmac.js";
import { dispatchWebhook } from "../src/webhooks/dispatcher.js";

interface FakeWebhookRow {
  id: number;
  user_id: string;
  url: string;
  secret: string | null;
  format: "raw" | "slack" | "google_chat";
  created_at: number;
}

interface DeliveryRow {
  user_id: string;
  webhook_id: number;
  event_id: string;
  event_type: string;
  url: string;
  status_code: number | null;
  ok: number;
  error: string | null;
  request_body_sha256: string;
}

let webhooksByUser: Map<string, FakeWebhookRow>;
let deliveries: DeliveryRow[];

function makeDb(): D1Database {
  const prepare = (sql: string) => ({
    bind: (...params: unknown[]) => ({
      first: async <T>() => {
        if (/^SELECT \* FROM webhooks WHERE user_id = \?/i.test(sql)) {
          const [userId] = params as [string];
          return (webhooksByUser.get(userId) as T | undefined) ?? null;
        }
        return null;
      },
      run: async () => {
        if (/^INSERT INTO webhook_deliveries/i.test(sql)) {
          const [
            userId,
            webhookId,
            eventId,
            eventType,
            url,
            statusCode,
            ok,
            error,
            sha,
          ] = params as [
            string,
            number,
            string,
            string,
            string,
            number | null,
            number,
            string | null,
            string,
          ];
          deliveries.push({
            user_id: userId,
            webhook_id: webhookId,
            event_id: eventId,
            event_type: eventType,
            url,
            status_code: statusCode,
            ok,
            error,
            request_body_sha256: sha,
          });
        }
        return { meta: {} } as never;
      },
      all: async <T>() => ({ results: [] as T[] }),
    }),
  });
  return { prepare } as unknown as D1Database;
}

beforeEach(() => {
  webhooksByUser = new Map();
  deliveries = [];
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("webhooks/dispatcher.dispatchWebhook", () => {
  it("returns null and does not fetch when the user has no webhook configured", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const db = makeDb();

    const result = await dispatchWebhook(db, "user-without-hook", {
      type: "webhook.test",
      data: { message: "ping" },
    });

    expect(result).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(deliveries).toHaveLength(0);
  });

  it("refuses to fetch a webhook URL pointing at an internal host (SSRF guard)", async () => {
    webhooksByUser.set("u1", {
      id: 99,
      user_id: "u1",
      url: "https://169.254.169.254/latest/meta-data/",
      secret: "shhh",
      format: "raw",
      created_at: 0,
    });
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const db = makeDb();

    const result = await dispatchWebhook(db, "u1", {
      type: "webhook.test",
      data: { message: "ping" },
    });

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(result?.ok).toBe(false);
    expect(result?.status).toBeNull();
    expect(result?.error).toMatch(/host is not allowed/i);
    // The blocked attempt is still recorded for the dashboard.
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].ok).toBe(0);
  });

  it("uses redirect: manual and treats an opaque-redirect (3xx) as a failed delivery", async () => {
    webhooksByUser.set("u1", {
      id: 88,
      user_id: "u1",
      url: "https://hook.example/receive",
      secret: "shhh",
      format: "raw",
      created_at: 0,
    });
    // A 3xx under redirect: "manual" surfaces as an opaque-redirect Response.
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      type: "opaqueredirect",
      ok: false,
      status: 0,
    } as unknown as Response);
    const db = makeDb();

    const result = await dispatchWebhook(db, "u1", {
      type: "webhook.test",
      data: { message: "ping" },
    });

    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(init.redirect).toBe("manual");
    expect(result?.ok).toBe(false);
    expect(result?.status).toBeNull();
    expect(result?.error).toMatch(/redirect not followed/i);
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].ok).toBe(0);
  });

  it("POSTs a signed envelope and records a successful delivery", async () => {
    webhooksByUser.set("u1", {
      id: 42,
      user_id: "u1",
      url: "https://hook.example/receive",
      secret: "shhh",
      format: "raw",
      created_at: 0,
    });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("", { status: 202 }));
    const db = makeDb();

    const result = await dispatchWebhook(
      db,
      "u1",
      { type: "webhook.test", data: { message: "ping" } },
      { now: 1_700_000_000 },
    );

    expect(result?.ok).toBe(true);
    expect(result?.status).toBe(202);
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    const [calledUrl, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(calledUrl).toBe("https://hook.example/receive");
    expect(init.method).toBe("POST");
    const headers = init.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
    const sig = headers["Dmarcheck-Signature"];
    expect(sig).toMatch(/^t=1700000000,v1=[0-9a-f]{64}$/);

    const body = String(init.body);
    const envelope = JSON.parse(body) as {
      id: string;
      type: string;
      created: number;
      data: { message: string };
    };
    expect(envelope.type).toBe("webhook.test");
    expect(envelope.created).toBe(1_700_000_000);
    expect(envelope.id).toMatch(/^evt_/);
    expect(envelope.data.message).toBe("ping");

    // Signature must validate against the webhook's secret.
    const expectedV1 = await hmacSha256Hex("shhh", `1700000000.${body}`);
    expect(sig).toBe(`t=1700000000,v1=${expectedV1}`);

    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].ok).toBe(1);
    expect(deliveries[0].status_code).toBe(202);
    expect(deliveries[0].webhook_id).toBe(42);
    expect(deliveries[0].event_type).toBe("webhook.test");
    expect(deliveries[0].request_body_sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("records a failed delivery when the receiver returns 500", async () => {
    webhooksByUser.set("u1", {
      id: 7,
      user_id: "u1",
      url: "https://hook.example/receive",
      secret: "shhh",
      format: "raw",
      created_at: 0,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("nope", { status: 500 }),
    );
    const db = makeDb();

    const result = await dispatchWebhook(db, "u1", {
      type: "webhook.test",
      data: { message: "ping" },
    });

    expect(result?.ok).toBe(false);
    expect(result?.status).toBe(500);
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].ok).toBe(0);
    expect(deliveries[0].status_code).toBe(500);
  });

  it("records a failed delivery when fetch throws (network/timeout)", async () => {
    webhooksByUser.set("u1", {
      id: 9,
      user_id: "u1",
      url: "https://hook.example/receive",
      secret: "shhh",
      format: "raw",
      created_at: 0,
    });
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("ECONNREFUSED"));
    const db = makeDb();

    const result = await dispatchWebhook(db, "u1", {
      type: "webhook.test",
      data: { message: "ping" },
    });

    expect(result?.ok).toBe(false);
    expect(result?.status).toBeNull();
    expect(result?.error).toMatch(/ECONNREFUSED/);
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].ok).toBe(0);
    expect(deliveries[0].status_code).toBeNull();
    expect(deliveries[0].error).toMatch(/ECONNREFUSED/);
  });

  it("skips dispatch and records an error when the webhook row has no secret", async () => {
    webhooksByUser.set("u1", {
      id: 11,
      user_id: "u1",
      url: "https://hook.example/receive",
      secret: null,
      format: "raw",
      created_at: 0,
    });
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const db = makeDb();

    const result = await dispatchWebhook(db, "u1", {
      type: "webhook.test",
      data: { message: "ping" },
    });

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(result?.ok).toBe(false);
    expect(result?.error).toMatch(/secret/i);
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].ok).toBe(0);
    expect(deliveries[0].status_code).toBeNull();
  });

  it("POSTs a Slack-shaped body with no signature header when format is slack", async () => {
    webhooksByUser.set("u1", {
      id: 21,
      user_id: "u1",
      url: "https://hooks.slack.com/services/T/B/X",
      secret: "ignored-for-chat-formats",
      format: "slack",
      created_at: 0,
    });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("ok", { status: 200 }));
    const db = makeDb();

    const result = await dispatchWebhook(
      db,
      "u1",
      { type: "webhook.test", data: { message: "Hello from dmarcheck" } },
      { now: 1_700_000_000 },
    );

    expect(result?.ok).toBe(true);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [calledUrl, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(calledUrl).toBe("https://hooks.slack.com/services/T/B/X");
    const headers = init.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers["Dmarcheck-Signature"]).toBeUndefined();

    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(["text"]);
    expect(body.text).toBe("dmarcheck webhook test — Hello from dmarcheck");

    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].ok).toBe(1);
    expect(deliveries[0].webhook_id).toBe(21);
  });

  it("POSTs a Google Chat-shaped body with no signature header when format is google_chat", async () => {
    webhooksByUser.set("u1", {
      id: 22,
      user_id: "u1",
      url: "https://chat.googleapis.com/v1/spaces/ABC/messages?key=x&token=y",
      secret: null,
      format: "google_chat",
      created_at: 0,
    });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("{}", { status: 200 }));
    const db = makeDb();

    const result = await dispatchWebhook(
      db,
      "u1",
      {
        type: "scan.completed",
        data: {
          domain: "example.com",
          grade: "A",
          scan_id: "scn_1",
          trigger: "cron",
          report_url: "https://dmarc.mx/check?domain=example.com",
        },
      },
      { now: 1_700_000_000 },
    );

    expect(result?.ok).toBe(true);
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["Dmarcheck-Signature"]).toBeUndefined();

    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(["text"]);
    expect(body.text).toBe(
      "DMARC scan complete: example.com → A — https://dmarc.mx/check?domain=example.com",
    );

    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].ok).toBe(1);
    expect(deliveries[0].event_type).toBe("scan.completed");
  });

  it("retries once after a 429 and records the retry result as ok=true", async () => {
    webhooksByUser.set("u1", {
      id: 30,
      user_id: "u1",
      url: "https://chat.googleapis.com/v1/spaces/X/messages?key=k",
      secret: null,
      format: "google_chat",
      created_at: 0,
    });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response("rate limited", { status: 429 }))
      .mockResolvedValueOnce(new Response("{}", { status: 200 }));
    const db = makeDb();

    // retryDelayMs: 0 skips the real 2s backoff so the test is instant.
    const result = await dispatchWebhook(
      db,
      "u1",
      {
        type: "scan.completed",
        data: {
          domain: "example.com",
          grade: "A",
          scan_id: "scn_1",
          trigger: "cron",
          report_url: "https://dmarc.mx/check?domain=example.com",
        },
      },
      { retryDelayMs: 0 },
    );

    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(result?.ok).toBe(true);
    expect(result?.status).toBe(200);
    // Only one delivery row recorded — the final (post-retry) outcome.
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].ok).toBe(1);
    expect(deliveries[0].status_code).toBe(200);
  });

  it("records ok=false when the retry after 429 also fails", async () => {
    webhooksByUser.set("u1", {
      id: 31,
      user_id: "u1",
      url: "https://chat.googleapis.com/v1/spaces/X/messages?key=k",
      secret: null,
      format: "google_chat",
      created_at: 0,
    });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("still limited", { status: 429 }));
    const db = makeDb();

    // retryDelayMs: 0 skips the real 2s backoff so the test is instant.
    const result = await dispatchWebhook(
      db,
      "u1",
      {
        type: "scan.completed",
        data: {
          domain: "example.com",
          grade: "B",
          scan_id: "scn_2",
          trigger: "cron",
          report_url: "https://dmarc.mx/check?domain=example.com",
        },
      },
      { retryDelayMs: 0 },
    );

    // Exactly 2 fetch calls — initial + one retry, no further recursion.
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(result?.ok).toBe(false);
    expect(result?.status).toBe(429);
    expect(result?.error).toBe("HTTP 429");
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].ok).toBe(0);
  });

  it("does NOT retry on non-429 errors (e.g. 500)", async () => {
    webhooksByUser.set("u1", {
      id: 32,
      user_id: "u1",
      url: "https://chat.googleapis.com/v1/spaces/X/messages?key=k",
      secret: null,
      format: "google_chat",
      created_at: 0,
    });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("server error", { status: 500 }));
    const db = makeDb();

    const result = await dispatchWebhook(db, "u1", {
      type: "scan.completed",
      data: {
        domain: "example.com",
        grade: "F",
        scan_id: "scn_3",
        trigger: "cron",
        report_url: "https://dmarc.mx/check?domain=example.com",
      },
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(result?.ok).toBe(false);
    expect(result?.status).toBe(500);
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].ok).toBe(0);
  });
});
