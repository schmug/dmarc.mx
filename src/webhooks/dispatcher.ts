import { insertWebhookDelivery } from "../db/webhook-deliveries.js";
import { getWebhookForUser } from "../db/webhooks.js";
import { hmacSha256Hex } from "../shared/hmac.js";
import { isAllowedWebhookUrl } from "../shared/ssrf.js";
import {
  getFormatAdapter,
  type ScanCompletedData,
  type WebhookEnvelope,
  type WebhookEvent,
  type WebhookTestData,
} from "./formats/index.js";

// Outbound webhook dispatcher. Single-attempt POST with a 5s timeout. Every
// attempt — success or failure — is recorded to webhook_deliveries so the
// dashboard can show recent results without us keeping request bodies around.
//
// The format adapter chosen for the webhook row decides what goes on the
// wire:
//   - raw: JSON-stringified envelope, signed like Stripe
//     (Dmarcheck-Signature: t=<unix>,v1=<hex of HMAC-SHA256 over
//     "<unix>.<body>" with the user's per-webhook secret).
//   - slack / google_chat: platform-specific text payload, no signature —
//     those chat receivers don't verify one.

const FETCH_TIMEOUT_MS = 5_000;

export type { ScanCompletedData, WebhookEvent, WebhookTestData };

export interface DispatchResult {
  ok: boolean;
  status: number | null;
  error: string | null;
  attempted_at: number;
  event_id: string;
}

const RETRY_DELAY_MS = 2000;

export interface DispatchOptions {
  // Override for tests so signatures and event timestamps are deterministic.
  now?: number;
  // Override for tests so generated event ids are deterministic.
  eventId?: string;
  // Override the 429-retry backoff delay (ms). Pass 0 in tests to skip the
  // real 2-second wait without needing fake timers.
  retryDelayMs?: number;
}

export async function dispatchWebhook(
  db: D1Database,
  userId: string,
  event: WebhookEvent,
  options: DispatchOptions = {},
): Promise<DispatchResult | null> {
  const webhook = await getWebhookForUser(db, userId);
  if (!webhook) return null;

  const now = options.now ?? Math.floor(Date.now() / 1000);
  const eventId = options.eventId ?? `evt_${crypto.randomUUID()}`;
  const envelope: WebhookEnvelope = {
    id: eventId,
    type: event.type,
    created: now,
    data: event.data,
  };

  const adapter = getFormatAdapter(webhook.format);
  const { body } = adapter(envelope);
  const bodySha = await sha256Hex(body);

  // SSRF guard at the sink (defense in depth alongside save-time validation in
  // dashboard routes): refuse to fetch a stored URL whose host is internal /
  // reserved. Catches rows saved before this check existed.
  if (!isAllowedWebhookUrl(webhook.url)) {
    const result: DispatchResult = {
      ok: false,
      status: null,
      error: "webhook URL host is not allowed (must be a public https host)",
      attempted_at: now,
      event_id: eventId,
    };
    await recordDelivery(
      db,
      userId,
      webhook.id,
      webhook.url,
      event.type,
      bodySha,
      result,
    );
    return result;
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "User-Agent": "dmarcheck-webhook/1",
  };

  // `raw` is the only format that signs — chat platforms don't verify and
  // sending the header to them is noise. The null-secret guard therefore
  // only blocks dispatch on the `raw` path: legacy rows that predate the
  // secret rotation can still deliver to Slack/Google Chat.
  if (webhook.format === "raw") {
    if (!webhook.secret) {
      const result: DispatchResult = {
        ok: false,
        status: null,
        error: "webhook secret missing — re-save the webhook to rotate",
        attempted_at: now,
        event_id: eventId,
      };
      await recordDelivery(
        db,
        userId,
        webhook.id,
        webhook.url,
        event.type,
        bodySha,
        result,
      );
      return result;
    }
    const signature = await hmacSha256Hex(webhook.secret, `${now}.${body}`);
    headers["Dmarcheck-Signature"] = `t=${now},v1=${signature}`;
  }

  // Map a fetch Response to a DispatchResult. With `redirect: "manual"` a 3xx
  // yields an opaque-redirect Response (type === "opaqueredirect", ok === false,
  // status === 0); treat it as a failure instead of following the hop, so an
  // attacker-controlled receiver cannot 30x-pivot the Worker past the SSRF
  // guard to a new host. Same posture as the MTA-STS fetch in
  // src/analyzers/mta-sts.ts.
  const toResult = (response: Response): DispatchResult => {
    if ((response.type as string) === "opaqueredirect") {
      return {
        ok: false,
        status: null,
        error:
          "redirect not followed (3xx) — receiver must accept the POST directly",
        attempted_at: now,
        event_id: eventId,
      };
    }
    return {
      ok: response.ok,
      status: response.status,
      error: response.ok ? null : `HTTP ${response.status}`,
      attempted_at: now,
      event_id: eventId,
    };
  };

  let result: DispatchResult;
  try {
    const response = await fetch(webhook.url, {
      method: "POST",
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });

    if (response.status === 429) {
      // One retry after a fixed backoff — Google Chat (and other platforms)
      // return 429 when the per-space rate limit is exceeded. A single retry
      // with a short pause clears the leaky-bucket window without looping.
      const delay = options.retryDelayMs ?? RETRY_DELAY_MS;
      await new Promise<void>((r) => setTimeout(r, delay));
      const retry = await fetch(webhook.url, {
        method: "POST",
        headers,
        body,
        redirect: "manual",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      result = toResult(retry);
    } else {
      result = toResult(response);
    }
  } catch (err) {
    result = {
      ok: false,
      status: null,
      error: err instanceof Error ? err.message : String(err),
      attempted_at: now,
      event_id: eventId,
    };
  }

  await recordDelivery(
    db,
    userId,
    webhook.id,
    webhook.url,
    event.type,
    bodySha,
    result,
  );
  return result;
}

async function recordDelivery(
  db: D1Database,
  userId: string,
  webhookId: number,
  url: string,
  eventType: string,
  bodySha: string,
  result: DispatchResult,
): Promise<void> {
  await insertWebhookDelivery(db, {
    userId,
    webhookId,
    eventId: result.event_id,
    eventType,
    url,
    statusCode: result.status,
    ok: result.ok,
    error: result.error,
    requestBodySha256: bodySha,
  });
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  let out = "";
  for (const b of new Uint8Array(digest)) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}
