// Outbound webhook format adapters. Each adapter transforms the canonical
// envelope into the body bytes a specific receiver expects. `raw` is the
// signed-JSON shape our own docs describe; `slack` / `google_chat` target
// incoming-webhook URLs on those chat platforms, which expect `{text: "..."}`
// and do not verify signatures.

import { formatGoogleChat } from "./google_chat.js";
import { formatRaw } from "./raw.js";
import { formatSlack } from "./slack.js";

export const WEBHOOK_FORMATS = ["raw", "slack", "google_chat"] as const;
export type WebhookFormat = (typeof WEBHOOK_FORMATS)[number];

export interface ScanCompletedData {
  domain: string;
  grade: string;
  scan_id: string | number;
  trigger: "dashboard" | "cron" | "bulk_api";
  report_url: string;
}

export interface WebhookTestData {
  message: string;
}

export type WebhookEvent =
  | { type: "scan.completed"; data: ScanCompletedData }
  | { type: "webhook.test"; data: WebhookTestData };

export interface WebhookEnvelope {
  id: string;
  type: WebhookEvent["type"];
  created: number;
  data: ScanCompletedData | WebhookTestData;
}

export interface FormatResult {
  body: string;
}

export type FormatAdapter = (envelope: WebhookEnvelope) => FormatResult;

const ADAPTERS: Record<WebhookFormat, FormatAdapter> = {
  raw: formatRaw,
  slack: formatSlack,
  google_chat: formatGoogleChat,
};

export function getFormatAdapter(format: WebhookFormat): FormatAdapter {
  return ADAPTERS[format];
}

// Per-format rate limit for outbound dispatches. Google Chat incoming webhooks
// are capped at ~1 msg/second per space; the 10% buffer avoids hitting the
// edge. `null` means "no enforced delay between sends" — the receiver (or a
// future per-format config) handles backpressure itself.
export const FORMAT_RATE_LIMIT_MS: Record<WebhookFormat, number | null> = {
  raw: null, // enterprise receivers handle their own rate limits
  slack: null, // Slack is more generous; throttle separately if needed
  google_chat: 1100, // 1 msg/s cap + 10% buffer
};

export function getFormatRateLimitMs(format: WebhookFormat): number | null {
  return FORMAT_RATE_LIMIT_MS[format];
}

export function isWebhookFormat(value: unknown): value is WebhookFormat {
  return (
    typeof value === "string" &&
    (WEBHOOK_FORMATS as readonly string[]).includes(value)
  );
}

// One-line human summary used by chat adapters. Kept here so divergence
// between slack/google_chat stays trivial to spot — both call this today.
export function renderMessage(envelope: WebhookEnvelope): string {
  if (envelope.type === "scan.completed") {
    const d = envelope.data as ScanCompletedData;
    return `DMARC scan complete: ${d.domain} → ${d.grade} — ${d.report_url}`;
  }
  const d = envelope.data as WebhookTestData;
  return `dmarcheck webhook test — ${d.message}`;
}
