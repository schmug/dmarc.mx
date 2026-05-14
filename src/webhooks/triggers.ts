import type { BulkResultEntry } from "../api/bulk-scan.js";
import { CANONICAL_ORIGIN } from "../api/catalog.js";
import { getWebhookForUser } from "../db/webhooks.js";
import { dispatchWebhook, type ScanCompletedData } from "./dispatcher.js";
import { getFormatRateLimitMs } from "./formats/index.js";

// Convenience wrapper used by every scan trigger (dashboard / cron / bulk).
// Centralizes the `scan.completed` payload shape so adding a field later
// (e.g. an alert summary) only touches one place.
export async function fireScanCompletedWebhook(
  db: D1Database,
  userId: string,
  input: {
    domain: string;
    grade: string;
    scanId: string | number;
    trigger: ScanCompletedData["trigger"];
  },
): Promise<void> {
  try {
    await dispatchWebhook(db, userId, {
      type: "scan.completed",
      data: {
        domain: input.domain,
        grade: input.grade,
        scan_id: input.scanId,
        trigger: input.trigger,
        report_url: `${CANONICAL_ORIGIN}/check?domain=${encodeURIComponent(input.domain)}`,
      },
    });
  } catch {
    // Dispatcher already records its own failures into webhook_deliveries; the
    // `try` here exists only so an unexpected throw can't bubble out of a
    // `waitUntil` and crash an unrelated request handler.
  }
}

// Bounded concurrency so a 30-domain bulk doesn't hit a single chat receiver
// with 30 simultaneous POSTs. Mirrors `BULK_BATCH_SIZE` in api/bulk-scan.
const WEBHOOK_BATCH_SIZE = 10;

// Fires one `scan.completed` event per successfully-scanned entry in a bulk
// outcome. Best-effort — callers should hand this to `waitUntil` so it never
// blocks the response. Queued/invalid/error entries are skipped (no scan
// happened, nothing to report).
//
// Dispatch strategy is format-aware:
//   - Rate-limited formats (google_chat: 1 msg/s): serial loop with a
//     per-send delay so we never exceed the platform cap.
//   - Unlimited formats (raw, slack): bounded-parallel batches of
//     WEBHOOK_BATCH_SIZE keep total wall-clock under the waitUntil budget
//     while capping burst per receiver.
export async function fireBulkScanWebhooks(
  db: D1Database,
  userId: string,
  results: BulkResultEntry[],
  trigger: ScanCompletedData["trigger"],
): Promise<void> {
  const toFire = results.filter(
    (entry): entry is BulkResultEntry & { grade: string } =>
      entry.status === "scanned" && !!entry.grade,
  );

  // Look up the user's webhook format once to decide the dispatch strategy.
  const webhook = await getWebhookForUser(db, userId);
  const rateLimitMs = webhook ? getFormatRateLimitMs(webhook.format) : null;

  if (rateLimitMs !== null) {
    // Serial path: rate-limited formats (e.g. google_chat at ~1 msg/s).
    // Insert a delay BETWEEN sends (not before the first one) so we respect
    // the platform cap without adding unnecessary latency to the first event.
    for (let i = 0; i < toFire.length; i++) {
      if (i > 0) await new Promise<void>((r) => setTimeout(r, rateLimitMs));
      await fireScanCompletedWebhook(db, userId, {
        domain: toFire[i].domain,
        grade: toFire[i].grade,
        // Bulk scans don't surface a stable scan_history.id; receivers can
        // re-fetch by domain via /api/domain/:name/history.
        scanId: toFire[i].domain,
        trigger,
      });
    }
  } else {
    // Parallel path: unbounded-rate formats use bounded concurrency batches.
    // Parallel matters: a serial loop over N webhooks accumulates wall-clock
    // time inside the waitUntil budget. Once the runtime decides to recycle
    // the isolate, every pending fetch is aborted. Batching keeps total
    // wall-clock under budget while still capping the burst per receiver.
    for (let i = 0; i < toFire.length; i += WEBHOOK_BATCH_SIZE) {
      const batch = toFire.slice(i, i + WEBHOOK_BATCH_SIZE);
      await Promise.allSettled(
        batch.map((entry) =>
          fireScanCompletedWebhook(db, userId, {
            domain: entry.domain,
            grade: entry.grade,
            scanId: entry.domain,
            trigger,
          }),
        ),
      );
    }
  }
}
