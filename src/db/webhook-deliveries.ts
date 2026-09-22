// Audit log for outbound webhook attempts. Read by the dashboard settings
// view to surface recent deliveries; written by the dispatcher after every
// POST attempt (success or failure). Bodies are not stored — only the
// SHA-256 of the request body so support can correlate without holding PII.
import { d1Read } from "./retry.js";

export interface WebhookDeliveryRow {
  id: number;
  user_id: string;
  webhook_id: number;
  event_id: string;
  event_type: string;
  url: string;
  status_code: number | null;
  ok: number;
  error: string | null;
  request_body_sha256: string;
  attempted_at: number;
}

export interface InsertWebhookDeliveryInput {
  userId: string;
  webhookId: number;
  eventId: string;
  eventType: string;
  url: string;
  statusCode: number | null;
  ok: boolean;
  error: string | null;
  requestBodySha256: string;
}

export async function insertWebhookDelivery(
  db: D1Database,
  input: InsertWebhookDeliveryInput,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO webhook_deliveries
        (user_id, webhook_id, event_id, event_type, url, status_code, ok, error, request_body_sha256)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.userId,
      input.webhookId,
      input.eventId,
      input.eventType,
      input.url,
      input.statusCode,
      input.ok ? 1 : 0,
      input.error,
      input.requestBodySha256,
    )
    .run();
}

export async function getRecentDeliveriesForUser(
  db: D1Database,
  userId: string,
  limit = 10,
): Promise<WebhookDeliveryRow[]> {
  const result = await d1Read(() =>
    db
      .prepare(
        `SELECT * FROM webhook_deliveries
         WHERE user_id = ?
         ORDER BY attempted_at DESC
         LIMIT ?`,
      )
      .bind(userId, limit)
      .all<WebhookDeliveryRow>(),
  );
  return result.results;
}
