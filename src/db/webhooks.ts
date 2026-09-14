// Lookup helpers for the user-configured outbound webhooks table. Writes
// (save URL / rotate secret) currently live inline in the dashboard route
// handler — leaving them there for now to keep route-level tests stable.

import type { WebhookFormat } from "../webhooks/formats/index.js";
import { d1Read } from "./retry.js";

export interface WebhookRow {
  id: number;
  user_id: string;
  url: string;
  secret: string | null;
  format: WebhookFormat;
  created_at: number;
}

// Returns the webhook config for a user, or null if none is set. The dispatch
// path treats null as "no-op, the user opted out" — not an error.
export async function getWebhookForUser(
  db: D1Database,
  userId: string,
): Promise<WebhookRow | null> {
  return d1Read(() =>
    db
      .prepare("SELECT * FROM webhooks WHERE user_id = ?")
      .bind(userId)
      .first<WebhookRow>(),
  );
}
