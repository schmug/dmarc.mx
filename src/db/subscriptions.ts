export interface Subscription {
  id: number;
  user_id: string;
  stripe_subscription_id: string;
  stripe_price_id: string;
  status: string;
  current_period_end: number | null;
  cancel_at_period_end: number;
  created_at: number;
  updated_at: number;
}

export type PlanTier = "free" | "pro";

// A subscription is considered "active" for plan-gating purposes only when
// Stripe says so. `past_due` is treated as pro (grace period) because Stripe
// retries the charge automatically; if it ultimately fails Stripe will flip
// to `unpaid` or `canceled` and the next webhook drops the plan.
const ACTIVE_STATUSES = new Set(["active", "trialing", "past_due"]);

export function statusToPlan(status: string | null | undefined): PlanTier {
  return status && ACTIVE_STATUSES.has(status) ? "pro" : "free";
}

export async function getSubscriptionByUserId(
  db: D1Database,
  userId: string,
): Promise<Subscription | null> {
  return db
    .prepare("SELECT * FROM subscriptions WHERE user_id = ?")
    .bind(userId)
    .first<Subscription>();
}

export async function getPlanForUser(
  db: D1Database,
  userId: string,
): Promise<PlanTier> {
  const row = await db
    .prepare("SELECT status FROM subscriptions WHERE user_id = ?")
    .bind(userId)
    .first<{ status: string }>();
  return statusToPlan(row?.status);
}

export interface UpsertSubscriptionInput {
  user_id: string;
  stripe_subscription_id: string;
  stripe_price_id: string;
  status: string;
  current_period_end: number | null;
  cancel_at_period_end: boolean;
}

// Idempotent upsert keyed on user_id. Stripe can send the same event twice
// via retry; the webhook handler's event-id ledger is the first line of
// defence, but this upsert is a second one — replaying the same body is a
// no-op relative to the final state.
export async function upsertSubscription(
  db: D1Database,
  input: UpsertSubscriptionInput,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO subscriptions (
        user_id, stripe_subscription_id, stripe_price_id, status,
        current_period_end, cancel_at_period_end, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, unixepoch())
      ON CONFLICT(user_id) DO UPDATE SET
        stripe_subscription_id = excluded.stripe_subscription_id,
        stripe_price_id        = excluded.stripe_price_id,
        status                 = excluded.status,
        current_period_end     = excluded.current_period_end,
        cancel_at_period_end   = excluded.cancel_at_period_end,
        updated_at             = unixepoch()`,
    )
    .bind(
      input.user_id,
      input.stripe_subscription_id,
      input.stripe_price_id,
      input.status,
      input.current_period_end,
      input.cancel_at_period_end ? 1 : 0,
    )
    .run();
}

// Whether the webhook idempotency ledger already contains this event id.
// Used to skip redundant upserts on Stripe replays while still repairing rows
// that were never written when the event was recorded before upsert failed.
export async function isStripeEventRecorded(
  db: D1Database,
  eventId: string,
): Promise<boolean> {
  const row = await db
    .prepare("SELECT 1 AS exists FROM stripe_events WHERE event_id = ?")
    .bind(eventId)
    .first();
  return row !== null;
}

// Returns true if this event id had not been seen before (caller should
// proceed with handling). Returns false on a replay (caller should 200 and
// skip). Relies on the PRIMARY KEY conflict to be atomic under D1.
export async function recordStripeEventOnce(
  db: D1Database,
  eventId: string,
): Promise<boolean> {
  const result = await db
    .prepare("INSERT OR IGNORE INTO stripe_events (event_id) VALUES (?)")
    .bind(eventId)
    .run();
  return (result.meta?.changes ?? 0) > 0;
}
