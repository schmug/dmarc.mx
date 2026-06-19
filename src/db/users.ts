export interface User {
  id: string;
  email: string;
  email_domain: string;
  stripe_customer_id: string | null;
  email_alerts_enabled: number;
  notify_on_change_only: number;
  api_key_retirement_acknowledged_at: number | null;
  max_domains_override: number | null;
  created_at: number;
}

export async function createUser(
  db: D1Database,
  input: { id: string; email: string },
): Promise<void> {
  const emailDomain = input.email.split("@")[1];
  // New users created after the Phase 3 M3 migration never had a legacy
  // cleartext API key, so pre-ack the retirement banner for them.
  const nowSeconds = Math.floor(Date.now() / 1000);
  await db
    .prepare(
      "INSERT INTO users (id, email, email_domain, api_key_retirement_acknowledged_at) VALUES (?, ?, ?, ?)",
    )
    .bind(input.id, input.email, emailDomain, nowSeconds)
    .run();
}

export async function getUserById(
  db: D1Database,
  id: string,
): Promise<User | null> {
  return db.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<User>();
}

// Hard-deletes a user and everything they own. The single DELETE cascades via
// ON DELETE CASCADE (see migrations/0004_api_keys.sql): domains →
// (scan_history, alerts), api_keys, webhooks → webhook_deliveries,
// subscriptions. `stripe_events` is a non-user idempotency ledger and is left
// intact. The target id MUST come from the verified session (session.sub),
// never request input — this is the cross-tenant-erasure (IDOR) guard, the
// same posture as deleteDomain's `WHERE user_id = ?`. There is deliberately no
// soft-delete: account deletion is immediate and permanent (issue #550).
export async function deleteUser(
  db: D1Database,
  userId: string,
): Promise<void> {
  await db.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();
}

export async function getUserByEmail(
  db: D1Database,
  email: string,
): Promise<User | null> {
  return db
    .prepare("SELECT * FROM users WHERE email = ?")
    .bind(email)
    .first<User>();
}

export async function getUserByStripeCustomerId(
  db: D1Database,
  stripeCustomerId: string,
): Promise<User | null> {
  return db
    .prepare("SELECT * FROM users WHERE stripe_customer_id = ?")
    .bind(stripeCustomerId)
    .first<User>();
}

export async function setStripeCustomerId(
  db: D1Database,
  userId: string,
  stripeCustomerId: string,
): Promise<void> {
  await db
    .prepare("UPDATE users SET stripe_customer_id = ? WHERE id = ?")
    .bind(stripeCustomerId, userId)
    .run();
}

export async function setEmailAlertsEnabled(
  db: D1Database,
  userId: string,
  enabled: boolean,
): Promise<void> {
  await db
    .prepare("UPDATE users SET email_alerts_enabled = ? WHERE id = ?")
    .bind(enabled ? 1 : 0, userId)
    .run();
}

export async function setNotifyOnChangeOnly(
  db: D1Database,
  userId: string,
  enabled: boolean,
): Promise<void> {
  await db
    .prepare("UPDATE users SET notify_on_change_only = ? WHERE id = ?")
    .bind(enabled ? 1 : 0, userId)
    .run();
}

export async function getMaxDomainsOverrideForUser(
  db: D1Database,
  userId: string,
): Promise<number | null> {
  const row = await db
    .prepare("SELECT max_domains_override FROM users WHERE id = ?")
    .bind(userId)
    .first<{ max_domains_override: number | null }>();
  return row?.max_domains_override ?? null;
}

// Dismisses the one-time "your old cleartext API key was retired" banner by
// stamping `now`. Called on first visit to the API keys settings page.
export async function acknowledgeApiKeyRetirement(
  db: D1Database,
  userId: string,
): Promise<void> {
  await db
    .prepare(
      "UPDATE users SET api_key_retirement_acknowledged_at = ? WHERE id = ?",
    )
    .bind(Math.floor(Date.now() / 1000), userId)
    .run();
}
