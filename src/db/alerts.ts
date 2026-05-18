import type { AlertType } from "../alerts/detector.js";

export interface AlertRow {
  id: number;
  domain_id: number;
  alert_type: string;
  previous_value: string | null;
  new_value: string | null;
  notified_via: string | null;
  acknowledged_at: number | null;
  created_at: number;
}

export interface RecordAlertInput {
  domainId: number;
  type: AlertType;
  previousValue: string;
  newValue: string;
  createdAt?: number;
}

// ⚡ Bolt Optimization: Batch insert multiple alerts in a single D1 transaction
// Reduces network round-trips and DB transaction overhead when a domain
// generates multiple protocol alerts in a single scan.
export async function recordAlerts(
  db: D1Database,
  inputs: RecordAlertInput[],
): Promise<void> {
  if (inputs.length === 0) return;
  const statements = inputs.map((input) => {
    const createdAt = input.createdAt ?? Math.floor(Date.now() / 1000);
    return db
      .prepare(
        "INSERT INTO alerts (domain_id, alert_type, previous_value, new_value, created_at) VALUES (?, ?, ?, ?, ?)",
      )
      .bind(
        input.domainId,
        input.type,
        input.previousValue,
        input.newValue,
        createdAt,
      );
  });
  await db.batch(statements);
}

export async function recordAlert(
  db: D1Database,
  input: RecordAlertInput,
): Promise<void> {
  const createdAt = input.createdAt ?? Math.floor(Date.now() / 1000);
  await db
    .prepare(
      "INSERT INTO alerts (domain_id, alert_type, previous_value, new_value, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(
      input.domainId,
      input.type,
      input.previousValue,
      input.newValue,
      createdAt,
    )
    .run();
}

// Returns alerts that haven't been delivered yet (notified_via IS NULL).
// Joins to domains to expose the owning user_id for alert routing.
export interface UnsentAlert extends AlertRow {
  user_id: string;
  domain: string;
}

export async function listUnsentAlerts(
  db: D1Database,
  limit = 100,
): Promise<UnsentAlert[]> {
  const result = await db
    .prepare(
      `SELECT a.*, d.user_id, d.domain
       FROM alerts a
       JOIN domains d ON d.id = a.domain_id
       WHERE a.notified_via IS NULL
       ORDER BY a.created_at ASC
       LIMIT ?`,
    )
    .bind(limit)
    .all<UnsentAlert>();
  return result.results;
}

export async function markAlertNotified(
  db: D1Database,
  alertId: number,
  channel: string,
): Promise<void> {
  await db
    .prepare("UPDATE alerts SET notified_via = ? WHERE id = ?")
    .bind(channel, alertId)
    .run();
}

// Alert plus its owning domain name, used by the dashboard "Needs attention"
// section. The JOIN gates the result on user ownership.
export interface UserAlert extends AlertRow {
  domain: string;
}

export async function listUnacknowledgedForUser(
  db: D1Database,
  userId: string,
  limit = 20,
): Promise<UserAlert[]> {
  const result = await db
    .prepare(
      `SELECT a.*, d.domain
       FROM alerts a
       JOIN domains d ON d.id = a.domain_id
       WHERE d.user_id = ? AND a.acknowledged_at IS NULL
       ORDER BY a.created_at DESC
       LIMIT ?`,
    )
    .bind(userId, limit)
    .all<UserAlert>();
  return result.results;
}

// IDOR-safe: the UPDATE only fires if the alert's owning domain belongs to
// the supplied userId. Returns true if a row was updated, false otherwise so
// the caller can choose between 303 and 404.
export async function acknowledgeAlert(
  db: D1Database,
  userId: string,
  alertId: number,
  now: number = Math.floor(Date.now() / 1000),
): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE alerts
       SET acknowledged_at = ?
       WHERE id = ?
         AND acknowledged_at IS NULL
         AND domain_id IN (SELECT id FROM domains WHERE user_id = ?)`,
    )
    .bind(now, alertId, userId)
    .run();
  return (result.meta?.changes ?? 0) > 0;
}

interface UnacknowledgedCountRow {
  domain_id: number;
  count: number;
}

export async function countUnacknowledgedByDomain(
  db: D1Database,
  userId: string,
): Promise<Map<number, number>> {
  const result = await db
    .prepare(
      `SELECT a.domain_id AS domain_id, COUNT(*) AS count
       FROM alerts a
       JOIN domains d ON d.id = a.domain_id
       WHERE d.user_id = ? AND a.acknowledged_at IS NULL
       GROUP BY a.domain_id`,
    )
    .bind(userId)
    .all<UnacknowledgedCountRow>();
  return new Map(result.results.map((r) => [r.domain_id, r.count]));
}
