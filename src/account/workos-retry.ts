import * as Sentry from "@sentry/cloudflare";
import { deleteWorkosUser } from "../auth/workos.js";

const MAX_ATTEMPTS = 10;

export interface SweepResult {
  retried: number;
  cleared: number;
  givenUp: number;
  errors: number;
}

interface RetryRow {
  workos_user_id: string;
  attempt_count: number;
  next_attempt_at: number;
  enqueued_at: number;
}

async function localUserExists(
  db: D1Database,
  workosUserId: string,
): Promise<boolean> {
  const row = await db
    .prepare("SELECT 1 AS exists FROM users WHERE id = ?")
    .bind(workosUserId)
    .first();
  return row !== null;
}

// Atomically remove a retry row only when no local user exists. Returns true
// when this sweep claimed the row and may proceed to deleteWorkosUser.
async function claimRetryRowIfNoLocalUser(
  db: D1Database,
  workosUserId: string,
): Promise<boolean> {
  const result = await db
    .prepare(
      `DELETE FROM workos_identity_retry
       WHERE workos_user_id = ?
         AND NOT EXISTS (SELECT 1 FROM users WHERE id = ?)`,
    )
    .bind(workosUserId, workosUserId)
    .run();
  return (result.meta?.changes ?? 0) > 0;
}

// Persists a failed WorkOS deletion so the nightly sweep can retry it.
// INSERT OR IGNORE is idempotent — a second enqueue for the same id is a no-op.
export async function enqueueWorkosRetry(
  db: D1Database,
  workosUserId: string,
): Promise<void> {
  await db
    .prepare(
      "INSERT OR IGNORE INTO workos_identity_retry (workos_user_id) VALUES (?)",
    )
    .bind(workosUserId)
    .run();
}

// Processes every due entry in the retry queue: calls deleteWorkosUser for
// each, clears the row on success (including 404 = already-deleted), and
// increments the retry counter + exponential backoff on transient failure.
// After MAX_ATTEMPTS exhausted, Sentry-alerts and removes the row so the
// table doesn't grow unbounded (bounded retention guarantee).
//
// No-op when apiKey is absent (self-host deploys without WorkOS configured).
// Accepts an optional `now` (Unix seconds) for deterministic testing.
export async function sweepWorkosRetries(
  db: D1Database,
  apiKey: string | undefined,
  now = Math.floor(Date.now() / 1000),
): Promise<SweepResult> {
  if (!apiKey) return { retried: 0, cleared: 0, givenUp: 0, errors: 0 };

  const { results } = await db
    .prepare(
      "SELECT workos_user_id, attempt_count, next_attempt_at, enqueued_at FROM workos_identity_retry WHERE next_attempt_at <= ? ORDER BY enqueued_at ASC",
    )
    .bind(now)
    .all<RetryRow>();

  let retried = 0;
  let cleared = 0;
  let givenUp = 0;
  let errors = 0;

  for (const row of results) {
    // A user may re-register with the same WorkOS id after a prior erasure left
    // a stale retry row (local delete succeeded, WorkOS delete failed). Never
    // delete a live identity — drop the obsolete queue entry instead.
    if (await localUserExists(db, row.workos_user_id)) {
      await db
        .prepare("DELETE FROM workos_identity_retry WHERE workos_user_id = ?")
        .bind(row.workos_user_id)
        .run();
      cleared += 1;
      continue;
    }

    // Claim the row only when no local user exists — signup that completes
    // between the guard above and this statement loses the race and leaves
    // zero rows deleted, so we skip the external delete.
    if (!(await claimRetryRowIfNoLocalUser(db, row.workos_user_id))) {
      if (await localUserExists(db, row.workos_user_id)) {
        cleared += 1;
      }
      continue;
    }

    try {
      // Final synchronous guard immediately before the outbound call — the only
      // remaining race is signup during the HTTP round-trip.
      if (await localUserExists(db, row.workos_user_id)) {
        cleared += 1;
        continue;
      }

      retried += 1;
      await deleteWorkosUser(apiKey, row.workos_user_id);

      if (await localUserExists(db, row.workos_user_id)) {
        Sentry.captureException(
          new Error(
            `WorkOS identity ${row.workos_user_id} was deleted after local re-registration during sweep — manual recovery required`,
          ),
        );
      }

      cleared += 1;
    } catch (err) {
      const nextCount = row.attempt_count + 1;
      // Row was claimed above — re-enqueue so a transient failure can retry.
      if (nextCount < MAX_ATTEMPTS) {
        const backoffSecs = Math.min(86400, 3600 * 2 ** row.attempt_count);
        await db
          .prepare(
            `INSERT OR IGNORE INTO workos_identity_retry
             (workos_user_id, attempt_count, next_attempt_at, enqueued_at)
             VALUES (?, ?, ?, ?)`,
          )
          .bind(
            row.workos_user_id,
            nextCount,
            now + backoffSecs,
            row.enqueued_at,
          )
          .run();
      }
      if (nextCount >= MAX_ATTEMPTS) {
        Sentry.captureException(
          new Error(
            `WorkOS identity ${row.workos_user_id} could not be deleted after ${MAX_ATTEMPTS} attempts; manual intervention required`,
          ),
        );
        await db
          .prepare("DELETE FROM workos_identity_retry WHERE workos_user_id = ?")
          .bind(row.workos_user_id)
          .run();
        givenUp += 1;
      } else {
        Sentry.captureException(err);
        errors += 1;
      }
    }
  }

  return { retried, cleared, givenUp, errors };
}
