-- Durable retry queue for WorkOS identity deletions that fail during
-- self-serve account deletion (#552). Persists only the opaque WorkOS user id
-- (not PII) + retry metadata. The nightly sweep processes due entries with
-- exponential backoff and gives up + Sentry-alerts after MAX_ATTEMPTS.
CREATE TABLE IF NOT EXISTS workos_identity_retry (
  workos_user_id  TEXT    PRIMARY KEY,
  attempt_count   INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL DEFAULT (unixepoch()),
  enqueued_at     INTEGER NOT NULL DEFAULT (unixepoch())
);
