import { DurableObject } from "cloudflare:workers";
import type { RateLimitResult } from "./rate-limit.js";

// Atomic per-identity rate-limit counter (GHSA-v7qc-7qh8-h69g).
//
// The previous limiter was a non-atomic read-modify-write on the Cache API
// (`match` → `count++` → `put`). The Cache API has no atomic increment/CAS, so
// a concurrent burst under one identity could all read the same stale count
// and each write `count + 1`, letting the effective ceiling exceed the
// configured limit. A Durable Object's single-threaded execution serializes
// the read-modify-write across isolates and colos, which is the canonical
// Workers primitive for an atomic counter.
//
// One DO instance per identity: callers route with `getByName("ip:<x>")` /
// `getByName("user:<id>")`, so each instance owns exactly one bucket (a single
// row). The whole `increment` body is synchronous SQL — it runs to completion
// without yielding, so overlapping RPCs cannot interleave their read and write.
export class RateLimiterDO extends DurableObject {
  constructor(ctx: DurableObjectState, env: Cloudflare.Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(
        `CREATE TABLE IF NOT EXISTS bucket (
          id INTEGER PRIMARY KEY,
          count INTEGER NOT NULL,
          reset_at INTEGER NOT NULL
        )`,
      );
      this.ctx.storage.sql.exec(
        `CREATE TABLE IF NOT EXISTS consumed_nonces (
          jti TEXT PRIMARY KEY,
          expires_at INTEGER NOT NULL
        )`,
      );
    });
  }

  // Atomically increments this identity's counter for the current window and
  // returns the resulting decision. `limit`/`windowSec` are passed per call so
  // the same DO class serves both tiers (free 10/60, pro 60/3600) — the bucket
  // is keyed entirely by the DO instance (identity), not the window size.
  increment(limit: number, windowSec: number): RateLimitResult {
    const nowSec = Math.floor(Date.now() / 1000);
    const existing = this.ctx.storage.sql
      .exec<{ count: number; reset_at: number }>(
        "SELECT count, reset_at FROM bucket WHERE id = 1",
      )
      .toArray()[0];

    let count: number;
    let resetAt: number;
    if (existing && existing.reset_at > nowSec) {
      count = existing.count + 1;
      resetAt = existing.reset_at;
    } else {
      // Fresh window: no row yet, or the previous window has elapsed.
      count = 1;
      resetAt = nowSec + windowSec;
    }

    this.ctx.storage.sql.exec(
      `INSERT INTO bucket (id, count, reset_at) VALUES (1, ?, ?)
       ON CONFLICT(id) DO UPDATE SET count = excluded.count, reset_at = excluded.reset_at`,
      count,
      resetAt,
    );

    return {
      allowed: count <= limit,
      remaining: Math.max(0, limit - count),
      limit,
      windowSec,
      resetAt,
      count,
    };
  }

  // Atomically marks a one-time nonce as consumed. Returns true the first time
  // this jti is presented (first use), false if it was already recorded (replay
  // attempt). Expired rows are treated as not-yet-consumed so a stale nonce
  // from a previous proof can't occupy the slot indefinitely.
  tryConsumeNonce(jti: string, expiresAt: number): boolean {
    const nowSec = Math.floor(Date.now() / 1000);
    // Purge this jti's entry only if it has expired (keeps storage bounded).
    this.ctx.storage.sql.exec(
      "DELETE FROM consumed_nonces WHERE jti = ? AND expires_at <= ?",
      jti,
      nowSec,
    );
    const result = this.ctx.storage.sql.exec(
      "INSERT OR IGNORE INTO consumed_nonces (jti, expires_at) VALUES (?, ?)",
      jti,
      expiresAt,
    );
    return result.rowsWritten === 1;
  }
}
