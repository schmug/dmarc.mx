import * as Sentry from "@sentry/cloudflare";

/**
 * Transient-failure retry for D1 **reads** (#741).
 *
 * D1 occasionally rejects an otherwise-valid query with an infrastructure
 * error that has nothing to do with the SQL — most visibly
 * `D1_ERROR: internal error; reference = <id>`, which surfaced as a 500 on
 * `GET /dashboard` when `getPlanForUser` was the first statement the page ran.
 * The query is fine; the same statement succeeds on the next attempt. Without
 * a retry every such blip is a hard error page for a logged-in user, because
 * the dashboard has no useful degraded mode (guessing "free" for a paying
 * account would be worse than failing).
 *
 * Deliberately **reads only**. D1 exposes no idempotency token, so a `.run()`
 * that failed after the write landed is indistinguishable from one that never
 * landed — retrying writes could double-apply an INSERT. Every mutation in
 * `src/db/` therefore stays un-retried and bubbles up as before. This module
 * is only ever wrapped around `.first()` / `.all()` / `.raw()`, none of which
 * this codebase uses with `RETURNING`.
 */

// Three attempts total (the original plus two retries). Worst case adds
// ~90ms of backoff to a page load — cheap next to serving an error page —
// while still bounding the extra D1 calls, which count as Workers
// subrequests against the per-invocation ceiling (see src/cron/rescan.ts).
export const D1_READ_ATTEMPTS = 3;
const D1_READ_BASE_DELAY_MS = 30;

// Matched case-insensitively against the error message and its `cause`.
// Scoped by call site rather than by prefix: `d1Read` only ever wraps a D1
// statement execution, so a loose marker like "internal error" cannot catch
// an unrelated application error. Anything NOT listed here (SQL syntax,
// constraint violations, missing tables) is a real bug and must fail fast
// instead of being retried three times.
const TRANSIENT_MARKERS = [
  "internal error",
  "network connection lost",
  "storage caused object to be reset",
  "reset because its code was updated",
  "please try again",
];

function messagesOf(err: unknown): string[] {
  const out: string[] = [];
  let current: unknown = err;
  // D1 wraps the underlying failure, so the marker can live on either the
  // thrown error or its cause (`Error: D1_ERROR: internal error; …` with
  // `cause: Error: internal error; …`). Depth-bounded so a self-referential
  // cause chain can't spin.
  for (let depth = 0; current instanceof Error && depth < 4; depth++) {
    out.push(current.message.toLowerCase());
    current = (current as { cause?: unknown }).cause;
  }
  return out;
}

export function isTransientD1Error(err: unknown): boolean {
  return messagesOf(err).some((msg) =>
    TRANSIENT_MARKERS.some((marker) => msg.includes(marker)),
  );
}

function sleep(ms: number): Promise<void> {
  return ms > 0
    ? new Promise((resolve) => setTimeout(resolve, ms))
    : Promise.resolve();
}

export interface D1ReadRetryOptions {
  /** Total attempts including the first. Defaults to `D1_READ_ATTEMPTS`. */
  attempts?: number;
  /** Backoff base in ms; doubles per retry. Tests pass 0 to skip waiting. */
  baseDelayMs?: number;
}

/**
 * Runs a D1 read, retrying it with jittered exponential backoff while the
 * failure looks transient. A non-transient error is rethrown immediately, and
 * the last transient error is rethrown once the attempts are spent — callers
 * see the same exception they would have seen before, just less often.
 */
export async function d1Read<T>(
  run: () => Promise<T>,
  options: D1ReadRetryOptions = {},
): Promise<T> {
  const attempts = options.attempts ?? D1_READ_ATTEMPTS;
  const baseDelayMs = options.baseDelayMs ?? D1_READ_BASE_DELAY_MS;

  for (let attempt = 1; ; attempt++) {
    try {
      return await run();
    } catch (err) {
      if (attempt >= attempts || !isTransientD1Error(err)) throw err;
      Sentry.addBreadcrumb({
        category: "d1.retry",
        message: err instanceof Error ? err.message : "transient D1 read error",
        data: { attempt, attempts },
        level: "warning",
      });
      // Full jitter on the upper half of the window: spreads the retries of
      // a burst of concurrent dashboard queries instead of re-firing them
      // all in lockstep against a D1 shard that is already unhappy.
      const delay = baseDelayMs * 2 ** (attempt - 1);
      await sleep(delay * (0.5 + Math.random()));
    }
  }
}
