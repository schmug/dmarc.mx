// Hono-level rate-limit wiring on top of the atomic counter in
// src/rate-limit.ts. Moved out of src/index.ts unchanged apart from `export`
// (#669); the per-path `app.use(path, rateLimitMiddleware(...))`
// registrations stay in src/index.ts.
import type { Context } from "hono";
import { BULK_IN_BAND_CAP } from "../api/bulk-scan.js";
import { resolveBearer } from "../auth/api-key.js";
import { getPlanForUser } from "../db/subscriptions.js";
import {
  checkRateLimit,
  getRateLimitConfig,
  type RateLimitResult,
  rateLimitHeaders,
} from "../rate-limit.js";
import { getClientIp } from "../shared/client.js";
import { normalizeDomain } from "../shared/domain.js";

// Resolves rate-limit identity + config for a request. Pro-authed bearers
// lift to the per-user bucket (60/hour). Everyone else — anonymous callers,
// bearers whose subscription isn't active, free-plan bearers — falls through
// to the per-IP anon bucket (10/60s). Free-authed keeps on IP on purpose: a
// free bearer hitting from two IPs gets two anon buckets, which matches what
// anonymous scanners already see and avoids making a free account worse than
// no account. Bearer identity is stashed on context so downstream handlers
// (/api/check scan-history persistence) can read it without re-verifying.
export async function resolveRateLimitScope(c: Context): Promise<{
  identity: string;
  config: ReturnType<typeof getRateLimitConfig>;
}> {
  const bearer = await resolveBearer(c);
  if (bearer) {
    c.set("bearer" as never, bearer);
    const db = (c.env as { DB?: D1Database }).DB;
    if (db) {
      const plan = await getPlanForUser(db, bearer.userId);
      if (plan === "pro") {
        return {
          identity: `user:${bearer.userId}`,
          config: getRateLimitConfig("pro"),
        };
      }
    }
  }
  return {
    identity: `ip:${getClientIp(c)}`,
    config: getRateLimitConfig("free"),
  };
}

export type RateLimitBlockedResponder = (
  c: Context,
  result: RateLimitResult,
  headers: Record<string, string>,
) => Response | Promise<Response>;

export function rateLimitMiddleware(
  onBlocked: RateLimitBlockedResponder,
  // Optional per-route weight resolver (issue #619). Omitted → every request
  // costs 1 token, the historical behavior. Bulk-scan uses this to charge
  // proportional to its in-band scan count instead of counting as one request.
  weightFn?: (c: Context) => Promise<number>,
) {
  return async (c: Context, next: () => Promise<void>) => {
    const { identity, config } = await resolveRateLimitScope(c);
    const weight = weightFn ? await weightFn(c) : 1;
    // The Durable Object RPC is awaited end-to-end, so the counter is durably
    // updated before the decision is used — no deferred write to drain.
    // `c.env` is always present at runtime; the optional chain keeps the
    // limiter working in lightweight unit tests that call `app.request(path)`
    // without an env (falls back to the in-memory limiter).
    const result = await checkRateLimit(
      identity,
      config,
      c.env?.RATE_LIMITER,
      weight,
    );

    const headers = rateLimitHeaders(result);

    if (!result.allowed) {
      return onBlocked(c, result, headers);
    }

    await next();
    // ⚡ Bolt Optimization: Use for...in instead of Object.entries() on hot paths.
    // Avoids allocating an array of key-value tuples for headers on every request,
    // reducing GC pressure for high-traffic middleware.
    for (const key in headers) {
      c.res.headers.set(key, headers[key]);
    }
  };
}

export function blockedMessage(result: RateLimitResult): string {
  const waitSec = Math.max(1, result.resetAt - Math.floor(Date.now() / 1000));
  return `Rate limit exceeded. Try again in ${waitSec} seconds.`;
}

// Rate-limit weight for /api/bulk-scan (issue #619): the number of distinct
// valid domains in the request body, capped at BULK_IN_BAND_CAP — mirrors the
// normalize+dedupe step `processBulkScan` runs before dispatching in-band
// scans, without its DB-backed watchlist-cap lookup, so the charge is known
// before the expensive work runs. `c.req.json()` is cached by Hono, so the
// handler's own body parse reuses this same parse rather than re-reading the
// request stream. Malformed/absent bodies fall back to the default weight of
// 1 — the handler's own validation still rejects them.
export async function bulkScanWeight(c: Context): Promise<number> {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return 1;
  }
  const rawDomains = (body as { domains?: unknown })?.domains;
  if (!Array.isArray(rawDomains)) return 1;
  const distinct = new Set<string>();
  for (const d of rawDomains) {
    if (typeof d !== "string") continue;
    const trimmed = d.trim();
    if (!trimmed) continue;
    const normalized = normalizeDomain(trimmed);
    if (normalized) distinct.add(normalized);
  }
  return Math.min(Math.max(distinct.size, 1), BULK_IN_BAND_CAP);
}
