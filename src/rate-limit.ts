import type { RateLimiterDO } from "./rate-limit-do.js";

export interface RateLimitConfig {
  limit: number;
  windowSec: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  windowSec: number;
  resetAt: number;
  // Post-increment value of the identity's counter for the current window.
  // Not surfaced in headers; exposed for observability and to let tests assert
  // the atomic counter reached the expected total under concurrency.
  count: number;
}

export type PlanTier = "free" | "pro";

const FREE_CONFIG: RateLimitConfig = { limit: 10, windowSec: 60 };
const PRO_CONFIG: RateLimitConfig = { limit: 60, windowSec: 3600 };

export function getRateLimitConfig(plan: PlanTier): RateLimitConfig {
  return plan === "pro" ? PRO_CONFIG : FREE_CONFIG;
}

interface MemoryEntry {
  count: number;
  expires: number;
  resetAt: number;
}

const memoryStore = new Map<string, MemoryEntry>();
let callCount = 0;
const SWEEP_INTERVAL = 100;

export async function checkRateLimit(
  identity: string,
  config: RateLimitConfig,
  namespace?: DurableObjectNamespace<RateLimiterDO>,
): Promise<RateLimitResult> {
  // Durable Object is the only atomic primitive on Workers: its single-threaded
  // RPC serializes the read-modify-write so a concurrent burst under one
  // identity cannot exceed the limit (GHSA-v7qc-7qh8-h69g). The Cache API
  // counter it replaces had no atomic increment, so bursts could bypass the
  // ceiling.
  if (namespace) {
    try {
      return await checkRateLimitDO(identity, config, namespace);
    } catch {
      // DO unreachable (transient error, or no binding at runtime). Fall back
      // to the in-memory limiter so requests stay bounded rather than failing
      // open or 500ing.
    }
  }
  // Graceful fallback for environments without the DO binding (self-host
  // deploys that strip it, and the Node test pool). Atomic within a single
  // isolate; not shared across isolates/colos.
  return checkRateLimitMemory(identity, config);
}

async function checkRateLimitDO(
  identity: string,
  config: RateLimitConfig,
  namespace: DurableObjectNamespace<RateLimiterDO>,
): Promise<RateLimitResult> {
  // One DO instance per identity bucket (`ip:<x>` / `user:<id>`). `getByName`
  // maps the identity string to a stable instance; the RPC returns the
  // post-increment decision for the current window.
  const stub = namespace.getByName(identity);
  return stub.increment(config.limit, config.windowSec);
}

function checkRateLimitMemory(
  identity: string,
  config: RateLimitConfig,
): RateLimitResult {
  const now = Date.now();
  const nowSec = Math.floor(now / 1000);

  if (++callCount >= SWEEP_INTERVAL) {
    callCount = 0;
    for (const [key, val] of memoryStore) {
      if (val.expires <= now) memoryStore.delete(key);
    }
  }

  const entry = memoryStore.get(identity);

  let count: number;
  let resetAt: number;
  if (entry && entry.expires > now) {
    count = entry.count + 1;
    resetAt = entry.resetAt;
  } else {
    count = 1;
    resetAt = nowSec + config.windowSec;
  }

  memoryStore.set(identity, {
    count,
    expires: now + config.windowSec * 1000,
    resetAt,
  });

  const allowed = count <= config.limit;
  const remaining = Math.max(0, config.limit - count);
  return {
    allowed,
    remaining,
    limit: config.limit,
    windowSec: config.windowSec,
    resetAt,
    count,
  };
}

export function rateLimitHeaders(
  result: RateLimitResult,
): Record<string, string> {
  return {
    "X-RateLimit-Limit": String(result.limit),
    "X-RateLimit-Remaining": String(result.remaining),
    "X-RateLimit-Window": `${result.windowSec}s`,
    "X-RateLimit-Reset": String(result.resetAt),
  };
}

function _resetCallCount() {
  callCount = 0;
}

export {
  _resetCallCount,
  FREE_CONFIG as _FREE_CONFIG,
  memoryStore as _memoryStore,
  PRO_CONFIG as _PRO_CONFIG,
  SWEEP_INTERVAL as _SWEEP_INTERVAL,
};
