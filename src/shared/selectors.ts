// Shared, side-effect-free DKIM selector parsing + validation used by both
// the public scan endpoints in src/index.ts and the dashboard CRUD routes
// in src/dashboard/routes.ts. Kept in src/shared/ to avoid a circular
// import (dashboard → index → dashboard), same reasoning as domain.ts.

// DoS guard (GHSA-6fqp-4vhc-59mf): every custom selector becomes one concurrent
// DNS lookup in analyzeDkim, so an unbounded attacker-supplied list is a DNS
// amplification vector charged against a single rate-limit token. Bound both
// the per-item length (RFC 1035 label limit) and the count. 16 custom selectors
// is generous given ~37 built-in COMMON_SELECTORS. parseSelectorsFromArray in
// src/mcp/handler.ts mirrors these limits for the MCP path.
export const MAX_SELECTOR_LENGTH = 63;
export const MAX_SELECTORS = 16;

// DKIM selector charset per RFC 6376 §3.1: sub-domain syntax, which is
// letters / digits / hyphens, with dot-separated labels. We also allow
// underscores since some providers use them in practice.
const VALID_SELECTOR = /^[A-Za-z0-9._-]+$/;

export function parseSelectors(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(
      (s) =>
        s.length > 0 &&
        s.length <= MAX_SELECTOR_LENGTH &&
        VALID_SELECTOR.test(s),
    )
    .slice(0, MAX_SELECTORS);
}

// Write-time counterpart to parseSelectors (issue #755): the query-string
// path above silently drops anything invalid because a bad selector is
// harmless — it just never matches a DNS record. Persisted per-domain
// selectors are different: silently truncating what a user typed into the
// add-domain form would save something other than what they asked for, with
// no indication anything was dropped. So this rejects instead of sanitizing,
// before the value ever reaches storage (and therefore a DNS query).
export function validateCustomSelectors(
  raw: string | undefined,
): { selectors: string[] } | { error: string } {
  const trimmed = raw?.trim();
  if (!trimmed) return { selectors: [] };
  const items = trimmed
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (items.length > MAX_SELECTORS) {
    return { error: `Too many selectors — up to ${MAX_SELECTORS} allowed.` };
  }
  const sanitized = parseSelectors(trimmed);
  if (sanitized.length !== items.length) {
    return {
      error:
        "Selectors may only contain letters, numbers, periods, underscores, and hyphens, up to 63 characters each.",
    };
  }
  return { selectors: sanitized };
}
