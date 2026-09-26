// DKIM selector input validation for the HTTP routes' `?selectors=` query
// param. Moved out of src/index.ts unchanged (#669).

// DKIM selector charset per RFC 6376 §3.1: sub-domain syntax, which is
// letters / digits / hyphens, with dot-separated labels. We also allow
// underscores since some providers use them in practice. Anything else
// is dropped silently — an invalid selector cannot match a real DKIM key.
const VALID_SELECTOR = /^[A-Za-z0-9._-]+$/;

// DoS guard (GHSA-6fqp-4vhc-59mf): every custom selector becomes one concurrent
// DNS lookup in analyzeDkim, so an unbounded attacker-supplied list is a DNS
// amplification vector charged against a single rate-limit token. Bound both
// the per-item length (RFC 1035 label limit) and the count. 16 custom selectors
// is generous given ~37 built-in COMMON_SELECTORS. parseSelectorsFromArray in
// src/mcp/handler.ts mirrors these limits for the MCP path.
export const MAX_SELECTOR_LENGTH = 63;
export const MAX_SELECTORS = 16;

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
