import type { MtaStsResult, MxResult, Validation } from "./types.js";

/**
 * Returns true when the MX hostname is covered by the given MTA-STS pattern.
 *
 * RFC 8461 §3.4 defines the wildcard rule:
 *   - `*.example.com` matches `mail.example.com` but NOT `mail.sub.example.com`
 *     (only one label may be wildcarded).
 *   - Exact hostname matches work without a wildcard.
 * Trailing dots (FQDN notation) are stripped before comparison.
 */
export function mxMatchesPattern(mx: string, pattern: string): boolean {
  const hParts = mx.toLowerCase().replace(/\.$/,  "").split(".");
  const pParts = pattern.toLowerCase().replace(/\.$/,  "").split(".");
  if (pParts[0] === "*") {
    // RFC 8461 §3.4: wildcard covers exactly one label (*.example.com matches
    // mail.example.com but not mail.sub.example.com).
    const pTail = pParts.slice(1);
    if (hParts.length !== pTail.length + 1) return false;
    return hParts.slice(1).join(".") === pTail.join(".");
  }
  return hParts.join(".") === pParts.join(".");
}

/**
 * Cross-checks MX hostnames against the MTA-STS policy `mx` patterns.
 *
 * Only runs when:
 *   - At least one MX record exists
 *   - An MTA-STS policy is present (not null)
 *   - The policy has at least one `mx` pattern
 *
 * Returns Validation[] entries to be appended to the MTA-STS result.
 */
export function checkMxMtaStsConsistency(
  mx: MxResult,
  mtaSts: MtaStsResult,
): Validation[] {
  if (mx.records.length === 0) return [];
  if (!mtaSts.policy) return [];
  if (mtaSts.policy.mx.length === 0) return [];

  const validations: Validation[] = [];
  const patterns = mtaSts.policy.mx;
  const uncovered: string[] = [];

  for (const record of mx.records) {
    const covered = patterns.some((pattern) =>
      mxMatchesPattern(record.exchange, pattern),
    );
    if (!covered) {
      uncovered.push(record.exchange);
    }
  }

  if (uncovered.length > 0) {
    for (const host of uncovered) {
      validations.push({
        status: "warn",
        message: `MX host ${host} is not covered by any MTA-STS policy mx pattern`,
      });
    }
  } else {
    validations.push({
      status: "pass",
      message: "All MX hosts are covered by MTA-STS policy mx patterns",
    });
  }

  return validations;
}
