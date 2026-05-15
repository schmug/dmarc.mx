import type { MtaStsResult, MxResult, Validation } from "./types.js";

export function mxMatchesPattern(mx: string, pattern: string): boolean {
  const hParts = mx.toLowerCase().replace(/\.$/, "").split(".");
  const pParts = pattern.toLowerCase().replace(/\.$/, "").split(".");
  if (pParts[0] === "*") {
    // RFC 8461 §3.4: wildcard covers exactly one label (*.example.com matches
    // mail.example.com but not mail.sub.example.com).
    const pTail = pParts.slice(1);
    if (hParts.length !== pTail.length + 1) return false;
    return hParts.slice(1).join(".") === pTail.join(".");
  }
  return hParts.join(".") === pParts.join(".");
}

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
