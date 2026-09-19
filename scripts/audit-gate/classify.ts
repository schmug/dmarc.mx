/**
 * Classifier for `npm audit --omit=dev --json` output.
 *
 * Exists because npm's exit code cannot distinguish "HIGH/CRITICAL advisories
 * were found" from "the advisory backend was unreachable" — both are 1. On
 * 2026-09-19 npm's bulk advisory endpoint went into maintenance, the CLI fell
 * back to the retired /quick endpoint, and every PR in the repo failed the
 * required `check` job with `Invalid package tree, run npm install to rebuild
 * your package-lock.json`. Nothing was wrong with the lockfile (#745).
 *
 * Design rule, fail closed: a payload is `clean` ONLY when it validates in
 * full. Anything else — unparseable, an error envelope, a missing or
 * non-numeric severity count, an unrecognized schema — is `unavailable`, which
 * the caller turns into a failed job with an unmistakable outage message. The
 * presence of a `metadata` key is deliberately NOT treated as proof the backend
 * answered; that check is too weak to carry a merge gate.
 */

/** Severities that block a merge. Runtime deps only — the caller passes --omit=dev. */
export const BLOCKING_SEVERITIES = ["critical", "high"] as const;

const SEVERITY_KEYS = [
  "info",
  "low",
  "moderate",
  "high",
  "critical",
  "total",
] as const;

export type SeverityCounts = Record<(typeof SEVERITY_KEYS)[number], number>;

export type AuditVerdict =
  | { kind: "clean"; counts: SeverityCounts }
  | { kind: "vulnerable"; counts: SeverityCounts; advisories: string[] }
  | { kind: "unavailable"; reason: string };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" && value !== null && !Array.isArray(value)
  );
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

/**
 * Decide from a completed `npm audit --json` invocation.
 *
 * `exitCode` is accepted for diagnostics only. It never overrides the payload:
 * npm exits 1 for any advisory at all (this repo carries a standing moderate),
 * and a payload reporting a high advisory blocks even on exit 0.
 */
export function classifyAuditResult(
  stdout: string,
  stderr: string,
  exitCode: number,
): AuditVerdict {
  const trimmed = stdout.trim();
  if (trimmed === "") {
    const detail = stderr.trim().split("\n").slice(-2).join(" ; ");
    return {
      kind: "unavailable",
      reason: `npm audit produced no JSON on stdout (exit ${exitCode})${detail ? `: ${detail}` : ""}`,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return {
      kind: "unavailable",
      reason: `npm audit output was not JSON (exit ${exitCode})`,
    };
  }

  if (!isPlainObject(parsed)) {
    return { kind: "unavailable", reason: "npm audit output was not a JSON object" };
  }

  // npm emits this envelope instead of a report when the registry rejects the
  // request — including the misleading "Invalid package tree" 400 from the
  // retired /quick endpoint.
  if (isPlainObject(parsed.error)) {
    const summary =
      typeof parsed.error.summary === "string" ? parsed.error.summary : "";
    return {
      kind: "unavailable",
      reason: `npm audit returned an error envelope${summary ? `: ${summary}` : ""}`,
    };
  }

  if (typeof parsed.auditReportVersion !== "number") {
    return {
      kind: "unavailable",
      reason: "npm audit output carried no auditReportVersion — unrecognized schema",
    };
  }

  const metadata = parsed.metadata;
  if (!isPlainObject(metadata) || !isPlainObject(metadata.vulnerabilities)) {
    return {
      kind: "unavailable",
      reason: "npm audit output carried no metadata.vulnerabilities block",
    };
  }

  const raw = metadata.vulnerabilities;
  const counts = {} as SeverityCounts;
  for (const key of SEVERITY_KEYS) {
    if (!isCount(raw[key])) {
      return {
        kind: "unavailable",
        reason: `npm audit severity count "${key}" was missing or not a non-negative integer`,
      };
    }
    counts[key] = raw[key];
  }

  const blocking = BLOCKING_SEVERITIES.reduce(
    (sum, severity) => sum + counts[severity],
    0,
  );
  if (blocking === 0) return { kind: "clean", counts };

  const advisories: string[] = [];
  if (isPlainObject(parsed.vulnerabilities)) {
    for (const [name, entry] of Object.entries(parsed.vulnerabilities)) {
      if (!isPlainObject(entry)) continue;
      const severity = entry.severity;
      if (
        typeof severity === "string" &&
        (BLOCKING_SEVERITIES as readonly string[]).includes(severity)
      ) {
        advisories.push(`${name}: ${severity}`);
      }
    }
    advisories.sort();
  }

  return { kind: "vulnerable", counts, advisories };
}
