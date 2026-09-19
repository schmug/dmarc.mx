import { describe, expect, it } from "vitest";
import { BLOCKING_SEVERITIES, classifyAuditResult } from "../classify.js";

// Shape captured from a real `npm audit --omit=dev --json` run on this repo
// (npm 10.9.8): auditReportVersion is a number, metadata.vulnerabilities carries
// six numeric severity counts, and `vulnerabilities` is keyed by package name.
function report(
  counts: Partial<Record<string, number>>,
  vulnerabilities: Record<string, unknown> = {},
): string {
  return JSON.stringify({
    auditReportVersion: 2,
    vulnerabilities,
    metadata: {
      vulnerabilities: {
        info: 0,
        low: 0,
        moderate: 0,
        high: 0,
        critical: 0,
        total: 0,
        ...counts,
      },
      dependencies: { prod: 4, dev: 0, total: 4 },
    },
  });
}

describe("classifyAuditResult — real advisory reports", () => {
  it("is clean when no high or critical advisories are present", () => {
    // The live baseline: one moderate hono advisory, nothing at or above high.
    const v = classifyAuditResult(
      report({ moderate: 1, total: 1 }, { hono: { severity: "moderate" } }),
      "",
      1, // npm exits 1 for any advisory; the payload, not the exit code, decides
    );
    expect(v.kind).toBe("clean");
  });

  it("blocks on a high advisory and names the package", () => {
    const v = classifyAuditResult(
      report({ high: 1, total: 1 }, { hono: { severity: "high" } }),
      "",
      1,
    );
    expect(v.kind).toBe("vulnerable");
    if (v.kind !== "vulnerable") return;
    expect(v.counts.high).toBe(1);
    expect(v.advisories).toEqual(["hono: high"]);
  });

  it("blocks on a critical advisory", () => {
    const v = classifyAuditResult(
      report({ critical: 2, total: 2 }, { jose: { severity: "critical" } }),
      "",
      1,
    );
    expect(v.kind).toBe("vulnerable");
    if (v.kind !== "vulnerable") return;
    expect(v.counts.critical).toBe(2);
  });

  it("blocks on counts even when npm reports exit 0", () => {
    // Fail closed: never let npm's exit code override a payload that says high.
    const v = classifyAuditResult(report({ high: 1, total: 1 }), "", 0);
    expect(v.kind).toBe("vulnerable");
  });

  it("only treats high and critical as blocking", () => {
    expect(BLOCKING_SEVERITIES).toEqual(["critical", "high"]);
  });
});

describe("classifyAuditResult — backend unavailable (#745 outage)", () => {
  // Observed 2026-09-19: npm's bulk advisory endpoint 503'd, the CLI fell back
  // to the retired /quick endpoint and surfaced its 400 instead. The message
  // blames package-lock.json, which is a red herring — a scratch project with a
  // lockfile npm generated seconds earlier reproduced it identically.
  it("classifies the non-JSON registry error as unavailable", () => {
    const stderr = [
      "npm warn audit 400 Bad Request - POST https://registry.npmjs.org/-/npm/v1/security/audits/quick",
      "npm error audit endpoint returned an error",
    ].join("\n");
    const v = classifyAuditResult("", stderr, 1);
    expect(v.kind).toBe("unavailable");
  });

  it("classifies a JSON error envelope as unavailable", () => {
    const stdout = JSON.stringify({
      error: {
        code: "E400",
        summary: "Invalid package tree, run  npm install  to rebuild your package-lock.json",
        detail: "",
      },
    });
    const v = classifyAuditResult(stdout, "", 1);
    expect(v.kind).toBe("unavailable");
  });

  it("classifies empty output as unavailable", () => {
    expect(classifyAuditResult("", "", 1).kind).toBe("unavailable");
  });
});

describe("classifyAuditResult — malformed payloads never read as clean", () => {
  // Both external reviewers flagged the same trap: presence of a `metadata` key
  // is not a stable "the backend answered" signal. Anything that does not
  // validate in full is unavailable (which fails the gate), never clean.
  it("does not treat a report missing metadata.vulnerabilities as clean", () => {
    const stdout = JSON.stringify({
      auditReportVersion: 2,
      vulnerabilities: {},
      metadata: { dependencies: { prod: 4, dev: 0, total: 4 } },
    });
    expect(classifyAuditResult(stdout, "", 0).kind).toBe("unavailable");
  });

  it("does not treat non-numeric severity counts as clean", () => {
    const stdout = JSON.stringify({
      auditReportVersion: 2,
      vulnerabilities: {},
      metadata: {
        vulnerabilities: {
          info: 0,
          low: 0,
          moderate: 0,
          high: "0",
          critical: 0,
          total: 0,
        },
      },
    });
    expect(classifyAuditResult(stdout, "", 0).kind).toBe("unavailable");
  });

  it("does not treat a report missing a severity key as clean", () => {
    const stdout = JSON.stringify({
      auditReportVersion: 2,
      vulnerabilities: {},
      metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, total: 0 } },
    });
    expect(classifyAuditResult(stdout, "", 0).kind).toBe("unavailable");
  });

  it("rejects a payload with no auditReportVersion (schema drift)", () => {
    const stdout = JSON.stringify({
      metadata: {
        vulnerabilities: {
          info: 0,
          low: 0,
          moderate: 0,
          high: 0,
          critical: 0,
          total: 0,
        },
      },
    });
    expect(classifyAuditResult(stdout, "", 0).kind).toBe("unavailable");
  });

  it("rejects unparseable JSON", () => {
    expect(classifyAuditResult("{not json", "", 1).kind).toBe("unavailable");
  });

  it("rejects a JSON array", () => {
    expect(classifyAuditResult("[]", "", 0).kind).toBe("unavailable");
  });

  it("rejects negative counts", () => {
    expect(classifyAuditResult(report({ high: -1 }), "", 0).kind).toBe(
      "unavailable",
    );
  });
});
