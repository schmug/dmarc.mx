import { describe, expect, it, vi } from "vitest";
import type { AuditRun } from "../gate.js";
import { MAX_ATTEMPTS, decideGate } from "../gate.js";

const CLEAN: AuditRun = {
  stdout: JSON.stringify({
    auditReportVersion: 2,
    vulnerabilities: {},
    metadata: {
      vulnerabilities: {
        info: 0,
        low: 0,
        moderate: 1,
        high: 0,
        critical: 0,
        total: 1,
      },
    },
  }),
  stderr: "",
  exitCode: 1,
};

const VULNERABLE: AuditRun = {
  stdout: JSON.stringify({
    auditReportVersion: 2,
    vulnerabilities: { hono: { severity: "high" } },
    metadata: {
      vulnerabilities: {
        info: 0,
        low: 0,
        moderate: 0,
        high: 1,
        critical: 0,
        total: 1,
      },
    },
  }),
  stderr: "",
  exitCode: 1,
};

const OUTAGE: AuditRun = {
  stdout: "",
  stderr: "npm error audit endpoint returned an error",
  exitCode: 1,
};

const noSleep = () => Promise.resolve();

describe("decideGate", () => {
  it("passes on a clean report without retrying", async () => {
    const runAudit = vi.fn().mockResolvedValue(CLEAN);
    const result = await decideGate(runAudit, noSleep);
    expect(result.exitCode).toBe(0);
    expect(runAudit).toHaveBeenCalledTimes(1);
  });

  it("fails on advisories without retrying, and says they are advisories", async () => {
    const runAudit = vi.fn().mockResolvedValue(VULNERABLE);
    const result = await decideGate(runAudit, noSleep);
    expect(result.exitCode).toBe(1);
    expect(runAudit).toHaveBeenCalledTimes(1);
    expect(result.output).toContain("hono: high");
    expect(result.output).toContain("HIGH/CRITICAL");
    // Must not be mistaken for the outage path.
    expect(result.output).not.toContain("registry outage");
  });

  it("retries a transient outage and passes once the backend answers", async () => {
    const runAudit = vi
      .fn()
      .mockResolvedValueOnce(OUTAGE)
      .mockResolvedValueOnce(CLEAN);
    const result = await decideGate(runAudit, noSleep);
    expect(result.exitCode).toBe(0);
    expect(runAudit).toHaveBeenCalledTimes(2);
  });

  it("fails closed after exhausting retries, flagged as an outage not a finding", async () => {
    const runAudit = vi.fn().mockResolvedValue(OUTAGE);
    const result = await decideGate(runAudit, noSleep);
    expect(result.exitCode).toBe(1);
    expect(runAudit).toHaveBeenCalledTimes(MAX_ATTEMPTS);
    expect(result.output).toContain("registry outage");
    expect(result.output).toContain("NOT a vulnerability finding");
  });

  it("never converts an outage into a pass", async () => {
    // The fail-open variant both reviewers rejected: an agent dependency bump
    // to a known critical could merge unaudited while `npm ci` still works.
    const runAudit = vi.fn().mockResolvedValue(OUTAGE);
    const result = await decideGate(runAudit, noSleep);
    expect(result.exitCode).not.toBe(0);
  });

  it("backs off between attempts", async () => {
    const sleep = vi.fn().mockResolvedValue(undefined);
    const runAudit = vi.fn().mockResolvedValue(OUTAGE);
    await decideGate(runAudit, sleep);
    // One sleep between each pair of attempts, none after the last.
    expect(sleep).toHaveBeenCalledTimes(MAX_ATTEMPTS - 1);
    const delays = sleep.mock.calls.map((c) => c[0] as number);
    expect(delays[1]).toBeGreaterThan(delays[0]);
  });

  it("treats a thrown spawn failure as unavailable rather than crashing", async () => {
    const runAudit = vi.fn().mockRejectedValue(new Error("spawn ENOENT"));
    const result = await decideGate(runAudit, noSleep);
    expect(result.exitCode).toBe(1);
    expect(result.output).toContain("registry outage");
  });
});
