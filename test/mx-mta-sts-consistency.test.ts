import { describe, expect, it } from "vitest";
import {
  checkMxMtaStsConsistency,
  mxMatchesPattern,
} from "../src/analyzers/mx-mta-sts-consistency.js";
import type { MtaStsResult, MxResult } from "../src/analyzers/types.js";

// ─── mxMatchesPattern unit tests ────────────────────────────────────────────

describe("mxMatchesPattern", () => {
  it("matches exact hostname (case-insensitive)", () => {
    expect(mxMatchesPattern("mail.example.com", "mail.example.com")).toBe(true);
    expect(mxMatchesPattern("MAIL.example.com", "mail.example.com")).toBe(true);
  });

  it("does not match a different exact hostname", () => {
    expect(mxMatchesPattern("smtp.example.com", "mail.example.com")).toBe(
      false,
    );
  });

  it("wildcard *.example.com covers mail.example.com", () => {
    expect(mxMatchesPattern("mail.example.com", "*.example.com")).toBe(true);
  });

  it("wildcard *.example.com does NOT cover mail.sub.example.com (RFC 8461 §3.4)", () => {
    expect(mxMatchesPattern("mail.sub.example.com", "*.example.com")).toBe(
      false,
    );
  });

  it("wildcard *.example.com does NOT cover example.com itself", () => {
    expect(mxMatchesPattern("example.com", "*.example.com")).toBe(false);
  });

  it("strips trailing dots (FQDN notation) before comparing", () => {
    expect(mxMatchesPattern("mail.example.com.", "*.example.com")).toBe(true);
    expect(mxMatchesPattern("mail.example.com", "*.example.com.")).toBe(true);
    expect(mxMatchesPattern("mail.example.com.", "mail.example.com.")).toBe(
      true,
    );
  });

  it("wildcard pattern is case-insensitive", () => {
    expect(mxMatchesPattern("MAIL.EXAMPLE.COM", "*.example.com")).toBe(true);
  });
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeMx(exchanges: string[]): MxResult {
  return {
    status: "info",
    records: exchanges.map((e, i) => ({ priority: (i + 1) * 10, exchange: e })),
    providers: [],
    validations: [],
  };
}

function makeMtaSts(policyMx: string[] | null, mode = "enforce"): MtaStsResult {
  return {
    status: "pass",
    dns_record: "v=STSv1; id=20240101",
    policy:
      policyMx !== null
        ? { version: "STSv1", mode, mx: policyMx, max_age: 86400 }
        : null,
    validations: [],
  };
}

// ─── checkMxMtaStsConsistency ────────────────────────────────────────────────

describe("checkMxMtaStsConsistency", () => {
  it("returns pass validation when all MX hosts are covered", () => {
    const mx = makeMx(["mail.example.com", "smtp.example.com"]);
    const mtaSts = makeMtaSts(["*.example.com"]);

    const result = checkMxMtaStsConsistency(mx, mtaSts);

    expect(result).toHaveLength(1);
    expect(result[0].status).toBe("pass");
    expect(result[0].message).toMatch(/all mx hosts are covered/i);
  });

  it("returns warn for each uncovered MX host", () => {
    const mx = makeMx(["mail.example.com", "smtp.other.com"]);
    const mtaSts = makeMtaSts(["*.example.com"]);

    const result = checkMxMtaStsConsistency(mx, mtaSts);

    expect(result).toHaveLength(1);
    expect(result[0].status).toBe("warn");
    expect(result[0].message).toContain("smtp.other.com");
  });

  it("returns a warn per uncovered host when multiple are missing", () => {
    const mx = makeMx(["a.other.com", "b.other.com"]);
    const mtaSts = makeMtaSts(["*.example.com"]);

    const result = checkMxMtaStsConsistency(mx, mtaSts);

    expect(result).toHaveLength(2);
    expect(result.every((v) => v.status === "warn")).toBe(true);
    const messages = result.map((v) => v.message);
    expect(messages.some((m) => m.includes("a.other.com"))).toBe(true);
    expect(messages.some((m) => m.includes("b.other.com"))).toBe(true);
  });

  it("wildcard *.example.com covers mail.example.com but not mail.sub.example.com", () => {
    const mx = makeMx(["mail.example.com", "mail.sub.example.com"]);
    const mtaSts = makeMtaSts(["*.example.com"]);

    const result = checkMxMtaStsConsistency(mx, mtaSts);

    expect(result).toHaveLength(1);
    expect(result[0].status).toBe("warn");
    expect(result[0].message).toContain("mail.sub.example.com");
  });

  it("returns empty array when no MTA-STS policy is present", () => {
    const mx = makeMx(["mail.example.com"]);
    const mtaSts = makeMtaSts(null);

    const result = checkMxMtaStsConsistency(mx, mtaSts);

    expect(result).toHaveLength(0);
  });

  it("returns empty array when no MX records exist", () => {
    const mx = makeMx([]);
    const mtaSts = makeMtaSts(["*.example.com"]);

    const result = checkMxMtaStsConsistency(mx, mtaSts);

    expect(result).toHaveLength(0);
  });

  it("returns empty array when policy has no mx patterns", () => {
    const mx = makeMx(["mail.example.com"]);
    const mtaSts = makeMtaSts([]);

    const result = checkMxMtaStsConsistency(mx, mtaSts);

    expect(result).toHaveLength(0);
  });

  it("MX host covered by exact pattern in policy passes", () => {
    const mx = makeMx(["mail.example.com"]);
    const mtaSts = makeMtaSts(["mail.example.com"]);

    const result = checkMxMtaStsConsistency(mx, mtaSts);

    expect(result).toHaveLength(1);
    expect(result[0].status).toBe("pass");
  });

  it("mix of exact and wildcard patterns can cover multiple MX hosts", () => {
    const mx = makeMx(["mail.example.com", "smtp.other.org"]);
    const mtaSts = makeMtaSts(["*.example.com", "smtp.other.org"]);

    const result = checkMxMtaStsConsistency(mx, mtaSts);

    expect(result).toHaveLength(1);
    expect(result[0].status).toBe("pass");
  });
});
