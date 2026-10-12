import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn(),
  queryMx: vi.fn(),
}));

import { analyzeSpf } from "../src/analyzers/spf.js";
import type {
  BimiResult,
  DkimResult,
  DmarcResult,
  MtaStsResult,
  SpfResult,
} from "../src/analyzers/types.js";
import { queryTxt } from "../src/dns/client.js";
import { computeGradeBreakdown } from "../src/shared/scoring.js";

const mockQueryTxt = vi.mocked(queryTxt);

beforeEach(() => {
  vi.resetAllMocks();
});

async function spf(record: string, redirectTarget?: string) {
  mockQueryTxt.mockResolvedValueOnce({ entries: [record], raw: record });
  if (redirectTarget) {
    mockQueryTxt.mockResolvedValueOnce({
      entries: [redirectTarget],
      raw: redirectTarget,
    });
  }
  return analyzeSpf("example.com");
}

const NEUTRAL_LABEL = "SPF ends in neutral (?all or no all)";

function breakdownFor(s: SpfResult) {
  const dmarc: DmarcResult = {
    status: "pass",
    record: "v=DMARC1; p=reject; rua=mailto:d@example.com",
    tags: { v: "DMARC1", p: "reject", rua: "mailto:d@example.com" },
    validations: [],
  };
  const dkim: DkimResult = {
    status: "pass",
    selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
    validations: [],
  };
  const bimi = { status: "info", validations: [] } as unknown as BimiResult;
  const mta_sts = {
    status: "info",
    validations: [],
  } as unknown as MtaStsResult;
  return computeGradeBreakdown({ dmarc, spf: s, dkim, bimi, mta_sts });
}

describe("SPF terminal all qualifier", () => {
  it("?all warns and exposes the ? qualifier", async () => {
    const r = await spf("v=spf1 mx ?all");
    expect(r.status).toBe("warn");
    expect(r.all_qualifier).toBe("?");
    expect(
      r.validations.some((v) => v.message.includes("Change it to ~all")),
    ).toBe(true);
  });

  it("missing all without redirect warns", async () => {
    const r = await spf("v=spf1 ip4:192.0.2.1");
    expect(r.status).toBe("warn");
    expect(r.all_qualifier).toBeNull();
    expect(r.has_redirect).toBe(false);
    expect(
      r.validations.some((v) => v.message.startsWith("No all mechanism")),
    ).toBe(true);
  });

  it("missing all with redirect= does not warn", async () => {
    const r = await spf("v=spf1 redirect=_spf.example.net", "v=spf1 -all");
    expect(
      r.validations.some((v) => v.message.startsWith("No all mechanism")),
    ).toBe(false);
    expect(r.has_redirect).toBe(true);
  });

  it("-all and ~all report their qualifier", async () => {
    expect((await spf("v=spf1 -all")).all_qualifier).toBe("-");
    expect((await spf("v=spf1 ~all")).all_qualifier).toBe("~");
  });

  it("+all and bare all fail", async () => {
    for (const rec of ["v=spf1 +all", "v=spf1 all"]) {
      const r = await spf(rec);
      expect(r.status).toBe("fail");
      expect(r.all_qualifier).toBe("+");
    }
  });
});

describe("SPF neutral scoring factor", () => {
  const hasFactor = async (rec: string, redirect?: string) =>
    breakdownFor(await spf(rec, redirect)).factors.some(
      (f) => f.label === NEUTRAL_LABEL,
    );

  it("applies -1 for ?all and for missing all without redirect", async () => {
    expect(await hasFactor("v=spf1 mx ?all")).toBe(true);
    expect(await hasFactor("v=spf1 mx")).toBe(true);
  });

  it("does not apply for -all, ~all, +all, or redirect", async () => {
    expect(await hasFactor("v=spf1 mx -all")).toBe(false);
    expect(await hasFactor("v=spf1 mx ~all")).toBe(false);
    expect(await hasFactor("v=spf1 +all")).toBe(false);
    expect(
      await hasFactor("v=spf1 redirect=_spf.example.net", "v=spf1 -all"),
    ).toBe(false);
  });

  it("?all grades one step below an otherwise identical -all domain", async () => {
    const strict = breakdownFor(await spf("v=spf1 mx -all"));
    const neutral = breakdownFor(await spf("v=spf1 mx ?all"));
    expect(neutral.modifier).toBe(strict.modifier - 1);
  });
});
