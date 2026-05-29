import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  BimiResult,
  DkimResult,
  DmarcResult,
  MtaStsResult,
  SpfResult,
} from "../src/analyzers/types.js";
import { computeGradeBreakdown } from "../src/shared/scoring.js";
import { parseScoringConfig } from "../src/shared/scoring-config.js";

function makeDmarc(overrides: Partial<DmarcResult> = {}): DmarcResult {
  return {
    status: "pass",
    record: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    tags: { v: "DMARC1", p: "reject", rua: "mailto:dmarc@example.com" },
    validations: [],
    ...overrides,
  };
}

function makeSpf(overrides: Partial<SpfResult> = {}): SpfResult {
  return {
    status: "pass",
    record: "v=spf1 -all",
    lookups_used: 3,
    lookup_limit: 10,
    include_tree: null,
    validations: [],
    ...overrides,
  };
}

function makeDkim(overrides: Partial<DkimResult> = {}): DkimResult {
  return {
    status: "pass",
    selectors: {
      google: { found: true, key_type: "rsa", key_bits: 2048 },
      selector1: { found: true, key_type: "rsa", key_bits: 2048 },
    },
    validations: [],
    ...overrides,
  };
}

function makeBimi(overrides: Partial<BimiResult> = {}): BimiResult {
  const base = {
    status: "warn" as const,
    record: null as string | null,
    tags: null as Record<string, string> | null,
    validations: [] as BimiResult["validations"],
  };
  const merged = { ...base, ...overrides };
  if (merged.status === "pass" && merged.record === null) {
    merged.record = "v=BIMI1; l=https://example.com/logo.svg";
    merged.tags = { v: "BIMI1", l: "https://example.com/logo.svg" };
  }
  return merged;
}

function makeMtaSts(overrides: Partial<MtaStsResult> = {}): MtaStsResult {
  return {
    status: "fail",
    dns_record: null,
    policy: null,
    validations: [],
    ...overrides,
  };
}

const enforcingMtaSts = makeMtaSts({
  status: "pass",
  policy: {
    version: "STSv1",
    mode: "enforce",
    mx: ["*.example.com"],
    max_age: 86400,
  },
});

describe("scoring config — requireBimiForAPlus", () => {
  it("lands in the A tier (not A+) for reject+SPF+DKIM+MTA-STS but no BIMI under defaults", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc(),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: enforcingMtaSts,
    });
    expect(bd.tier).toBe("A");
  });

  it("lands in the A+ tier for the same domain when requireBimiForAPlus is false", () => {
    const bd = computeGradeBreakdown(
      {
        dmarc: makeDmarc(),
        spf: makeSpf(),
        dkim: makeDkim(),
        bimi: makeBimi(),
        mta_sts: enforcingMtaSts,
      },
      { requireBimiForAPlus: false },
    );
    expect(bd.tier).toBe("A+");
  });
});

describe("scoring config — requireMtaStsForAPlus", () => {
  it("lands in the A+ tier with BIMI but no MTA-STS when requireMtaStsForAPlus is false", () => {
    const bd = computeGradeBreakdown(
      {
        dmarc: makeDmarc(),
        spf: makeSpf(),
        dkim: makeDkim(),
        bimi: makeBimi({ status: "pass" }),
        mta_sts: makeMtaSts(),
      },
      { requireMtaStsForAPlus: false },
    );
    expect(bd.tier).toBe("A+");
  });
});

describe("scoring config — numeric factor knobs", () => {
  const base = {
    dmarc: makeDmarc(),
    dkim: makeDkim(),
    bimi: makeBimi(),
    mta_sts: makeMtaSts(),
  };

  it("withholds the SPF efficiency bonus above the configured threshold by default", () => {
    const bd = computeGradeBreakdown({
      ...base,
      spf: makeSpf({ lookups_used: 7 }),
    });
    expect(bd.factors.some((f) => f.protocol === "spf" && f.effect === 1)).toBe(
      false,
    );
  });

  it("awards the SPF efficiency bonus when spfEfficientLookupThreshold is raised", () => {
    const bd = computeGradeBreakdown(
      { ...base, spf: makeSpf({ lookups_used: 7 }) },
      { spfEfficientLookupThreshold: 8 },
    );
    expect(bd.factors.some((f) => f.protocol === "spf" && f.effect === 1)).toBe(
      true,
    );
  });

  it("penalizes a 2048-bit DKIM key when dkimKeyMinBits is raised to 4096", () => {
    const bd = computeGradeBreakdown(
      { ...base, spf: makeSpf() },
      { dkimKeyMinBits: 4096 },
    );
    expect(
      bd.factors.some((f) => f.protocol === "dkim" && f.effect === -1),
    ).toBe(true);
  });

  it("withholds the DKIM rotation bonus when dkimRotationSelectorCount exceeds the selector count", () => {
    const bd = computeGradeBreakdown(
      { ...base, spf: makeSpf() },
      { dkimRotationSelectorCount: 3 },
    );
    expect(
      bd.factors.some((f) => f.protocol === "dkim" && f.effect === 1),
    ).toBe(false);
  });
});

describe("scoring config — lowPctDowngradeThreshold", () => {
  const lowPctDmarc = makeDmarc({
    tags: {
      v: "DMARC1",
      p: "reject",
      rua: "mailto:dmarc@example.com",
      pct: "5",
    },
  });

  it("downgrades reject to the C tier at pct=5 under the default threshold of 10", () => {
    const bd = computeGradeBreakdown({
      dmarc: lowPctDmarc,
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(bd.tier).toBe("C");
  });

  it("keeps reject in the B tier at pct=5 when lowPctDowngradeThreshold is 3", () => {
    const bd = computeGradeBreakdown(
      {
        dmarc: lowPctDmarc,
        spf: makeSpf(),
        dkim: makeDkim(),
        bimi: makeBimi(),
        mta_sts: makeMtaSts(),
      },
      { lowPctDowngradeThreshold: 3 },
    );
    expect(bd.tier).toBe("B");
  });
});

describe("scoring config — recommendations follow the knobs (AC#3)", () => {
  it("recommends a DKIM key upgrade when dkimKeyMinBits is raised above the actual key size", () => {
    const bd = computeGradeBreakdown(
      {
        dmarc: makeDmarc(),
        spf: makeSpf(),
        dkim: makeDkim(),
        bimi: makeBimi(),
        mta_sts: makeMtaSts(),
      },
      { dkimKeyMinBits: 4096 },
    );
    expect(
      bd.recommendations.some(
        (r) => r.protocol === "dkim" && /upgrade dkim key/i.test(r.title),
      ),
    ).toBe(true);
  });
});

describe("parseScoringConfig", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns an empty partial when the var is undefined", () => {
    expect(parseScoringConfig(undefined)).toEqual({});
  });

  it("returns an empty partial for an empty string", () => {
    expect(parseScoringConfig("")).toEqual({});
  });

  it("parses a valid subset of known keys", () => {
    expect(
      parseScoringConfig(
        '{"spfEfficientLookupThreshold":8,"requireMtaStsForAPlus":false}',
      ),
    ).toEqual({ spfEfficientLookupThreshold: 8, requireMtaStsForAPlus: false });
  });

  it("ignores unknown keys", () => {
    expect(parseScoringConfig('{"dkimKeyMinBits":4096,"foo":1}')).toEqual({
      dkimKeyMinBits: 4096,
    });
  });

  it("warns once and falls back to {} on invalid JSON", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(parseScoringConfig("not json{")).toEqual({});
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("drops a knob whose value is the wrong type", () => {
    expect(parseScoringConfig('{"requireBimiForAPlus":"yes"}')).toEqual({});
  });

  it("drops a numeric knob that is out of range", () => {
    expect(parseScoringConfig('{"dkimKeyMinBits":-5}')).toEqual({});
  });

  it("falls back to {} when the JSON is not an object", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(parseScoringConfig("42")).toEqual({});
    expect(warn).toHaveBeenCalledTimes(1);
  });
});
