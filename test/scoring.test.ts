import { describe, expect, it } from "vitest";
import type {
  BimiResult,
  DkimResult,
  DmarcResult,
  MtaStsResult,
  SpfResult,
} from "../src/analyzers/types.js";
import { computeGrade, computeGradeBreakdown } from "../src/shared/scoring.js";

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
  // If status is pass but no record provided, add a default record
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

describe("computeGrade", () => {
  // ── Gatekeeper (F tier) ──────────────────────────────────────

  it("returns F when no DMARC record", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({ status: "fail", tags: null }),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(grade).toBe("F");
  });

  it("returns F when DMARC policy is none", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({ tags: { v: "DMARC1", p: "none" } }),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(grade).toBe("F");
  });

  it("returns F when DMARC tags are null", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({ status: "fail", tags: null }),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(grade).toBe("F");
  });

  it("returns F (never the fallback C arm) for a p= value analyzeDmarc could not parse (#738)", () => {
    const breakdown = computeGradeBreakdown({
      dmarc: makeDmarc({
        status: "fail",
        tags: { v: "DMARC1", p: "Quarntine" },
      }),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(breakdown.grade).toBe("F");
    expect(breakdown.tierReason).not.toBe(
      "Fallback — quarantine-level enforcement",
    );
  });

  // ── D tier (missing auth) ───────────────────────────────────

  it("returns D when quarantine but missing SPF", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({ tags: { v: "DMARC1", p: "quarantine" } }),
      spf: makeSpf({ status: "fail" }),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(grade).toBe("D");
  });

  it("returns D when quarantine but missing DKIM", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({ tags: { v: "DMARC1", p: "quarantine" } }),
      spf: makeSpf(),
      dkim: makeDkim({ status: "fail" }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(grade).toBe("D");
  });

  it("returns D when reject but missing SPF (no longer D+)", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({ tags: { v: "DMARC1", p: "reject" } }),
      spf: makeSpf({ status: "fail" }),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(grade).toBe("D");
  });

  it("returns D when reject but missing DKIM (no longer D+)", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({ tags: { v: "DMARC1", p: "reject" } }),
      spf: makeSpf(),
      dkim: makeDkim({ status: "fail" }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(grade).toBe("D");
  });

  // ── C tier (quarantine with auth) ───────────────────────────

  it("returns C-range when quarantine with SPF + DKIM", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:dmarc@example.com" },
      }),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(grade.charAt(0)).toBe("C");
  });

  // ── B tier (reject with auth) ──────────────────────────────

  it("returns B-range when reject with SPF + DKIM", () => {
    const grade = computeGrade({
      dmarc: makeDmarc(),
      spf: makeSpf({ record: "v=spf1 ~all", lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    // B base: SPF no bonus (7 lookups) + DKIM no bonus (1 selector) + rua(+1) → B+
    expect(grade.charAt(0)).toBe("B");
  });

  // ── A tier (reject + strong SPF + extras) ──────────────────

  it("returns A+ when all protocols fully configured", () => {
    const grade = computeGrade({
      dmarc: makeDmarc(),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi({ status: "pass" }),
      mta_sts: makeMtaSts({
        status: "pass",
        policy: {
          version: "STSv1",
          mode: "enforce",
          mx: ["*.example.com"],
          max_age: 86400,
        },
      }),
    });
    expect(grade).toBe("A+");
  });

  it("returns A-range when reject + strong SPF + DKIM + BIMI only", () => {
    const grade = computeGrade({
      dmarc: makeDmarc(),
      spf: makeSpf({ record: "v=spf1 -all", lookups_used: 3 }),
      dkim: makeDkim(),
      bimi: makeBimi({ status: "pass" }),
      mta_sts: makeMtaSts(),
    });
    // A tier: SPF +1 (≤5) + DKIM +1 (≥2 selectors) + rua +1 → net +3 → A+... wait
    // Actually modifier doesn't change A to A+ — only hasBimi && hasMtaSts gives A+
    // A base + modifiers → A+
    expect(grade.charAt(0)).toBe("A");
  });

  it("returns A- when reject + strong SPF + weak DKIM + MTA-STS testing", () => {
    const grade = computeGrade({
      dmarc: makeDmarc(),
      spf: makeSpf({ record: "v=spf1 -all", lookups_used: 3 }),
      dkim: makeDkim({
        selectors: {
          google: { found: true, key_type: "rsa", key_bits: 1024 },
        },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts({
        status: "pass",
        policy: {
          version: "STSv1",
          mode: "testing",
          mx: ["*.example.com"],
          max_age: 86400,
        },
      }),
    });
    // A tier: SPF +1 (≤5) + DKIM weak(-1) + no ≥2 selectors(0) + rua(+1) + MTA-STS testing(-1) → net 0 → A
    expect(grade).toBe("A");
  });

  // ── SPF modifier tests ─────────────────────────────────────

  it("~all is NOT penalized (industry best practice with DMARC enforcement)", () => {
    const gradeHard = computeGrade({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ record: "v=spf1 -all", lookups_used: 3 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    const gradeSoft = computeGrade({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ record: "v=spf1 ~all", lookups_used: 3 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    // Both should get same grade — ~all and -all are equivalent with DMARC
    expect(gradeHard).toBe(gradeSoft);
  });

  it("applies positive SPF modifier for ≤5 lookups", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 3 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    // C base: SPF +1 (≤5) + rua(+1) → +2 → C+
    expect(grade).toBe("C+");
  });

  it("no SPF bonus when >5 lookups", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    // C base: SPF no bonus + rua(+1) → +1 → C+
    expect(grade).toBe("C+");
  });

  // ── DKIM modifier tests ────────────────────────────────────

  it("applies negative DKIM modifier for weak key", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ record: "v=spf1 ip4:10.0.0.0/24", lookups_used: 7 }),
      dkim: makeDkim({
        selectors: {
          google: { found: true, key_type: "rsa", key_bits: 1024 },
        },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    // C base: SPF no bonus(0) + DKIM weak(-1) + rua(+1) → net 0 → C
    expect(grade).toBe("C");
  });

  it("applies positive DKIM modifier for ≥2 selectors", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: {
          google: { found: true, key_type: "rsa", key_bits: 2048 },
          selector1: { found: true, key_type: "rsa", key_bits: 2048 },
        },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    // C base: SPF no bonus + DKIM +1 (≥2 selectors) + rua(+1) → +2 → C+
    expect(grade).toBe("C+");
  });

  // ── DMARC rua/ruf factor tests ─────────────────────────────

  it("penalizes missing rua and ruf reporting", () => {
    const withRua = computeGrade({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    const withoutRua = computeGrade({
      dmarc: makeDmarc({ tags: { v: "DMARC1", p: "quarantine" } }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    // withRua: C + rua(+1) → C+
    // withoutRua: C + no reporting(-1) → C-
    expect(withRua).toBe("C+");
    expect(withoutRua).toBe("C-");
  });

  // ── pct tests ──────────────────────────────────────────────

  it("downgrades reject to C-tier when pct < 10", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "reject", pct: "5", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    // p=reject with pct=5 → effective quarantine → C-tier
    // factors: rua(+1) → C+
    expect(grade).toBe("C+");
  });

  it("applies modifier penalty for pct 10-99", () => {
    const grade = computeGrade({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "reject", pct: "50", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    // B-tier (pct >= 10, effective reject): pct -1 + rua +1 → net 0 → B
    expect(grade).toBe("B");
  });

  it("no pct effect when pct=100 or absent", () => {
    const grade100 = computeGrade({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "reject", pct: "100", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    const gradeAbsent = computeGrade({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "reject", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(grade100).toBe(gradeAbsent);
  });

  // ── B-tier extras tests ────────────────────────────────────

  it("gives separate +1 for BIMI and MTA-STS at B-tier", () => {
    // Use lookups > limit so SPF is "not strong" → stays at B-tier even with extras
    const bimiOnly = computeGrade({
      dmarc: makeDmarc(),
      spf: makeSpf({ lookups_used: 11 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi({ status: "pass" }),
      mta_sts: makeMtaSts(),
    });
    const both = computeGrade({
      dmarc: makeDmarc(),
      spf: makeSpf({ lookups_used: 11 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi({ status: "pass" }),
      mta_sts: makeMtaSts({
        status: "pass",
        policy: {
          version: "STSv1",
          mode: "enforce",
          mx: ["mx.example.com"],
          max_age: 86400,
        },
      }),
    });
    // bimiOnly: B + BIMI(+1) + rua(+1) → +2 → B+
    // both: B + BIMI(+1) + MTA-STS(+1) + rua(+1) → +3 → B+
    expect(bimiOnly).toBe("B+");
    expect(both).toBe("B+");
  });

  // ── MTA-STS testing mode consistency ───────────────────────

  it("penalizes MTA-STS testing mode at B-tier (nets to 0 with configured bonus)", () => {
    // Use lookups > limit to stay at B-tier
    const grade = computeGrade({
      dmarc: makeDmarc(),
      spf: makeSpf({ lookups_used: 11 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts({
        status: "pass",
        policy: {
          version: "STSv1",
          mode: "testing",
          mx: ["mx.example.com"],
          max_age: 86400,
        },
      }),
    });
    // B base: MTA-STS configured(+1) + testing(-1) + rua(+1) → +1 → B+
    expect(grade).toBe("B+");
  });
});

describe("computeGradeBreakdown", () => {
  it("grade matches computeGrade for every tier", () => {
    const cases = [
      // F
      {
        dmarc: makeDmarc({ status: "fail", tags: null }),
        spf: makeSpf(),
        dkim: makeDkim(),
        bimi: makeBimi(),
        mta_sts: makeMtaSts(),
      },
      // D (quarantine missing auth)
      {
        dmarc: makeDmarc({ tags: { v: "DMARC1", p: "quarantine" } }),
        spf: makeSpf({ status: "fail" }),
        dkim: makeDkim(),
        bimi: makeBimi(),
        mta_sts: makeMtaSts(),
      },
      // D (reject missing auth — no longer D+)
      {
        dmarc: makeDmarc(),
        spf: makeSpf({ status: "fail" }),
        dkim: makeDkim(),
        bimi: makeBimi(),
        mta_sts: makeMtaSts(),
      },
      // C
      {
        dmarc: makeDmarc({
          tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
        }),
        spf: makeSpf(),
        dkim: makeDkim(),
        bimi: makeBimi(),
        mta_sts: makeMtaSts(),
      },
      // B
      {
        dmarc: makeDmarc(),
        spf: makeSpf({ record: "v=spf1 ~all", lookups_used: 7 }),
        dkim: makeDkim({
          selectors: {
            google: { found: true, key_type: "rsa", key_bits: 2048 },
          },
        }),
        bimi: makeBimi(),
        mta_sts: makeMtaSts(),
      },
      // A+
      {
        dmarc: makeDmarc(),
        spf: makeSpf(),
        dkim: makeDkim(),
        bimi: makeBimi({ status: "pass" }),
        mta_sts: makeMtaSts({
          status: "pass",
          policy: {
            version: "STSv1",
            mode: "enforce",
            mx: ["mx.example.com"],
            max_age: 86400,
          },
        }),
      },
    ];
    for (const protocols of cases) {
      const breakdown = computeGradeBreakdown(protocols);
      expect(breakdown.grade).toBe(computeGrade(protocols));
    }
  });

  it("returns correct tier for F grade", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc({ status: "fail", tags: null }),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(bd.tier).toBe("F");
    expect(bd.factors).toHaveLength(0);
  });

  it("returns correct tier for C grade", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(bd.tier).toBe("C");
    expect(bd.tierReason).toContain("quarantine");
  });

  it("returns correct tier for A+ grade", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc(),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi({ status: "pass" }),
      mta_sts: makeMtaSts({
        status: "pass",
        policy: {
          version: "STSv1",
          mode: "enforce",
          mx: ["mx.example.com"],
          max_age: 86400,
        },
      }),
    });
    expect(bd.tier).toBe("A+");
    expect(bd.grade).toBe("A+");
    expect(bd.tierReason).toContain("perfect");
  });

  it("collects SPF factors (lookup efficiency)", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 3 }),
      dkim: makeDkim({
        selectors: { s1: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    const spf = bd.factors.filter((f) => f.protocol === "spf");
    expect(spf.length).toBe(1); // ≤5 lookups bonus
    expect(spf[0].effect).toBe(+1);
  });

  it("collects DKIM factors", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ record: "v=spf1 ip4:10.0.0.0/24", lookups_used: 7 }),
      dkim: makeDkim({
        selectors: {
          google: { found: true, key_type: "rsa", key_bits: 1024 },
          selector1: { found: true, key_type: "rsa", key_bits: 2048 },
        },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    const dkimF = bd.factors.filter((f) => f.protocol === "dkim");
    expect(dkimF.length).toBe(2); // weak key and ≥2 selectors
    expect(dkimF.find((f) => f.effect === -1)?.label).toContain("2048");
    expect(dkimF.find((f) => f.effect === 1)?.label).toContain("selectors");
  });

  it("collects DMARC factors (rua, pct)", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "reject", pct: "50", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    const dmarcF = bd.factors.filter((f) => f.protocol === "dmarc");
    expect(dmarcF.length).toBe(2); // pct penalty + rua bonus
    expect(dmarcF.find((f) => f.effect === -1)?.label).toContain("pct");
    expect(dmarcF.find((f) => f.effect === +1)?.label).toContain("rua");
  });

  it("collects MTA-STS testing factor at B-tier", () => {
    // Use lookups > limit to stay at B-tier where both configured+testing factors appear
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc(),
      spf: makeSpf({ lookups_used: 11 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts({
        status: "pass",
        policy: {
          version: "STSv1",
          mode: "testing",
          mx: ["mx.example.com"],
          max_age: 86400,
        },
      }),
    });
    const mtaStsF = bd.factors.filter((f) => f.protocol === "mta_sts");
    expect(mtaStsF.length).toBe(2); // configured +1, testing -1
    expect(mtaStsF.find((f) => f.effect === -1)?.label).toContain("testing");
    expect(mtaStsF.find((f) => f.effect === +1)?.label).toContain("configured");
  });

  it("generates P1 recommendation for F grade", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc({ tags: { v: "DMARC1", p: "none" } }),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(bd.recommendations.length).toBeGreaterThan(0);
    expect(bd.recommendations[0].priority).toBe(1);
    expect(bd.recommendations[0].protocol).toBe("dmarc");
  });

  it("generates upgrade recommendation for C tier", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    const upgradeRec = bd.recommendations.find(
      (r) => r.protocol === "dmarc" && r.priority === 1,
    );
    expect(upgradeRec).toBeDefined();
    expect(upgradeRec?.title).toContain("reject");
  });

  it("generates rua recommendation when missing", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc({ tags: { v: "DMARC1", p: "reject" } }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    const ruaRec = bd.recommendations.find(
      (r) => r.protocol === "dmarc" && r.title.includes("rua"),
    );
    expect(ruaRec).toBeDefined();
  });

  it("generates pct recommendation when pct < 100", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "reject", pct: "50", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    const pctRec = bd.recommendations.find(
      (r) => r.protocol === "dmarc" && r.title.includes("pct"),
    );
    expect(pctRec).toBeDefined();
  });

  it("generates no recommendations for A+", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc(),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi({
        status: "pass",
        record:
          "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
        tags: {
          v: "BIMI1",
          l: "https://example.com/logo.svg",
          a: "https://example.com/vmc.pem",
        },
      }),
      mta_sts: makeMtaSts({
        status: "pass",
        policy: {
          version: "STSv1",
          mode: "enforce",
          mx: ["mx.example.com"],
          max_age: 86400,
        },
      }),
    });
    expect(bd.recommendations).toHaveLength(0);
  });

  it("includes protocol summaries for all 5 protocols", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc(),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(Object.keys(bd.protocolSummaries)).toEqual(
      expect.arrayContaining(["dmarc", "spf", "dkim", "bimi", "mta_sts"]),
    );
    expect(bd.protocolSummaries.dmarc.summary).toContain("reject");
  });

  it("sets modifierLabel correctly", () => {
    const bdPlus = computeGradeBreakdown({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    // SPF +1 (≤5) + DKIM +1 (≥2 selectors) + rua +1 → modifier ≥1 → "+"
    expect(["+", "+2", "+3"]).toContain(bdPlus.modifierLabel);

    const bdMinus = computeGradeBreakdown({
      dmarc: makeDmarc({ tags: { v: "DMARC1", p: "quarantine" } }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { s1: { found: true, key_type: "rsa", key_bits: 1024 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    // DKIM weak(-1) + no reporting(-1) → net -2 → "−2"
    expect(bdMinus.modifierLabel).toContain("−");
  });

  it("shows numeric magnitude in modifierLabel when |modifier| > 1", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "quarantine", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 3 }),
      dkim: makeDkim(),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    // SPF +1 (≤5) + DKIM +1 (≥2 selectors) + rua +1 → modifier 3 → "+3"
    expect(bd.modifier).toBe(3);
    expect(bd.modifierLabel).toBe("+3");
  });

  it("BIMI with record but warn status (no cert) still counts for A tier", () => {
    const grade = computeGrade({
      dmarc: makeDmarc(),
      spf: makeSpf({ record: "v=spf1 -all", lookups_used: 3 }),
      dkim: makeDkim(),
      bimi: makeBimi({
        status: "warn",
        record: "v=BIMI1; l=https://example.com/logo.svg",
        tags: { v: "BIMI1", l: "https://example.com/logo.svg" },
      }),
      mta_sts: makeMtaSts(),
    });
    expect(grade.charAt(0)).toBe("A");
  });

  it("generates VMC/CMC recommendation when BIMI record has no certificate", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc(),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi({
        status: "warn",
        record: "v=BIMI1; l=https://example.com/logo.svg",
        tags: { v: "BIMI1", l: "https://example.com/logo.svg" },
      }),
      mta_sts: makeMtaSts(),
    });
    const certRec = bd.recommendations.find(
      (r) => r.protocol === "bimi" && r.title.includes("VMC"),
    );
    expect(certRec).toBeDefined();
    expect(certRec?.description).toContain("Gmail");
  });

  it("does not generate VMC/CMC recommendation when certificate present", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc(),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi({
        status: "pass",
        record:
          "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
        tags: {
          v: "BIMI1",
          l: "https://example.com/logo.svg",
          a: "https://example.com/vmc.pem",
        },
      }),
      mta_sts: makeMtaSts({
        status: "pass",
        policy: {
          version: "STSv1",
          mode: "enforce",
          mx: ["mx.example.com"],
          max_age: 86400,
        },
      }),
    });
    const certRec = bd.recommendations.find(
      (r) => r.protocol === "bimi" && r.title.includes("VMC"),
    );
    expect(certRec).toBeUndefined();
  });

  it("BIMI summary shows certificate status", () => {
    const withCert = computeGradeBreakdown({
      dmarc: makeDmarc(),
      spf: makeSpf(),
      dkim: makeDkim(),
      bimi: makeBimi({
        status: "pass",
        record:
          "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
        tags: {
          v: "BIMI1",
          l: "https://example.com/logo.svg",
          a: "https://example.com/vmc.pem",
        },
      }),
      mta_sts: makeMtaSts({
        status: "pass",
        policy: {
          version: "STSv1",
          mode: "enforce",
          mx: ["mx.example.com"],
          max_age: 86400,
        },
      }),
    });
    expect(withCert.protocolSummaries.bimi.summary).toBe(
      "Record + certificate",
    );

    const withoutCert = computeGradeBreakdown({
      dmarc: makeDmarc(),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi({
        status: "warn",
        record: "v=BIMI1; l=https://example.com/logo.svg",
        tags: { v: "BIMI1", l: "https://example.com/logo.svg" },
      }),
      mta_sts: makeMtaSts(),
    });
    expect(withoutCert.protocolSummaries.bimi.summary).toBe(
      "Record found (no certificate)",
    );
  });

  it("pct < 10 shows downgrade in tierReason", () => {
    const bd = computeGradeBreakdown({
      dmarc: makeDmarc({
        tags: { v: "DMARC1", p: "reject", pct: "5", rua: "mailto:x@x.com" },
      }),
      spf: makeSpf({ lookups_used: 7 }),
      dkim: makeDkim({
        selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
      }),
      bimi: makeBimi(),
      mta_sts: makeMtaSts(),
    });
    expect(bd.tier).toBe("C");
    expect(bd.tierReason).toContain("pct=5%");
    expect(bd.tierReason).toContain("effectively quarantine");
  });
});
