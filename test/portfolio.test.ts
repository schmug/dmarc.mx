import { describe, expect, it } from "vitest";
import {
  emptyPortfolioStats,
  gradeBucket,
  tallyGradeCounts,
  tallyProtocolFailures,
} from "../src/shared/portfolio.js";

describe("gradeBucket", () => {
  it("buckets S, A, and B grades (with modifiers) as healthy", () => {
    for (const g of ["S", "A+", "A", "A-", "B+", "B", "B-"]) {
      expect(gradeBucket(g)).toBe("healthy");
    }
  });

  it("buckets C and D grades (with modifiers) as drifting", () => {
    for (const g of ["C+", "C", "C-", "D+", "D", "D-"]) {
      expect(gradeBucket(g)).toBe("drifting");
    }
  });

  it("buckets F as failing", () => {
    expect(gradeBucket("F")).toBe("failing");
  });

  it("buckets null, empty, the placeholder dash, and unknown grades as ungraded", () => {
    expect(gradeBucket(null)).toBe("ungraded");
    expect(gradeBucket(undefined)).toBe("ungraded");
    expect(gradeBucket("")).toBe("ungraded");
    expect(gradeBucket("—")).toBe("ungraded");
    expect(gradeBucket("ungraded")).toBe("ungraded");
  });

  it("is case-insensitive on the leading letter", () => {
    expect(gradeBucket("a")).toBe("healthy");
    expect(gradeBucket("f")).toBe("failing");
  });
});

describe("emptyPortfolioStats", () => {
  it("returns an all-zero stats object", () => {
    expect(emptyPortfolioStats()).toEqual({
      total: 0,
      healthy: 0,
      drifting: 0,
      failing: 0,
      ungraded: 0,
    });
  });
});

describe("tallyProtocolFailures", () => {
  function row(protocols: Record<string, { status: string }> | null) {
    return {
      protocol_results: protocols ? JSON.stringify(protocols) : null,
    };
  }

  it("returns null when there are no rows", () => {
    expect(tallyProtocolFailures([])).toBeNull();
  });

  it("returns null when all rows have null protocol_results", () => {
    expect(tallyProtocolFailures([{ protocol_results: null }])).toBeNull();
  });

  it("returns null when no protocol has status=fail", () => {
    expect(
      tallyProtocolFailures([
        row({ dmarc: { status: "pass" }, spf: { status: "warn" } }),
        row({ dmarc: { status: "pass" } }),
      ]),
    ).toBeNull();
  });

  it("identifies the single failing protocol", () => {
    const result = tallyProtocolFailures([
      row({ dmarc: { status: "fail" }, spf: { status: "pass" } }),
      row({ dmarc: { status: "fail" } }),
      row({ dmarc: { status: "pass" } }),
    ]);
    expect(result).toEqual({ protocol: "dmarc", count: 2 });
  });

  it("picks the most-common failing protocol across mixed rows", () => {
    const result = tallyProtocolFailures([
      row({ dmarc: { status: "fail" }, dkim: { status: "fail" } }),
      row({ dkim: { status: "fail" }, spf: { status: "pass" } }),
      row({ dkim: { status: "fail" } }),
      row({ dmarc: { status: "pass" } }),
    ]);
    // dkim fails 3 times, dmarc fails 1 time
    expect(result).toEqual({ protocol: "dkim", count: 3 });
  });

  it("breaks ties alphabetically (lower protocol name wins)", () => {
    const result = tallyProtocolFailures([
      row({ bimi: { status: "fail" }, spf: { status: "fail" } }),
      row({ bimi: { status: "fail" }, spf: { status: "fail" } }),
    ]);
    // bimi and spf both fail 2 times; bimi < spf alphabetically
    expect(result).toEqual({ protocol: "bimi", count: 2 });
  });

  it("skips rows with invalid JSON gracefully", () => {
    const rows = [
      { protocol_results: "not-json" },
      row({ dmarc: { status: "fail" } }),
    ];
    expect(tallyProtocolFailures(rows)).toEqual({
      protocol: "dmarc",
      count: 1,
    });
  });

  it("skips rows with null protocol_results", () => {
    const rows = [{ protocol_results: null }, row({ spf: { status: "fail" } })];
    expect(tallyProtocolFailures(rows)).toEqual({ protocol: "spf", count: 1 });
  });

  it("returns null for an all-healthy portfolio", () => {
    const rows = [
      row({
        dmarc: { status: "pass" },
        spf: { status: "pass" },
        dkim: { status: "pass" },
      }),
      row({ dmarc: { status: "warn" }, mta_sts: { status: "warn" } }),
    ];
    expect(tallyProtocolFailures(rows)).toBeNull();
  });
});

describe("tallyGradeCounts", () => {
  it("sums grouped grade counts into the right buckets", () => {
    const stats = tallyGradeCounts([
      { grade: "A", count: 5 },
      { grade: "B-", count: 2 },
      { grade: "C", count: 3 },
      { grade: "F", count: 12 },
      { grade: null, count: 4 },
    ]);
    expect(stats).toEqual({
      total: 26,
      healthy: 7,
      drifting: 3,
      failing: 12,
      ungraded: 4,
    });
  });

  it("returns an empty stats object for no rows", () => {
    expect(tallyGradeCounts([])).toEqual(emptyPortfolioStats());
  });
});
