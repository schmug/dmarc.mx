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
  function row(
    protocols: Record<string, { status: string }> | null,
    grade: string | null = "F",
  ) {
    return {
      last_grade: grade,
      protocol_results: protocols ? JSON.stringify(protocols) : null,
    };
  }

  it("returns null when there are no rows", () => {
    expect(tallyProtocolFailures([])).toBeNull();
  });

  it("returns null when all rows have null protocol_results", () => {
    expect(
      tallyProtocolFailures([{ last_grade: "F", protocol_results: null }]),
    ).toBeNull();
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
      { last_grade: "F", protocol_results: "not-json" },
      row({ dmarc: { status: "fail" } }),
    ];
    expect(tallyProtocolFailures(rows)).toEqual({
      protocol: "dmarc",
      count: 1,
    });
  });

  it("skips rows with null protocol_results", () => {
    const rows = [
      { last_grade: "F", protocol_results: null },
      row({ spf: { status: "fail" } }),
    ];
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

  it("ignores protocol failures on domains outside the failing bucket", () => {
    // The 2026-06 dashboard bug: MTA-STS fails on most *healthy* domains too
    // (no _mta-sts record → status "fail"), so a watchlist-wide tally reported
    // "MTA-STS — 342 of 199 failing domains". Only failing-bucket rows count.
    const result = tallyProtocolFailures([
      row({ mta_sts: { status: "fail" } }, "A"),
      row({ mta_sts: { status: "fail" } }, "A"),
      row({ mta_sts: { status: "fail" } }, "B+"),
      row({ spf: { status: "fail" } }, "C"),
      row({ dmarc: { status: "fail" }, mta_sts: { status: "fail" } }, "F"),
      row({ dmarc: { status: "fail" } }, "F"),
    ]);
    // dmarc fails on both F domains; mta_sts on only one of them. The three
    // healthy MTA-STS failures and the drifting SPF failure are ignored.
    expect(result).toEqual({ protocol: "dmarc", count: 2 });
  });

  it("never counts more domains than are in the failing bucket", () => {
    const rows = [
      ...Array.from({ length: 5 }, () =>
        row({ mta_sts: { status: "fail" } }, "A"),
      ),
      row({ dmarc: { status: "fail" } }, "F"),
    ];
    const result = tallyProtocolFailures(rows);
    expect(result).toEqual({ protocol: "dmarc", count: 1 });
  });

  it("returns null when failures exist only on healthy, drifting, or ungraded domains", () => {
    const rows = [
      row({ mta_sts: { status: "fail" } }, "A"),
      row({ spf: { status: "fail" } }, "D"),
      row({ dkim: { status: "fail" } }, null),
      row({ dmarc: { status: "fail" } }, "—"),
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
