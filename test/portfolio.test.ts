import { describe, expect, it } from "vitest";
import {
  emptyPortfolioStats,
  gradeBucket,
  tallyGradeCounts,
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
