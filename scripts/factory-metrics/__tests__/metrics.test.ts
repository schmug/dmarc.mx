import { describe, expect, it } from "vitest";
import {
  computeMergeRate,
  formatMergeRate,
  isRoutineBranch,
  needsHuman,
} from "../metrics.js";

const pr = (
  number: number,
  headRef: string,
  mergedAt: string | null,
  labels: string[] = [],
) => ({ number, headRef, mergedAt, labels });

describe("isRoutineBranch", () => {
  it("counts the implementer routine's branches", () => {
    expect(isRoutineBranch("claude/issue-723")).toBe(true);
  });
  it("excludes agent and human branches", () => {
    expect(isRoutineBranch("dmarcus/gate-ci-diagnostics")).toBe(false);
    expect(isRoutineBranch("fix-typo")).toBe(false);
  });
});

describe("needsHuman", () => {
  it("returns the intervention labels present, case-insensitively", () => {
    expect(needsHuman(["ci", "Needs-You", "blocked"])).toEqual([
      "blocked",
      "needs-you",
    ]);
  });
  it("ignores ordinary labels", () => {
    expect(needsHuman(["enhancement", "ci"])).toEqual([]);
  });
});

describe("computeMergeRate", () => {
  const window = "2026-06-23T00:00:00Z";

  it("rates only routine PRs merged inside the window", () => {
    const r = computeMergeRate(
      [
        pr(1, "claude/a", "2026-07-01T00:00:00Z"),
        pr(2, "claude/b", "2026-07-02T00:00:00Z", ["needs-you"]),
        pr(3, "dmarcus/c", "2026-07-03T00:00:00Z"),
        pr(4, "claude/d", "2026-01-01T00:00:00Z"),
        pr(5, "claude/e", null, ["blocked"]),
      ],
      window,
    );
    expect(r.mergedTotal).toBe(3);
    expect(r.routineTotal).toBe(2);
    expect(r.autonomous).toBe(1);
    expect(r.ratePercent).toBe(50);
    expect(r.intervenedPrs).toEqual([2]);
  });

  it("counts a PR once even with several intervention labels", () => {
    const r = computeMergeRate(
      [pr(9, "claude/x", "2026-08-01T00:00:00Z", ["needs-you", "blocked"])],
      window,
    );
    expect(r.intervened).toBe(1);
    expect(r.interventionCounts).toEqual({ blocked: 1, "needs-you": 1 });
  });

  it("reports 0% for an empty window instead of dividing by zero", () => {
    const r = computeMergeRate([], window);
    expect(r.routineTotal).toBe(0);
    expect(r.ratePercent).toBe(0);
  });

  it("keeps one decimal place, matching how the goal is stated", () => {
    const prs = Array.from({ length: 38 }, (_, i) =>
      pr(i + 1, "claude/p", "2026-08-01T00:00:00Z", i < 23 ? ["needs-you"] : []),
    );
    expect(computeMergeRate(prs, window).ratePercent).toBe(39.5);
  });

  it("rejects an unparseable window", () => {
    expect(() => computeMergeRate([], "last tuesday")).toThrow(/not a date/);
  });
});

describe("formatMergeRate", () => {
  it("omits the intervention section when nothing needed a human", () => {
    const out = formatMergeRate(
      computeMergeRate(
        [pr(1, "claude/a", "2026-08-01T00:00:00Z")],
        "2026-06-23T00:00:00Z",
      ),
    );
    expect(out).toContain("autonomous rate:     100%");
    expect(out).not.toContain("intervention labels");
  });
});
