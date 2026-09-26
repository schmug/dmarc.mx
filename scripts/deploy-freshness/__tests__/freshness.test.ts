import { describe, expect, it } from "vitest";
import { evaluateFreshness } from "../freshness.js";

const grace = 900;

describe("evaluateFreshness", () => {
  it("is fresh when the deployment follows the commit within the grace period", () => {
    const result = evaluateFreshness({
      mainCommitIso: "2026-09-20T01:20:00Z",
      activeDeployIso: "2026-09-20T01:23:00Z",
      graceSeconds: grace,
    });

    expect(result.stale).toBe(false);
    expect(result.lagSeconds).toBe(-180);
  });

  it("is fresh when a deployment is far newer than main, as after a manual deploy", () => {
    const result = evaluateFreshness({
      mainCommitIso: "2026-09-20T01:20:00Z",
      activeDeployIso: "2026-09-21T09:00:00Z",
      graceSeconds: grace,
    });

    expect(result.stale).toBe(false);
  });

  it("is fresh while a deploy is still rolling out", () => {
    const result = evaluateFreshness({
      mainCommitIso: "2026-09-20T01:20:00Z",
      activeDeployIso: "2026-09-20T01:10:00Z",
      graceSeconds: grace,
    });

    expect(result.stale).toBe(false);
    expect(result.lagSeconds).toBe(600);
  });

  it("is stale when main has run ahead of production, the 2026-09-21 token failure", () => {
    const result = evaluateFreshness({
      mainCommitIso: "2026-09-22T01:08:00Z",
      activeDeployIso: "2026-09-20T01:20:00Z",
      graceSeconds: grace,
    });

    expect(result.stale).toBe(true);
    expect(result.summary).toContain("A deploy has failed or never ran");
  });

  it("treats the grace boundary as fresh", () => {
    const result = evaluateFreshness({
      mainCommitIso: "2026-09-20T01:35:00Z",
      activeDeployIso: "2026-09-20T01:20:00Z",
      graceSeconds: grace,
    });

    expect(result.lagSeconds).toBe(grace);
    expect(result.stale).toBe(false);
  });

  it("rejects an unparseable timestamp rather than guessing", () => {
    expect(() =>
      evaluateFreshness({
        mainCommitIso: "not-a-date",
        activeDeployIso: "2026-09-20T01:20:00Z",
        graceSeconds: grace,
      }),
    ).toThrow(/main commit date is not a date/);
  });
});
