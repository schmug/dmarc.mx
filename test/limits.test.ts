import { describe, expect, it } from "vitest";
import {
  FREE_WATCHLIST_CAP,
  PRO_WATCHLIST_CAP,
  watchlistCapFor,
  watchlistCapForPlan,
} from "../src/shared/limits.js";

describe("watchlistCapForPlan", () => {
  it("returns PRO_WATCHLIST_CAP for pro", () => {
    expect(watchlistCapForPlan("pro")).toBe(PRO_WATCHLIST_CAP);
  });
  it("returns FREE_WATCHLIST_CAP for free", () => {
    expect(watchlistCapForPlan("free")).toBe(FREE_WATCHLIST_CAP);
  });
});

describe("watchlistCapFor — override logic", () => {
  it("returns plan cap when override is null", () => {
    expect(watchlistCapFor("pro", null)).toBe(PRO_WATCHLIST_CAP);
    expect(watchlistCapFor("free", null)).toBe(FREE_WATCHLIST_CAP);
  });

  it("returns plan cap when override is undefined", () => {
    expect(watchlistCapFor("pro", undefined)).toBe(PRO_WATCHLIST_CAP);
    expect(watchlistCapFor("free", undefined)).toBe(FREE_WATCHLIST_CAP);
  });

  it("override wins over pro plan cap", () => {
    expect(watchlistCapFor("pro", 50)).toBe(50);
  });

  it("override wins over free plan cap (override applies regardless of plan)", () => {
    expect(watchlistCapFor("free", 50)).toBe(50);
  });

  it("override of 0 wins (edge case: explicitly zero)", () => {
    expect(watchlistCapFor("pro", 0)).toBe(0);
  });
});
