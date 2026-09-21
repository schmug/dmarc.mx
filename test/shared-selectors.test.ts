import { describe, expect, it } from "vitest";
import {
  MAX_SELECTORS,
  parseSelectors,
  validateCustomSelectors,
} from "../src/shared/selectors.js";

describe("validateCustomSelectors", () => {
  it("accepts undefined/empty input as no selectors", () => {
    expect(validateCustomSelectors(undefined)).toEqual({ selectors: [] });
    expect(validateCustomSelectors("")).toEqual({ selectors: [] });
    expect(validateCustomSelectors("   ")).toEqual({ selectors: [] });
  });

  it("accepts a valid comma-separated list", () => {
    expect(validateCustomSelectors("agentmail, selector1")).toEqual({
      selectors: ["agentmail", "selector1"],
    });
  });

  // #755 acceptance criterion 3: an invalid-character selector is rejected
  // at write time, not silently dropped like the read-path parseSelectors
  // does — so it never reaches storage or a DNS query.
  it("rejects an invalid-character selector instead of silently dropping it", () => {
    const result = validateCustomSelectors("google,<script>");
    expect(result).toHaveProperty("error");
    if ("selectors" in result) throw new Error("expected an error result");
    expect(result.error).toMatch(/letters, numbers/);
  });

  it("rejects an over-cap selector count instead of truncating it", () => {
    const many = Array.from(
      { length: MAX_SELECTORS + 1 },
      (_, i) => `s${i}`,
    ).join(",");
    const result = validateCustomSelectors(many);
    expect(result).toHaveProperty("error");
    if ("selectors" in result) throw new Error("expected an error result");
    expect(result.error).toMatch(/Too many selectors/);
  });

  it("rejects a selector over the per-item length limit", () => {
    const tooLong = "a".repeat(64);
    const result = validateCustomSelectors(tooLong);
    expect(result).toHaveProperty("error");
  });

  // Confirms the write-time validator reuses parseSelectors' own filtering
  // (same regex/length rules) rather than a second sanitizing regex: any
  // input parseSelectors would leave untouched round-trips through
  // validateCustomSelectors unchanged.
  it("accepts exactly what parseSelectors accepts unmodified", () => {
    const raw = "google,selector1,s2";
    const result = validateCustomSelectors(raw);
    expect("selectors" in result && result.selectors).toEqual(
      parseSelectors(raw),
    );
  });
});
