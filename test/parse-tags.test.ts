import { describe, expect, it } from "vitest";
import { parseTags } from "../src/shared/parse-tags.js";

describe("parseTags", () => {
  it("parses semicolon-separated key=value pairs", () => {
    expect(parseTags("v=DMARC1; p=reject")).toEqual({
      v: "DMARC1",
      p: "reject",
    });
  });

  it("trims whitespace around keys and values", () => {
    expect(parseTags("  v = DMARC1 ;  p = reject  ")).toEqual({
      v: "DMARC1",
      p: "reject",
    });
  });

  it("skips empty segments", () => {
    expect(parseTags("v=DMARC1;;p=reject;")).toEqual({
      v: "DMARC1",
      p: "reject",
    });
  });

  it("skips segments without =", () => {
    expect(parseTags("v=DMARC1; badentry; p=reject")).toEqual({
      v: "DMARC1",
      p: "reject",
    });
  });

  it("lowercases keys by default", () => {
    expect(parseTags("V=DMARC1; P=reject")).toEqual({
      v: "DMARC1",
      p: "reject",
    });
  });

  it("preserves key case when lowercaseKeys is false", () => {
    expect(parseTags("V=DMARC1; P=reject", { lowercaseKeys: false })).toEqual({
      V: "DMARC1",
      P: "reject",
    });
  });

  it("splits only on first = to preserve values containing =", () => {
    expect(parseTags("rua=mailto:d@example.com")).toEqual({
      rua: "mailto:d@example.com",
    });
  });

  it("returns empty object for empty string", () => {
    expect(parseTags("")).toEqual({});
  });

  it("stores a __proto__ tag as a normal own key without altering the prototype", () => {
    const result = parseTags("v=DMARC1; __proto__=evil");
    expect(result.v).toBe("DMARC1");
    expect(Object.getPrototypeOf({})).toBe(Object.prototype);
    expect(Object.prototype).not.toHaveProperty("evil");
    expect(Object.getOwnPropertyDescriptor(result, "__proto__")?.value).toBe(
      "evil",
    );
  });

  it("stores a constructor tag as a normal own key", () => {
    const result = parseTags("v=DMARC1; constructor=evil");
    expect(result.constructor).toBe("evil");
  });
});
