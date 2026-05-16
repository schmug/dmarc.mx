import { describe, it, expect } from "vitest";
import { CONFIG } from "../config";
import { parseClosesIssue, isProvenanceTrusted } from "../gate-core";
import { touchesRiskPath, withinSizeEnvelope, scopeDrift } from "../gate-core";

describe("CONFIG", () => {
  it("only allowlists the repo owner", () => {
    expect(CONFIG.allowlistAuthors).toEqual(["schmug"]);
  });
  it("uses the higher-throughput envelope", () => {
    expect(CONFIG.size.maxChangedLines).toBe(250);
    expect(CONFIG.size.maxChangedFiles).toBe(8);
    expect(CONFIG.implementerBatch).toBe(6);
  });
  it("has a non-empty risk-path denylist and the four labels", () => {
    expect(CONFIG.riskPathDenylist.length).toBeGreaterThan(5);
    expect(CONFIG.labels).toMatchObject({
      specApproved: "spec-approved",
      autoImpl: "auto-impl",
      needsYou: "needs-you",
      implBlocked: "impl-blocked",
    });
  });
  it("knows dmarcheck is main-flow and donthype-me is dev-flow", () => {
    expect(CONFIG.baseBranchByRepo["dmarcheck"]).toBe("main");
    expect(CONFIG.baseBranchByRepo["donthype-me"]).toBe("dev");
  });
});

describe("parseClosesIssue", () => {
  it("extracts the issue number from a Closes line", () => {
    expect(parseClosesIssue("Adds X.\n\nCloses #42")).toBe(42);
  });
  it("is case-insensitive", () => {
    expect(parseClosesIssue("closes #7")).toBe(7);
  });
  it("returns null when absent", () => {
    expect(parseClosesIssue("no link here")).toBeNull();
  });
});

describe("isProvenanceTrusted", () => {
  const cfg = CONFIG;
  it("trusts allowlisted author WITH spec-approved label", () => {
    expect(isProvenanceTrusted({ number: 1, author: "schmug", labels: ["spec-approved"], filePointers: [] }, cfg)).toBe(true);
  });
  it("rejects a stranger even if labelled", () => {
    expect(isProvenanceTrusted({ number: 1, author: "drive-by", labels: ["spec-approved"], filePointers: [] }, cfg)).toBe(false);
  });
  it("rejects allowlisted author WITHOUT the label", () => {
    expect(isProvenanceTrusted({ number: 1, author: "schmug", labels: [], filePointers: [] }, cfg)).toBe(false);
  });
  it("rejects a null issue (fail-closed)", () => {
    expect(isProvenanceTrusted(null, cfg)).toBe(false);
  });
});

describe("touchesRiskPath", () => {
  it("flags a workflow file", () => {
    expect(touchesRiskPath([".github/workflows/ci.yml"], CONFIG.riskPathDenylist))
      .toEqual([".github/workflows/ci.yml"]);
  });
  it("flags an mta-sts source file", () => {
    expect(touchesRiskPath(["src/mta-sts-fetch.ts"], CONFIG.riskPathDenylist))
      .toEqual(["src/mta-sts-fetch.ts"]);
  });
  it("passes an ordinary source file", () => {
    expect(touchesRiskPath(["src/analyzers/spf.ts"], CONFIG.riskPathDenylist)).toEqual([]);
  });
});

describe("withinSizeEnvelope", () => {
  const base = { number: 1, body: "", changedFiles: ["a.ts"], ciAllGreen: true };
  it("accepts a small diff", () => {
    expect(withinSizeEnvelope({ ...base, additions: 100, deletions: 40 }, CONFIG)).toBe(true);
  });
  it("rejects too many lines", () => {
    expect(withinSizeEnvelope({ ...base, additions: 300, deletions: 0 }, CONFIG)).toBe(false);
  });
  it("rejects too many files", () => {
    expect(withinSizeEnvelope(
      { ...base, additions: 10, deletions: 0, changedFiles: Array(9).fill("x.ts") }, CONFIG)).toBe(false);
  });
});

describe("scopeDrift", () => {
  it("returns files outside declared pointers", () => {
    expect(scopeDrift(["src/a.ts", "src/b.ts"], ["src/a.ts"])).toEqual(["src/b.ts"]);
  });
  it("treats empty pointers as total drift (fail-closed)", () => {
    expect(scopeDrift(["src/a.ts"], [])).toEqual(["src/a.ts"]);
  });
  it("matches glob pointers", () => {
    expect(scopeDrift(["src/analyzers/spf.ts"], ["src/analyzers/**"])).toEqual([]);
  });
});
