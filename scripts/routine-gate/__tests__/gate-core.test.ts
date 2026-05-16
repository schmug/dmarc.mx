import { describe, it, expect } from "vitest";
import { CONFIG } from "../config";

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
