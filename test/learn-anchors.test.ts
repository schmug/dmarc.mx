import { describe, expect, it } from "vitest";
import { LEARN_ANCHORS, learnAnchorHref } from "../src/shared/learn-anchors";
import {
  renderLearnBimi,
  renderLearnDkim,
  renderLearnDmarc,
  renderLearnSpf,
} from "../src/views/learn";

// Maps each learn-page path used by LEARN_ANCHORS to its renderer so the
// contract test below can assert the target id actually renders (#524).
const PAGE_RENDERERS: Record<string, () => string> = {
  "/learn/dmarc": renderLearnDmarc,
  "/learn/spf": renderLearnSpf,
  "/learn/dkim": renderLearnDkim,
  "/learn/bimi": renderLearnBimi,
};

describe("learn anchors contract (#524)", () => {
  it("learnAnchorHref builds page#id", () => {
    expect(learnAnchorHref(LEARN_ANCHORS.spfLookupLimit)).toBe(
      "/learn/spf#lookup-limit",
    );
  });

  it("covers the curated finding set", () => {
    expect(Object.keys(LEARN_ANCHORS).sort()).toEqual(
      [
        "bimiCertification",
        "dkimFindSelector",
        "dkimKeyRotation",
        "dmarcPolicyNone",
        "spfLookupLimit",
      ].sort(),
    );
  });

  for (const [key, anchor] of Object.entries(LEARN_ANCHORS)) {
    it(`${key}: ${anchor.page} renders an element with id="${anchor.id}"`, () => {
      // Anchor ids are a stable kebab-case contract.
      expect(anchor.id).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/);
      const render = PAGE_RENDERERS[anchor.page];
      expect(
        render,
        `no learn-page renderer mapped for ${anchor.page}`,
      ).toBeDefined();
      expect(render()).toContain(`id="${anchor.id}"`);
    });
  }
});
