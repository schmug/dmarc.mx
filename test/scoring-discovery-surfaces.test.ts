/**
 * #404 — the /scoring FAQ JSON-LD and the markdown rubric must reflect the
 * active SCORING_CONFIG, while staying byte-identical to the shipped output
 * when the config is unset (so hosted dmarc.mx is unaffected).
 */
import { describe, expect, it } from "vitest";
import { DEFAULT_SCORING_CONFIG } from "../src/shared/scoring.js";
import { buildScoringJsonLd } from "../src/views/html.js";
import { renderScoringRubricMarkdown } from "../src/views/markdown.js";

// The exact DKIM answer that shipped before #404. dkimKeyMinBits is the only
// config-dependent value in the JSON-LD, so pinning this sentence (with the
// default 2048) guards the byte-identical-when-unset invariant.
const SHIPPED_DKIM_ANSWER =
  "DomainKeys Identified Mail. Adds a cryptographic signature to outgoing messages, proving they haven't been tampered with in transit. Key strength of 2048 bits or more and multiple selectors improve your score.";

describe("buildScoringJsonLd (#404)", () => {
  it("is byte-identical to the shipped JSON-LD when config is unset", () => {
    const def = buildScoringJsonLd();
    expect(def).toBe(buildScoringJsonLd({}));
    expect(def).toBe(buildScoringJsonLd(DEFAULT_SCORING_CONFIG));
    // Structurally intact: FAQPage with the original six questions.
    const parsed = JSON.parse(def);
    expect(parsed["@type"]).toBe("FAQPage");
    expect(parsed.mainEntity).toHaveLength(6);
    // The default DKIM answer is unchanged, character for character.
    expect(def).toContain(JSON.stringify(SHIPPED_DKIM_ANSWER).slice(1, -1));
  });

  it("reflects a non-default dkimKeyMinBits", () => {
    const custom = buildScoringJsonLd({ dkimKeyMinBits: 4096 });
    expect(custom).toContain("Key strength of 4096 bits or more");
    expect(custom).not.toContain("2048 bits or more");
    // Still valid, still six questions — only the number moved.
    expect(JSON.parse(custom).mainEntity).toHaveLength(6);
  });
});

describe("renderScoringRubricMarkdown (#404)", () => {
  it("renders the default thresholds when config is unset", () => {
    const md = renderScoringRubricMarkdown();
    expect(md).toContain("## Active scoring thresholds");
    expect(md).toContain("below **2048 bits**");
    expect(md).toContain("**2 or more** DKIM selectors");
    expect(md).toContain("≤ 5 DNS lookups");
    expect(md).toContain("below **10%**");
    expect(md).toContain("both BIMI and enforcing MTA-STS");
  });

  it("reflects non-default thresholds from the active config", () => {
    const md = renderScoringRubricMarkdown({
      dkimKeyMinBits: 4096,
      dkimRotationSelectorCount: 3,
      spfEfficientLookupThreshold: 3,
      lowPctDowngradeThreshold: 20,
      requireBimiForAPlus: false,
      requireMtaStsForAPlus: true,
    });
    expect(md).toContain("below **4096 bits**");
    expect(md).toContain("**3 or more** DKIM selectors");
    expect(md).toContain("≤ 3 DNS lookups");
    expect(md).toContain("below **20%**");
    // With BIMI no longer required, the A+ extra prose narrows to MTA-STS.
    expect(md).toContain("A+ requires enforcing MTA-STS");
    expect(md).not.toContain("below **2048 bits**");
  });
});
