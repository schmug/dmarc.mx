/**
 * Integration anchor: proves the SCORING_CONFIG knob actually reaches the
 * grade computation through scan() → buildScanResult() → computeGradeBreakdown().
 * The analyzer layer is mocked to a fixed A-tier domain (p=reject + strong SPF
 * + DKIM + enforcing MTA-STS, no BIMI). Under defaults that domain is the A
 * tier; flipping requireBimiForAPlus off must promote it to A+ — which can only
 * happen if scan() forwarded the config.
 */
import { describe, expect, it, vi } from "vitest";

vi.mock("../src/analyzers/dmarc.js", () => ({
  analyzeDmarc: vi.fn().mockResolvedValue({
    status: "pass",
    record: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    tags: { v: "DMARC1", p: "reject", rua: "mailto:dmarc@example.com" },
    validations: [],
  }),
}));
vi.mock("../src/analyzers/spf.js", () => ({
  analyzeSpf: vi.fn().mockResolvedValue({
    status: "pass",
    record: "v=spf1 -all",
    lookups_used: 3,
    lookup_limit: 10,
    include_tree: null,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/dkim.js", () => ({
  analyzeDkim: vi.fn().mockResolvedValue({
    status: "pass",
    selectors: {
      google: { found: true, key_type: "rsa", key_bits: 2048 },
      selector1: { found: true, key_type: "rsa", key_bits: 2048 },
    },
    validations: [],
  }),
}));
vi.mock("../src/analyzers/bimi.js", () => ({
  prefetchBimiDns: vi.fn().mockResolvedValue(null),
  analyzeBimi: vi.fn().mockResolvedValue({
    status: "warn",
    record: null,
    tags: null,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/mta-sts.js", () => ({
  analyzeMtaSts: vi.fn().mockResolvedValue({
    status: "pass",
    dns_record: "v=STSv1; id=20260101",
    policy: {
      version: "STSv1",
      mode: "enforce",
      mx: ["*.example.com"],
      max_age: 86400,
    },
    validations: [],
  }),
}));
vi.mock("../src/analyzers/mx.js", () => ({
  analyzeMx: vi.fn().mockResolvedValue({
    status: "info",
    records: [],
    providers: [],
    validations: [],
  }),
}));
vi.mock("../src/analyzers/mx-mta-sts-consistency.js", () => ({
  checkMxMtaStsConsistency: vi.fn().mockReturnValue([]),
}));
vi.mock("../src/analyzers/security-txt.js", () => ({
  analyzeSecurityTxt: vi.fn().mockResolvedValue({
    status: "info",
    source_url: null,
    signed: false,
    fields: null,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/tls-rpt.js", () => ({
  analyzeTlsRpt: vi.fn().mockResolvedValue({
    status: "info",
    record: null,
    tags: null,
    validations: [],
  }),
}));
vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn().mockResolvedValue(null),
  queryMx: vi.fn().mockResolvedValue(null),
}));

import { scan } from "../src/orchestrator.js";

describe("scan() forwards SCORING_CONFIG to the grade computation", () => {
  it("grades the A tier under default config", async () => {
    const result = await scan("example.com", [], {});
    expect(result.breakdown.tier).toBe("A");
  });

  it("grades the A+ tier when requireBimiForAPlus is disabled", async () => {
    const result = await scan("example.com", [], {
      requireBimiForAPlus: false,
    });
    expect(result.breakdown.tier).toBe("A+");
  });
});
