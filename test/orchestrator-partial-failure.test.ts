/**
 * #378 — a single analyzer rejection must not abort the whole scan. The
 * orchestrator isolates each analyzer: a thrown error surfaces as a synthetic
 * `status: "fail"` result for that protocol while every sibling still resolves,
 * for both scan() and scanStreaming(). The analyzer layer is mocked to a fixed
 * passing domain; individual tests override one analyzer to reject.
 */
import { describe, expect, it, vi } from "vitest";
import type { ProtocolId, ProtocolResult } from "../src/orchestrator.js";

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
    selectors: { google: { found: true, key_type: "rsa", key_bits: 2048 } },
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

import { analyzeDmarc } from "../src/analyzers/dmarc.js";
import { analyzeMtaSts } from "../src/analyzers/mta-sts.js";
import { analyzeMx } from "../src/analyzers/mx.js";
import { analyzeSpf } from "../src/analyzers/spf.js";
import { scan, scanStreaming } from "../src/orchestrator.js";

describe("scan() isolates a single analyzer failure (#378)", () => {
  it("surfaces a synthetic fail for the crashed analyzer while siblings resolve", async () => {
    vi.mocked(analyzeSpf).mockRejectedValueOnce(
      new Error("SPF analyzer crashed"),
    );

    // Must not throw — the whole scan no longer aborts on one rejection.
    const result = await scan("example.com", [], {});

    // The crashed analyzer is reported as a synthetic failure...
    expect(result.protocols.spf.status).toBe("fail");
    expect(
      result.protocols.spf.validations.some((v) => v.status === "fail"),
    ).toBe(true);
    // ...while every sibling still has its real result.
    expect(result.protocols.dmarc.status).toBe("pass");
    expect(result.protocols.mta_sts.status).toBe("pass");
    // A grade is still produced from partial results.
    expect(result.grade).toBeTruthy();
    expect(result.summary.spf_result).toBe("fail");
  });

  it("routes a dmarc analyzer crash through the lookup-failure scoring path", async () => {
    vi.mocked(analyzeDmarc).mockRejectedValueOnce(
      new Error("DMARC analyzer crashed"),
    );

    const result = await scan("example.com", [], {});

    expect(result.protocols.dmarc.status).toBe("fail");
    expect(result.protocols.dmarc.lookup_error?.code).toBe("analyzer_error");
    // scoring.ts maps a dmarc lookup_error to D ("policy could not be verified"),
    // not a false F, and an independent sibling is unaffected.
    expect(result.grade).toBe("D");
    expect(result.protocols.spf.status).toBe("pass");
  });

  it("cascades an MX crash to its dependent DKIM without aborting siblings", async () => {
    // DKIM is chained off MX (dkimPromise = mxPromise.then(...)), so when MX
    // rejects, dkimPromise rejects too. Both must be isolated independently —
    // each surfaces a synthetic fail — while unrelated analyzers stay intact.
    vi.mocked(analyzeMx).mockRejectedValueOnce(
      new Error("MX analyzer crashed"),
    );

    const result = await scan("example.com", [], {});

    expect(result.protocols.mx.status).toBe("fail");
    expect(result.protocols.dkim.status).toBe("fail");
    // Independent siblings are untouched by the MX→DKIM cascade.
    expect(result.protocols.dmarc.status).toBe("pass");
    expect(result.protocols.spf.status).toBe("pass");
    expect(result.grade).toBeTruthy();
  });
});

describe("scanStreaming() isolates a single analyzer failure (#378)", () => {
  it("streams a synthetic fail card for the crashed analyzer and still completes", async () => {
    vi.mocked(analyzeMtaSts).mockRejectedValueOnce(
      new Error("MTA-STS analyzer crashed"),
    );

    const streamed = new Map<ProtocolId, ProtocolResult>();
    const result = await scanStreaming(
      "example.com",
      [],
      (id, r) => {
        streamed.set(id, r);
      },
      {},
    );

    // Every protocol streamed exactly once, including the crashed one.
    for (const id of [
      "mx",
      "dmarc",
      "spf",
      "dkim",
      "bimi",
      "mta_sts",
      "security_txt",
      "tls_rpt",
    ] as ProtocolId[]) {
      expect(streamed.has(id)).toBe(true);
    }
    // The crashed analyzer streamed a synthetic fail...
    expect(streamed.get("mta_sts")?.status).toBe("fail");
    // ...and the final aggregate agrees, with siblings intact.
    expect(result.protocols.mta_sts.status).toBe("fail");
    expect(result.protocols.dmarc.status).toBe("pass");
    expect(result.grade).toBeTruthy();
  });
});
