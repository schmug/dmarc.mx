/**
 * #587 — DNSBL analyzer wiring into the orchestrator.
 *
 * Proves the credential-gated contract end-to-end at the scan() / scanStreaming()
 * level: with no DNSBL_DQS_KEY the result carries a clean no-op DNSBL card (never
 * a fail, no DNS), and when the key is threaded in, the orchestrator passes it to
 * the analyzer which then queries the derivable sending IPs. Every analyzer EXCEPT
 * dnsbl is stubbed; analyzeDnsbl runs for real against a mocked DNS client.
 */
import { describe, expect, it, vi } from "vitest";
import type { ProtocolId, ProtocolResult } from "../src/orchestrator.js";

vi.mock("@sentry/cloudflare", () => ({
  addBreadcrumb: vi.fn(),
  captureException: vi.fn(),
}));

vi.mock("../src/analyzers/dmarc.js", () => ({
  analyzeDmarc: vi.fn().mockResolvedValue({
    status: "pass",
    record: "v=DMARC1; p=reject; rua=mailto:d@example.com",
    tags: { v: "DMARC1", p: "reject", rua: "mailto:d@example.com" },
    validations: [],
  }),
}));
// SPF carries one literal ip4 the DNSBL analyzer can derive without any DNS.
vi.mock("../src/analyzers/spf.js", () => ({
  analyzeSpf: vi.fn().mockResolvedValue({
    status: "pass",
    record: "v=spf1 ip4:192.0.2.5 -all",
    lookups_used: 1,
    lookup_limit: 10,
    include_tree: {
      domain: "example.com",
      record: "v=spf1 ip4:192.0.2.5 -all",
      mechanisms: ["ip4:192.0.2.5", "-all"],
      includes: [],
    },
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
    status: "fail",
    dns_record: null,
    policy: null,
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
vi.mock("../src/analyzers/dnssec.js", () => ({
  analyzeDnssec: vi.fn().mockResolvedValue({
    status: "info",
    signed: false,
    validated: false,
    validations: [],
  }),
}));
vi.mock("../src/analyzers/dane.js", () => ({
  analyzeDane: vi.fn().mockResolvedValue({
    status: "info",
    hosts: [],
    validations: [],
  }),
}));
// Real analyzeDnsbl runs against this mocked DNS client.
vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn().mockResolvedValue(null),
  queryMx: vi.fn().mockResolvedValue(null),
  queryDoh: vi.fn().mockResolvedValue(null),
  queryDnsbl: vi.fn().mockResolvedValue(null),
  DnsLookupError: class DnsLookupError extends Error {
    constructor(
      public readonly code: string,
      message: string,
    ) {
      super(message);
      this.name = "DnsLookupError";
    }
  },
}));

import { queryDnsbl } from "../src/dns/client.js";
import { scan, scanStreaming } from "../src/orchestrator.js";

const mockedQueryDnsbl = vi.mocked(queryDnsbl);

describe("scan() — DNSBL credential-gated no-op (#587)", () => {
  it("produces a clean no-op DNSBL card and issues no DNSBL query when no key is set", async () => {
    mockedQueryDnsbl.mockClear();
    const result = await scan("example.com", [], {});

    const dnsbl = result.protocols.dnsbl;
    expect(dnsbl).toBeDefined();
    expect(dnsbl?.enabled).toBe(false);
    expect(dnsbl?.status).toBe("info");
    expect(dnsbl?.status).not.toBe("fail");
    expect(mockedQueryDnsbl).not.toHaveBeenCalled();
    // The rest of the scan is unaffected — a grade is still produced.
    expect(result.grade).toBeTruthy();
  });

  it("does not let the DNSBL result change the letter grade", async () => {
    mockedQueryDnsbl.mockClear();
    const withoutKey = await scan("example.com", [], {});
    mockedQueryDnsbl.mockResolvedValue(["127.0.0.2"]); // a listing
    const withListing = await scan("example.com", [], {}, undefined, "testkey");
    // DNSBL is informational only — a listing must not move the grade.
    expect(withListing.grade).toBe(withoutKey.grade);
    expect(withListing.protocols.dnsbl?.status).toBe("warn");
    mockedQueryDnsbl.mockResolvedValue(null);
  });
});

describe("scan() — threads the DQS key into the analyzer (#587)", () => {
  it("checks the derivable sending IP against the reversed-IP DQS zone", async () => {
    mockedQueryDnsbl.mockClear();
    mockedQueryDnsbl.mockResolvedValue(null);

    const result = await scan("example.com", [], {}, undefined, "testkey");

    const dnsbl = result.protocols.dnsbl;
    expect(dnsbl?.enabled).toBe(true);
    expect(dnsbl?.ips_checked).toBe(1);
    expect(dnsbl?.checked[0]?.ip).toBe("192.0.2.5");
    expect(dnsbl?.status).toBe("pass");
    expect(mockedQueryDnsbl).toHaveBeenCalledWith(
      "5.2.0.192",
      "testkey",
      "zen.dq.spamhaus.net",
      expect.anything(),
    );
  });
});

describe("scanStreaming() — emits the DNSBL card exactly once (#587)", () => {
  it("streams a dnsbl protocol card", async () => {
    mockedQueryDnsbl.mockClear();
    mockedQueryDnsbl.mockResolvedValue(null);

    const streamed = new Map<ProtocolId, ProtocolResult>();
    let dnsblEmits = 0;
    await scanStreaming(
      "example.com",
      [],
      (id, r) => {
        if (id === "dnsbl") dnsblEmits++;
        streamed.set(id, r);
      },
      {},
      undefined,
      "testkey",
    );

    expect(streamed.has("dnsbl")).toBe(true);
    expect(dnsblEmits).toBe(1);
    expect((streamed.get("dnsbl") as { enabled?: boolean }).enabled).toBe(true);
  });
});
