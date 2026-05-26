import { beforeEach, describe, expect, it, vi } from "vitest";
import { scanStreaming } from "../src/orchestrator.js";

const { mxPass, mtaStsPassBeforeConsistency } = vi.hoisted(() => ({
  mxPass: {
    status: "info" as const,
    records: [{ priority: 10, exchange: "mail.sub.example.com" }],
    providers: [],
    validations: [],
  },
  mtaStsPassBeforeConsistency: {
    status: "pass" as const,
    dns_record: "v=STSv1; id=1",
    policy: {
      version: "STSv1",
      mode: "enforce" as const,
      mx: ["*.example.com"],
      max_age: 86400,
    },
    validations: [{ status: "pass" as const, message: "Policy file fetched" }],
  },
}));

vi.mock("../src/analyzers/mx.js", () => ({
  analyzeMx: vi.fn().mockResolvedValue(mxPass),
}));

vi.mock("../src/analyzers/mta-sts.js", () => ({
  analyzeMtaSts: vi.fn().mockResolvedValue(mtaStsPassBeforeConsistency),
}));

vi.mock("../src/analyzers/dmarc.js", () => ({
  analyzeDmarc: vi.fn().mockResolvedValue({
    status: "fail",
    record: null,
    tags: null,
    validations: [],
  }),
}));

vi.mock("../src/analyzers/spf.js", () => ({
  analyzeSpf: vi.fn().mockResolvedValue({
    status: "fail",
    record: null,
    lookups_used: 0,
    lookup_limit: 10,
    validations: [],
  }),
}));

vi.mock("../src/analyzers/dkim.js", () => ({
  analyzeDkim: vi.fn().mockResolvedValue({
    status: "fail",
    selectors: {},
    validations: [],
  }),
}));

vi.mock("../src/analyzers/bimi.js", () => ({
  analyzeBimi: vi.fn().mockResolvedValue({
    status: "fail",
    record: null,
    validations: [],
  }),
  prefetchBimiDns: vi.fn().mockResolvedValue(null),
}));

vi.mock("../src/analyzers/security-txt.js", () => ({
  analyzeSecurityTxt: vi.fn().mockResolvedValue({
    status: "info",
    url: null,
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
}));

describe("scanStreaming MTA-STS consistency", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("streams MTA-STS after MX consistency check, not the raw analyzer status", async () => {
    const streamed: Array<{ id: string; status: string }> = [];

    const result = await scanStreaming("example.com", [], (id, proto) => {
      if (id === "mta_sts") {
        streamed.push({ id, status: proto.status });
      }
    });

    expect(streamed).toHaveLength(1);
    expect(streamed[0].status).toBe("warn");
    expect(result.protocols.mta_sts.status).toBe("warn");
    expect(
      result.protocols.mta_sts.validations.some(
        (v) =>
          v.status === "warn" && v.message.includes("mail.sub.example.com"),
      ),
    ).toBe(true);
  });
});
