import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn(),
  queryMx: vi.fn(),
  DnsLookupError: class DnsLookupError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(message);
      this.name = "DnsLookupError";
      this.code = code;
    }
  },
}));

import { analyzeDmarc } from "../src/analyzers/dmarc.js";
import { DnsLookupError, queryTxt } from "../src/dns/client.js";

const mockQueryTxt = vi.mocked(queryTxt);

beforeEach(() => {
  vi.resetAllMocks();
});

describe("analyzeDmarc — external rua/ruf authorization", () => {
  it("does not warn when rua points to the same domain", async () => {
    // First call: _dmarc.mydomain.com
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject; rua=mailto:reports@mydomain.com"],
      raw: "v=DMARC1; p=reject; rua=mailto:reports@mydomain.com",
    });
    // No second call expected (same domain)

    const result = await analyzeDmarc("mydomain.com");
    expect(mockQueryTxt).toHaveBeenCalledTimes(1);
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("authorized"),
      ),
    ).toBe(false);
  });

  it("warns when rua points to external domain and authorization record is absent", async () => {
    // First call: _dmarc.mydomain.com
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject; rua=mailto:reports@example.com"],
      raw: "v=DMARC1; p=reject; rua=mailto:reports@example.com",
    });
    // Second call: mydomain.com._report._dmarc.example.com → null (absent)
    mockQueryTxt.mockResolvedValueOnce(null);

    const result = await analyzeDmarc("mydomain.com");
    expect(mockQueryTxt).toHaveBeenCalledTimes(2);
    expect(mockQueryTxt).toHaveBeenNthCalledWith(
      2,
      "mydomain.com._report._dmarc.example.com",
    );
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("rua") &&
          v.message.includes("example.com"),
      ),
    ).toBe(true);
  });

  it("does not warn when rua points to external domain and authorization record exists", async () => {
    // First call: _dmarc.mydomain.com
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject; rua=mailto:reports@example.com"],
      raw: "v=DMARC1; p=reject; rua=mailto:reports@example.com",
    });
    // Second call: mydomain.com._report._dmarc.example.com → valid auth record
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1"],
      raw: "v=DMARC1",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(mockQueryTxt).toHaveBeenCalledTimes(2);
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("rua") &&
          v.message.includes("authorized"),
      ),
    ).toBe(false);
  });

  it("warns instead of throwing when external authorization lookup fails with DnsLookupError", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject; rua=mailto:reports@example.com"],
      raw: "v=DMARC1; p=reject; rua=mailto:reports@example.com",
    });
    mockQueryTxt.mockRejectedValueOnce(
      new DnsLookupError("ESERVFAIL", "DNS server failure (SERVFAIL)"),
    );

    const result = await analyzeDmarc("mydomain.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("authorization lookup") &&
          v.message.includes("ESERVFAIL"),
      ),
    ).toBe(true);
  });

  it("warns when ruf points to external domain and authorization record is absent", async () => {
    // First call: _dmarc.mydomain.com
    mockQueryTxt.mockResolvedValueOnce({
      entries: [
        "v=DMARC1; p=reject; rua=mailto:rua@mydomain.com; ruf=mailto:forensic@thirdparty.com",
      ],
      raw: "v=DMARC1; p=reject; rua=mailto:rua@mydomain.com; ruf=mailto:forensic@thirdparty.com",
    });
    // Second call: rua same domain — skipped, so next is ruf auth check
    // mydomain.com._report._dmarc.thirdparty.com → null
    mockQueryTxt.mockResolvedValueOnce(null);

    const result = await analyzeDmarc("mydomain.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("ruf") &&
          v.message.includes("thirdparty.com"),
      ),
    ).toBe(true);
  });
});

describe("analyzeDmarc — pct warnings", () => {
  it("warns specifically when pct=0", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject; rua=mailto:r@mydomain.com; pct=0"],
      raw: "v=DMARC1; p=reject; rua=mailto:r@mydomain.com; pct=0",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("pct=0") &&
          v.message.includes("no messages"),
      ),
    ).toBe(true);
  });

  it("warns when pct is between 1 and 99", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject; rua=mailto:r@mydomain.com; pct=50"],
      raw: "v=DMARC1; p=reject; rua=mailto:r@mydomain.com; pct=50",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("pct=50") &&
          v.message.includes("50%"),
      ),
    ).toBe(true);
  });

  it("does not warn when pct=100", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject; rua=mailto:r@mydomain.com; pct=100"],
      raw: "v=DMARC1; p=reject; rua=mailto:r@mydomain.com; pct=100",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("pct"),
      ),
    ).toBe(false);
  });

  it("does not warn when pct is absent (default is full enforcement)", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject; rua=mailto:r@mydomain.com"],
      raw: "v=DMARC1; p=reject; rua=mailto:r@mydomain.com",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("pct"),
      ),
    ).toBe(false);
  });
});

describe("analyzeDmarc — sp=none weakness", () => {
  it("warns when sp=none overrides p=reject", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject; sp=none; rua=mailto:r@mydomain.com"],
      raw: "v=DMARC1; p=reject; sp=none; rua=mailto:r@mydomain.com",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("sp=none") &&
          v.message.includes("subdomains"),
      ),
    ).toBe(true);
  });

  it("warns when sp=none overrides p=quarantine", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=quarantine; sp=none; rua=mailto:r@mydomain.com"],
      raw: "v=DMARC1; p=quarantine; sp=none; rua=mailto:r@mydomain.com",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("sp=none") &&
          v.message.includes("subdomains"),
      ),
    ).toBe(true);
  });

  it("does not warn for sp=none when p=none (parent already weak)", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=none; sp=none; rua=mailto:r@mydomain.com"],
      raw: "v=DMARC1; p=none; sp=none; rua=mailto:r@mydomain.com",
    });

    const result = await analyzeDmarc("mydomain.com");
    // Should not have the sp=none override warning
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("sp=none") &&
          v.message.includes("subdomains"),
      ),
    ).toBe(false);
  });

  it("does not warn when sp=quarantine (not a weakening)", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject; sp=quarantine; rua=mailto:r@mydomain.com"],
      raw: "v=DMARC1; p=reject; sp=quarantine; rua=mailto:r@mydomain.com",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("sp=none") &&
          v.message.includes("subdomains"),
      ),
    ).toBe(false);
  });
});

describe("analyzeDmarc — multiple records", () => {
  it("fails with permerror when more than one DMARC record is published (RFC 7489 §6.6.3)", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject", "v=DMARC1; p=none"],
      raw: "v=DMARC1; p=reject",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(result.status).toBe("fail");
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" && v.message.includes("Multiple DMARC records"),
      ),
    ).toBe(true);
  });

  it("does not flag multiple-record permerror for a single record", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject; rua=mailto:r@mydomain.com"],
      raw: "v=DMARC1; p=reject; rua=mailto:r@mydomain.com",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(
      result.validations.some((v) =>
        v.message.includes("Multiple DMARC records"),
      ),
    ).toBe(false);
  });
});

describe("analyzeDmarc — alignment and failure-reporting tags", () => {
  it("explains strict alignment when adkim=s and aspf=s", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: [
        "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:r@mydomain.com",
      ],
      raw: "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:r@mydomain.com",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(
      result.validations.some(
        (v) =>
          v.message.includes("DKIM alignment") && v.message.includes("strict"),
      ),
    ).toBe(true);
    expect(
      result.validations.some(
        (v) =>
          v.message.includes("SPF alignment") && v.message.includes("strict"),
      ),
    ).toBe(true);
  });

  it("explains the relaxed default alignment when adkim/aspf are absent", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=DMARC1; p=reject; rua=mailto:r@mydomain.com"],
      raw: "v=DMARC1; p=reject; rua=mailto:r@mydomain.com",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(
      result.validations.some(
        (v) =>
          v.message.includes("DKIM alignment") &&
          v.message.includes("relaxed") &&
          v.message.includes("default"),
      ),
    ).toBe(true);
  });

  it("explains the fo failure-reporting options when present", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: [
        "v=DMARC1; p=reject; fo=1; ruf=mailto:f@mydomain.com; rua=mailto:r@mydomain.com",
      ],
      raw: "v=DMARC1; p=reject; fo=1; ruf=mailto:f@mydomain.com; rua=mailto:r@mydomain.com",
    });

    const result = await analyzeDmarc("mydomain.com");
    expect(result.validations.some((v) => v.message.includes("fo=1"))).toBe(
      true,
    );
  });
});
