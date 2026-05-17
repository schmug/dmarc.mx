import { beforeEach, describe, expect, it, vi } from "vitest";
import { analyzeTlsRpt } from "../src/analyzers/tls-rpt.js";

// Mock the DNS client — imported by the analyzer
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

import { DnsLookupError, queryTxt } from "../src/dns/client.js";

const mockQueryTxt = vi.mocked(queryTxt);

beforeEach(() => {
  vi.resetAllMocks();
});

describe("analyzeTlsRpt", () => {
  it("returns info when no TXT record exists", async () => {
    mockQueryTxt.mockResolvedValue(null);
    const result = await analyzeTlsRpt("example.com");
    expect(result.status).toBe("info");
    expect(result.record).toBeNull();
    expect(result.tags).toBeNull();
    expect(
      result.validations.some(
        (v) => v.status === "info" && v.message.includes("No TLS-RPT record"),
      ),
    ).toBe(true);
  });

  it("queries the correct DNS name (_smtp._tls.<domain>)", async () => {
    mockQueryTxt.mockResolvedValue(null);
    await analyzeTlsRpt("example.com");
    expect(mockQueryTxt).toHaveBeenCalledWith("_smtp._tls.example.com");
  });

  it("returns pass for a valid record with mailto rua", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"],
      raw: "v=TLSRPTv1; rua=mailto:tlsrpt@example.com",
    });
    const result = await analyzeTlsRpt("example.com");
    expect(result.status).toBe("pass");
    expect(result.record).toBe("v=TLSRPTv1; rua=mailto:tlsrpt@example.com");
    expect(result.tags?.rua).toBe("mailto:tlsrpt@example.com");
    expect(
      result.validations.some(
        (v) => v.status === "info" && v.message.includes("v=TLSRPTv1"),
      ),
    ).toBe(true);
    expect(
      result.validations.some(
        (v) => v.status === "info" && v.message.includes("tlsrpt@example.com"),
      ),
    ).toBe(true);
  });

  it("returns pass for a valid record with https rua", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=TLSRPTv1; rua=https://example.com/tlsrpt"],
      raw: "v=TLSRPTv1; rua=https://example.com/tlsrpt",
    });
    const result = await analyzeTlsRpt("example.com");
    expect(result.status).toBe("pass");
  });

  it("warns when rua= tag is missing", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=TLSRPTv1"],
      raw: "v=TLSRPTv1",
    });
    const result = await analyzeTlsRpt("example.com");
    expect(result.status).toBe("warn");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("rua="),
      ),
    ).toBe(true);
  });

  it("warns for multiple TLS-RPT records", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=TLSRPTv1; rua=mailto:a@example.com",
        "v=TLSRPTv1; rua=mailto:b@example.com",
      ],
      raw: "v=TLSRPTv1; rua=mailto:a@example.com v=TLSRPTv1; rua=mailto:b@example.com",
    });
    const result = await analyzeTlsRpt("example.com");
    expect(result.status).toBe("warn");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("2 TLS-RPT records") &&
          v.message.includes("exactly one"),
      ),
    ).toBe(true);
  });

  it("warns for unrelated TXT records alongside TLSRPTv1", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=TLSRPTv1; rua=mailto:r@example.com",
        "some-unrelated-record",
      ],
      raw: "v=TLSRPTv1; rua=mailto:r@example.com some-unrelated-record",
    });
    const result = await analyzeTlsRpt("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("unrelated TXT"),
      ),
    ).toBe(true);
  });

  it("warns when TXT records exist but none start with v=TLSRPTv1", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=spf1 include:example.com ~all"],
      raw: "v=spf1 include:example.com ~all",
    });
    const result = await analyzeTlsRpt("example.com");
    expect(result.status).toBe("warn");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("v=TLSRPTv1"),
      ),
    ).toBe(true);
  });

  it("warns for rua= destinations not in mailto:/https:// format", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=TLSRPTv1; rua=ftp://invalid.example.com"],
      raw: "v=TLSRPTv1; rua=ftp://invalid.example.com",
    });
    const result = await analyzeTlsRpt("example.com");
    expect(result.status).toBe("warn");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" && v.message.includes("mailto:/https:// format"),
      ),
    ).toBe(true);
  });

  it("accepts multiple comma-separated rua destinations", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=TLSRPTv1; rua=mailto:a@example.com,https://example.com/report",
      ],
      raw: "v=TLSRPTv1; rua=mailto:a@example.com,https://example.com/report",
    });
    const result = await analyzeTlsRpt("example.com");
    expect(result.status).toBe("pass");
    expect(
      result.validations.some(
        (v) =>
          v.status === "info" &&
          v.message.includes("Report destinations") &&
          v.message.includes("a@example.com"),
      ),
    ).toBe(true);
  });

  it("is case-insensitive for v=TLSRPTv1", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["V=TLSRPTV1; rua=mailto:r@example.com"],
      raw: "V=TLSRPTV1; rua=mailto:r@example.com",
    });
    const result = await analyzeTlsRpt("example.com");
    expect(result.status).toBe("pass");
  });

  it("returns warn + lookup_error on SERVFAIL", async () => {
    mockQueryTxt.mockRejectedValue(
      new DnsLookupError("ESERVFAIL", "DNS server failure (SERVFAIL)"),
    );
    const result = await analyzeTlsRpt("example.com");
    expect(result.status).toBe("warn");
    expect(result.record).toBeNull();
    expect(result.tags).toBeNull();
    expect(result.lookup_error).toEqual({
      code: "ESERVFAIL",
      message: "DNS server failure (SERVFAIL)",
    });
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("ESERVFAIL"),
      ),
    ).toBe(true);
  });

  it("returns warn + lookup_error on DNS timeout", async () => {
    mockQueryTxt.mockRejectedValue(
      new DnsLookupError("DNS_TIMEOUT", "DNS query timed out"),
    );
    const result = await analyzeTlsRpt("example.com");
    expect(result.status).toBe("warn");
    expect(result.lookup_error?.code).toBe("DNS_TIMEOUT");
  });

  it("re-throws non-DnsLookupError errors", async () => {
    mockQueryTxt.mockRejectedValue(new Error("unexpected error"));
    await expect(analyzeTlsRpt("example.com")).rejects.toThrow(
      "unexpected error",
    );
  });

  it("returns info (no lookup_error) when record is absent (NXDOMAIN)", async () => {
    mockQueryTxt.mockResolvedValue(null);
    const result = await analyzeTlsRpt("example.com");
    expect(result.status).toBe("info");
    expect(result.lookup_error).toBeUndefined();
  });
});
