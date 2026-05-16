import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn(),
  queryMx: vi.fn(),
  DnsLookupError: class DnsLookupError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(message);
      this.code = code;
    }
  },
}));

import { analyzeTlsRpt } from "../src/analyzers/tls-rpt.js";
import { queryTxt } from "../src/dns/client.js";

const mockQueryTxt = vi.mocked(queryTxt);

beforeEach(() => {
  vi.resetAllMocks();
});

describe("analyzeTlsRpt — no record", () => {
  it("returns fail status when no TXT record at _smtp._tls", async () => {
    mockQueryTxt.mockResolvedValueOnce(null);

    const result = await analyzeTlsRpt("example.com");

    expect(result.status).toBe("fail");
    expect(result.record).toBeNull();
    expect(result.tags).toBeNull();
    expect(result.validations.some((v) => v.status === "fail")).toBe(true);
    expect(mockQueryTxt).toHaveBeenCalledWith("_smtp._tls.example.com");
  });

  it("returns fail when TXT record exists but has no v=TLSRPTv1", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=spf1 include:example.com -all"],
      raw: "v=spf1 include:example.com -all",
    });

    const result = await analyzeTlsRpt("example.com");

    expect(result.status).toBe("fail");
    expect(
      result.validations.some(
        (v) => v.status === "fail" && v.message.includes("v=TLSRPTv1"),
      ),
    ).toBe(true);
  });
});

describe("analyzeTlsRpt — valid record", () => {
  it("returns pass status for a well-formed v=TLSRPTv1 record with rua", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=TLSRPTv1; rua=mailto:reports@example.com"],
      raw: "v=TLSRPTv1; rua=mailto:reports@example.com",
    });

    const result = await analyzeTlsRpt("example.com");

    expect(result.status).toBe("pass");
    expect(result.record).toBe("v=TLSRPTv1; rua=mailto:reports@example.com");
    expect(result.tags?.rua).toBe("mailto:reports@example.com");
    expect(result.validations.some((v) => v.status === "pass")).toBe(true);
  });

  it("returns pass for https:// rua destination", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=TLSRPTv1; rua=https://example.com/tls-report"],
      raw: "v=TLSRPTv1; rua=https://example.com/tls-report",
    });

    const result = await analyzeTlsRpt("example.com");

    expect(result.status).toBe("pass");
  });

  it("returns pass for multiple rua destinations", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: [
        "v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://report.example.com/tls",
      ],
      raw: "v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://report.example.com/tls",
    });

    const result = await analyzeTlsRpt("example.com");

    expect(result.status).toBe("pass");
    expect(
      result.validations.some(
        (v) =>
          v.status === "pass" && v.message.includes("2 reporting destination"),
      ),
    ).toBe(true);
  });
});

describe("analyzeTlsRpt — warnings", () => {
  it("warns when multiple TLS-RPT records are present", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: [
        "v=TLSRPTv1; rua=mailto:a@example.com",
        "v=TLSRPTv1; rua=mailto:b@example.com",
      ],
      raw: "v=TLSRPTv1; rua=mailto:a@example.com",
    });

    const result = await analyzeTlsRpt("example.com");

    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("Multiple TLS-RPT"),
      ),
    ).toBe(true);
  });

  it("warns when unrelated TXT records exist at _smtp._tls", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: [
        "v=TLSRPTv1; rua=mailto:reports@example.com",
        "some unrelated record",
      ],
      raw: "v=TLSRPTv1; rua=mailto:reports@example.com",
    });

    const result = await analyzeTlsRpt("example.com");

    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("unrelated TXT"),
      ),
    ).toBe(true);
  });

  it("warns when rua= tag is missing", async () => {
    mockQueryTxt.mockResolvedValueOnce({
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

  it("warns when rua= contains a malformed URI (not mailto: or https://)", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=TLSRPTv1; rua=ftp://invalid.example.com"],
      raw: "v=TLSRPTv1; rua=ftp://invalid.example.com",
    });

    const result = await analyzeTlsRpt("example.com");

    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("malformed"),
      ),
    ).toBe(true);
  });
});
