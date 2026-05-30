import { beforeEach, describe, expect, it, vi } from "vitest";
import { analyzeDnssec } from "../src/analyzers/dnssec.js";

vi.mock("../src/dns/client.js", () => ({
  queryDoh: vi.fn(),
  DnsLookupError: class DnsLookupError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(message);
      this.name = "DnsLookupError";
      this.code = code;
    }
  },
}));

import { DnsLookupError, queryDoh } from "../src/dns/client.js";

const mockQueryDoh = vi.mocked(queryDoh);

beforeEach(() => {
  vi.resetAllMocks();
});

describe("analyzeDnssec", () => {
  it("returns info when no DS records exist (unsigned zone)", async () => {
    mockQueryDoh.mockResolvedValue(null);
    const result = await analyzeDnssec("example.com");
    expect(result.status).toBe("info");
    expect(result.signed).toBe(false);
    expect(result.validated).toBe(false);
    expect(result.lookup_error).toBeUndefined();
    expect(
      result.validations.some(
        (v) =>
          v.status === "info" && v.message.includes("DNSSEC not configured"),
      ),
    ).toBe(true);
  });

  it("queries DS records for the domain", async () => {
    mockQueryDoh.mockResolvedValue(null);
    await analyzeDnssec("example.com");
    expect(mockQueryDoh).toHaveBeenCalledWith("example.com", "DS");
  });

  it("returns pass when DS records present and AD flag set", async () => {
    mockQueryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [
        { name: "example.com", type: 43, TTL: 3600, data: "12345 13 2 abc123" },
      ],
    });
    const result = await analyzeDnssec("example.com");
    expect(result.status).toBe("pass");
    expect(result.signed).toBe(true);
    expect(result.validated).toBe(true);
    expect(
      result.validations.some(
        (v) => v.status === "pass" && v.message.includes("AD flag"),
      ),
    ).toBe(true);
  });

  it("returns warn when DS records present but AD flag not set", async () => {
    mockQueryDoh.mockResolvedValue({
      Status: 0,
      AD: false,
      Answer: [
        { name: "example.com", type: 43, TTL: 3600, data: "12345 13 2 abc123" },
      ],
    });
    const result = await analyzeDnssec("example.com");
    expect(result.status).toBe("warn");
    expect(result.signed).toBe(true);
    expect(result.validated).toBe(false);
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("AD flag not set"),
      ),
    ).toBe(true);
  });

  it("returns fail + lookup_error on DnsLookupError", async () => {
    mockQueryDoh.mockRejectedValue(
      new DnsLookupError("ESERVFAIL", "DNS server failure (SERVFAIL)"),
    );
    const result = await analyzeDnssec("example.com");
    expect(result.status).toBe("fail");
    expect(result.signed).toBe(false);
    expect(result.validated).toBe(false);
    expect(result.lookup_error).toEqual({
      code: "ESERVFAIL",
      message: "DNS server failure (SERVFAIL)",
    });
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" && v.message.includes("DNSSEC lookup failed"),
      ),
    ).toBe(true);
  });

  it("returns fail + lookup_error on DNS timeout", async () => {
    mockQueryDoh.mockRejectedValue(
      new DnsLookupError("DNS_TIMEOUT", "DNS query timed out"),
    );
    const result = await analyzeDnssec("example.com");
    expect(result.status).toBe("fail");
    expect(result.lookup_error?.code).toBe("DNS_TIMEOUT");
  });

  it("re-throws non-DnsLookupError errors", async () => {
    mockQueryDoh.mockRejectedValue(new Error("unexpected network error"));
    await expect(analyzeDnssec("example.com")).rejects.toThrow(
      "unexpected network error",
    );
  });
});
