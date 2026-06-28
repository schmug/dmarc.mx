import { beforeEach, describe, expect, it, vi } from "vitest";
import { analyzeDnsbl } from "../src/analyzers/dnsbl.js";
import type { MxResult, SpfResult } from "../src/analyzers/types.js";

vi.mock("../src/dns/client.js", () => ({
  queryDoh: vi.fn(),
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

vi.mock("@sentry/cloudflare", () => ({
  addBreadcrumb: vi.fn(),
  captureException: vi.fn(),
}));

const { queryDoh, DnsLookupError } = (await import("../src/dns/client.js")) as {
  queryDoh: ReturnType<typeof vi.fn>;
  DnsLookupError: new (
    code: string,
    message: string,
  ) => Error & { code: string };
};

const MX_RESULT: MxResult = {
  status: "info",
  records: [{ priority: 10, exchange: "mx.example.com" }],
  providers: [],
  validations: [],
};

const SPF_RESULT: SpfResult = {
  status: "pass",
  record: "v=spf1 ip4:1.2.3.4 -all",
  lookups_used: 0,
  lookup_limit: 10,
  include_tree: {
    domain: "example.com",
    record: "v=spf1 ip4:1.2.3.4 -all",
    mechanisms: ["ip4:1.2.3.4", "-all"],
    includes: [],
  },
  validations: [],
};

const EMPTY_MX: MxResult = {
  status: "info",
  records: [],
  providers: [],
  validations: [],
};

const EMPTY_SPF: SpfResult = {
  status: "pass",
  record: "v=spf1 -all",
  lookups_used: 0,
  lookup_limit: 10,
  include_tree: {
    domain: "example.com",
    record: "v=spf1 -all",
    mechanisms: ["-all"],
    includes: [],
  },
  validations: [],
};

beforeEach(() => {
  queryDoh.mockReset();
});

describe("analyzeDnsbl — no DQS key", () => {
  it("returns info with not-configured message when key is absent", async () => {
    const result = await analyzeDnsbl(
      "example.com",
      MX_RESULT,
      SPF_RESULT,
      undefined,
    );
    expect(result.status).toBe("info");
    expect(result.checked).toBe(0);
    expect(result.listed).toHaveLength(0);
    expect(result.validations[0].message).toMatch(/not configured/i);
    expect(queryDoh).not.toHaveBeenCalled();
  });
});

describe("analyzeDnsbl — no derivable IPs", () => {
  it("returns info when SPF has no IPs and MX resolution yields none", async () => {
    // MX A-record resolution returns nothing
    queryDoh.mockResolvedValue(null);
    const result = await analyzeDnsbl(
      "example.com",
      EMPTY_MX,
      EMPTY_SPF,
      "testkey",
    );
    expect(result.status).toBe("info");
    expect(result.checked).toBe(0);
    expect(result.validations[0].message).toMatch(/no sending IPs/i);
  });
});

describe("analyzeDnsbl — clean IPs (pass)", () => {
  it("returns pass when DNSBL query returns null (NXDOMAIN)", async () => {
    // MX A-record lookup returns nothing; SPF has 1.2.3.4
    queryDoh.mockImplementation((name: string) => {
      if (name === "mx.example.com") return Promise.resolve(null);
      // DNSBL lookup → NXDOMAIN = not listed
      return Promise.resolve(null);
    });
    const result = await analyzeDnsbl(
      "example.com",
      MX_RESULT,
      SPF_RESULT,
      "testkey",
    );
    expect(result.status).toBe("pass");
    expect(result.checked).toBeGreaterThan(0);
    expect(result.listed).toHaveLength(0);
    expect(result.validations[0].message).toMatch(/none listed/i);
  });
});

describe("analyzeDnsbl — listed IP (warn)", () => {
  it("returns warn with listing details when an IP is on Spamhaus ZEN", async () => {
    queryDoh.mockImplementation((name: string) => {
      if (name === "mx.example.com") return Promise.resolve(null);
      // DNSBL listing response for 4.3.2.1.testkey.zen.dq.spamhaus.net
      return Promise.resolve({
        Status: 0,
        AD: false,
        Answer: [{ name, type: 1, TTL: 300, data: "127.0.0.2" }],
      });
    });
    const result = await analyzeDnsbl(
      "example.com",
      MX_RESULT,
      SPF_RESULT,
      "testkey",
    );
    expect(result.status).toBe("warn");
    expect(result.listed).toHaveLength(1);
    expect(result.listed[0].ip).toBe("1.2.3.4");
    expect(result.listed[0].zones).toContain("zen");
    expect(result.validations[0].message).toMatch(/spamhaus zen/i);
  });
});

describe("analyzeDnsbl — DnsLookupError degradation", () => {
  it("returns warn with lookup_error when DNSBL query throws DnsLookupError", async () => {
    queryDoh.mockImplementation((name: string) => {
      if (name === "mx.example.com") return Promise.resolve(null);
      return Promise.reject(
        new DnsLookupError("ESERVFAIL", "DNS server failure (SERVFAIL)"),
      );
    });
    const result = await analyzeDnsbl(
      "example.com",
      MX_RESULT,
      SPF_RESULT,
      "testkey",
    );
    expect(result.status).toBe("warn");
    expect(result.lookup_error).toBeDefined();
    expect(result.lookup_error?.code).toBe("ESERVFAIL");
    expect(result.validations[0].message).toMatch(/could not verify/i);
  });
});

describe("analyzeDnsbl — IP cap enforcement", () => {
  it("checks at most 10 IPs even when SPF declares more", async () => {
    // Build SPF with 20 ip4 mechanisms
    const mechanisms = Array.from(
      { length: 20 },
      (_, i) => `ip4:10.0.0.${i + 1}`,
    );
    const spfResult: SpfResult = {
      status: "pass",
      record: `v=spf1 ${mechanisms.join(" ")} -all`,
      lookups_used: 0,
      lookup_limit: 10,
      include_tree: {
        domain: "example.com",
        record: "",
        mechanisms: [...mechanisms, "-all"],
        includes: [],
      },
      validations: [],
    };
    // All DNSBL lookups return clean (null)
    queryDoh.mockResolvedValue(null);
    const result = await analyzeDnsbl(
      "example.com",
      EMPTY_MX,
      spfResult,
      "testkey",
    );
    // At most 10 IPs checked despite 20 available
    expect(result.checked).toBeLessThanOrEqual(10);
    expect(result.status).toBe("pass");
  });
});

describe("analyzeDnsbl — IPv6 reversal", () => {
  it("handles IPv6 IPs from SPF ip6 mechanisms", async () => {
    const spfResult: SpfResult = {
      status: "pass",
      record: "v=spf1 ip6:2001:db8::1 -all",
      lookups_used: 0,
      lookup_limit: 10,
      include_tree: {
        domain: "example.com",
        record: "",
        mechanisms: ["ip6:2001:db8::1", "-all"],
        includes: [],
      },
      validations: [],
    };
    queryDoh.mockResolvedValue(null);
    const result = await analyzeDnsbl(
      "example.com",
      EMPTY_MX,
      spfResult,
      "testkey",
    );
    expect(result.status).toBe("pass");
    expect(result.checked).toBe(1);
  });
});

describe("analyzeDnsbl — MX A-record resolution adds IPs", () => {
  it("resolves MX hostnames and checks those IPs too", async () => {
    queryDoh.mockImplementation((name: string) => {
      if (name === "mx.example.com") {
        return Promise.resolve({
          Status: 0,
          AD: false,
          Answer: [{ name, type: 1, TTL: 300, data: "5.6.7.8" }],
        });
      }
      // DNSBL lookup → clean
      return Promise.resolve(null);
    });
    const spfNoIps: SpfResult = {
      ...EMPTY_SPF,
      include_tree: {
        domain: "example.com",
        record: "v=spf1 -all",
        mechanisms: ["-all"],
        includes: [],
      },
    };
    const result = await analyzeDnsbl(
      "example.com",
      MX_RESULT,
      spfNoIps,
      "testkey",
    );
    // 5.6.7.8 was derived from MX A-record resolution
    expect(result.checked).toBe(1);
    expect(result.status).toBe("pass");
  });
});
