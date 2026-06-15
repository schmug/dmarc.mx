import { beforeEach, describe, expect, it, vi } from "vitest";
import { analyzeDane } from "../src/analyzers/dane.js";

// Mock the DNS client's queryDoh function
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

const { queryDoh, DnsLookupError } = (await import("../src/dns/client.js")) as {
  queryDoh: ReturnType<typeof vi.fn>;
  DnsLookupError: new (
    code: string,
    message: string,
  ) => Error & { code: string };
};

function makeTlsaAnswer(data: string) {
  return { name: "_25._tcp.mx.example.com.", type: 52, TTL: 300, data };
}

describe("analyzeDane — no MX records", () => {
  it("returns info when mxExchanges is empty", async () => {
    const result = await analyzeDane("example.com", []);
    expect(result.status).toBe("info");
    expect(result.hosts).toHaveLength(0);
    expect(result.validations[0].message).toMatch(/no MX records/i);
  });
});

describe("analyzeDane — no TLSA records", () => {
  beforeEach(() => {
    queryDoh.mockResolvedValue(null);
  });

  it("returns info when no TLSA records exist", async () => {
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.status).toBe("info");
    expect(result.hosts).toHaveLength(1);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.validations[0].message).toMatch(/not configured/i);
  });

  it("queries _25._tcp.<exchange> for each MX host", async () => {
    await analyzeDane("example.com", ["mx1.example.com", "mx2.example.com"]);
    // URL-parse-safe: check the full name, not a substring. Trailing
    // `undefined` is the optional per-scan ScanBudget (unset in unit tests).
    expect(queryDoh).toHaveBeenCalledWith(
      "_25._tcp.mx1.example.com",
      "TLSA",
      undefined,
    );
    expect(queryDoh).toHaveBeenCalledWith(
      "_25._tcp.mx2.example.com",
      "TLSA",
      undefined,
    );
  });
});

describe("analyzeDane — TLSA with DNSSEC validated (pass)", () => {
  beforeEach(() => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("3 1 1 abcdef1234")],
    });
  });

  it("returns pass when TLSA present and AD=true", async () => {
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.status).toBe("pass");
    expect(result.hosts[0].tlsaRecords).toHaveLength(1);
    expect(result.hosts[0].dnssecValidated).toBe(true);
  });

  it("parses TLSA record fields correctly", async () => {
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    const record = result.hosts[0].tlsaRecords[0];
    expect(record.usage).toBe(3);
    expect(record.selector).toBe(1);
    expect(record.matchingType).toBe(1);
    expect(record.data).toBe("abcdef1234");
  });

  it("includes validated host in pass validation message", async () => {
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.validations[0].status).toBe("pass");
    expect(result.validations[0].message).toMatch(/mx\.example\.com/);
  });
});

describe("analyzeDane — TLSA without DNSSEC (warn)", () => {
  beforeEach(() => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: false,
      Answer: [makeTlsaAnswer("3 1 1 abcdef1234")],
    });
  });

  it("returns warn when TLSA present but AD=false", async () => {
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.status).toBe("warn");
    expect(result.hosts[0].tlsaRecords).toHaveLength(1);
    expect(result.hosts[0].dnssecValidated).toBe(false);
  });

  it("validation message explains DNSSEC requirement", async () => {
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.validations[0].status).toBe("warn");
    expect(result.validations[0].message).toMatch(/DNSSEC/i);
  });
});

describe("analyzeDane — lookup error", () => {
  it("returns fail with lookup_error when all queries fail", async () => {
    queryDoh.mockRejectedValue(
      new DnsLookupError("ESERVFAIL", "DNS server failure (SERVFAIL)"),
    );
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.status).toBe("fail");
    expect(result.lookup_error).toBeDefined();
    expect(result.lookup_error?.code).toBe("ESERVFAIL");
  });

  it("returns info when some queries succeed with no TLSA and others fail", async () => {
    queryDoh
      .mockResolvedValueOnce(null) // mx1 — no TLSA
      .mockRejectedValueOnce(
        new DnsLookupError("ESERVFAIL", "DNS server failure"),
      ); // mx2 — error
    const result = await analyzeDane("example.com", [
      "mx1.example.com",
      "mx2.example.com",
    ]);
    // At least one query succeeded (returned null = no TLSA), so status is info not fail
    expect(result.status).toBe("info");
  });
});

describe("analyzeDane — Cloudflare DoH generic (RFC 3597) TLSA format", () => {
  // Cloudflare's DoH JSON API returns TLSA rdata in RFC 3597 generic format
  // ("\# <rdlength> <hex bytes>") rather than the "<usage> <selector>
  // <matching-type> <hex>" presentation format. These fixtures are the actual
  // records published for dmarc.mx's MX hosts (_25._tcp.route1.mx.cloudflare.net).
  beforeEach(() => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [
        makeTlsaAnswer(
          "\\# 35 02 01 01 59 e7 38 e6 74 22 17 02 af 1e db 87 c5 20 0c 1a 4b 75 f6 4f ae 3d 2c 3d 26 51 24 c6 1b d8 3c 79",
        ),
        makeTlsaAnswer(
          "\\# 35 03 01 01 0f 0c 6c 16 4a 36 f9 7e 7b 4c 5a 5b 69 d6 f4 f2 39 d4 22 fc 3e c2 59 20 72 ec fa b8 c2 71 c4 52",
        ),
      ],
    });
  });

  it("parses generic-format TLSA records instead of dropping them", async () => {
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.status).toBe("pass");
    expect(result.hosts[0].tlsaRecords).toHaveLength(2);
    expect(result.hosts[0].dnssecValidated).toBe(true);
  });

  it("decodes usage/selector/matching-type/data from the hex octets", async () => {
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    const [ta, ee] = result.hosts[0].tlsaRecords;
    // First record: DANE-TA (usage 2), SPKI selector (1), SHA-256 (1)
    expect(ta.usage).toBe(2);
    expect(ta.selector).toBe(1);
    expect(ta.matchingType).toBe(1);
    expect(ta.data).toBe(
      "59e738e674221702af1edb87c5200c1a4b75f64fae3d2c3d265124c61bd83c79",
    );
    // Second record: DANE-EE (usage 3)
    expect(ee.usage).toBe(3);
    expect(ee.selector).toBe(1);
    expect(ee.matchingType).toBe(1);
    expect(ee.data).toBe(
      "0f0c6c164a36f97e7b4c5a5b69d6f4f239d422fc3ec2592072ecfab8c271c452",
    );
  });
});

describe("analyzeDane — malformed generic-format TLSA", () => {
  it("drops a non-hex generic record and reports not configured", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("\\# 4 zz zz")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.status).toBe("info");
  });

  it("drops a truncated generic record shorter than the 3-octet header", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("\\# 1 03")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.status).toBe("info");
  });
});

describe("analyzeDane — mixed validated and unvalidated", () => {
  it("returns pass with warn validation when one host is validated and another is not", async () => {
    queryDoh
      .mockResolvedValueOnce({
        Status: 0,
        AD: true,
        Answer: [makeTlsaAnswer("3 1 1 aabbcc")],
      }) // mx1 — DNSSEC validated
      .mockResolvedValueOnce({
        Status: 0,
        AD: false,
        Answer: [makeTlsaAnswer("3 1 1 ddeeff")],
      }); // mx2 — not validated
    const result = await analyzeDane("example.com", [
      "mx1.example.com",
      "mx2.example.com",
    ]);
    expect(result.status).toBe("pass");
    const warnValidation = result.validations.find((v) => v.status === "warn");
    expect(warnValidation).toBeDefined();
    expect(warnValidation?.message).toMatch(/mx2\.example\.com/);
  });
});
