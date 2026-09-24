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

// RFC 6698 §2.1: matching type 1 is SHA-256 (32 octets / 64 hex chars).
const VALID_SHA256 = "ab".repeat(32);
// Matching type 2 is SHA-512 (64 octets / 128 hex chars).
const VALID_SHA512 = "ab".repeat(64);

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
      Answer: [makeTlsaAnswer(`3 1 1 ${VALID_SHA256}`)],
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
    expect(record.data).toBe(VALID_SHA256);
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
      Answer: [makeTlsaAnswer(`3 1 1 ${VALID_SHA256}`)],
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

  it("accepts a generic record whose RDLENGTH matches the hex octet count", async () => {
    // 4 octets: usage, selector, matching-type (0, exact match — no fixed
    // association-data length), 1 data byte. RDLENGTH=4 matches.
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("\\# 4 03 01 00 0f")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(1);
    expect(result.hosts[0].tlsaRecords[0]).toMatchObject({
      usage: 3,
      selector: 1,
      matchingType: 0,
      data: "0f",
    });
    expect(result.status).toBe("pass");
  });

  it("drops a generic record whose hex octets are truncated relative to RDLENGTH", async () => {
    // RDLENGTH claims 35 octets (as in the real Cloudflare fixture above) but
    // only 4 octets of hex are actually present — RFC 3597 §5 requires these
    // to match, so this must be rejected rather than decoded as a short record.
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("\\# 35 03 01 01 0f")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.status).toBe("info");
  });

  it("drops a generic record whose hex octets exceed RDLENGTH", async () => {
    // RDLENGTH claims only 4 octets but more hex data is present than declared.
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("\\# 4 03 01 01 0f 0c 6c")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.status).toBe("info");
  });
});

describe("analyzeDane — presentation-format field range validation", () => {
  it("accepts a valid record (usage 3, selector 1, matching type 1)", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer(`3 1 1 ${VALID_SHA256}`)],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(1);
    expect(result.hosts[0].tlsaRecords[0]).toMatchObject({
      usage: 3,
      selector: 1,
      matchingType: 1,
    });
    expect(result.status).toBe("pass");
  });

  it("drops a record with trailing garbage on the usage token (3x)", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("3x 1 1 abcdef1234")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.status).toBe("info");
  });

  it("drops a record with an out-of-range usage (9)", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("9 1 1 abcdef1234")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.status).toBe("info");
  });

  it("drops a record with an out-of-range selector (7)", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("3 7 1 abcdef1234")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.status).toBe("info");
  });

  it("drops a record with an out-of-range matching type (8)", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("3 1 8 abcdef1234")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.status).toBe("info");
  });

  it("drops a record with a negative field", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("-1 1 1 abcdef1234")],
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
        Answer: [makeTlsaAnswer(`3 1 1 ${VALID_SHA256}`)],
      }) // mx1 — DNSSEC validated
      .mockResolvedValueOnce({
        Status: 0,
        AD: false,
        Answer: [makeTlsaAnswer(`3 1 1 ${VALID_SHA256}`)],
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

describe("analyzeDane — association data hex/length validation (RFC 6698 §2.1)", () => {
  it("drops a matching-type-1 record with non-hex association data", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("3 1 1 zz")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.status).toBe("info");
  });

  it("drops a matching-type-1 (SHA-256) record shorter than 32 octets", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("3 1 1 abcdef1234")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.status).toBe("info");
  });

  it("accepts a matching-type-1 record with a correct 32-octet SHA-256", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer(`3 1 1 ${VALID_SHA256}`)],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(1);
    expect(result.hosts[0].tlsaRecords[0].data).toBe(VALID_SHA256);
    expect(result.status).toBe("pass");
  });

  it("accepts a matching-type-2 record with a correct 64-octet SHA-512", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer(`3 1 2 ${VALID_SHA512}`)],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(1);
    expect(result.hosts[0].tlsaRecords[0].data).toBe(VALID_SHA512);
    expect(result.status).toBe("pass");
  });

  it("drops a matching-type-2 (SHA-512) record shorter than 64 octets", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer(`3 1 2 ${VALID_SHA256}`)],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.status).toBe("info");
  });

  it("accepts a matching-type-0 (exact match) record of any length", async () => {
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("3 1 0 aa")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(1);
    expect(result.hosts[0].tlsaRecords[0]).toMatchObject({
      matchingType: 0,
      data: "aa",
    });
    expect(result.status).toBe("pass");
  });

  it("drops a generic-format (RFC 3597) matching-type-1 record shorter than 32 octets", async () => {
    // usage=3, selector=1, matchingType=1, 1-octet association data — 4
    // octets total, RDLENGTH matches, but the SHA-256 length check must
    // still reject it.
    queryDoh.mockResolvedValue({
      Status: 0,
      AD: true,
      Answer: [makeTlsaAnswer("\\# 4 03 01 01 0f")],
    });
    const result = await analyzeDane("example.com", ["mx.example.com"]);
    expect(result.hosts[0].tlsaRecords).toHaveLength(0);
    expect(result.status).toBe("info");
  });
});
