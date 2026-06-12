import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock the DNS client before importing analyzers
vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn(),
  queryMx: vi.fn(),
}));

import { analyzeDmarc } from "../src/analyzers/dmarc.js";
import { analyzeSpf } from "../src/analyzers/spf.js";
import { queryTxt } from "../src/dns/client.js";

const mockQueryTxt = vi.mocked(queryTxt);

beforeEach(() => {
  vi.resetAllMocks();
});

describe("analyzeDmarc", () => {
  it("returns fail when no record found", async () => {
    mockQueryTxt.mockResolvedValue(null);
    const result = await analyzeDmarc("example.com");
    expect(result.status).toBe("fail");
    expect(result.record).toBeNull();
    expect(result.validations[0].message).toContain("No DMARC record");
  });

  it("parses a valid DMARC record with reject policy", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject; rua=mailto:d@example.com; pct=100"],
      raw: "v=DMARC1; p=reject; rua=mailto:d@example.com; pct=100",
    });

    const result = await analyzeDmarc("example.com");
    expect(result.status).toBe("pass");
    expect(result.tags?.p).toBe("reject");
    expect(result.tags?.rua).toBe("mailto:d@example.com");
    expect(result.validations.some((v) => v.message.includes("reject"))).toBe(
      true,
    );
  });

  it("warns on p=none", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=none"],
      raw: "v=DMARC1; p=none",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "fail" && v.message.includes("none"),
      ),
    ).toBe(true);
  });

  it("warns when no rua configured", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject"],
      raw: "v=DMARC1; p=reject",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("rua"),
      ),
    ).toBe(true);
  });

  it("warns on partial pct", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject; pct=50"],
      raw: "v=DMARC1; p=reject; pct=50",
    });

    const result = await analyzeDmarc("example.com");
    expect(result.validations.some((v) => v.message.includes("50%"))).toBe(
      true,
    );
  });

  it("fails when TXT record exists but is not a valid DMARC record", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["some random text record"],
      raw: "some random text record",
    });

    const result = await analyzeDmarc("example.com");
    expect(result.status).toBe("fail");
    expect(
      result.validations.some((v) =>
        v.message.includes("not a valid DMARC record"),
      ),
    ).toBe(true);
  });

  it("fails when policy tag is missing", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; rua=mailto:d@example.com"],
      raw: "v=DMARC1; rua=mailto:d@example.com",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "fail" && v.message.includes("Missing policy tag"),
      ),
    ).toBe(true);
  });

  it("warns on quarantine policy", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=quarantine; rua=mailto:d@example.com"],
      raw: "v=DMARC1; p=quarantine; rua=mailto:d@example.com",
    });

    const result = await analyzeDmarc("example.com");
    expect(result.status).toBe("warn");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("quarantine"),
      ),
    ).toBe(true);
  });

  it("passes when subdomain policy (sp=) is present", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject; sp=quarantine"],
      raw: "v=DMARC1; p=reject; sp=quarantine",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "pass" && v.message.includes("Subdomain policy"),
      ),
    ).toBe(true);
  });

  it("passes when forensic reporting (ruf=) is configured", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject; ruf=mailto:forensic@example.com"],
      raw: "v=DMARC1; p=reject; ruf=mailto:forensic@example.com",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "pass" && v.message.includes("Forensic reporting"),
      ),
    ).toBe(true);
  });

  it("returns pass status when all validations pass", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject; rua=mailto:d@example.com; pct=100"],
      raw: "v=DMARC1; p=reject; rua=mailto:d@example.com; pct=100",
    });

    const result = await analyzeDmarc("example.com");
    expect(result.status).toBe("pass");
  });
});

describe("analyzeSpf", () => {
  it("returns fail when no record found", async () => {
    mockQueryTxt.mockResolvedValue(null);
    const result = await analyzeSpf("example.com");
    expect(result.status).toBe("fail");
    expect(result.record).toBeNull();
  });

  it("parses a simple SPF record", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=spf1 ip4:192.0.2.0/24 -all"],
      raw: "v=spf1 ip4:192.0.2.0/24 -all",
    });

    const result = await analyzeSpf("example.com");
    expect(result.status).toBe("pass");
    expect(result.lookups_used).toBe(0);
    expect(result.validations.some((v) => v.message.includes("hardfail"))).toBe(
      true,
    );
  });

  it("counts DNS lookup mechanisms", async () => {
    // First call: root domain
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=spf1 include:_spf.google.com mx a -all"],
      raw: "v=spf1 include:_spf.google.com mx a -all",
    });
    // Second call: _spf.google.com include
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=spf1 ip4:35.190.247.0/24 -all"],
      raw: "v=spf1 ip4:35.190.247.0/24 -all",
    });

    const result = await analyzeSpf("example.com");
    // include(1) + mx(1) + a(1) = 3
    expect(result.lookups_used).toBe(3);
  });

  it("warns on softfail ~all", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=spf1 ~all"],
      raw: "v=spf1 ~all",
    });

    const result = await analyzeSpf("example.com");
    expect(result.validations.some((v) => v.message.includes("softfail"))).toBe(
      true,
    );
  });

  it("fails on +all mechanism", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=spf1 +all"],
      raw: "v=spf1 +all",
    });

    const result = await analyzeSpf("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "fail" && v.message.includes("allows any sender"),
      ),
    ).toBe(true);
  });

  it("warns on ?all (neutral) mechanism", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=spf1 ?all"],
      raw: "v=spf1 ?all",
    });

    const result = await analyzeSpf("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("neutral"),
      ),
    ).toBe(true);
  });

  it("warns on deprecated ptr mechanism", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=spf1 ptr -all"],
      raw: "v=spf1 ptr -all",
    });

    const result = await analyzeSpf("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("deprecated ptr"),
      ),
    ).toBe(true);
  });

  it("reports no deprecated ptr when not present", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=spf1 ip4:192.0.2.0/24 -all"],
      raw: "v=spf1 ip4:192.0.2.0/24 -all",
    });

    const result = await analyzeSpf("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "pass" && v.message.includes("No deprecated ptr"),
      ),
    ).toBe(true);
  });

  it("fails when exceeding 10-lookup limit", async () => {
    // Create an SPF record with many include mechanisms
    const includes = Array.from(
      { length: 11 },
      (_, i) => `include:spf${i}.example.com`,
    ).join(" ");
    mockQueryTxt.mockResolvedValueOnce({
      entries: [`v=spf1 ${includes} -all`],
      raw: `v=spf1 ${includes} -all`,
    });
    // Each include lookup returns a simple record
    for (let i = 0; i < 11; i++) {
      mockQueryTxt.mockResolvedValueOnce({
        entries: ["v=spf1 ip4:10.0.0.1 -all"],
        raw: "v=spf1 ip4:10.0.0.1 -all",
      });
    }

    const result = await analyzeSpf("example.com");
    expect(result.lookups_used).toBeGreaterThan(10);
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" && v.message.includes("Exceeds 10-lookup limit"),
      ),
    ).toBe(true);
    const overLimit = result.validations.find((v) =>
      v.message.includes("Exceeds 10-lookup limit"),
    );
    expect(overLimit?.learnAnchor).toBe("/learn/spf#lookup-limit");
  });

  it("handles redirect modifier", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=spf1 redirect=_spf.example.com"],
      raw: "v=spf1 redirect=_spf.example.com",
    });
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=spf1 ip4:192.0.2.0/24 -all"],
      raw: "v=spf1 ip4:192.0.2.0/24 -all",
    });

    const result = await analyzeSpf("example.com");
    expect(result.status).not.toBe("fail");
    expect(result.include_tree?.includes.length).toBeGreaterThan(0);
  });

  it("handles bare v=spf1 record", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=spf1"],
      raw: "v=spf1",
    });

    const result = await analyzeSpf("example.com");
    expect(result.status).not.toBe("fail");
    expect(result.record).toBe("v=spf1");
  });

  it("detects circular self-include and reports permerror", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "pcsnc.us") {
        return {
          entries: ["v=spf1 include:pcsnc.us include:_spf.google.com ~all"],
          raw: "v=spf1 include:pcsnc.us include:_spf.google.com ~all",
        };
      }
      if (name === "_spf.google.com") {
        return {
          entries: ["v=spf1 ip4:35.190.247.0/24 -all"],
          raw: "v=spf1 ip4:35.190.247.0/24 -all",
        };
      }
      return null;
    });

    const result = await analyzeSpf("pcsnc.us");
    expect(result.status).toBe("fail");
    expect(
      result.validations.some(
        (v) => v.status === "fail" && v.message.includes("Circular include"),
      ),
    ).toBe(true);
    // include:pcsnc.us(1) + include:_spf.google.com(1) = 2
    expect(result.lookups_used).toBe(2);
  });

  it("detects indirect circular include (A -> B -> A)", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "a.example.com") {
        return {
          entries: ["v=spf1 include:b.example.com -all"],
          raw: "v=spf1 include:b.example.com -all",
        };
      }
      if (name === "b.example.com") {
        return {
          entries: ["v=spf1 include:a.example.com -all"],
          raw: "v=spf1 include:a.example.com -all",
        };
      }
      return null;
    });

    const result = await analyzeSpf("a.example.com");
    expect(result.status).toBe("fail");
    expect(
      result.validations.some(
        (v) => v.status === "fail" && v.message.includes("Circular include"),
      ),
    ).toBe(true);
    // a includes b(1), b includes a(1) but cycle stops = 2
    expect(result.lookups_used).toBe(2);
  });

  it("fails with permerror when multiple SPF records are published (RFC 7208 §4.5)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=spf1 ip4:192.0.2.0/24 -all",
        "v=spf1 ip4:198.51.100.0/24 ~all",
      ],
      raw: "v=spf1 ip4:192.0.2.0/24 -all",
    });

    const result = await analyzeSpf("example.com");
    expect(result.status).toBe("fail");
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" && v.message.includes("Multiple SPF records"),
      ),
    ).toBe(true);
  });

  it("does not flag multiple-record permerror for a single record", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=spf1 ip4:192.0.2.0/24 -all"],
      raw: "v=spf1 ip4:192.0.2.0/24 -all",
    });

    const result = await analyzeSpf("example.com");
    expect(
      result.validations.some((v) =>
        v.message.includes("Multiple SPF records"),
      ),
    ).toBe(false);
  });

  it("fails with permerror when more than 2 void lookups occur (RFC 7208 §4.6.4)", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "example.com") {
        return {
          entries: [
            "v=spf1 include:a.void.test include:b.void.test include:c.void.test -all",
          ],
          raw: "v=spf1 include:a.void.test include:b.void.test include:c.void.test -all",
        };
      }
      // Every include target resolves to NXDOMAIN/NODATA → void lookup.
      return null;
    });

    const result = await analyzeSpf("example.com");
    expect(result.status).toBe("fail");
    expect(
      result.validations.some(
        (v) => v.status === "fail" && v.message.includes("void"),
      ),
    ).toBe(true);
  });

  it("does not flag a void-lookup permerror at or below 2 void lookups", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "example.com") {
        return {
          entries: ["v=spf1 include:a.void.test include:b.void.test -all"],
          raw: "v=spf1 include:a.void.test include:b.void.test -all",
        };
      }
      return null;
    });

    const result = await analyzeSpf("example.com");
    expect(result.validations.some((v) => v.message.includes("void"))).toBe(
      false,
    );
  });

  it("fails when a typo'd mechanism is present (RFC 7208 §4.6.1 unknown term)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=spf1 inculde:spf.google.com -all"],
      raw: "v=spf1 inculde:spf.google.com -all",
    });

    const result = await analyzeSpf("example.com");
    expect(result.status).toBe("fail");
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" &&
          v.message.includes("Unknown") &&
          v.message.includes("inculde:spf.google.com"),
      ),
    ).toBe(true);
  });

  it("flags multiple unknown terms in a single validation (RFC 7208 §4.6.1)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=spf1 inculde:a.example.com somejunk -all"],
      raw: "v=spf1 inculde:a.example.com somejunk -all",
    });

    const result = await analyzeSpf("example.com");
    expect(result.status).toBe("fail");
    const unknownValidation = result.validations.find(
      (v) => v.status === "fail" && v.message.includes("Unknown"),
    );
    expect(unknownValidation?.message).toContain("inculde:a.example.com");
    expect(unknownValidation?.message).toContain("somejunk");
  });

  it("does not flag unknown terms for a clean record with all known mechanisms", async () => {
    mockQueryTxt.mockResolvedValueOnce({
      entries: [
        "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx include:_spf.example.com ~all",
      ],
      raw: "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx include:_spf.example.com ~all",
    });
    mockQueryTxt.mockResolvedValueOnce({
      entries: ["v=spf1 ip4:203.0.113.0/24 -all"],
      raw: "v=spf1 ip4:203.0.113.0/24 -all",
    });

    const result = await analyzeSpf("example.com");
    expect(result.validations.some((v) => v.message.includes("Unknown"))).toBe(
      false,
    );
  });
});
