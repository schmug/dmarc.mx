import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock the DNS client before importing analyzers
vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn(),
  queryMx: vi.fn(),
}));

import { analyzeDmarc } from "../src/analyzers/dmarc.js";
import { queryTxt } from "../src/dns/client.js";

const mockQueryTxt = vi.mocked(queryTxt);

beforeEach(() => {
  vi.resetAllMocks();
});

// ---------------------------------------------------------------------------
// rua= external authorization checks (RFC 7489 §7.1)
// ---------------------------------------------------------------------------

describe("analyzeDmarc – rua external authorization", () => {
  it("does not warn when rua mailto is on the same domain", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "_dmarc.example.com") {
        return {
          entries: ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
          raw: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        };
      }
      return null;
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("report authorization record"),
      ),
    ).toBe(false);
  });

  it("warns when rua mailto is on a different domain and has no auth record", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "_dmarc.example.com") {
        return {
          entries: ["v=DMARC1; p=reject; rua=mailto:reports@thirdparty.com"],
          raw: "v=DMARC1; p=reject; rua=mailto:reports@thirdparty.com",
        };
      }
      // _report._dmarc.thirdparty.com → NXDOMAIN (not authorized)
      if (name === "_report._dmarc.thirdparty.com") {
        return null;
      }
      return null;
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("thirdparty.com") &&
          v.message.includes("report authorization record"),
      ),
    ).toBe(true);
  });

  it("does not warn when rua external domain has a valid auth record", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "_dmarc.example.com") {
        return {
          entries: ["v=DMARC1; p=reject; rua=mailto:reports@thirdparty.com"],
          raw: "v=DMARC1; p=reject; rua=mailto:reports@thirdparty.com",
        };
      }
      if (name === "_report._dmarc.thirdparty.com") {
        return {
          entries: ["v=DMARC1"],
          raw: "v=DMARC1",
        };
      }
      return null;
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("report authorization record"),
      ),
    ).toBe(false);
  });

  it("warns for each unauthorized rua destination in a multi-URI list", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "_dmarc.example.com") {
        return {
          entries: [
            "v=DMARC1; p=reject; rua=mailto:a@vendor1.com,mailto:b@vendor2.com",
          ],
          raw: "v=DMARC1; p=reject; rua=mailto:a@vendor1.com,mailto:b@vendor2.com",
        };
      }
      // vendor1 is authorized, vendor2 is not
      if (name === "_report._dmarc.vendor1.com") {
        return { entries: ["v=DMARC1"], raw: "v=DMARC1" };
      }
      if (name === "_report._dmarc.vendor2.com") {
        return null;
      }
      return null;
    });

    const result = await analyzeDmarc("example.com");
    const authWarnings = result.validations.filter(
      (v) =>
        v.status === "warn" &&
        v.message.includes("report authorization record"),
    );
    expect(authWarnings).toHaveLength(1);
    expect(authWarnings[0].message).toContain("vendor2.com");
  });
});

// ---------------------------------------------------------------------------
// ruf= external authorization checks
// ---------------------------------------------------------------------------

describe("analyzeDmarc – ruf external authorization", () => {
  it("warns when ruf mailto is on a different domain without auth record", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "_dmarc.example.com") {
        return {
          entries: [
            "v=DMARC1; p=reject; rua=mailto:rua@example.com; ruf=mailto:forensic@external.org",
          ],
          raw: "v=DMARC1; p=reject; rua=mailto:rua@example.com; ruf=mailto:forensic@external.org",
        };
      }
      if (name === "_report._dmarc.external.org") {
        return null;
      }
      return null;
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("external.org") &&
          v.message.includes("report authorization record"),
      ),
    ).toBe(true);
  });

  it("does not warn when ruf external domain has a valid auth record", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "_dmarc.example.com") {
        return {
          entries: [
            "v=DMARC1; p=reject; rua=mailto:rua@example.com; ruf=mailto:forensic@external.org",
          ],
          raw: "v=DMARC1; p=reject; rua=mailto:rua@example.com; ruf=mailto:forensic@external.org",
        };
      }
      if (name === "_report._dmarc.external.org") {
        return { entries: ["v=DMARC1"], raw: "v=DMARC1" };
      }
      return null;
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("report authorization record"),
      ),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// pct= warnings
// ---------------------------------------------------------------------------

describe("analyzeDmarc – pct warnings", () => {
  it("warns with specific message when pct=0", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject; rua=mailto:d@example.com; pct=0"],
      raw: "v=DMARC1; p=reject; rua=mailto:d@example.com; pct=0",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("pct=0") &&
          v.message.includes("policy is effectively disabled"),
      ),
    ).toBe(true);
  });

  it("warns when pct is between 1 and 99", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject; rua=mailto:d@example.com; pct=75"],
      raw: "v=DMARC1; p=reject; rua=mailto:d@example.com; pct=75",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("75%"),
      ),
    ).toBe(true);
  });

  it("does not warn when pct=100", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject; rua=mailto:d@example.com; pct=100"],
      raw: "v=DMARC1; p=reject; rua=mailto:d@example.com; pct=100",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.match(/pct|%/),
      ),
    ).toBe(false);
  });

  it("does not warn about pct when tag is absent (default is 100)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
      raw: "v=DMARC1; p=reject; rua=mailto:d@example.com",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.match(/pct|%/),
      ),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// sp= warnings (sp=none weakens subdomain enforcement)
// ---------------------------------------------------------------------------

describe("analyzeDmarc – sp=none weakening subdomain enforcement", () => {
  it("warns when sp=none and p=reject", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"],
      raw: "v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("sp=none") &&
          v.message.includes("subdomain"),
      ),
    ).toBe(true);
  });

  it("warns when sp=none and p=quarantine", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=quarantine; sp=none; rua=mailto:d@example.com"],
      raw: "v=DMARC1; p=quarantine; sp=none; rua=mailto:d@example.com",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("sp=none") &&
          v.message.includes("subdomain"),
      ),
    ).toBe(true);
  });

  it("does not warn when sp=none and p=none (sp matches parent, no weakening)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=none; sp=none; rua=mailto:d@example.com"],
      raw: "v=DMARC1; p=none; sp=none; rua=mailto:d@example.com",
    });

    const result = await analyzeDmarc("example.com");
    // sp=none with p=none is not a weakening (parent is also none)
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("sp=none") &&
          v.message.includes("weakens"),
      ),
    ).toBe(false);
  });

  it("does not warn for sp=reject alongside p=reject", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com"],
      raw: "v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("sp=none"),
      ),
    ).toBe(false);
    expect(
      result.validations.some(
        (v) => v.status === "pass" && v.message.includes("Subdomain policy"),
      ),
    ).toBe(true);
  });

  it("does not warn for sp=quarantine alongside p=reject", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com"],
      raw: "v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com",
    });

    const result = await analyzeDmarc("example.com");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("sp=none"),
      ),
    ).toBe(false);
  });
});
