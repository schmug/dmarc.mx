import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn(),
  queryMx: vi.fn(),
}));

import { analyzeMtaSts, checkMxCoverage } from "../src/analyzers/mta-sts.js";
import { queryTxt } from "../src/dns/client.js";

const mockQueryTxt = vi.mocked(queryTxt);

beforeEach(() => {
  vi.resetAllMocks();
  vi.restoreAllMocks();
});

function mockFetchPolicy(body: string | null, ok = true) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    body === null
      ? ({ ok: false, text: async () => "" } as Response)
      : ({ ok, text: async () => body } as Response),
  );
}

function mockFetchError() {
  vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Network error"));
}

const validPolicy = `version: STSv1
mode: enforce
mx: *.example.com
mx: mail.example.com
max_age: 86400`;

describe("analyzeMtaSts", () => {
  it("returns fail when no DNS record and no policy file", async () => {
    mockQueryTxt.mockResolvedValue(null);
    mockFetchError();

    const result = await analyzeMtaSts("example.com");
    expect(result.status).toBe("fail");
    expect(result.dns_record).toBeNull();
    expect(result.policy).toBeNull();
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" && v.message.includes("No _mta-sts TXT record"),
      ),
    ).toBe(true);
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" &&
          v.message.includes("Policy file not accessible"),
      ),
    ).toBe(true);
  });

  it("passes when DNS record found with v=STSv1", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(validPolicy);

    const result = await analyzeMtaSts("example.com");
    expect(result.dns_record).toBe("v=STSv1; id=20240101");
    expect(
      result.validations.some(
        (v) =>
          v.status === "pass" && v.message.includes("MTA-STS DNS record found"),
      ),
    ).toBe(true);
  });

  it("fails when TXT record exists but missing v=STSv1", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["some other txt record"],
      raw: "some other txt record",
    });
    mockFetchPolicy(validPolicy);

    const result = await analyzeMtaSts("example.com");
    expect(result.dns_record).toBeNull();
    expect(
      result.validations.some(
        (v) => v.status === "fail" && v.message.includes("missing v=STSv1"),
      ),
    ).toBe(true);
  });

  it("detects enforce mode as pass", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(validPolicy);

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.mode).toBe("enforce");
    expect(
      result.validations.some(
        (v) => v.status === "pass" && v.message.includes("enforce"),
      ),
    ).toBe(true);
  });

  it("warns on testing mode", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(
      `version: STSv1\nmode: testing\nmx: *.example.com\nmax_age: 86400`,
    );

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.mode).toBe("testing");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("testing"),
      ),
    ).toBe(true);
  });

  it("warns on none mode", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(
      `version: STSv1\nmode: none\nmx: *.example.com\nmax_age: 86400`,
    );

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.mode).toBe("none");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("none"),
      ),
    ).toBe(true);
  });

  it("warns on low max_age (less than 1 day)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(
      `version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 3600`,
    );

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.max_age).toBe(3600);
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("max_age"),
      ),
    ).toBe(true);
  });

  it("warns when no MX patterns in policy", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(`version: STSv1\nmode: enforce\nmax_age: 86400`);

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.mx).toEqual([]);
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("No MX patterns"),
      ),
    ).toBe(true);
  });

  it("handles fetch failure gracefully", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchError();

    const result = await analyzeMtaSts("example.com");
    expect(result.policy).toBeNull();
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" &&
          v.message.includes("Policy file not accessible"),
      ),
    ).toBe(true);
  });

  it("handles non-ok HTTP response gracefully", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(null);

    const result = await analyzeMtaSts("example.com");
    expect(result.policy).toBeNull();
  });

  it("parses policy with multiple MX entries", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(validPolicy);

    const result = await analyzeMtaSts("example.com");
    expect(result.policy?.mx).toEqual(["*.example.com", "mail.example.com"]);
    expect(result.policy?.version).toBe("STSv1");
    expect(result.policy?.max_age).toBe(86400);
  });

  it("returns pass status when DNS and policy are both valid with enforce mode", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    mockFetchPolicy(validPolicy);

    const result = await analyzeMtaSts("example.com");
    expect(result.status).toBe("pass");
  });

  // Regression guard for PRs #58 and #92: the policy fetch must use
  // redirect:"manual", NOT "error". `"error"` throws in the Cloudflare
  // Workers fetch runtime and breaks every scan. See src/analyzers/mta-sts.ts
  // and commit 2b47fe7 for the history.
  it("passes redirect:'manual' to fetch (regression guard for PR #58/#92)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      text: async () => validPolicy,
    } as Response);

    await analyzeMtaSts("example.com");

    expect(fetchSpy).toHaveBeenCalledWith(
      "https://mta-sts.example.com/.well-known/mta-sts.txt",
      expect.objectContaining({ redirect: "manual" }),
    );
  });

  it("returns null policy when fetch returns an opaque-redirect response", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=STSv1; id=20240101"],
      raw: "v=STSv1; id=20240101",
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false,
      status: 0,
      type: "opaqueredirect",
      text: async () => "",
    } as Response);

    const result = await analyzeMtaSts("example.com");
    expect(result.policy).toBeNull();
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" &&
          v.message.includes("Policy file not accessible"),
      ),
    ).toBe(true);
  });
});

describe("checkMxCoverage", () => {
  it("returns empty array when all MX hosts are covered by literal patterns", () => {
    const uncovered = checkMxCoverage(
      ["mail.example.com", "backup.example.com"],
      ["mail.example.com", "backup.example.com"],
    );
    expect(uncovered).toEqual([]);
  });

  it("returns uncovered host when one MX host is missing from policy", () => {
    const uncovered = checkMxCoverage(
      ["mail.example.com", "unlisted.example.com"],
      ["mail.example.com"],
    );
    expect(uncovered).toEqual(["unlisted.example.com"]);
  });

  it("wildcard pattern *.example.com matches mail.example.com (one subdomain level)", () => {
    const uncovered = checkMxCoverage(["mail.example.com"], ["*.example.com"]);
    expect(uncovered).toEqual([]);
  });

  it("wildcard pattern *.example.com does NOT match sub.mail.example.com (two subdomain levels)", () => {
    const uncovered = checkMxCoverage(
      ["sub.mail.example.com"],
      ["*.example.com"],
    );
    expect(uncovered).toEqual(["sub.mail.example.com"]);
  });

  it("wildcard pattern *.example.com does NOT match example.com itself", () => {
    const uncovered = checkMxCoverage(["example.com"], ["*.example.com"]);
    expect(uncovered).toEqual(["example.com"]);
  });

  it("matching is case-insensitive for both host and pattern", () => {
    const uncovered = checkMxCoverage(
      ["MAIL.Example.COM"],
      ["mail.example.com"],
    );
    expect(uncovered).toEqual([]);
  });

  it("wildcard matching is case-insensitive", () => {
    const uncovered = checkMxCoverage(["MAIL.EXAMPLE.COM"], ["*.example.com"]);
    expect(uncovered).toEqual([]);
  });

  it("returns empty array when mxHosts is empty", () => {
    const uncovered = checkMxCoverage([], ["*.example.com"]);
    expect(uncovered).toEqual([]);
  });

  it("returns all hosts as uncovered when stsMxPatterns is empty", () => {
    const uncovered = checkMxCoverage(
      ["mail.example.com", "backup.example.com"],
      [],
    );
    expect(uncovered).toEqual(["mail.example.com", "backup.example.com"]);
  });

  it("multiple patterns: host covered by any one pattern is not flagged", () => {
    const uncovered = checkMxCoverage(
      ["mail.example.com", "mx.other.com"],
      ["*.example.com", "mx.other.com"],
    );
    expect(uncovered).toEqual([]);
  });
});
