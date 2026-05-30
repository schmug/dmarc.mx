import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn(),
  queryMx: vi.fn(),
}));

import { analyzeDkim } from "../src/analyzers/dkim.js";
import { queryTxt } from "../src/dns/client.js";

const mockQueryTxt = vi.mocked(queryTxt);

beforeEach(() => {
  vi.resetAllMocks();
});

describe("analyzeDkim", () => {
  it("returns fail when no selectors found", async () => {
    mockQueryTxt.mockResolvedValue(null);
    const result = await analyzeDkim("example.com");
    expect(result.status).toBe("fail");
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" && v.message.includes("No DKIM selectors found"),
      ),
    ).toBe(true);
  });

  it("finds a single DKIM selector with RSA 2048 key", async () => {
    // All common selectors return null except "google"
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "google._domainkey.example.com") {
        // RSA 2048-bit key: DER-encoded SubjectPublicKeyInfo is ~294 bytes
        const fakeKey = btoa("x".repeat(294));
        return {
          entries: [`v=DKIM1; k=rsa; p=${fakeKey}`],
          raw: `v=DKIM1; k=rsa; p=${fakeKey}`,
        };
      }
      return null;
    });

    const result = await analyzeDkim("example.com");
    expect(result.status).toBe("pass");
    expect(result.selectors.google.found).toBe(true);
    expect(result.selectors.google.key_type).toBe("rsa");
    expect(result.selectors.google.key_bits).toBe(2048);
    expect(
      result.validations.some((v) =>
        v.message.includes("1 DKIM selector found"),
      ),
    ).toBe(true);
  });

  it("detects weak key under 2048 bits", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "google._domainkey.example.com") {
        // RSA 1024-bit key: DER-encoded SubjectPublicKeyInfo is ~162 bytes
        const fakeKey = btoa("x".repeat(162));
        return {
          entries: [`v=DKIM1; k=rsa; p=${fakeKey}`],
          raw: `v=DKIM1; k=rsa; p=${fakeKey}`,
        };
      }
      return null;
    });

    const result = await analyzeDkim("example.com");
    expect(result.status).toBe("warn");
    expect(result.selectors.google.key_bits).toBe(1024);
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("under 2048 bits"),
      ),
    ).toBe(true);
  });

  it("detects revoked key (empty p= tag)", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "google._domainkey.example.com") {
        return {
          entries: ["v=DKIM1; k=rsa; p="],
          raw: "v=DKIM1; k=rsa; p=",
        };
      }
      return null;
    });

    const result = await analyzeDkim("example.com");
    expect(result.selectors.google.found).toBe(true);
    expect(result.selectors.google.revoked).toBe(true);
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("revoked"),
      ),
    ).toBe(true);
  });

  it("detects testing mode (t=y)", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "google._domainkey.example.com") {
        const fakeKey = btoa("x".repeat(294));
        return {
          entries: [`v=DKIM1; k=rsa; t=y; p=${fakeKey}`],
          raw: `v=DKIM1; k=rsa; t=y; p=${fakeKey}`,
        };
      }
      return null;
    });

    const result = await analyzeDkim("example.com");
    expect(result.selectors.google.testing).toBe(true);
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("testing mode"),
      ),
    ).toBe(true);
  });

  it("accepts Ed25519 key as valid modern key with no weak-key warning", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "google._domainkey.example.com") {
        const fakeKey = btoa("x".repeat(32));
        return {
          entries: [`v=DKIM1; k=ed25519; p=${fakeKey}`],
          raw: `v=DKIM1; k=ed25519; p=${fakeKey}`,
        };
      }
      return null;
    });

    const result = await analyzeDkim("example.com");
    expect(result.status).toBe("pass");
    expect(result.selectors.google.found).toBe(true);
    expect(result.selectors.google.key_type).toBe("ed25519");
    expect(result.selectors.google.key_bits).toBeUndefined();
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("weak"),
      ),
    ).toBe(false);
    expect(
      result.validations.some(
        (v) =>
          v.status === "pass" &&
          v.message.includes("Ed25519 key") &&
          v.message.includes("modern curve"),
      ),
    ).toBe(true);
  });

  it("merges custom selectors with common selectors (deduplication)", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "myselector._domainkey.example.com") {
        const fakeKey = btoa("x".repeat(294));
        return {
          entries: [`v=DKIM1; p=${fakeKey}`],
          raw: `v=DKIM1; p=${fakeKey}`,
        };
      }
      return null;
    });

    const result = await analyzeDkim("example.com", ["myselector", "google"]);
    // "google" is in common selectors, should be deduplicated
    expect(result.selectors.myselector).toBeDefined();
    expect(result.selectors.myselector.found).toBe(true);
    expect(result.selectors.google).toBeDefined();
  });

  it("reports multiple selectors found with plural message", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (
        name === "google._domainkey.example.com" ||
        name === "selector1._domainkey.example.com"
      ) {
        const fakeKey = btoa("x".repeat(294));
        return {
          entries: [`v=DKIM1; k=rsa; p=${fakeKey}`],
          raw: `v=DKIM1; k=rsa; p=${fakeKey}`,
        };
      }
      return null;
    });

    const result = await analyzeDkim("example.com");
    expect(result.status).toBe("pass");
    expect(
      result.validations.some((v) =>
        v.message.includes("2 DKIM selectors found"),
      ),
    ).toBe(true);
  });

  it("handles rejected promise from queryTxt gracefully", async () => {
    mockQueryTxt.mockRejectedValue(new Error("DNS timeout"));
    const result = await analyzeDkim("example.com");
    // All selectors should be { found: false } due to Promise.allSettled
    const allNotFound = Object.values(result.selectors).every((s) => !s.found);
    expect(allNotFound).toBe(true);
    expect(result.status).toBe("fail");
  });

  it("finds Cloudflare Email Routing selector (cf2024-1)", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "cf2024-1._domainkey.example.com") {
        const fakeKey = btoa("x".repeat(294));
        return {
          entries: [`v=DKIM1; k=rsa; p=${fakeKey}`],
          raw: `v=DKIM1; k=rsa; p=${fakeKey}`,
        };
      }
      return null;
    });

    const result = await analyzeDkim("example.com");
    expect(result.status).toBe("pass");
    expect(result.selectors["cf2024-1"].found).toBe(true);
    expect(result.selectors["cf2024-1"].key_bits).toBe(2048);
  });

  it("defaults key_type to rsa when k= tag is absent", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "google._domainkey.example.com") {
        const fakeKey = btoa("x".repeat(294));
        return {
          entries: [`v=DKIM1; p=${fakeKey}`],
          raw: `v=DKIM1; p=${fakeKey}`,
        };
      }
      return null;
    });

    const result = await analyzeDkim("example.com");
    expect(result.selectors.google.key_type).toBe("rsa");
  });

  it("maps DER-encoded 1024-bit RSA key (162 bytes) to 1024 bits", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "google._domainkey.example.com") {
        const fakeKey = btoa("x".repeat(162));
        return {
          entries: [`v=DKIM1; k=rsa; p=${fakeKey}`],
          raw: `v=DKIM1; k=rsa; p=${fakeKey}`,
        };
      }
      return null;
    });

    const result = await analyzeDkim("example.com");
    expect(result.selectors.google.key_bits).toBe(1024);
  });

  it("maps DER-encoded 2048-bit RSA key (294 bytes) to 2048 bits", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "google._domainkey.example.com") {
        const fakeKey = btoa("x".repeat(294));
        return {
          entries: [`v=DKIM1; k=rsa; p=${fakeKey}`],
          raw: `v=DKIM1; k=rsa; p=${fakeKey}`,
        };
      }
      return null;
    });

    const result = await analyzeDkim("example.com");
    expect(result.selectors.google.key_bits).toBe(2048);
  });

  it("maps DER-encoded 4096-bit RSA key (550 bytes) to 4096 bits", async () => {
    mockQueryTxt.mockImplementation(async (name: string) => {
      if (name === "google._domainkey.example.com") {
        const fakeKey = btoa("x".repeat(550));
        return {
          entries: [`v=DKIM1; k=rsa; p=${fakeKey}`],
          raw: `v=DKIM1; k=rsa; p=${fakeKey}`,
        };
      }
      return null;
    });

    const result = await analyzeDkim("example.com");
    expect(result.selectors.google.key_bits).toBe(4096);
  });

  it("probes provider-relevant selectors first when providerNames given", async () => {
    const callOrder: string[] = [];
    mockQueryTxt.mockImplementation(async (name: string) => {
      callOrder.push(name);
      if (name === "google._domainkey.example.com") {
        const fakeKey = btoa("x".repeat(294));
        return {
          entries: [`v=DKIM1; k=rsa; p=${fakeKey}`],
          raw: `v=DKIM1; k=rsa; p=${fakeKey}`,
        };
      }
      return null;
    });

    await analyzeDkim("example.com", [], ["Google Workspace"]);

    // "google" selector should be probed before non-provider selectors like "default"
    const googleIdx = callOrder.indexOf("google._domainkey.example.com");
    const defaultIdx = callOrder.indexOf("default._domainkey.example.com");
    expect(googleIdx).toBe(0);
    expect(googleIdx).toBeLessThan(defaultIdx);
  });

  it("probes Microsoft selectors first when Microsoft 365 detected", async () => {
    const callOrder: string[] = [];
    mockQueryTxt.mockImplementation(async (name: string) => {
      callOrder.push(name);
      return null;
    });

    await analyzeDkim("example.com", [], ["Microsoft 365"]);

    // selector1 and selector2 should be first two probes
    expect(callOrder[0]).toBe("selector1._domainkey.example.com");
    expect(callOrder[1]).toBe("selector2._domainkey.example.com");
  });

  it("still probes all selectors when providerNames given", async () => {
    mockQueryTxt.mockResolvedValue(null);

    const result = await analyzeDkim("example.com", [], ["Google Workspace"]);

    // All common selectors should still be present in results
    expect(Object.keys(result.selectors)).toContain("google");
    expect(Object.keys(result.selectors)).toContain("selector1");
    expect(Object.keys(result.selectors)).toContain("default");
  });

  it("ignores unknown provider names gracefully", async () => {
    mockQueryTxt.mockResolvedValue(null);

    const result = await analyzeDkim("example.com", [], ["Unknown Provider"]);

    // Should behave like no providers — all selectors present
    expect(Object.keys(result.selectors).length).toBeGreaterThanOrEqual(36);
  });

  it("behaves identically with empty providerNames", async () => {
    mockQueryTxt.mockResolvedValue(null);

    const resultDefault = await analyzeDkim("example.com");
    const resultEmpty = await analyzeDkim("example.com", [], []);

    expect(Object.keys(resultDefault.selectors)).toEqual(
      Object.keys(resultEmpty.selectors),
    );
  });
});
