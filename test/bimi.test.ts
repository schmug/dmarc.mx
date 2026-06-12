import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn(),
  queryMx: vi.fn(),
}));

import { analyzeBimi, prefetchBimiDns } from "../src/analyzers/bimi.js";
import { queryTxt } from "../src/dns/client.js";

const mockQueryTxt = vi.mocked(queryTxt);

// ---------------------------------------------------------------------------
// Fetch mock helpers
// ---------------------------------------------------------------------------

/** Build a minimal ReadableStream from a string body. */
function makeBody(text: string): ReadableStream<Uint8Array> {
  const bytes = new TextEncoder().encode(text);
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

/** Mock a successful SVG logo fetch response. */
function svgLogoResponse(): Response {
  return {
    ok: true,
    status: 200,
    headers: new Headers({ "content-type": "image/svg+xml" }),
    body: makeBody("<svg/>"),
  } as unknown as Response;
}

/** Mock a successful PEM cert fetch response with a configurable Not After date. */
function pemCertResponse(notAfter = "Jan  1 00:00:00 2099 GMT"): Response {
  const pem = `-----BEGIN CERTIFICATE-----\nMIIFake==\n-----END CERTIFICATE-----\nNot After : ${notAfter}\n`;
  return {
    ok: true,
    status: 200,
    headers: new Headers({ "content-type": "application/x-pem-file" }),
    body: makeBody(pem),
  } as unknown as Response;
}

/** Mock an HTTP error response (e.g. 404). */
function errorResponse(status: number): Response {
  return {
    ok: false,
    status,
    headers: new Headers({}),
    body: makeBody(""),
  } as unknown as Response;
}

/**
 * Set up a fetch spy that serves happy-path responses for both logo and cert.
 * Tests that need different behaviour override per-call with mockResolvedValueOnce.
 */
function mockFetchHappy() {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(svgLogoResponse()) // logo fetch
    .mockResolvedValueOnce(pemCertResponse()); // cert fetch
}

/** Mock only the logo fetch (for records with l= but no a=). */
function mockFetchLogoOnly() {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(svgLogoResponse());
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// analyzeBimi
// ---------------------------------------------------------------------------

describe("analyzeBimi", () => {
  it("returns warn when no BIMI record found", async () => {
    mockQueryTxt.mockResolvedValue(null);
    const result = await analyzeBimi("example.com", "reject");
    expect(result.status).toBe("warn");
    expect(result.record).toBeNull();
    expect(result.tags).toBeNull();
    expect(
      result.validations.some((v) => v.message.includes("No BIMI record")),
    ).toBe(true);
  });

  it("shows DMARC policy pass when no record but policy is reject", async () => {
    mockQueryTxt.mockResolvedValue(null);
    const result = await analyzeBimi("example.com", "reject");
    expect(
      result.validations.some(
        (v) =>
          v.status === "pass" &&
          v.message.includes("DMARC policy meets BIMI requirement"),
      ),
    ).toBe(true);
  });

  it("shows DMARC policy pass when no record but policy is quarantine", async () => {
    mockQueryTxt.mockResolvedValue(null);
    const result = await analyzeBimi("example.com", "quarantine");
    expect(
      result.validations.some(
        (v) =>
          v.status === "pass" &&
          v.message.includes("DMARC policy meets BIMI requirement"),
      ),
    ).toBe(true);
  });

  it("warns about DMARC policy when no record and policy is none", async () => {
    mockQueryTxt.mockResolvedValue(null);
    const result = await analyzeBimi("example.com", "none");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("BIMI requires"),
      ),
    ).toBe(true);
  });

  it("warns about DMARC policy when no record and policy is null", async () => {
    mockQueryTxt.mockResolvedValue(null);
    const result = await analyzeBimi("example.com", null);
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("BIMI requires"),
      ),
    ).toBe(true);
  });

  it("parses valid BIMI record with logo and authority", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    mockFetchHappy();

    const result = await analyzeBimi("example.com", "reject");
    expect(result.status).toBe("pass");
    expect(result.tags?.l).toBe("https://example.com/logo.svg");
    expect(result.tags?.a).toBe("https://example.com/vmc.pem");
    expect(
      result.validations.some((v) => v.message.includes("BIMI record found")),
    ).toBe(true);
    expect(
      result.validations.some(
        (v) => v.message.includes("Logo URL") && v.message.includes("HTTPS"),
      ),
    ).toBe(true);
    expect(
      result.validations.some((v) => v.message.includes("Authority evidence")),
    ).toBe(true);
  });

  it("warns when logo URL does not use HTTPS", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=BIMI1; l=http://example.com/logo.svg"],
      raw: "v=BIMI1; l=http://example.com/logo.svg",
    });

    const result = await analyzeBimi("example.com", "reject");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("should use HTTPS"),
      ),
    ).toBe(true);
  });

  it("warns when no logo URL specified", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=BIMI1"],
      raw: "v=BIMI1",
    });

    const result = await analyzeBimi("example.com", "reject");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("No logo URL"),
      ),
    ).toBe(true);
  });

  it("fails when DMARC policy is none with BIMI record present", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=BIMI1; l=https://example.com/logo.svg"],
      raw: "v=BIMI1; l=https://example.com/logo.svg",
    });
    mockFetchLogoOnly();

    const result = await analyzeBimi("example.com", "none");
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" && v.message.includes("DMARC policy must be"),
      ),
    ).toBe(true);
  });

  it("fails when DMARC policy is null with BIMI record present", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=BIMI1; l=https://example.com/logo.svg"],
      raw: "v=BIMI1; l=https://example.com/logo.svg",
    });
    mockFetchLogoOnly();

    const result = await analyzeBimi("example.com", null);
    expect(
      result.validations.some(
        (v) =>
          v.status === "fail" && v.message.includes("DMARC policy must be"),
      ),
    ).toBe(true);
  });

  it("handles TXT record that exists but is not valid BIMI", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["some random text record"],
      raw: "some random text record",
    });

    const result = await analyzeBimi("example.com", "reject");
    expect(result.status).toBe("warn");
    expect(
      result.validations.some((v) =>
        v.message.includes("not a valid BIMI record"),
      ),
    ).toBe(true);
  });

  it("warns when no authority certificate specified", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: ["v=BIMI1; l=https://example.com/logo.svg"],
      raw: "v=BIMI1; l=https://example.com/logo.svg",
    });
    mockFetchLogoOnly();

    const result = await analyzeBimi("example.com", "reject");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("No authority certificate") &&
          v.message.includes("VMC or CMC"),
      ),
    ).toBe(true);
    const noCert = result.validations.find((v) =>
      v.message.includes("No authority certificate"),
    );
    expect(noCert?.learnAnchor).toBe("/learn/bimi#bimi-certification");
  });

  it("shows VMC/CMC message when authority certificate present", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    mockFetchHappy();

    const result = await analyzeBimi("example.com", "reject");
    expect(
      result.validations.some(
        (v) =>
          v.status === "pass" && v.message.includes("VMC/CMC certificate URL"),
      ),
    ).toBe(true);
  });

  it("returns pass status when all checks pass", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    mockFetchHappy();

    const result = await analyzeBimi("example.com", "reject");
    expect(result.status).toBe("pass");
  });

  it("uses prefetched DNS result instead of querying again", async () => {
    const prefetched = {
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    };
    mockFetchHappy();
    const result = await analyzeBimi("example.com", "reject", prefetched);
    expect(result.status).toBe("pass");
    expect(mockQueryTxt).not.toHaveBeenCalled();
  });

  it("uses prefetched null (no record) without querying", async () => {
    const result = await analyzeBimi("example.com", "reject", null);
    expect(result.status).toBe("warn");
    expect(mockQueryTxt).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Fetch-and-validate: logo
  // -------------------------------------------------------------------------

  it("warns when logo returns HTTP 404", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(errorResponse(404)) // logo → 404
      .mockResolvedValueOnce(pemCertResponse()); // cert → ok

    const result = await analyzeBimi("example.com", "reject");
    expect(result.status).toBe("warn");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("Logo fetch failed") &&
          v.message.includes("404"),
      ),
    ).toBe(true);
  });

  it("warns when logo Content-Type is not SVG", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    const pngResponse: Response = {
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "image/png" }),
      body: makeBody("\x89PNG"),
    } as unknown as Response;
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(pngResponse) // logo → wrong content-type
      .mockResolvedValueOnce(pemCertResponse()); // cert → ok

    const result = await analyzeBimi("example.com", "reject");
    expect(result.status).toBe("warn");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" && v.message.includes("Content-Type is not SVG"),
      ),
    ).toBe(true);
  });

  it("warns when logo fetch throws (network error)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    vi.spyOn(globalThis, "fetch")
      .mockRejectedValueOnce(new Error("Network error")) // logo → network error
      .mockResolvedValueOnce(pemCertResponse()); // cert → ok

    const result = await analyzeBimi("example.com", "reject");
    expect(result.status).toBe("warn");
    expect(
      result.validations.some(
        (v) => v.status === "warn" && v.message.includes("Logo fetch failed"),
      ),
    ).toBe(true);
  });

  it("passes when logo SVG content-type includes charset", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    const svgWithCharset: Response = {
      ok: true,
      status: 200,
      headers: new Headers({
        "content-type": "image/svg+xml; charset=utf-8",
      }),
      body: makeBody("<svg/>"),
    } as unknown as Response;
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(svgWithCharset) // logo → svg+xml with charset
      .mockResolvedValueOnce(pemCertResponse()); // cert → ok

    const result = await analyzeBimi("example.com", "reject");
    expect(result.status).toBe("pass");
    expect(
      result.validations.some(
        (v) => v.status === "pass" && v.message.includes("confirmed SVG"),
      ),
    ).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Fetch-and-validate: cert
  // -------------------------------------------------------------------------

  it("warns when cert returns HTTP 404", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(svgLogoResponse()) // logo → ok
      .mockResolvedValueOnce(errorResponse(404)); // cert → 404

    const result = await analyzeBimi("example.com", "reject");
    expect(result.status).toBe("warn");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" &&
          v.message.includes("Certificate fetch failed") &&
          v.message.includes("404"),
      ),
    ).toBe(true);
  });

  it("fails when cert is expired", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(svgLogoResponse()) // logo → ok
      .mockResolvedValueOnce(pemCertResponse("Jan  1 00:00:00 2020 GMT")); // cert → expired

    const result = await analyzeBimi("example.com", "reject");
    expect(result.status).toBe("fail");
    expect(
      result.validations.some(
        (v) => v.status === "fail" && v.message.includes("expired"),
      ),
    ).toBe(true);
    const expired = result.validations.find(
      (v) => v.status === "fail" && v.message.includes("expired"),
    );
    expect(expired?.learnAnchor).toBe("/learn/bimi#bimi-certification");
  });

  it("passes when cert is valid PEM and not expired", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    mockFetchHappy(); // uses Jan 1 2099

    const result = await analyzeBimi("example.com", "reject");
    expect(
      result.validations.some(
        (v) => v.status === "pass" && v.message.includes("not expired"),
      ),
    ).toBe(true);
    const validCert = result.validations.find((v) =>
      v.message.includes("not expired"),
    );
    expect(validCert?.learnAnchor).toBeUndefined();
  });

  it("warns when cert fetch throws (network error)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(svgLogoResponse()) // logo → ok
      .mockRejectedValueOnce(new Error("Network error")); // cert → network error

    const result = await analyzeBimi("example.com", "reject");
    expect(result.status).toBe("warn");
    expect(
      result.validations.some(
        (v) =>
          v.status === "warn" && v.message.includes("Certificate fetch failed"),
      ),
    ).toBe(true);
  });

  it("passes best-effort when cert body is binary (DER-like, no PEM header)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    const derResponse: Response = {
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/pkix-cert" }),
      body: makeBody("\x30\x82binary"),
    } as unknown as Response;
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(svgLogoResponse()) // logo → ok
      .mockResolvedValueOnce(derResponse); // cert → binary/DER

    const result = await analyzeBimi("example.com", "reject");
    // DER should not break the scan — best-effort pass with a note.
    expect(
      result.validations.some(
        (v) =>
          v.status === "pass" && v.message.includes("expiry check skipped"),
      ),
    ).toBe(true);
  });

  it("uses redirect:follow for BIMI fetches (not manual)", async () => {
    mockQueryTxt.mockResolvedValue({
      entries: [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
      ],
      raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
    });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(svgLogoResponse())
      .mockResolvedValueOnce(pemCertResponse());

    await analyzeBimi("example.com", "reject");

    // Both calls must use redirect:"follow" (not "manual" which is MTA-STS-specific)
    for (const call of fetchSpy.mock.calls) {
      expect(call[1]).toEqual(expect.objectContaining({ redirect: "follow" }));
    }
  });
});

// ---------------------------------------------------------------------------
// prefetchBimiDns
// ---------------------------------------------------------------------------

describe("prefetchBimiDns", () => {
  it("queries the correct BIMI subdomain", async () => {
    mockQueryTxt.mockResolvedValue(null);
    await prefetchBimiDns("example.com");
    expect(mockQueryTxt).toHaveBeenCalledWith("default._bimi.example.com");
  });
});
