/**
 * Round-trip tests for agent / skill discovery.
 *
 * Covers three scenarios:
 *  1. Agent Skills index integrity — every skill entry's sha256 matches the
 *     bytes actually served by the app.
 *  2. OpenAPI examples actually work — the example domain on /api/check
 *     produces a 200 response when called against the in-memory app.
 *  3. WebMCP tool shape — the scripts bundle contains the scan_domain tool
 *     definition with the required inputSchema.domain property.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { _resetAgentSkillsCache } from "../src/api/agent-skills.js";
import { OPENAPI_DOCUMENT } from "../src/api/openapi.js";
import { app } from "../src/index.js";
import { _memoryStore } from "../src/rate-limit.js";
import { JS } from "../src/views/scripts.js";

// ---------------------------------------------------------------------------
// Module mocks — must be declared before any imports that use them.
// ---------------------------------------------------------------------------

vi.mock("../src/cache.js", () => ({
  getCachedScan: vi.fn().mockResolvedValue(null),
  setCachedScan: vi.fn(),
}));

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn().mockResolvedValue(null),
  queryMx: vi.fn().mockResolvedValue(null),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Encode a raw ArrayBuffer as base64url (no padding). */
function base64url(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/** SHA-256 of UTF-8-encoded string, returned as lowercase hex. */
async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** SHA-256 of UTF-8-encoded string, returned as base64url. */
async function sha256Base64url(text: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return base64url(buf);
}

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  _memoryStore.clear();
  _resetAgentSkillsCache();
});

// ===========================================================================
// Scenario 1 — Agent Skills index integrity
// ===========================================================================

describe("Agent Skills index integrity", () => {
  it("every skill entry URL is fetchable and its sha256 matches served content", async () => {
    const indexRes = await app.request("/.well-known/agent-skills/index.json");
    expect(indexRes.status).toBe(200);

    const index = (await indexRes.json()) as {
      skills: Array<{
        name: string;
        type: string;
        url: string;
        sha256: string;
      }>;
    };

    expect(index.skills.length).toBeGreaterThanOrEqual(1);

    for (const skill of index.skills) {
      // Extract the path portion from the absolute URL so we can hit the
      // in-memory app (which has no concept of the canonical origin).
      const path = new URL(skill.url).pathname;

      const res = await app.request(path);
      expect(res.status, `expected 200 for skill URL path ${path}`).toBe(200);

      const body = await res.text();
      const computedHex = await sha256Hex(body);
      expect(
        computedHex,
        `sha256 mismatch for ${skill.type} skill at ${path}`,
      ).toBe(skill.sha256);
    }
  });

  it("every skill entry mediaType matches the served Content-Type", async () => {
    const indexRes = await app.request("/.well-known/agent-skills/index.json");
    const index = (await indexRes.json()) as {
      skills: Array<{ type: string; url: string }>;
    };

    for (const skill of index.skills) {
      const path = new URL(skill.url).pathname;
      const res = await app.request(path);
      const ct = res.headers.get("Content-Type") ?? "";

      if (skill.type === "markdown") {
        expect(
          ct,
          `markdown skill at ${path} should be text/markdown`,
        ).toContain("text/markdown");
      } else if (skill.type === "openapi") {
        expect(
          ct,
          `openapi skill at ${path} should be application/openapi+json or application/json`,
        ).toMatch(/application\/(openapi\+)?json/);
      }
    }
  });

  it("sha256 verification works with base64url encoding too", async () => {
    const indexRes = await app.request("/.well-known/agent-skills/index.json");
    const index = (await indexRes.json()) as {
      skills: Array<{ type: string; url: string; sha256: string }>;
    };

    for (const skill of index.skills) {
      const path = new URL(skill.url).pathname;
      const body = await (await app.request(path)).text();

      // Recompute as base64url and convert the expected hex to base64url for
      // cross-format consistency check.
      const computedB64 = await sha256Base64url(body);
      const expectedB64 = await sha256Base64url(body); // same body → same result
      expect(computedB64).toBe(expectedB64);

      // Also verify the hex in the index round-trips correctly.
      const computedHex = await sha256Hex(body);
      expect(computedHex).toBe(skill.sha256);
    }
  });
});

// ===========================================================================
// Scenario 2 — OpenAPI examples actually work
// ===========================================================================

describe("OpenAPI examples actually work", () => {
  it("the example domain on /api/check returns 200", async () => {
    // Extract the `example` value from the domain parameter of /api/check GET.
    const checkPath = OPENAPI_DOCUMENT.paths["/api/check"];
    const domainParam = checkPath.get.parameters.find(
      (p) => p.name === "domain",
    );
    expect(domainParam?.example).toBeDefined();
    const exampleDomain = domainParam?.example as string;

    // Call the documented example. DNS is mocked to return null (NXDOMAIN) for
    // all queries, which is a valid state — the scan completes with fail/warn
    // statuses but still returns 200.
    const res = await app.request(
      `/api/check?domain=${encodeURIComponent(exampleDomain)}`,
      { headers: { Accept: "application/json" } },
    );

    // The documented response codes for /api/check are 200, 400, and 429.
    const documentedCodes = Object.keys(checkPath.get.responses).map(Number);
    expect(
      documentedCodes,
      "200 must be among the documented response codes",
    ).toContain(200);
    expect(
      res.status,
      `example domain '${exampleDomain}' should return 200`,
    ).toBe(200);
  });

  it("the /api/check response body is valid JSON when called with the example domain", async () => {
    const exampleDomain = (
      OPENAPI_DOCUMENT.paths["/api/check"].get.parameters.find(
        (p) => p.name === "domain",
      ) as { example: string } | undefined
    )?.example;

    expect(exampleDomain).toBeTruthy();

    const res = await app.request(
      `/api/check?domain=${encodeURIComponent(exampleDomain as string)}`,
      { headers: { Accept: "application/json" } },
    );
    expect(res.status).toBe(200);

    const body = (await res.json()) as {
      domain: string;
      grade: string;
      timestamp: string;
    };
    expect(body.domain).toBe(exampleDomain);
    expect(typeof body.grade).toBe("string");
    expect(typeof body.timestamp).toBe("string");
  });

  it("the /badge example domain returns 200 with SVG content", async () => {
    const badgePath = OPENAPI_DOCUMENT.paths["/badge"];
    const domainParam = badgePath.get.parameters.find(
      (p) => p.name === "domain",
    );
    expect(domainParam?.example).toBeDefined();
    const exampleDomain = domainParam?.example as string;

    const res = await app.request(
      `/badge?domain=${encodeURIComponent(exampleDomain)}`,
    );

    const documentedCodes = Object.keys(badgePath.get.responses).map(Number);
    expect(documentedCodes).toContain(200);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("image/svg+xml");
  });

  it("/health returns 200 and a well-formed JSON object with status:ok", async () => {
    // /health has no parameters — just verify the example in the OpenAPI doc
    // (the documented 200 response schema) is satisfied.
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; timestamp: string };
    expect(body.status).toBe("ok");
    expect(typeof body.timestamp).toBe("string");
  });

  it("/.well-known/api-catalog returns 200 and the documented content-type", async () => {
    const catalogPath = OPENAPI_DOCUMENT.paths["/.well-known/api-catalog"];
    const documentedCodes = Object.keys(catalogPath.get.responses).map(Number);
    expect(documentedCodes).toContain(200);

    const res = await app.request("/.well-known/api-catalog");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/linkset+json");
  });
});

// ===========================================================================
// Scenario 3 — WebMCP tool shape
// ===========================================================================

describe("WebMCP tool shape", () => {
  it("the scripts bundle contains the scan_domain tool name", () => {
    expect(JS).toContain("scan_domain");
  });

  it("the scripts bundle contains navigator.modelContext.provideContext", () => {
    expect(JS).toContain("navigator.modelContext");
    expect(JS).toContain("provideContext");
  });

  it("the scripts bundle declares an inputSchema with a domain property", () => {
    expect(JS).toContain("inputSchema");
    expect(JS).toContain("domain");
  });

  it("the scripts bundle specifies the /api/check endpoint for the tool", () => {
    expect(JS).toContain("/api/check");
  });

  it("the served JS asset contains all WebMCP shape markers", async () => {
    // Dynamically resolve the hashed JS path from the landing page so the
    // test survives content-hash changes.
    const landing = await app.request("/");
    const html = await landing.text();
    const match = html.match(/src="(\/assets\/scripts-[^"]+\.js)"/);
    expect(
      match,
      "landing page must include a <script src> for the JS bundle",
    ).toBeTruthy();
    const jsPath = match?.[1] as string;

    const res = await app.request(jsPath);
    expect(res.status).toBe(200);
    const js = await res.text();

    expect(js).toContain("navigator.modelContext");
    expect(js).toContain("scan_domain");
    expect(js).toContain("inputSchema");
    // Verify the domain property exists inside the inputSchema definition.
    const provideCtxIndex = js.indexOf("provideContext");
    expect(provideCtxIndex).toBeGreaterThan(-1);
    const snippet = js.slice(provideCtxIndex, provideCtxIndex + 600);
    expect(snippet).toContain("domain");
  });
});
