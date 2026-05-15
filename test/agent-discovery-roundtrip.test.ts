import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { _resetAgentSkillsCache } from "../src/api/agent-skills.js";
import { app } from "../src/index.js";
import { _memoryStore } from "../src/rate-limit.js";

vi.mock("../src/cache.js", () => ({
  getCachedScan: vi.fn().mockResolvedValue(null),
  setCachedScan: vi.fn(),
}));

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn().mockResolvedValue(null),
  queryMx: vi.fn().mockResolvedValue(null),
}));

beforeEach(() => {
  _memoryStore.clear();
  _resetAgentSkillsCache();
  // Stub global fetch so MTA-STS and security-txt analyzers don't make real
  // network calls during the OpenAPI round-trip test — they would hang or
  // time out in CI. The DNS mock already handles DNS-only analyzers.
  vi.spyOn(globalThis, "fetch").mockRejectedValue(
    new Error("network disabled in tests"),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Helper: compute sha256 as base64 (sha256-<base64>) or hex
// ---------------------------------------------------------------------------
async function sha256Base64(bytes: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// 1. Agent Skills index integrity — digest + mediaType round-trip
// ---------------------------------------------------------------------------
describe("Agent Skills index integrity", () => {
  it("index.json is fetchable and has the expected shape", async () => {
    const res = await app.request("/.well-known/agent-skills/index.json");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty("skills");
    expect(Array.isArray((body as { skills: unknown[] }).skills)).toBe(true);
  });

  it("every skill entry digest matches the artifact served by the app", async () => {
    // The index uses the legacy flat shape: { skills: [{ url, sha256, type }] }
    const indexRes = await app.request("/.well-known/agent-skills/index.json");
    const index = (await indexRes.json()) as {
      skills: Array<{
        name: string;
        url: string;
        sha256: string;
        type: string;
      }>;
    };

    for (const entry of index.skills) {
      // Derive the in-process path from the absolute URL in the index
      const url = new URL(entry.url);
      const path = url.pathname;

      const artifactRes = await app.request(path);
      expect(artifactRes.status, `artifact fetch for ${path}`).toBe(200);

      const bodyText = await artifactRes.text();
      const computed = await sha256Hex(bodyText);
      expect(
        computed,
        `sha256 mismatch for ${entry.type} artifact at ${path}`,
      ).toBe(entry.sha256);
    }
  });

  it("skill entries with type=markdown are served as text/markdown", async () => {
    const indexRes = await app.request("/.well-known/agent-skills/index.json");
    const index = (await indexRes.json()) as {
      skills: Array<{ type: string; url: string }>;
    };
    const markdownEntries = index.skills.filter((s) => s.type === "markdown");
    expect(markdownEntries.length).toBeGreaterThan(0);

    for (const entry of markdownEntries) {
      const path = new URL(entry.url).pathname;
      const res = await app.request(path);
      expect(
        res.headers.get("Content-Type"),
        `expected text/markdown Content-Type for ${path}`,
      ).toContain("text/markdown");
    }
  });

  it("skill entries with type=openapi are served as application/openapi+json", async () => {
    const indexRes = await app.request("/.well-known/agent-skills/index.json");
    const index = (await indexRes.json()) as {
      skills: Array<{ type: string; url: string }>;
    };
    const openapiEntries = index.skills.filter((s) => s.type === "openapi");
    expect(openapiEntries.length).toBeGreaterThan(0);

    for (const entry of openapiEntries) {
      const path = new URL(entry.url).pathname;
      const res = await app.request(path);
      expect(
        res.headers.get("Content-Type"),
        `expected application/openapi+json Content-Type for ${path}`,
      ).toContain("application/openapi+json");
    }
  });
});

// ---------------------------------------------------------------------------
// 2. OpenAPI examples actually work — GET /api/check with documented example
// ---------------------------------------------------------------------------
describe("OpenAPI examples round-trip", () => {
  it("fetches /openapi.json and finds the /api/check path", async () => {
    const res = await app.request("/openapi.json");
    expect(res.status).toBe(200);
    const doc = (await res.json()) as {
      openapi: string;
      paths: Record<string, unknown>;
    };
    expect(doc.openapi).toBe("3.1.0");
    expect(doc.paths["/api/check"]).toBeDefined();
  });

  it("GET /api/check with the documented domain example returns 200 or 429", async () => {
    // Extract the domain example from the OpenAPI spec
    const openapiRes = await app.request("/openapi.json");
    const doc = (await openapiRes.json()) as {
      paths: Record<
        string,
        {
          get?: {
            parameters?: Array<{
              name: string;
              in: string;
              example?: string;
            }>;
          };
        }
      >;
    };

    const checkPath = doc.paths["/api/check"];
    expect(checkPath).toBeDefined();
    const params = checkPath.get?.parameters ?? [];
    const domainParam = params.find(
      (p) => p.name === "domain" && p.in === "query",
    );
    expect(domainParam).toBeDefined();

    const exampleDomain = domainParam?.example ?? "example.com";
    expect(typeof exampleDomain).toBe("string");

    // Execute the request against the in-memory app
    const scanRes = await app.request(
      `/api/check?domain=${encodeURIComponent(exampleDomain)}`,
      { headers: { Accept: "application/json" } },
    );

    // Must be one of the documented response codes (200 = ok, 429 = rate limited)
    expect([200, 429]).toContain(scanRes.status);
  });

  it("every documented response code for /api/check is a number in 200-599", async () => {
    const openapiRes = await app.request("/openapi.json");
    const doc = (await openapiRes.json()) as {
      paths: Record<
        string,
        {
          get?: { responses?: Record<string, unknown> };
        }
      >;
    };
    const responses = doc.paths["/api/check"]?.get?.responses ?? {};
    const codes = Object.keys(responses).map(Number);
    expect(codes.length).toBeGreaterThan(0);
    for (const code of codes) {
      expect(code).toBeGreaterThanOrEqual(200);
      expect(code).toBeLessThan(600);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. WebMCP tool shape — verified against the JS source served by the app
// ---------------------------------------------------------------------------
describe("WebMCP tool shape", () => {
  it("locates the hashed JS asset from the landing page", async () => {
    const landing = await app.request("/");
    const html = await landing.text();
    const match = html.match(/src="(\/assets\/scripts-[^"]+\.js)"/);
    expect(
      match,
      "could not find hashed JS asset in landing HTML",
    ).toBeTruthy();
  });

  it("JS bundle contains navigator.modelContext and scan_domain tool registration", async () => {
    const landing = await app.request("/");
    const html = await landing.text();
    const match = html.match(/src="(\/assets\/scripts-[^"]+\.js)"/);
    const jsPath = match?.[1] as string;

    const jsRes = await app.request(jsPath);
    expect(jsRes.status).toBe(200);
    const js = await jsRes.text();

    // Must register using WebMCP's provideContext API
    expect(js).toContain("navigator.modelContext");
    expect(js).toContain("provideContext");
  });

  it("tool name is scan_domain", async () => {
    const landing = await app.request("/");
    const html = await landing.text();
    const match = html.match(/src="(\/assets\/scripts-[^"]+\.js)"/);
    const jsPath = match?.[1] as string;
    const js = await (await app.request(jsPath)).text();

    expect(js).toContain("'scan_domain'");
  });

  it("inputSchema has a domain property of type string", async () => {
    const landing = await app.request("/");
    const html = await landing.text();
    const match = html.match(/src="(\/assets\/scripts-[^"]+\.js)"/);
    const jsPath = match?.[1] as string;
    const js = await (await app.request(jsPath)).text();

    // The schema object appears in source: domain: { type: 'string', ... }
    expect(js).toMatch(/domain\s*:\s*\{\s*type\s*:\s*['"']string['"']/);
  });

  it("execute function URL pattern references /api/check", async () => {
    const landing = await app.request("/");
    const html = await landing.text();
    const match = html.match(/src="(\/assets\/scripts-[^"]+\.js)"/);
    const jsPath = match?.[1] as string;
    const js = await (await app.request(jsPath)).text();

    expect(js).toContain("/api/check");
  });

  it("sha256-base64 helper round-trip (sanity check)", async () => {
    const input = new TextEncoder().encode("hello");
    const b64 = await sha256Base64(input);
    // SHA-256("hello") in base64 is well-known
    expect(b64).toBe("LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
  });
});
