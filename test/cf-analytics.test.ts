import { beforeEach, describe, expect, it, vi } from "vitest";
import { app } from "../src/index.js";
import { _memoryStore } from "../src/rate-limit.js";

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn().mockResolvedValue(null),
  queryMx: vi.fn().mockResolvedValue(null),
}));

beforeEach(() => {
  _memoryStore.clear();
});

const VALID_TOKEN = "4fd7e22413e84811bd71ed466613bb26";
const BEACON_SRC = "static.cloudflareinsights.com/beacon.min.js";

// Hono's request() signature is (input, init, env). We only care about
// CF_ANALYTICS_TOKEN — everything else is left undefined so the route
// handlers see the same shape as a self-host deploy.
const envWithToken = { CF_ANALYTICS_TOKEN: VALID_TOKEN };
const envBlank = {};

describe("Cloudflare Web Analytics beacon injection", () => {
  describe("with CF_ANALYTICS_TOKEN set", () => {
    const publicPaths = ["/", "/scoring", "/pricing", "/learn", "/learn/dmarc"];

    for (const path of publicPaths) {
      it(`injects beacon on ${path}`, async () => {
        const res = await app.request(path, {}, envWithToken);
        expect(res.status).toBe(200);
        const html = await res.text();
        expect(html).toContain(BEACON_SRC);
        expect(html).toContain(`"token":"${VALID_TOKEN}"`);
        // Beacon must sit just before </body> so DOM is available before
        // the script parses performance metrics. String indices avoid a
        // regex built from BEACON_SRC (CodeQL: js/incomplete-hostname-regexp).
        const beaconIdx = html.lastIndexOf(BEACON_SRC);
        const bodyCloseIdx = html.lastIndexOf("</body>");
        expect(beaconIdx).toBeGreaterThan(-1);
        expect(bodyCloseIdx).toBeGreaterThan(beaconIdx);
        // Nothing but the closing </script> should sit between the beacon
        // src and </body>.
        const between = html.slice(beaconIdx, bodyCloseIdx);
        expect(between).toContain("</script>");
        expect(between).not.toContain("<div");
      });
    }

    it("injects exactly one beacon script", async () => {
      const res = await app.request("/", {}, envWithToken);
      const html = await res.text();
      const matches = html.match(/static\.cloudflareinsights\.com/g);
      expect(matches).toHaveLength(1);
    });

    const skipPaths = [
      "/dashboard",
      "/dashboard/settings",
      "/auth/login",
      "/webhooks/stripe",
    ];

    for (const path of skipPaths) {
      it(`does NOT inject beacon on ${path}`, async () => {
        const res = await app.request(path, {}, envWithToken);
        // These routes may 4xx/5xx (no auth, no Stripe config), but whatever
        // HTML comes back must NOT carry the beacon.
        const contentType = res.headers.get("content-type") ?? "";
        if (contentType.includes("text/html")) {
          const html = await res.text();
          expect(html).not.toContain(BEACON_SRC);
        }
      });
    }

    it("does NOT inject beacon on JSON API responses", async () => {
      const res = await app.request(
        "/api/check?domain=dmarc.mx",
        {},
        envWithToken,
      );
      const body = await res.text();
      expect(body).not.toContain(BEACON_SRC);
    });
  });

  describe("with CF_ANALYTICS_TOKEN unset (self-host default)", () => {
    const publicPaths = ["/", "/scoring", "/pricing", "/learn"];

    for (const path of publicPaths) {
      it(`omits beacon on ${path}`, async () => {
        const res = await app.request(path, {}, envBlank);
        expect(res.status).toBe(200);
        const html = await res.text();
        expect(html).not.toContain(BEACON_SRC);
      });
    }
  });

  describe("with malformed CF_ANALYTICS_TOKEN", () => {
    const badTokens = [
      "not-a-token",
      "UPPERCASE0123456789ABCDEF01234567",
      "short",
      "<script>alert(1)</script>",
      "4fd7e22413e84811bd71ed466613bb26-injected",
    ];

    for (const token of badTokens) {
      it(`omits beacon when token is ${JSON.stringify(token).slice(0, 40)}`, async () => {
        const res = await app.request("/", {}, { CF_ANALYTICS_TOKEN: token });
        const html = await res.text();
        expect(html).not.toContain(BEACON_SRC);
        // Also verify we never passed the bad string through
        expect(html).not.toContain(token);
      });
    }
  });

  describe("CSP nonce covers the beacon script", () => {
    it("beacon script tag carries the per-request nonce", async () => {
      const res = await app.request("/", {}, envWithToken);
      const csp = res.headers.get("content-security-policy") ?? "";
      // With 'strict-dynamic' + nonce, external URLs need not be listed in script-src
      expect(csp).toMatch(
        /script-src 'nonce-[A-Za-z0-9+/]+=*' 'strict-dynamic'/,
      );
      const nonceMatch = csp.match(/'nonce-([A-Za-z0-9+/]+=*)'/);
      expect(nonceMatch).not.toBeNull();
      const nonce = nonceMatch?.[1];
      const body = await res.text();
      expect(body).toContain(`nonce="${nonce}" src="https://${BEACON_SRC}"`);
    });
  });
});
