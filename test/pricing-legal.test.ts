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

describe("pricing page", () => {
  it("GET /pricing returns indexable HTML", async () => {
    const res = await app.request("/pricing");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toMatch(/^text\/html/);
    const html = await res.text();
    expect(html).not.toContain('name="robots"');
    expect(html).toContain(
      '<link rel="canonical" href="https://dmarc.mx/pricing">',
    );
  });

  it("advertises $19/mo, nightly monitoring, and every protocol name in the hero", async () => {
    const res = await app.request("/pricing");
    const html = await res.text();
    expect(html).toContain("$19/mo");
    expect(html).toContain("Nightly email-security monitoring");
    expect(html).toContain("DMARC");
    expect(html).toContain("MTA-STS");
  });

  it("links upgrade CTA to /dashboard/billing/subscribe", async () => {
    const res = await app.request("/pricing");
    const html = await res.text();
    expect(html).toContain('href="/dashboard/billing/subscribe"');
  });

  it("includes the explicit 'not in Pro' list", async () => {
    const res = await app.request("/pricing");
    const html = await res.text();
    expect(html).toContain("RUA");
    expect(html.toLowerCase()).toContain("team seats");
    expect(html.toLowerCase()).toContain("white-label");
  });

  it("exposes Product/Offer + FAQPage JSON-LD", async () => {
    const res = await app.request("/pricing");
    const html = await res.text();
    expect(html).toContain('"@type":"Product"');
    expect(html).toContain('"@type":"FAQPage"');
    expect(html).toContain('"price":"19"');
    expect(html).toContain('"priceCurrency":"USD"');
  });

  it("markdown rendering honors Accept: text/markdown", async () => {
    const res = await app.request("/pricing", {
      headers: { Accept: "text/markdown" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe(
      "text/markdown; charset=utf-8",
    );
    const body = await res.text();
    expect(body).toContain("$19/mo");
    expect(body).toContain("Nightly email-security monitoring");
    expect(body).not.toMatch(/\[PLACEHOLDER/);
  });

  it("sitemap.xml lists /pricing", async () => {
    const res = await app.request("/sitemap.xml");
    const body = await res.text();
    expect(body).toContain("<loc>https://dmarc.mx/pricing</loc>");
  });
});

describe("privacy policy", () => {
  it("GET /legal/privacy returns indexable HTML", async () => {
    const res = await app.request("/legal/privacy");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toMatch(/^text\/html/);
    const html = await res.text();
    expect(html).not.toContain('name="robots"');
    expect(html).toContain(
      '<link rel="canonical" href="https://dmarc.mx/legal/privacy">',
    );
    expect(html).toContain("Privacy Policy");
  });

  it("uses first-person voice and names DMarcus as operator", async () => {
    const res = await app.request("/legal/privacy");
    const html = await res.text();
    expect(html).toContain("DMarcus");
    expect(html).toContain("Who I am");
    expect(html).toContain("What I collect");
    expect(html).toContain("How long I keep it");
  });

  it("contains the anti-AI-training trust line", async () => {
    const res = await app.request("/legal/privacy");
    const html = await res.text();
    expect(html.toLowerCase()).toContain("not using this to train ai");
  });

  it("lists the five subprocessors", async () => {
    const res = await app.request("/legal/privacy");
    const html = await res.text();
    for (const proc of [
      "Cloudflare",
      "WorkOS",
      "Stripe",
      "Cloudflare Email Sending",
      "Sentry",
    ]) {
      expect(html).toContain(proc);
    }
  });

  it("discloses Cloudflare Web Analytics in 'What I collect' and subprocessor list", async () => {
    const res = await app.request("/legal/privacy");
    const html = await res.text();
    expect(html).toContain("Cloudflare Web Analytics");
    expect(html).toContain("cookieless beacon");
    // Subprocessor line folds Web Analytics into the Cloudflare entry
    expect(html).toMatch(/Cloudflare[^<]*Web Analytics/);
  });

  it("does not contain placeholder markers or pending banners", async () => {
    const res = await app.request("/legal/privacy");
    const html = await res.text();
    expect(html).not.toMatch(/\[PLACEHOLDER/);
    expect(html.toLowerCase()).not.toContain("legal text pending");
    expect(html.toLowerCase()).not.toContain("copy pending");
    expect(html.toLowerCase()).not.toContain("coming soon");
  });

  it("links support@dmarc.mx as the contact", async () => {
    const res = await app.request("/legal/privacy");
    const html = await res.text();
    expect(html).toContain('href="mailto:support@dmarc.mx"');
  });

  it("markdown rendering honors Accept: text/markdown", async () => {
    const res = await app.request("/legal/privacy", {
      headers: { Accept: "text/markdown" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe(
      "text/markdown; charset=utf-8",
    );
    const body = await res.text();
    expect(body).toContain("# Privacy Policy");
    expect(body).toContain("DMarcus");
    expect(body).not.toMatch(/\[PLACEHOLDER/);
  });

  it("sitemap.xml lists /legal/privacy", async () => {
    const res = await app.request("/sitemap.xml");
    const body = await res.text();
    expect(body).toContain("<loc>https://dmarc.mx/legal/privacy</loc>");
  });
});

describe("removed legal routes (terms + index)", () => {
  it("GET /legal/terms returns 404", async () => {
    const res = await app.request("/legal/terms");
    expect(res.status).toBe(404);
  });

  it("GET /legal returns 404", async () => {
    const res = await app.request("/legal");
    expect(res.status).toBe(404);
  });

  it("sitemap.xml does not list /legal/terms or /legal index", async () => {
    const res = await app.request("/sitemap.xml");
    const body = await res.text();
    expect(body).not.toContain("<loc>https://dmarc.mx/legal/terms</loc>");
    expect(body).not.toContain("<loc>https://dmarc.mx/legal</loc>");
  });
});

describe("site footer links", () => {
  it("landing footer links to /pricing and /legal/privacy only", async () => {
    const res = await app.request("/");
    const html = await res.text();
    expect(html).toContain('href="/pricing"');
    expect(html).toContain('href="/legal/privacy"');
    expect(html).not.toContain('href="/legal/terms"');
  });

  it("scoring page footer links to /pricing and /legal/privacy only", async () => {
    const res = await app.request("/scoring");
    const html = await res.text();
    expect(html).toContain('href="/pricing"');
    expect(html).toContain('href="/legal/privacy"');
    expect(html).not.toContain('href="/legal/terms"');
  });

  it("pricing page footer references Privacy only (not Terms)", async () => {
    const res = await app.request("/pricing");
    const html = await res.text();
    expect(html).toContain('href="/legal/privacy"');
    expect(html).not.toContain('href="/legal/terms"');
  });

  it("indexable pages (/, /scoring, /pricing, /legal/privacy) stay free of noindex", async () => {
    for (const path of ["/", "/scoring", "/pricing", "/legal/privacy"]) {
      const res = await app.request(path);
      const html = await res.text();
      expect(html).not.toContain('name="robots"');
    }
  });
});
