import { describe, expect, it } from "vitest";
import { app } from "../src/index.js";
import { FIX_PAGES } from "../src/views/learn-fixes.js";

describe("/learn fix pages", () => {
  it.each(FIX_PAGES.map((p) => p.slug))(
    "/learn/%s renders with title, scan CTA and pricing link",
    async (slug) => {
      const page = FIX_PAGES.find((p) => p.slug === slug);
      const res = await app.request(`/learn/${slug}`);
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain(`<title>${page?.title}`);
      expect(html).toContain('href="/pricing"');
      expect(html).toContain(
        '<link rel="canonical" href="https://dmarc.mx/learn/' + slug,
      );
    },
  );

  it("lists every fix page in the sitemap and links it from the learn hub", async () => {
    const sitemap = await (await app.request("/sitemap.xml")).text();
    const hub = await (await app.request("/learn")).text();
    for (const { slug } of FIX_PAGES) {
      expect(sitemap).toContain(`<loc>https://dmarc.mx/learn/${slug}</loc>`);
      expect(hub).toContain(`href="/learn/${slug}"`);
    }
  });

  it("only links to internal pages that exist", async () => {
    for (const { body } of FIX_PAGES) {
      for (const [, href] of body.matchAll(/href="(\/[^"#]*)"/g)) {
        const res = await app.request(href);
        expect(res.status, href).not.toBe(404);
      }
    }
  });
});
