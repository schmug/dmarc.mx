import { describe, expect, it } from "vitest";
import { app } from "../src/index.js";

describe("/learn/spf-too-many-lookups", () => {
  it("returns 200 with the limit, RFC citation, permerror and a pricing link", async () => {
    const res = await app.request("/learn/spf-too-many-lookups");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("10");
    expect(html).toContain("RFC 7208");
    expect(html).toContain("permerror");
    expect(html).toContain('href="/pricing"');
  });

  it("is listed in the sitemap and linked from the learn hub and /learn/spf", async () => {
    const sitemap = await (await app.request("/sitemap.xml")).text();
    expect(sitemap).toContain(
      "<loc>https://dmarc.mx/learn/spf-too-many-lookups</loc>",
    );
    const hub = await (await app.request("/learn")).text();
    expect(hub).toContain('href="/learn/spf-too-many-lookups"');
    const spf = await (await app.request("/learn/spf")).text();
    expect(spf).toContain('href="/learn/spf-too-many-lookups"');
  });
});
