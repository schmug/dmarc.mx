import { describe, expect, it } from "vitest";
import { app } from "../src/index.js";

describe("/learn/sender-requirements", () => {
  it("returns 200 with the provider rules and a pricing link", async () => {
    const res = await app.request("/learn/sender-requirements");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("0.3%");
    expect(html).toContain("RFC 8058");
    expect(html).toContain("Outlook");
    expect(html).toContain('href="/pricing"');
  });

  it("is listed in the sitemap and linked from the learn hub", async () => {
    const sitemap = await (await app.request("/sitemap.xml")).text();
    expect(sitemap).toContain(
      "<loc>https://dmarc.mx/learn/sender-requirements</loc>",
    );
    const hub = await (await app.request("/learn")).text();
    expect(hub).toContain('href="/learn/sender-requirements"');
  });
});
