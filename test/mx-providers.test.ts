import { describe, expect, it } from "vitest";
import { lookupMxSlug, MX_PROVIDERS } from "../src/data/mx-providers.js";
import { app } from "../src/index.js";

describe("lookupMxSlug", () => {
  it("matches Microsoft 365 protection.outlook.com hostnames", () => {
    expect(lookupMxSlug("github-com.mail.protection.outlook.com")).toBe(
      "outlook",
    );
    expect(lookupMxSlug("contoso-com.mail.protection.outlook.com")).toBe(
      "outlook",
    );
    expect(lookupMxSlug("contoso-com.olc.protection.outlook.com")).toBe(
      "outlook",
    );
  });

  it("matches Google Workspace hostnames", () => {
    expect(lookupMxSlug("aspmx.l.google.com")).toBe("google");
    expect(lookupMxSlug("alt1.aspmx.l.google.com")).toBe("google");
    expect(lookupMxSlug("alt4.aspmx.l.google.com")).toBe("google");
    expect(lookupMxSlug("aspmx2.googlemail.com")).toBe("google");
  });

  it("matches Mimecast hostnames", () => {
    expect(lookupMxSlug("us-smtp-inbound-1.mimecast.com")).toBe("mimecast");
    expect(lookupMxSlug("eu-smtp-inbound-2.mimecast.com")).toBe("mimecast");
  });

  it("matches Proofpoint pphosted.com hostnames", () => {
    expect(lookupMxSlug("mail.pphosted.com")).toBe("proofpoint");
    expect(lookupMxSlug("mx-eu.pphosted.com")).toBe("proofpoint");
  });

  it("matches Proofpoint ppe-hosted.com hostnames", () => {
    expect(lookupMxSlug("inbound.ppe-hosted.com")).toBe("proofpoint");
  });

  it("matches Fastmail messagingengine.com hostnames", () => {
    expect(lookupMxSlug("in1-smtp.messagingengine.com")).toBe("fastmail");
    expect(lookupMxSlug("in2-smtp.messagingengine.com")).toBe("fastmail");
  });

  it("matches Zoho Mail hostnames", () => {
    expect(lookupMxSlug("mx.zoho.com")).toBe("zoho");
    expect(lookupMxSlug("mx2.zoho.com")).toBe("zoho");
    expect(lookupMxSlug("mx3.zoho.com")).toBe("zoho");
  });

  it("matches Amazon SES inbound hostnames", () => {
    expect(lookupMxSlug("inbound-smtp.us-east-1.amazonaws.com")).toBe(
      "amazon-ses",
    );
    expect(lookupMxSlug("inbound-smtp.eu-west-1.amazonaws.com")).toBe(
      "amazon-ses",
    );
    expect(lookupMxSlug("inbound-smtp.us-west-2.amazonaws.com")).toBe(
      "amazon-ses",
    );
  });

  it("matches Cloudflare Email Routing hostnames", () => {
    expect(lookupMxSlug("route1.mx.cloudflare.net")).toBe("cloudflare");
    expect(lookupMxSlug("route2.mx.cloudflare.net")).toBe("cloudflare");
    expect(lookupMxSlug("route3.mx.cloudflare.net")).toBe("cloudflare");
  });

  it("is case-insensitive", () => {
    expect(lookupMxSlug("ASPMX.L.GOOGLE.COM")).toBe("google");
    expect(lookupMxSlug("GITHUB-COM.MAIL.PROTECTION.OUTLOOK.COM")).toBe(
      "outlook",
    );
  });

  it("strips trailing dot from FQDN", () => {
    expect(lookupMxSlug("aspmx.l.google.com.")).toBe("google");
    expect(lookupMxSlug("route1.mx.cloudflare.net.")).toBe("cloudflare");
  });

  it("returns undefined for unknown hostnames", () => {
    expect(lookupMxSlug("mail.example.com")).toBeUndefined();
    expect(lookupMxSlug("mx.unknown-provider.net")).toBeUndefined();
    expect(lookupMxSlug("")).toBeUndefined();
  });

  it("does not match partial domain names (no false substring matches)", () => {
    expect(lookupMxSlug("notgoogle.com")).toBeUndefined();
    expect(lookupMxSlug("fakeoutlook.com")).toBeUndefined();
    expect(lookupMxSlug("mimecast.com.attacker.net")).toBeUndefined();
  });
});

describe("MX_PROVIDERS data integrity", () => {
  it("each provider has a unique slug", () => {
    const slugs = MX_PROVIDERS.map((p) => p.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it("each provider has at least one pattern and one mxExample", () => {
    for (const p of MX_PROVIDERS) {
      expect(p.patterns.length).toBeGreaterThan(0);
      expect(p.mxExamples.length).toBeGreaterThan(0);
    }
  });

  it("each provider mxExample matches at least one of its patterns", () => {
    for (const p of MX_PROVIDERS) {
      for (const example of p.mxExamples) {
        const normalized = example.toLowerCase();
        const matched = p.patterns.some((pat) => pat.test(normalized));
        expect(matched, `${example} should match a pattern for ${p.slug}`).toBe(
          true,
        );
      }
    }
  });
});

describe("/mx routes", () => {
  it("GET /mx returns 200 with hub content", async () => {
    const res = await app.request("/mx");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("What does this MX hostname mean");
    expect(html).toContain("/mx/outlook");
    expect(html).toContain("/mx/google");
  });

  it("GET /mx/outlook returns 200 with Microsoft 365 content", async () => {
    const res = await app.request("/mx/outlook");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("protection.outlook.com");
    expect(html).toContain("Microsoft 365");
  });

  it("GET /mx/google returns 200 with Google Workspace content", async () => {
    const res = await app.request("/mx/google");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("aspmx.l.google.com");
    expect(html).toContain("Google Workspace");
  });

  it("GET /mx/mimecast returns 200", async () => {
    const res = await app.request("/mx/mimecast");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("mimecast.com");
  });

  it("GET /mx/proofpoint returns 200", async () => {
    const res = await app.request("/mx/proofpoint");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("pphosted.com");
  });

  it("GET /mx/fastmail returns 200", async () => {
    const res = await app.request("/mx/fastmail");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("messagingengine.com");
  });

  it("GET /mx/zoho returns 200", async () => {
    const res = await app.request("/mx/zoho");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("mx.zoho.com");
  });

  it("GET /mx/amazon-ses returns 200", async () => {
    const res = await app.request("/mx/amazon-ses");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("amazonaws.com");
  });

  it("GET /mx/cloudflare returns 200", async () => {
    const res = await app.request("/mx/cloudflare");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("cloudflare.net");
  });

  it("GET /mx/unknown-slug returns 404", async () => {
    const res = await app.request("/mx/not-a-real-provider");
    expect(res.status).toBe(404);
  });

  it("all 8 provider slugs return 200", async () => {
    const slugs = [
      "outlook",
      "google",
      "mimecast",
      "proofpoint",
      "fastmail",
      "zoho",
      "amazon-ses",
      "cloudflare",
    ];
    for (const slug of slugs) {
      const res = await app.request(`/mx/${slug}`);
      expect(res.status, `expected 200 for /mx/${slug}`).toBe(200);
    }
  });
});

describe("/mx sitemap entries", () => {
  it("sitemap includes /mx hub and all 8 provider pages", async () => {
    const res = await app.request("/sitemap.xml");
    const xml = await res.text();
    expect(xml).toContain("https://dmarc.mx/mx");
    expect(xml).toContain("https://dmarc.mx/mx/outlook");
    expect(xml).toContain("https://dmarc.mx/mx/google");
    expect(xml).toContain("https://dmarc.mx/mx/mimecast");
    expect(xml).toContain("https://dmarc.mx/mx/proofpoint");
    expect(xml).toContain("https://dmarc.mx/mx/fastmail");
    expect(xml).toContain("https://dmarc.mx/mx/zoho");
    expect(xml).toContain("https://dmarc.mx/mx/amazon-ses");
    expect(xml).toContain("https://dmarc.mx/mx/cloudflare");
  });
});
