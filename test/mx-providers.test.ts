import { describe, expect, it } from "vitest";
import {
  getMxProvider,
  lookupMxProvider,
  MX_PROVIDERS,
} from "../src/data/mx-providers.js";
import { renderMxProviderMarkdown } from "../src/views/markdown.js";
import { renderMxProviderPage } from "../src/views/mx.js";

describe("lookupMxProvider", () => {
  it("matches Microsoft 365 MX hostnames", () => {
    expect(
      lookupMxProvider("github-com.mail.protection.outlook.com")?.slug,
    ).toBe("outlook");
    expect(
      lookupMxProvider("contoso-onmicrosoft-com.mail.protection.outlook.com")
        ?.slug,
    ).toBe("outlook");
  });

  it("matches Google Workspace MX hostnames", () => {
    expect(lookupMxProvider("aspmx.l.google.com")?.slug).toBe("google");
    expect(lookupMxProvider("alt1.aspmx.l.google.com")?.slug).toBe("google");
    expect(lookupMxProvider("alt4.aspmx.l.google.com")?.slug).toBe("google");
  });

  it("matches Mimecast", () => {
    expect(lookupMxProvider("us-smtp-inbound-1.mimecast.com")?.slug).toBe(
      "mimecast",
    );
  });

  it("distinguishes Proofpoint Enterprise (pphosted) from Essentials (ppe-hosted)", () => {
    // Both currently map to the same /mx/proofpoint page, but the lookup must
    // succeed for either family — the distinction is documented on the page,
    // not in the catalog routing.
    expect(lookupMxProvider("mx0a-001a8b01.pphosted.com")?.slug).toBe(
      "proofpoint",
    );
    expect(lookupMxProvider("mx1-us1.ppe-hosted.com")?.slug).toBe("proofpoint");
  });

  it("matches Fastmail by messagingengine.com, not fastmail.com", () => {
    expect(lookupMxProvider("in1-smtp.messagingengine.com")?.slug).toBe(
      "fastmail",
    );
    expect(lookupMxProvider("in2-smtp.messagingengine.com")?.slug).toBe(
      "fastmail",
    );
  });

  it("matches Zoho Mail across regions", () => {
    expect(lookupMxProvider("mx.zoho.com")?.slug).toBe("zoho");
    expect(lookupMxProvider("mx2.zoho.eu")?.slug).toBe("zoho");
    expect(lookupMxProvider("mx.zoho.in")?.slug).toBe("zoho");
  });

  it("matches Amazon SES across regions", () => {
    expect(lookupMxProvider("inbound-smtp.us-east-1.amazonaws.com")?.slug).toBe(
      "amazon-ses",
    );
    expect(lookupMxProvider("inbound-smtp.eu-west-1.amazonaws.com")?.slug).toBe(
      "amazon-ses",
    );
    expect(
      lookupMxProvider("inbound-smtp.ap-southeast-2.amazonaws.com")?.slug,
    ).toBe("amazon-ses");
  });

  it("matches Cloudflare Email Routing", () => {
    expect(lookupMxProvider("route1.mx.cloudflare.net")?.slug).toBe(
      "cloudflare",
    );
    expect(lookupMxProvider("route3.mx.cloudflare.net")?.slug).toBe(
      "cloudflare",
    );
  });

  it("is case-insensitive", () => {
    expect(lookupMxProvider("ASPMX.L.GOOGLE.COM")?.slug).toBe("google");
    expect(
      lookupMxProvider("Github-Com.Mail.Protection.Outlook.Com")?.slug,
    ).toBe("outlook");
  });

  it("tolerates trailing dot from DNS resolvers", () => {
    expect(lookupMxProvider("aspmx.l.google.com.")?.slug).toBe("google");
    expect(lookupMxProvider("in1-smtp.messagingengine.com.")?.slug).toBe(
      "fastmail",
    );
  });

  it("returns undefined for unknown hostnames", () => {
    expect(lookupMxProvider("mail.custom-server.example.org")).toBeUndefined();
    expect(lookupMxProvider("smtp.acme.invalid")).toBeUndefined();
    expect(lookupMxProvider("")).toBeUndefined();
  });

  it("does not match arbitrary amazonaws.com hostnames (only inbound-smtp)", () => {
    expect(
      lookupMxProvider("email-smtp.us-east-1.amazonaws.com"),
    ).toBeUndefined();
    expect(lookupMxProvider("ec2.us-east-1.amazonaws.com")).toBeUndefined();
  });
});

describe("getMxProvider", () => {
  it("returns a provider by slug", () => {
    expect(getMxProvider("outlook")?.shortName).toBe("Microsoft 365");
    expect(getMxProvider("google")?.shortName).toBe("Google Workspace");
  });

  it("returns undefined for unknown slugs", () => {
    expect(getMxProvider("does-not-exist")).toBeUndefined();
    expect(getMxProvider("")).toBeUndefined();
  });
});

describe("MX_PROVIDERS catalog", () => {
  it("has 8 entries with unique slugs", () => {
    expect(MX_PROVIDERS).toHaveLength(8);
    const slugs = MX_PROVIDERS.map((p) => p.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it("requires every provider to have unique meta description and headline", () => {
    // Google demotes near-duplicate pages — keep this invariant tight.
    const descriptions = MX_PROVIDERS.map((p) => p.description);
    expect(new Set(descriptions).size).toBe(descriptions.length);
    const headlines = MX_PROVIDERS.map((p) => p.headline);
    expect(new Set(headlines).size).toBe(headlines.length);
  });

  it("requires every provider to declare at least one hostname pattern and example", () => {
    for (const p of MX_PROVIDERS) {
      expect(p.hostnames.length).toBeGreaterThan(0);
      expect(p.hostnameExamples.length).toBeGreaterThan(0);
    }
  });
});

describe("record guidance sections (#525)", () => {
  // One verified official record string per provider — sourced from vendor
  // docs (learn.microsoft.com, knowledge.workspace.google.com, Mimecast KB,
  // Proofpoint Essentials getting-started guides, fastmail.help, zoho.com,
  // docs.aws.amazon.com, developers.cloudflare.com). If one of these fails,
  // the page no longer quotes the canonical string admins search for.
  const EXPECTED_RECORD_STRINGS: Record<string, string[]> = {
    outlook: [
      "v=spf1 include:spf.protection.outlook.com -all",
      "selector1._domainkey",
    ],
    google: ["v=spf1 include:_spf.google.com ~all", "google._domainkey"],
    mimecast: ["include:us._netblocks.mimecast.com"],
    proofpoint: ["v=spf1 a:dispatch-us.ppe-hosted.com ~all"],
    fastmail: ["v=spf1 include:spf.messagingengine.com ?all", "fm1._domainkey"],
    zoho: ["include:zohomail.com"],
    "amazon-ses": ["v=spf1 include:amazonses.com ~all", "dkim.amazonses.com"],
    cloudflare: ["v=spf1 include:_spf.mx.cloudflare.net ~all"],
  };

  it("every provider has a record-guidance section", () => {
    for (const p of MX_PROVIDERS) {
      const guidance = p.sections.find((s) =>
        /SPF, DKIM, and DMARC records/i.test(s.title),
      );
      expect(
        guidance,
        `${p.slug} is missing a record-guidance section`,
      ).toBeDefined();
    }
  });

  it("each provider's HTML page contains its official record strings", () => {
    for (const [slug, strings] of Object.entries(EXPECTED_RECORD_STRINGS)) {
      const html = renderMxProviderPage(slug);
      expect(html, `no HTML page for ${slug}`).not.toBeNull();
      for (const s of strings) {
        expect(html, `${slug} HTML page is missing "${s}"`).toContain(s);
      }
    }
  });

  it("each provider's markdown rendering contains its official record strings", () => {
    for (const [slug, strings] of Object.entries(EXPECTED_RECORD_STRINGS)) {
      const md = renderMxProviderMarkdown(slug);
      expect(md, `no markdown rendering for ${slug}`).not.toBeNull();
      for (const s of strings) {
        expect(md, `${slug} markdown is missing "${s}"`).toContain(s);
      }
    }
  });

  it("no two providers share identical section prose", () => {
    // Google demotes duplicate-shaped content (#364) — every paragraph on
    // every provider page must be written for that provider, not stamped
    // from a template.
    const seen = new Map<string, string>();
    for (const p of MX_PROVIDERS) {
      for (const section of p.sections) {
        for (const paragraph of section.paragraphs) {
          const firstOwner = seen.get(paragraph);
          expect(
            firstOwner,
            `paragraph shared by ${firstOwner} and ${p.slug}: "${paragraph.slice(0, 60)}..."`,
          ).toBeUndefined();
          seen.set(paragraph, p.slug);
        }
      }
    }
  });
});
