import { describe, expect, it } from "vitest";
import {
  getMxProvider,
  lookupMxProvider,
  MX_PROVIDERS,
} from "../src/data/mx-providers.js";

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
