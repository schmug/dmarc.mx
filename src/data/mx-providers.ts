export interface MxProviderData {
  slug: string;
  name: string;
  operator: string;
  category: "email-platform" | "security-gateway" | "cdn";
  patterns: RegExp[];
  mxExamples: string[];
  description: string;
  headline: string;
  metaDescription: string;
}

export const MX_PROVIDERS: MxProviderData[] = [
  {
    slug: "outlook",
    name: "Microsoft 365",
    operator: "Microsoft",
    category: "email-platform",
    patterns: [
      /\.protection\.outlook\.com$/i,
      /\.olc\.protection\.outlook\.com$/i,
    ],
    mxExamples: [
      "yourdomain-com.mail.protection.outlook.com",
      "yourdomain-com.olc.protection.outlook.com",
    ],
    description:
      "Microsoft 365 / Exchange Online MX records — what the protection.outlook.com hostname means, how tenant routing works, and how to verify DMARC alignment.",
    headline: "Microsoft 365 MX records (protection.outlook.com)",
    metaDescription:
      "What does *.mail.protection.outlook.com mean in a DNS MX record? Microsoft 365 / Exchange Online routes inbound mail through these hostnames. Learn how tenant routing works and how to check DMARC alignment.",
  },
  {
    slug: "google",
    name: "Google Workspace",
    operator: "Google",
    category: "email-platform",
    patterns: [/\.google\.com$/i, /\.googlemail\.com$/i],
    mxExamples: [
      "aspmx.l.google.com",
      "alt1.aspmx.l.google.com",
      "alt2.aspmx.l.google.com",
      "alt3.aspmx.l.google.com",
      "alt4.aspmx.l.google.com",
    ],
    description:
      "Google Workspace MX records — what aspmx.l.google.com and the alt hostnames mean, MX priority setup, and how Google enforces DMARC for Workspace.",
    headline: "Google Workspace MX records (aspmx.l.google.com)",
    metaDescription:
      "What does aspmx.l.google.com mean in a DNS MX record? Google Workspace routes inbound mail through these five hostnames with specific priorities. Learn how to set them up and verify DMARC alignment.",
  },
  {
    slug: "mimecast",
    name: "Mimecast",
    operator: "Mimecast",
    category: "security-gateway",
    patterns: [/\.mimecast\.com$/i],
    mxExamples: [
      "us-smtp-inbound-1.mimecast.com",
      "us-smtp-inbound-2.mimecast.com",
      "eu-smtp-inbound-1.mimecast.com",
    ],
    description:
      "Mimecast MX records — how the mimecast.com gateway sits in front of Microsoft 365 or Google Workspace, what the regional hostnames mean, and DMARC considerations.",
    headline: "Mimecast MX records (*.mimecast.com)",
    metaDescription:
      "What does *.mimecast.com mean in a DNS MX record? Mimecast is an email security gateway that sits in front of Microsoft 365 or Google Workspace. Learn how it routes mail and what DMARC policies apply.",
  },
  {
    slug: "proofpoint",
    name: "Proofpoint",
    operator: "Proofpoint",
    category: "security-gateway",
    patterns: [/\.pphosted\.com$/i, /\.ppe-hosted\.com$/i],
    mxExamples: [
      "mail.pphosted.com",
      "mx-eu.pphosted.com",
      "inbound.ppe-hosted.com",
    ],
    description:
      "Proofpoint MX records — what pphosted.com and ppe-hosted.com mean, how Proofpoint Essentials differs from the enterprise product, and DMARC alignment with a gateway.",
    headline: "Proofpoint MX records (pphosted.com / ppe-hosted.com)",
    metaDescription:
      "What does pphosted.com or ppe-hosted.com mean in a DNS MX record? Proofpoint is an enterprise email security gateway. Learn how it routes inbound mail and how DMARC reporting flows through a gateway.",
  },
  {
    slug: "fastmail",
    name: "Fastmail",
    operator: "Fastmail",
    category: "email-platform",
    patterns: [/\.messagingengine\.com$/i, /\.fastmail\.com$/i],
    mxExamples: [
      "in1-smtp.messagingengine.com",
      "in2-smtp.messagingengine.com",
    ],
    description:
      "Fastmail MX records — what in1-smtp.messagingengine.com and in2-smtp.messagingengine.com mean, how Fastmail supports custom domains, and DMARC setup.",
    headline: "Fastmail MX records (messagingengine.com)",
    metaDescription:
      "What does in1-smtp.messagingengine.com mean in a DNS MX record? Fastmail routes inbound mail through messagingengine.com hostnames. Learn how to set up a custom domain with Fastmail and configure DMARC.",
  },
  {
    slug: "zoho",
    name: "Zoho Mail",
    operator: "Zoho",
    category: "email-platform",
    patterns: [/\.zoho\.com$/i, /\.zoho\.eu$/i, /\.zoho\.com\.au$/i],
    mxExamples: ["mx.zoho.com", "mx2.zoho.com", "mx3.zoho.com"],
    description:
      "Zoho Mail MX records — what mx.zoho.com, mx2.zoho.com, and mx3.zoho.com mean, MX priority requirements, and DMARC alignment for Zoho-hosted custom domains.",
    headline: "Zoho Mail MX records (mx.zoho.com)",
    metaDescription:
      "What does mx.zoho.com mean in a DNS MX record? Zoho Mail routes custom-domain inbound mail through three MX hostnames with specific priorities. Learn how to set them up and configure DMARC.",
  },
  {
    slug: "amazon-ses",
    name: "Amazon SES",
    operator: "Amazon Web Services",
    category: "email-platform",
    patterns: [/inbound-smtp\.[a-z0-9-]+\.amazonaws\.com$/i],
    mxExamples: [
      "inbound-smtp.us-east-1.amazonaws.com",
      "inbound-smtp.eu-west-1.amazonaws.com",
    ],
    description:
      "Amazon SES inbound MX records — what inbound-smtp.*.amazonaws.com means, how SES inbound email processing works per region, and DMARC considerations for SES.",
    headline: "Amazon SES inbound MX records (amazonaws.com)",
    metaDescription:
      "What does inbound-smtp.us-east-1.amazonaws.com mean in a DNS MX record? Amazon SES routes inbound mail through regional amazonaws.com hostnames. Learn how SES inbound processing works and how to configure DMARC.",
  },
  {
    slug: "cloudflare",
    name: "Cloudflare Email Routing",
    operator: "Cloudflare",
    category: "email-platform",
    patterns: [/\.mx\.cloudflare\.net$/i],
    mxExamples: [
      "route1.mx.cloudflare.net",
      "route2.mx.cloudflare.net",
      "route3.mx.cloudflare.net",
    ],
    description:
      "Cloudflare Email Routing MX records — what route1-3.mx.cloudflare.net means, how Cloudflare Email Routing forwards mail to another inbox, and DMARC behavior.",
    headline: "Cloudflare Email Routing MX records (mx.cloudflare.net)",
    metaDescription:
      "What does route1.mx.cloudflare.net mean in a DNS MX record? Cloudflare Email Routing is a free forwarding service that relays custom-domain email to another inbox. Learn how it works and what DMARC posture to use.",
  },
];

export function lookupMxSlug(exchange: string): string | undefined {
  const normalized = exchange.toLowerCase().replace(/\.$/, "");
  for (const provider of MX_PROVIDERS) {
    for (const pattern of provider.patterns) {
      if (pattern.test(normalized)) {
        return provider.slug;
      }
    }
  }
  return undefined;
}

export function getMxProvider(slug: string): MxProviderData | undefined {
  return MX_PROVIDERS.find((p) => p.slug === slug);
}
