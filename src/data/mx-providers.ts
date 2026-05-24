// MX provider catalog. Powers two surfaces:
//   1. The /mx/<slug> SEO pages (one ranking target per common MX host) —
//      see src/views/mx.ts and src/views/markdown.ts.
//   2. The MX card on /check?domain=... — components.ts looks up the provider
//      for each MX record and links the badge to /mx/<slug> when matched.
//
// The MX analyzer's own PROVIDER_SIGNATURES (src/analyzers/mx.ts) is tuned for
// detection labels and is intentionally not the source for these patterns —
// some entries here are more specific (e.g. messagingengine.com, not
// fastmail.com, is the real Fastmail inbound MX).

export interface MxProviderSection {
  title: string;
  paragraphs: string[];
  list?: string[];
}

export interface MxProvider {
  slug: string;
  /** Long form used in <title> and meta og:title. */
  displayName: string;
  /** Short form used in breadcrumbs and badge link text. */
  shortName: string;
  /** Vendor that operates the service (publisher in JSON-LD). */
  operator: string;
  /** Patterns matched case-insensitively against the MX exchange (after
   * lowercasing and stripping the trailing dot). Order matters only for
   * collisions — the first match wins. */
  hostnames: RegExp[];
  /** Verbatim hostname strings to show on the page ("how it appears in DNS"). */
  hostnameExamples: string[];
  /** Common parent domains using this provider. Rendered as scan-link CTAs. */
  parentExamples: string[];
  /** Meta description — must be unique per provider per the SEO contract. */
  description: string;
  /** H1 / og:title body — must be unique per provider. */
  headline: string;
  /** First paragraph rendered as the page intro. */
  intro: string;
  /** Body sections rendered as bd-cards (HTML) or H2s (markdown). */
  sections: MxProviderSection[];
}

const OUTLOOK_DESCRIPTION =
  "Microsoft 365 (formerly Office 365) routes inbound mail through *.mail.protection.outlook.com. Here's what that MX hostname is, who runs it, and which large domains use it.";

const GOOGLE_DESCRIPTION =
  "Google Workspace receives mail at aspmx.l.google.com and four alt MX hosts. Here's what those hostnames mean, who runs them, and how to spot a Workspace tenant.";

const MIMECAST_DESCRIPTION =
  "Mimecast is a perimeter security gateway, not a mailbox host — *.mimecast.com MX hostnames sit in front of Microsoft 365 or Google Workspace. Here's how to read them.";

const PROOFPOINT_DESCRIPTION =
  "Proofpoint runs *.pphosted.com (enterprise) and *.ppe-hosted.com (Essentials/SMB) as MX-front-ends in front of customer mailbox tenants. Here's how to identify each.";

const FASTMAIL_DESCRIPTION =
  "Fastmail's inbound MX hosts are in1-smtp.messagingengine.com and in2-smtp.messagingengine.com — not fastmail.com. The MessagingEngine name trips up most lookup tools.";

const ZOHO_DESCRIPTION =
  "Zoho Mail's inbound MX hosts are mx.zoho.com / mx2.zoho.com (or mx.zoho.eu / mx.zoho.in for regional plans). Here's what those mean and which businesses use them.";

const SES_DESCRIPTION =
  "Amazon SES receives mail at inbound-smtp.<region>.amazonaws.com. The region in the hostname tells you which AWS region the receiving account uses.";

const CLOUDFLARE_DESCRIPTION =
  "Cloudflare Email Routing uses route1-3.mx.cloudflare.net as inbound MX hosts. It's a free forwarding service — useful for catch-alls, not a full mailbox.";

export const MX_PROVIDERS: readonly MxProvider[] = [
  {
    slug: "outlook",
    displayName: "Microsoft 365 / Exchange Online",
    shortName: "Microsoft 365",
    operator: "Microsoft",
    hostnames: [
      /\.mail\.protection\.outlook\.com$/,
      /\.olc\.protection\.outlook\.com$/,
    ],
    hostnameExamples: [
      "<tenant>.mail.protection.outlook.com",
      "<tenant>-com.mail.protection.outlook.com",
      "<tenant>.olc.protection.outlook.com",
    ],
    parentExamples: ["github.com", "microsoft.com", "linkedin.com"],
    description: OUTLOOK_DESCRIPTION,
    headline:
      "What is *.mail.protection.outlook.com? Microsoft 365 inbound MX explained",
    intro:
      "An MX record that ends in <code>mail.protection.outlook.com</code> means the domain receives mail through Microsoft 365 — formerly Office 365, and the same service that powers Exchange Online tenants. The slug before <code>mail.protection.outlook.com</code> is the tenant identifier, derived from the primary domain with dots replaced by dashes.",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Microsoft 365 publishes a single MX target per tenant. The hostname is generated from the domain name itself, so it's easy to recognise once you've seen the pattern.",
        ],
        list: [
          "<code>github.com</code> &rarr; <code>github-com.mail.protection.outlook.com</code>",
          "<code>microsoft.com</code> &rarr; <code>microsoft-com.mail.protection.outlook.com</code>",
          "Government Community Cloud (GCC) tenants use <code>*.olc.protection.outlook.com</code> instead — same operator, different ring.",
        ],
      },
      {
        title: "Who runs it",
        paragraphs: [
          "Microsoft 365 is operated by Microsoft. The MX endpoint is part of Exchange Online Protection (EOP), which performs anti-spam and anti-malware filtering before mail lands in the tenant's mailbox. Customers can layer a third-party gateway (Mimecast, Proofpoint, etc.) in front of EOP, in which case EOP becomes the secondary destination and the gateway's MX is what you'll see externally.",
        ],
      },
      {
        title: "How to tell it's actually Microsoft 365",
        paragraphs: [
          "The MX hostname alone is enough — only Microsoft can serve that domain. If you want a second signal, look at the SPF record: a Microsoft 365 tenant will <code>include:spf.protection.outlook.com</code>. The DKIM keys live at <code>selector1._domainkey</code> and <code>selector2._domainkey</code> and point at <code>selector*-&lt;tenant&gt;._domainkey.&lt;tenant&gt;.onmicrosoft.com</code>.",
        ],
      },
    ],
  },
  {
    slug: "google",
    displayName: "Google Workspace (Gmail)",
    shortName: "Google Workspace",
    operator: "Google",
    hostnames: [
      /^aspmx\.l\.google\.com$/,
      /^alt[1-4]\.aspmx\.l\.google\.com$/,
      /^aspmx[2-5]\.googlemail\.com$/,
      /\.googlemail\.com$/,
    ],
    hostnameExamples: [
      "aspmx.l.google.com",
      "alt1.aspmx.l.google.com",
      "alt2.aspmx.l.google.com",
      "alt3.aspmx.l.google.com",
      "alt4.aspmx.l.google.com",
    ],
    parentExamples: ["google.com", "stripe.com", "ycombinator.com"],
    description: GOOGLE_DESCRIPTION,
    headline:
      "What is aspmx.l.google.com? Google Workspace inbound MX explained",
    intro:
      "An MX record set that lists <code>aspmx.l.google.com</code> as the primary plus four <code>alt[1-4].aspmx.l.google.com</code> hosts is Google Workspace — the business mail service formerly known as G Suite and, before that, Google Apps. Every Workspace tenant uses the same five hostnames, regardless of which domain they're for.",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Workspace's recommended MX configuration is five records with different priorities. The primary is the lowest priority value; the alt hosts are stand-bys for when the primary is at capacity or unreachable.",
        ],
        list: [
          "<code>1 aspmx.l.google.com</code>",
          "<code>5 alt1.aspmx.l.google.com</code>",
          "<code>5 alt2.aspmx.l.google.com</code>",
          "<code>10 alt3.aspmx.l.google.com</code>",
          "<code>10 alt4.aspmx.l.google.com</code>",
        ],
      },
      {
        title: "Who runs it",
        paragraphs: [
          "Google Workspace is operated by Google. The MX endpoints terminate at Gmail's anti-spam and anti-malware infrastructure — the same engine that handles consumer Gmail, configured for the tenant's domain.",
        ],
      },
      {
        title: "Identifying a Workspace tenant",
        paragraphs: [
          "Unlike Microsoft 365's per-tenant hostname, every Workspace customer shares the same MX hosts — so the MX alone doesn't reveal the tenant. The tenant identifier shows up elsewhere: the SPF record includes <code>_spf.google.com</code>, and DKIM uses <code>google._domainkey</code> by default. If the domain publishes DMARC with a <code>rua</code> mailto pointing at <code>*.google.com</code>, that's another tell.",
        ],
      },
    ],
  },
  {
    slug: "mimecast",
    displayName: "Mimecast Secure Email Gateway",
    shortName: "Mimecast",
    operator: "Mimecast",
    hostnames: [/\.mimecast\.com$/, /\.mimecast\.co\.za$/],
    hostnameExamples: [
      "<tenant>-com.mail.eu.mimecast.com",
      "<tenant>-com.mail.us.mimecast.com",
      "<tenant>-com.mail.za.mimecast.com",
    ],
    parentExamples: ["barclays.com", "publix.com"],
    description: MIMECAST_DESCRIPTION,
    headline:
      "What is *.mimecast.com? Mimecast secure email gateway, explained",
    intro:
      "Mimecast is a security gateway, not a mailbox provider. When a domain's MX points at <code>*.mimecast.com</code>, inbound mail lands at Mimecast first — Mimecast performs anti-spam, anti-phishing, sandboxing and policy enforcement, and then relays the cleaned mail to the customer's actual mailbox host (most commonly Microsoft 365 or Google Workspace).",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Mimecast hostnames embed a region segment that tells you which data centre the tenant is provisioned in.",
        ],
        list: [
          "<code>*.mail.eu.mimecast.com</code> — Europe",
          "<code>*.mail.us.mimecast.com</code> — North America",
          "<code>*.mail.za.mimecast.com</code> — South Africa",
          "<code>*.mail.au.mimecast.com</code> — Australia/Pacific",
        ],
      },
      {
        title: "Gateway vs platform",
        paragraphs: [
          "If you see a Mimecast MX hostname externally and a Microsoft 365 or Google Workspace fingerprint internally (in SPF, DKIM, or auto-discover), that's expected — the gateway is the inbound front-door, not the mailbox. From an attacker's perspective the surface is still the upstream platform; the gateway is a filter, not an authoritative MTA for the tenant.",
        ],
      },
      {
        title: "Who runs it",
        paragraphs: [
          "Mimecast Limited, headquartered in the UK, runs the service. It's a publicly-known enterprise email security vendor used by tens of thousands of organisations, often in regulated industries where a separate filtering perimeter is a compliance requirement.",
        ],
      },
    ],
  },
  {
    slug: "proofpoint",
    displayName: "Proofpoint email protection",
    shortName: "Proofpoint",
    operator: "Proofpoint",
    hostnames: [/\.pphosted\.com$/, /\.ppe-hosted\.com$/],
    hostnameExamples: [
      "mx0a-<tenant>.pphosted.com",
      "mx0b-<tenant>.pphosted.com",
      "mx1-<region>.ppe-hosted.com",
    ],
    parentExamples: ["uber.com", "intuit.com"],
    description: PROOFPOINT_DESCRIPTION,
    headline:
      "What is *.pphosted.com and *.ppe-hosted.com? Proofpoint MX explained",
    intro:
      "Two MX hostname families both belong to Proofpoint. <code>*.pphosted.com</code> is the enterprise tier — large organisations on Proofpoint's flagship Enterprise Protection product. <code>*.ppe-hosted.com</code> is Proofpoint Essentials, the SMB tier sold through partner MSPs. Both are perimeter filtering gateways in front of the customer's real mailbox host.",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Enterprise Protection publishes a pair of MX records with <code>mx0a-</code> and <code>mx0b-</code> prefixes for high availability. The slug after the prefix is a tenant identifier.",
        ],
        list: [
          "<code>10 mx0a-&lt;tenant&gt;.pphosted.com</code>",
          "<code>10 mx0b-&lt;tenant&gt;.pphosted.com</code>",
          "Essentials customers see <code>mx1-&lt;region&gt;.ppe-hosted.com</code> and <code>mx2-&lt;region&gt;.ppe-hosted.com</code>.",
        ],
      },
      {
        title: "Enterprise vs Essentials",
        paragraphs: [
          "The two product lines have different feature sets, different administrative consoles, and different SLAs, but they share the Proofpoint detection engine. From a recipient's perspective the difference matters mostly for who to contact about a false-positive — Essentials is partner-supported, Enterprise is direct.",
        ],
      },
      {
        title: "Who runs it",
        paragraphs: [
          "Proofpoint, Inc. is a US-based security vendor (now owned by Thoma Bravo since 2021). It's one of the largest commercial email security providers, particularly common in financial services, healthcare and government supply chains.",
        ],
      },
    ],
  },
  {
    slug: "fastmail",
    displayName: "Fastmail",
    shortName: "Fastmail",
    operator: "Fastmail Pty Ltd",
    hostnames: [
      /^in1-smtp\.messagingengine\.com$/,
      /^in2-smtp\.messagingengine\.com$/,
      /\.messagingengine\.com$/,
    ],
    hostnameExamples: [
      "in1-smtp.messagingengine.com",
      "in2-smtp.messagingengine.com",
    ],
    parentExamples: ["fastmail.com", "fastmail.fm"],
    description: FASTMAIL_DESCRIPTION,
    headline:
      "What is in1-smtp.messagingengine.com? Fastmail inbound MX explained",
    intro:
      "Fastmail's inbound MX hosts are <code>in1-smtp.messagingengine.com</code> and <code>in2-smtp.messagingengine.com</code>. The <code>messagingengine.com</code> domain — not <code>fastmail.com</code> — is what trips up most reverse-lookup tools: <code>messagingengine.com</code> is Fastmail's infrastructure brand, used for SMTP, IMAP, and SPF includes as well.",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Fastmail publishes two MX records with equal priority for round-robin delivery.",
        ],
        list: [
          "<code>10 in1-smtp.messagingengine.com</code>",
          "<code>20 in2-smtp.messagingengine.com</code>",
        ],
      },
      {
        title: "Why it's called messagingengine.com",
        paragraphs: [
          "MessagingEngine is the operational arm of Fastmail Pty Ltd. The split between the consumer brand and the infrastructure brand goes back to Fastmail's days as Opera Software's mail division — keeping infrastructure under a separate name made it portable when Fastmail spun out in 2013. Today the two are the same company, but the DNS naming has stuck.",
        ],
      },
      {
        title: "Who runs it",
        paragraphs: [
          "Fastmail Pty Ltd is an Australian, privately-held mailbox provider. It's a popular choice for technical users and small businesses that want a paid alternative to Gmail or Outlook with strong CalDAV/CardDAV support and no advertising.",
        ],
      },
    ],
  },
  {
    slug: "zoho",
    displayName: "Zoho Mail",
    shortName: "Zoho Mail",
    operator: "Zoho Corporation",
    hostnames: [
      /\.zoho\.com$/,
      /\.zoho\.eu$/,
      /\.zoho\.in$/,
      /\.zoho\.com\.au$/,
      /\.zohomail\.com$/,
    ],
    hostnameExamples: [
      "mx.zoho.com",
      "mx2.zoho.com",
      "mx3.zoho.com",
      "mx.zoho.eu",
      "mx.zoho.in",
    ],
    parentExamples: ["zoho.com"],
    description: ZOHO_DESCRIPTION,
    headline: "What is mx.zoho.com? Zoho Mail inbound MX explained",
    intro:
      "Zoho Mail is the business email service from Zoho Corporation, bundled with the broader Zoho CRM/Workplace suite. Customers point their MX records at <code>mx.zoho.com</code>, <code>mx2.zoho.com</code>, and <code>mx3.zoho.com</code> — or the regional equivalents <code>mx.zoho.eu</code>, <code>mx.zoho.in</code>, and <code>mx.zoho.com.au</code> depending on the data residency tier they chose at signup.",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Zoho's recommended setup is three MX records with ascending priorities. Regional plans swap the TLD on every host — once you pick a region you're committed to it for the lifetime of the account.",
        ],
        list: [
          "<code>10 mx.zoho.com</code>",
          "<code>20 mx2.zoho.com</code>",
          "<code>50 mx3.zoho.com</code>",
          "European tenants substitute <code>mx.zoho.eu</code> / <code>mx2.zoho.eu</code>.",
          "Indian tenants substitute <code>mx.zoho.in</code> / <code>mx2.zoho.in</code>.",
        ],
      },
      {
        title: "Who runs it",
        paragraphs: [
          "Zoho Corporation is a privately-held software vendor headquartered in Chennai, India, with major US and EU offices. Zoho Mail is most often seen on small-business and freelance domains, plus international branches of larger companies that pick it for the bundled CRM rather than the mail product itself.",
        ],
      },
      {
        title: "Identifying a Zoho tenant",
        paragraphs: [
          "The MX hostname is unambiguous — only Zoho can serve those. The SPF record will <code>include:zoho.com</code> (or the regional equivalent). DKIM selectors are named <code>zoho._domainkey</code> by default but can be renamed.",
        ],
      },
    ],
  },
  {
    slug: "amazon-ses",
    displayName: "Amazon SES (inbound)",
    shortName: "Amazon SES",
    operator: "Amazon Web Services",
    hostnames: [/^inbound-smtp\.[a-z0-9-]+\.amazonaws\.com$/],
    hostnameExamples: [
      "inbound-smtp.us-east-1.amazonaws.com",
      "inbound-smtp.eu-west-1.amazonaws.com",
      "inbound-smtp.ap-southeast-2.amazonaws.com",
    ],
    parentExamples: [],
    description: SES_DESCRIPTION,
    headline:
      "What is inbound-smtp.amazonaws.com? Amazon SES inbound MX explained",
    intro:
      "Amazon SES (Simple Email Service) is a transactional email API. Its inbound side — receiving mail at a domain — uses MX hostnames of the form <code>inbound-smtp.&lt;region&gt;.amazonaws.com</code>. The region segment tells you which AWS region the receiving SES configuration lives in.",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Only the regions that have SES inbound enabled get an inbound-smtp hostname. The available regions are a moving target but at time of writing include us-east-1, us-west-2, eu-west-1, eu-central-1, and ap-southeast-2.",
        ],
        list: [
          "<code>10 inbound-smtp.us-east-1.amazonaws.com</code> — N. Virginia",
          "<code>10 inbound-smtp.us-west-2.amazonaws.com</code> — Oregon",
          "<code>10 inbound-smtp.eu-west-1.amazonaws.com</code> — Ireland",
          "<code>10 inbound-smtp.eu-central-1.amazonaws.com</code> — Frankfurt",
        ],
      },
      {
        title: "Inbound vs outbound SES",
        paragraphs: [
          "Most domains use SES outbound (sending email programmatically) without using SES inbound. If a domain only sends via SES, you won't see <code>inbound-smtp</code> in its MX — the MX will point elsewhere. <code>inbound-smtp</code> means the operators are routing received mail into an S3 bucket, Lambda function, or SNS topic for processing.",
        ],
      },
      {
        title: "Who runs it",
        paragraphs: [
          "Amazon Web Services. SES inbound is a developer-facing service — its presence usually indicates an application is processing received mail programmatically, not a human reading an inbox.",
        ],
      },
    ],
  },
  {
    slug: "cloudflare",
    displayName: "Cloudflare Email Routing",
    shortName: "Cloudflare",
    operator: "Cloudflare",
    hostnames: [/^route[1-3]\.mx\.cloudflare\.net$/, /\.mx\.cloudflare\.net$/],
    hostnameExamples: [
      "route1.mx.cloudflare.net",
      "route2.mx.cloudflare.net",
      "route3.mx.cloudflare.net",
    ],
    parentExamples: [],
    description: CLOUDFLARE_DESCRIPTION,
    headline:
      "What is route1.mx.cloudflare.net? Cloudflare Email Routing explained",
    intro:
      "Cloudflare Email Routing is a free email-forwarding service for domains whose DNS is managed by Cloudflare. It doesn't host mailboxes — it accepts mail at <code>route1-3.mx.cloudflare.net</code> and forwards it to a destination address the domain owner specified (a Gmail account, a Fastmail account, anything that accepts SMTP).",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Email Routing publishes three MX records, all at equal priority, so any of Cloudflare's edge can accept inbound mail.",
        ],
        list: [
          "<code>2 route1.mx.cloudflare.net</code>",
          "<code>3 route2.mx.cloudflare.net</code>",
          "<code>15 route3.mx.cloudflare.net</code>",
        ],
      },
      {
        title: "Forwarder, not a mailbox",
        paragraphs: [
          "Email Routing is one-way — it accepts mail and forwards it; the destination mailbox is the real authoritative MTA. That means a domain using Email Routing won't have meaningful DKIM keys at its own selectors and may have SPF set up only for forwarding. It also means Cloudflare can't reply to bounces; non-deliverable mail gets dropped at the destination.",
        ],
      },
      {
        title: "Who runs it",
        paragraphs: [
          "Cloudflare, Inc. The service launched in 2021 and is free for domains using Cloudflare DNS. It's a popular choice for personal domains, side projects, and aliases that don't justify a full mailbox plan.",
        ],
      },
    ],
  },
];

/** Lookup a provider by an MX exchange hostname. Returns undefined when no
 * provider in the catalog matches. Case-insensitive; tolerates a trailing dot. */
export function lookupMxProvider(exchange: string): MxProvider | undefined {
  const normalized = exchange.toLowerCase().replace(/\.$/, "");
  for (const provider of MX_PROVIDERS) {
    for (const pattern of provider.hostnames) {
      if (pattern.test(normalized)) return provider;
    }
  }
  return undefined;
}

/** Lookup a provider by its slug. Returns undefined for unknown slugs. */
export function getMxProvider(slug: string): MxProvider | undefined {
  return MX_PROVIDERS.find((p) => p.slug === slug);
}
