// MX provider catalog. Powers two surfaces:
//   1. The /mx/<slug> SEO pages (one ranking target per common MX host) —
//      see src/views/mx.ts and src/views/markdown.ts.
//   2. The MX card on /check?domain=... — components.ts looks up the provider
//      for each MX record and links the badge to /mx/<slug> when matched.
//
// Prose is stored as plain text with backticks for inline code (markdown
// convention). The HTML renderer escapes the text and then promotes backticks
// to <code>; the markdown renderer passes the text through. This avoids any
// HTML-stripping regex (and the double-escape footguns that come with one).
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
      "An MX record that ends in `mail.protection.outlook.com` means the domain receives mail through Microsoft 365 — formerly Office 365, and the same service that powers Exchange Online tenants. The slug before `mail.protection.outlook.com` is the tenant identifier, derived from the primary domain with dots replaced by dashes.",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Microsoft 365 publishes a single MX target per tenant. The hostname is generated from the domain name itself, so it's easy to recognise once you've seen the pattern.",
        ],
        list: [
          "`github.com` → `github-com.mail.protection.outlook.com`",
          "`microsoft.com` → `microsoft-com.mail.protection.outlook.com`",
          "Government Community Cloud (GCC) tenants use `*.olc.protection.outlook.com` instead — same operator, different ring.",
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
          "The MX hostname alone is enough — only Microsoft can serve that domain. If you want a second signal, look at the SPF record: a Microsoft 365 tenant will `include:spf.protection.outlook.com`. The DKIM keys live at `selector1._domainkey` and `selector2._domainkey` and point at `selector*-<tenant>._domainkey.<tenant>.onmicrosoft.com`.",
        ],
      },
      {
        title: "SPF, DKIM, and DMARC records for Microsoft 365",
        paragraphs: [
          "Microsoft's documented SPF record for a domain that sends only through Microsoft 365 is `v=spf1 include:spf.protection.outlook.com -all`. The hard-fail `-all` is Microsoft's own recommendation — they expect DKIM and DMARC to carry the authentication load. If anything else sends as your domain (a CRM, a newsletter tool), add its mechanism to this one record; publishing a second SPF record alongside it is a permanent error, not a backup.",
          "DKIM is two CNAME records with fixed names and tenant-specific targets. The hostnames are always `selector1._domainkey` and `selector2._domainkey`; the targets embed your domain (dots replaced by dashes) and your `<tenant>.onmicrosoft.com` initial domain. Domains added since May 2025 get a newer target format ending in `dkim.mail.microsoft` with an unpredictable partition character — either way, copy the exact values from the Defender portal rather than constructing them by hand.",
          "Microsoft's DMARC guidance is the standard ramp: start at `v=DMARC1; p=none;` with a `rua` reporting address, then move to `quarantine` and finally `reject` once the reports are clean. After all three records are live, run your domain through dmarcheck to confirm they parse and align.",
        ],
        list: [
          "SPF: `v=spf1 include:spf.protection.outlook.com -all`",
          "DKIM: `selector1._domainkey` → `selector1-<domain-with-dashes>._domainkey.<tenant>.onmicrosoft.com` (CNAME; tenant-specific target)",
          "DKIM: `selector2._domainkey` → same pattern with `selector2-`",
          "DMARC: `v=DMARC1; p=none; rua=mailto:<reports>@<yourdomain>` to start — Microsoft's stated goal is `p=reject`",
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
      "An MX record set that lists `aspmx.l.google.com` as the primary plus four `alt[1-4].aspmx.l.google.com` hosts is Google Workspace — the business mail service formerly known as G Suite and, before that, Google Apps. Every Workspace tenant uses the same five hostnames, regardless of which domain they're for.",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Workspace's recommended MX configuration is five records with different priorities. The primary is the lowest priority value; the alt hosts are stand-bys for when the primary is at capacity or unreachable.",
        ],
        list: [
          "`1 aspmx.l.google.com`",
          "`5 alt1.aspmx.l.google.com`",
          "`5 alt2.aspmx.l.google.com`",
          "`10 alt3.aspmx.l.google.com`",
          "`10 alt4.aspmx.l.google.com`",
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
          "Unlike Microsoft 365's per-tenant hostname, every Workspace customer shares the same MX hosts — so the MX alone doesn't reveal the tenant. The tenant identifier shows up elsewhere: the SPF record includes `_spf.google.com`, and DKIM uses `google._domainkey` by default. If the domain publishes DMARC with a `rua` mailto pointing at `*.google.com`, that's another tell.",
        ],
      },
      {
        title: "SPF, DKIM, and DMARC records for Google Workspace",
        paragraphs: [
          "For a domain that sends mail only through Workspace, the record Google documents is `v=spf1 include:_spf.google.com ~all` — note the softfail `~all`; Google's setup page doesn't ask for `-all`. Domains that also send through other services fold every sender into that single TXT record (Google's own examples show `include:_spf.google.com include:amazonses.com` side by side), because SPF permits exactly one record per name — two records fail outright.",
          "DKIM is a TXT record at `google._domainkey` — `google` is the default selector — whose value is a public key you generate per-domain in the Admin console (Apps → Google Workspace → Gmail → Authenticate email). Pick a 2048-bit key unless your DNS host can't store one, in which case fall back to 1024.",
          "Google's DMARC examples start at `v=DMARC1; p=none;` with `rua` reporting and tighten to `quarantine` or `reject` as the reports come back clean. Once the three records are published, a dmarcheck scan will show whether they parse the way Gmail's own checks expect.",
        ],
        list: [
          "SPF: `v=spf1 include:_spf.google.com ~all`",
          "DKIM: TXT at `google._domainkey` — key generated per-domain in the Admin console (2048-bit preferred)",
          "DMARC: `v=DMARC1; p=none; rua=mailto:<reports>@<yourdomain>` to start",
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
      "Mimecast is a security gateway, not a mailbox provider. When a domain's MX points at `*.mimecast.com`, inbound mail lands at Mimecast first — Mimecast performs anti-spam, anti-phishing, sandboxing and policy enforcement, and then relays the cleaned mail to the customer's actual mailbox host (most commonly Microsoft 365 or Google Workspace).",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Mimecast hostnames embed a region segment that tells you which data centre the tenant is provisioned in.",
        ],
        list: [
          "`*.mail.eu.mimecast.com` — Europe",
          "`*.mail.us.mimecast.com` — North America",
          "`*.mail.za.mimecast.com` — South Africa",
          "`*.mail.au.mimecast.com` — Australia/Pacific",
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
      {
        title: "SPF, DKIM, and DMARC records for Mimecast",
        paragraphs: [
          "Mimecast's SPF include is regional — you authorise the data centre your tenant lives in, not one global hostname. A US tenant publishes `v=spf1 include:us._netblocks.mimecast.com ~all`; the prefix changes per region. A catch-all `include:_netblocks.mimecast.com` exists too, but it burns six DNS lookups against SPF's limit of ten where a regional include costs one — and any other senders your domain uses must share that budget inside the same single TXT record (a duplicate SPF record is an instant permerror).",
          'There is no universal Mimecast DKIM selector. Signing keys are generated per customer, per domain, in the Mimecast Administration Console (a DNS Authentication – Outbound Signing definition); you publish the generated public key as a TXT record at `<selector>._domainkey.<yourdomain>`, with generated selectors shaped like `mimecast20260612`. Anyone quoting you a fixed "Mimecast DKIM record" is guessing.',
          "DMARC sits on top as usual — `v=DMARC1; p=none;` with reporting, walked up to `reject`; Mimecast sells DMARC Analyzer for exactly that ramp. Scan your domain with dmarcheck after cutover to check the gateway's records and your policy in one pass.",
        ],
        list: [
          "`v=spf1 include:us._netblocks.mimecast.com ~all` — United States",
          "`v=spf1 include:eu._netblocks.mimecast.com ~all` — Europe (excluding Germany)",
          "`v=spf1 include:de._netblocks.mimecast.com ~all` — Germany",
          "`za` (South Africa), `au` (Australia), and `ca` (Canada) follow the same pattern",
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
      "Two MX hostname families both belong to Proofpoint. `*.pphosted.com` is the enterprise tier — large organisations on Proofpoint's flagship Enterprise Protection product. `*.ppe-hosted.com` is Proofpoint Essentials, the SMB tier sold through partner MSPs. Both are perimeter filtering gateways in front of the customer's real mailbox host.",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Enterprise Protection publishes a pair of MX records with `mx0a-` and `mx0b-` prefixes for high availability. The slug after the prefix is a tenant identifier.",
        ],
        list: [
          "`10 mx0a-<tenant>.pphosted.com`",
          "`10 mx0b-<tenant>.pphosted.com`",
          "Essentials customers see `mx1-<region>.ppe-hosted.com` and `mx2-<region>.ppe-hosted.com`.",
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
      {
        title: "SPF, DKIM, and DMARC records for Proofpoint",
        paragraphs: [
          "Which SPF record you publish depends on the tier. Proofpoint Essentials documents stack-specific records — `v=spf1 a:dispatch-us.ppe-hosted.com ~all` for US stacks, `v=spf1 a:dispatch-eu.ppe-hosted.com ~all` for EU — matching the `ppe-hosted.com` infrastructure your account was provisioned on. Enterprise (`pphosted.com`) customers get no universal include at all: authorized sending hosts are per-customer, supplied in the admin console or by your Proofpoint account team, so treat any blog quoting a generic `pphosted.com` SPF include with suspicion.",
          "DKIM is per-customer too. You create a signing key per domain in the Proofpoint console, the selector is yours to choose (the console pre-fills one), and what lands in DNS is a TXT record at `<selector>._domainkey.<yourdomain>` holding your generated public key. No fixed selector exists across Proofpoint customers.",
          "Proofpoint's published DMARC starter is `v=DMARC1; p=none; rua=mailto:<reports>@<yourdomain>; pct=100`, walked up to `quarantine` and then `reject` over a few months. Whatever the tier, keep every SPF mechanism in one TXT record — adding a second record makes evaluation fail outright — then run the domain through dmarcheck to confirm the result.",
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
      "Fastmail's inbound MX hosts are `in1-smtp.messagingengine.com` and `in2-smtp.messagingengine.com`. The `messagingengine.com` domain — not `fastmail.com` — is what trips up most reverse-lookup tools: `messagingengine.com` is Fastmail's infrastructure brand, used for SMTP, IMAP, and SPF includes as well.",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Fastmail publishes two MX records with equal priority for round-robin delivery.",
        ],
        list: [
          "`10 in1-smtp.messagingengine.com`",
          "`20 in2-smtp.messagingengine.com`",
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
      {
        title: "SPF, DKIM, and DMARC records for Fastmail",
        paragraphs: [
          "Fastmail's documented SPF record is `v=spf1 include:spf.messagingengine.com ?all` — and yes, that's a neutral `?all`, not the softfail most providers suggest: Fastmail leans on DKIM for authentication and treats SPF as advisory. Other services that send for the domain get their includes merged into this same record, never published as a second one (SPF tolerates exactly one TXT record per hostname).",
          "DKIM is three CNAME records, and your domain appears inside the target as well as the host: `fm1._domainkey.<yourdomain>` points at `fm1.<yourdomain>.dkim.fmhosted.com`, with `fm2` and `fm3` following suit. The CNAME indirection is what lets Fastmail rotate the underlying keys without you ever touching DNS again. Older domains may still carry a deprecated `mesmtp._domainkey` record; new setups need only fm1–fm3.",
          "Fastmail's manual-DNS table ships DMARC as a bare `v=DMARC1; p=none;` — monitoring-grade, with no reporting address. Tightening to `quarantine` or `reject` is on you once you've added `rua` and watched the reports. Scan the domain on dmarcheck to see how that default actually scores.",
        ],
        list: [
          "SPF: `v=spf1 include:spf.messagingengine.com ?all`",
          "DKIM: `fm1._domainkey` → `fm1.<yourdomain>.dkim.fmhosted.com` (CNAME)",
          "DKIM: `fm2._domainkey` and `fm3._domainkey` → same pattern",
          "DMARC: `v=DMARC1; p=none;` (Fastmail's documented baseline)",
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
      "Zoho Mail is the business email service from Zoho Corporation, bundled with the broader Zoho CRM/Workplace suite. Customers point their MX records at `mx.zoho.com`, `mx2.zoho.com`, and `mx3.zoho.com` — or the regional equivalents `mx.zoho.eu`, `mx.zoho.in`, and `mx.zoho.com.au` depending on the data residency tier they chose at signup.",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Zoho's recommended setup is three MX records with ascending priorities. Regional plans swap the TLD on every host — once you pick a region you're committed to it for the lifetime of the account.",
        ],
        list: [
          "`10 mx.zoho.com`",
          "`20 mx2.zoho.com`",
          "`50 mx3.zoho.com`",
          "European tenants substitute `mx.zoho.eu` / `mx2.zoho.eu`.",
          "Indian tenants substitute `mx.zoho.in` / `mx2.zoho.in`.",
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
          "The MX hostname is unambiguous — only Zoho can serve those. The SPF record will `include:zohomail.com` (or `one.zoho.com` for multi-service accounts). DKIM selectors are named `zoho._domainkey` by default but can be renamed.",
        ],
      },
      {
        title: "SPF, DKIM, and DMARC records for Zoho Mail",
        paragraphs: [
          "Zoho's SPF include is `include:zohomail.com` regardless of which data centre hosts the tenant — only the MX hostnames are regional. Zoho's own help pages waver on the qualifier (the headline prescription says `-all`, the step-by-step walkthroughs say `~all`), so `v=spf1 include:zohomail.com ~all` is the safe form while you're still validating; tighten to `-all` once DKIM is live. Accounts using several Zoho services can swap in `include:one.zoho.com` to save lookups — always within the one permitted SPF record, since publishing two is a permerror.",
          "DKIM keys are generated per domain in the Zoho Mail Admin Console (Email Configuration → DKIM). The selector is your choice — Zoho's setup docs use `zoho` as the example — and the result is a TXT record at `<selector>._domainkey.<yourdomain>` holding the generated public key, verified and enabled back in the console.",
          "Zoho documents the full DMARC ramp explicitly: `v=DMARC1; p=none; rua=mailto:admin@<yourdomain>`, then `p=quarantine` (optionally throttled with `pct=`), then `p=reject`. Publish all three record types, then check the domain on dmarcheck to confirm they resolve and parse.",
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
      "Amazon SES (Simple Email Service) is a transactional email API. Its inbound side — receiving mail at a domain — uses MX hostnames of the form `inbound-smtp.<region>.amazonaws.com`. The region segment tells you which AWS region the receiving SES configuration lives in.",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Only the regions that have SES inbound enabled get an inbound-smtp hostname. The available regions are a moving target but at time of writing include us-east-1, us-west-2, eu-west-1, eu-central-1, and ap-southeast-2.",
        ],
        list: [
          "`10 inbound-smtp.us-east-1.amazonaws.com` — N. Virginia",
          "`10 inbound-smtp.us-west-2.amazonaws.com` — Oregon",
          "`10 inbound-smtp.eu-west-1.amazonaws.com` — Ireland",
          "`10 inbound-smtp.eu-central-1.amazonaws.com` — Frankfurt",
        ],
      },
      {
        title: "Inbound vs outbound SES",
        paragraphs: [
          "Most domains use SES outbound (sending email programmatically) without using SES inbound. If a domain only sends via SES, you won't see `inbound-smtp` in its MX — the MX will point elsewhere. `inbound-smtp` means the operators are routing received mail into an S3 bucket, Lambda function, or SNS topic for processing.",
        ],
      },
      {
        title: "Who runs it",
        paragraphs: [
          "Amazon Web Services. SES inbound is a developer-facing service — its presence usually indicates an application is processing received mail programmatically, not a human reading an inbox.",
        ],
      },
      {
        title: "SPF, DKIM, and DMARC records for Amazon SES",
        paragraphs: [
          "SES inverts the usual order: DKIM comes first and SPF needs an extra step. Easy DKIM gives you three CNAME records — `<token>._domainkey.<yourdomain>` pointing at `<token>.dkim.amazonses.com` — where each `<token>` is a random per-identity string from the SES console. In some newer regions the target is `dkim.<region>.amazonses.com` (or a cell-based hosted zone), so copy the exact values SES generates rather than assuming the suffix.",
          "Out of the box SES sends from an `amazonses.com` MAIL FROM, which passes SPF but never aligns for DMARC. The fix is a custom MAIL FROM subdomain carrying two records: an MX of `10 feedback-smtp.<region>.amazonses.com` and the TXT `v=spf1 include:amazonses.com ~all`, with `<region>` matching where the identity lives. Those live on the MAIL FROM subdomain — the apex domain keeps its own single SPF record (merge mechanisms into it; a second `v=spf1` TXT breaks both).",
          "AWS's documented DMARC example is `v=DMARC1;p=quarantine;rua=mailto:<reports>@<yourdomain>`, and their recommendation is to let Easy DKIM carry alignment — it signs with your exact domain and survives forwarding, while SPF alignment through the MAIL FROM subdomain only works relaxed (no `aspf=s`). A dmarcheck scan of the domain shows whether the selectors and policy resolve.",
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
      "Cloudflare Email Routing is a free email-forwarding service for domains whose DNS is managed by Cloudflare. It doesn't host mailboxes — it accepts mail at `route1-3.mx.cloudflare.net` and forwards it to a destination address the domain owner specified (a Gmail account, a Fastmail account, anything that accepts SMTP).",
    sections: [
      {
        title: "How it appears in DNS",
        paragraphs: [
          "Email Routing publishes three MX records, all at equal priority, so any of Cloudflare's edge can accept inbound mail.",
        ],
        list: [
          "`2 route1.mx.cloudflare.net`",
          "`3 route2.mx.cloudflare.net`",
          "`15 route3.mx.cloudflare.net`",
        ],
      },
      {
        title: "Forwarder, not a mailbox",
        paragraphs: [
          "Email Routing is one-way — it accepts mail and forwards it; the destination mailbox is the real authoritative MTA. The SPF and DKIM records Cloudflare adds to the zone authenticate the forwarding hop, not outbound sending — the service can't originate or reply as your domain. It also means Cloudflare can't reply to bounces; non-deliverable mail gets dropped at the destination.",
        ],
      },
      {
        title: "Who runs it",
        paragraphs: [
          "Cloudflare, Inc. The service launched in 2021 and is free for domains using Cloudflare DNS. It's a popular choice for personal domains, side projects, and aliases that don't justify a full mailbox plan.",
        ],
      },
      {
        title: "SPF, DKIM, and DMARC records for Cloudflare Email Routing",
        paragraphs: [
          "Email Routing writes its own DNS when you enable it: the three `route1-3.mx.cloudflare.net` MX records, the SPF TXT `v=spf1 include:_spf.mx.cloudflare.net ~all`, and a DKIM TXT at `cf2024-1._domainkey` with a Cloudflare-provided key that signs forwarded mail. There's nothing to construct by hand — but if the domain also sends from somewhere (routing is receive-only), that sender's SPF mechanism has to be merged into the same TXT record, because a second `v=spf1` record invalidates both.",
          "Forwarding is the hard case for authentication, and Cloudflare papers over it with SRS (rewriting the envelope sender so SPF passes downstream), DKIM signatures on forwarded messages, and ARC seals so the destination can trust the original verdicts. Strict DMARC policies on the sender's side can still make forwarded mail bounce — that's inherent to forwarding, not a misconfiguration.",
          "Because Email Routing can't send as your domain, your DMARC policy mostly governs what everyone else may do with it. `v=DMARC1; p=none;` plus a `rua` address is the observing start, and many routing-only domains can go straight to `p=reject` once they've confirmed nothing legitimate sends. A dmarcheck scan of the domain shows all of these records in one report.",
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
