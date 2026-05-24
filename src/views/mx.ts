import {
  getMxProvider,
  MX_PROVIDERS,
  type MxProviderData,
} from "../data/mx-providers.js";
import { esc, generateCreature } from "./components.js";
import { page, SITE_ORIGIN } from "./html.js";

const MX_PUBLISHED = "2026-05-24";

function mxJsonLd(provider: MxProviderData): string {
  return JSON.stringify({
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "TechArticle",
        headline: provider.headline,
        description: provider.metaDescription,
        datePublished: MX_PUBLISHED,
        dateModified: MX_PUBLISHED,
        author: {
          "@type": "Organization",
          name: "dmarcheck",
          url: `${SITE_ORIGIN}/`,
        },
        publisher: {
          "@type": "Organization",
          name: "dmarcheck",
          url: `${SITE_ORIGIN}/`,
          logo: {
            "@type": "ImageObject",
            url: `${SITE_ORIGIN}/logo.svg`,
          },
        },
        image: `${SITE_ORIGIN}/og-image.png`,
        mainEntityOfPage: `${SITE_ORIGIN}/mx/${provider.slug}`,
      },
      {
        "@type": "BreadcrumbList",
        itemListElement: [
          {
            "@type": "ListItem",
            position: 1,
            name: "dmarcheck",
            item: `${SITE_ORIGIN}/`,
          },
          {
            "@type": "ListItem",
            position: 2,
            name: "MX Providers",
            item: `${SITE_ORIGIN}/mx`,
          },
          {
            "@type": "ListItem",
            position: 3,
            name: provider.name,
            item: `${SITE_ORIGIN}/mx/${provider.slug}`,
          },
        ],
      },
    ],
  });
}

function mxHubJsonLd(): string {
  return JSON.stringify({
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "CollectionPage",
        name: "MX record providers — dmarcheck",
        description:
          "What each MX hostname means: Microsoft 365, Google Workspace, Mimecast, Proofpoint, Fastmail, Zoho, Amazon SES, and Cloudflare Email Routing.",
        url: `${SITE_ORIGIN}/mx`,
        mainEntity: {
          "@type": "ItemList",
          itemListElement: MX_PROVIDERS.map((p, i) => ({
            "@type": "ListItem",
            position: i + 1,
            url: `${SITE_ORIGIN}/mx/${p.slug}`,
            name: p.name,
          })),
        },
      },
      {
        "@type": "BreadcrumbList",
        itemListElement: [
          {
            "@type": "ListItem",
            position: 1,
            name: "dmarcheck",
            item: `${SITE_ORIGIN}/`,
          },
          {
            "@type": "ListItem",
            position: 2,
            name: "MX Providers",
            item: `${SITE_ORIGIN}/mx`,
          },
        ],
      },
    ],
  });
}

const MX_FOOTER = `<div class="foss-callout">
    <a href="https://github.com/schmug/dmarcheck" class="foss-link">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      Free and open source &mdash; MIT License
    </a>
  </div>`;

function providerSiblingLinks(currentSlug: string): string {
  const items = MX_PROVIDERS.filter((p) => p.slug !== currentSlug)
    .map(
      (p) =>
        `<li><a href="/mx/${esc(p.slug)}"><strong>${esc(p.name)}</strong> &mdash; ${esc(p.operator)}</a></li>`,
    )
    .join("");
  return `<ul class="learn-siblings">${items}</ul>`;
}

function exampleDomains(provider: MxProviderData): string {
  const examples: Record<string, string[]> = {
    outlook: ["github.com", "microsoft.com", "outlook.com"],
    google: ["google.com", "alphabet.com", "youtube.com"],
    mimecast: ["barclays.com", "hsbc.com"],
    proofpoint: ["salesforce.com", "oracle.com"],
    fastmail: ["fastmail.com", "fastmail.fm"],
    zoho: ["zoho.com", "zohocrm.com"],
    "amazon-ses": ["amazon.com", "aws.amazon.com"],
    cloudflare: ["cloudflare.com"],
  };
  const domains = examples[provider.slug] ?? [];
  if (domains.length === 0) return "";
  const links = domains
    .map(
      (d) => `<a href="/check?domain=${encodeURIComponent(d)}">${esc(d)}</a>`,
    )
    .join(" &middot; ");
  return `<p class="tier-text">See it live: scan ${links}</p>`;
}

function renderProviderBody(provider: MxProviderData): string {
  return `
  <p class="rubric-intro">${esc(provider.description)}</p>

  <div class="bd-card">
    <div class="bd-card-title">What these MX hostnames look like</div>
    <div class="bd-card-body">
      <p class="tier-text">When a domain uses ${esc(provider.name)}, its MX records point to hostnames like:</p>
      <pre class="learn-example"><code>${provider.mxExamples.map(esc).join("\n")}</code></pre>
      <p class="tier-text">You will see these in a DNS MX lookup: <code>dig MX yourdomain.com</code> or when dmarcheck scans a domain.</p>
      ${exampleDomains(provider)}
    </div>
  </div>

  ${providerContent(provider)}

  <div class="bd-card">
    <div class="bd-card-title">DMARC and SPF considerations</div>
    <div class="bd-card-body">
      ${dmarcContent(provider)}
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Other mail providers</div>
    <div class="bd-card-body">
      ${providerSiblingLinks(provider.slug)}
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Scan a domain using ${esc(provider.name)}</div>
    <div class="bd-card-body">
      <form action="/check" method="GET" class="learn-cta-form">
        <div class="search-box">
          <input type="text" name="domain" placeholder="Enter a domain to scan" aria-label="Enter a domain" autocapitalize="none" autocorrect="off" spellcheck="false" required>
          <button type="submit">Scan</button>
        </div>
      </form>
    </div>
  </div>`;
}

function providerContent(provider: MxProviderData): string {
  switch (provider.slug) {
    case "outlook":
      return `<div class="bd-card">
    <div class="bd-card-title">How Microsoft 365 tenant routing works</div>
    <div class="bd-card-body">
      <p class="tier-text">Each Microsoft 365 tenant gets a unique MX hostname derived from its initial <code>.onmicrosoft.com</code> domain. For a tenant whose initial domain is <code>contoso.onmicrosoft.com</code>, the MX record will point to <code>contoso-com.mail.protection.outlook.com</code> — the dots in the domain name become hyphens.</p>
      <p class="tier-text">This hostname is how Exchange Online identifies which tenant should receive the message. The MX hostname is public information — it is visible in any DNS lookup — but it does not expose mailbox names or tenant credentials.</p>
      <p class="tier-text">Some tenants use the <code>.olc.</code> variant (<code>*.olc.protection.outlook.com</code>) when Outlook.com personal accounts share the same Exchange Online infrastructure. The routing behavior is identical.</p>
      <p class="tier-text">Microsoft also publishes Autodiscover and SPF records for each tenant. The SPF record at <code>_spf.protection.outlook.com</code> authorizes all Exchange Online sending IPs and must appear in your domain's SPF record as <code>include:spf.protection.outlook.com</code>.</p>
    </div>
  </div>`;

    case "google":
      return `<div class="bd-card">
    <div class="bd-card-title">How Google Workspace MX priorities work</div>
    <div class="bd-card-body">
      <p class="tier-text">Google Workspace requires five MX records with specific priority values. The standard configuration is:</p>
      <pre class="learn-example"><code>1   ASPMX.L.GOOGLE.COM.
5   ALT1.ASPMX.L.GOOGLE.COM.
5   ALT2.ASPMX.L.GOOGLE.COM.
10  ALT3.ASPMX.L.GOOGLE.COM.
10  ALT4.ASPMX.L.GOOGLE.COM.</code></pre>
      <p class="tier-text">The primary record (<code>aspmx.l.google.com</code>, priority 1) handles the majority of inbound traffic. The four <code>alt</code> records at priorities 5 and 10 are fallbacks — sending servers try lower-priority hosts only when higher-priority hosts are unreachable.</p>
      <p class="tier-text">Unlike Microsoft 365, these MX hostnames are the same for every Google Workspace customer — Google identifies the destination tenant from the SMTP envelope recipient address, not the MX hostname.</p>
      <p class="tier-text">Google's outbound SPF IP ranges are published via <code>include:_spf.google.com</code>. If you use Google Workspace to send mail, this include must appear in your domain's SPF record.</p>
    </div>
  </div>`;

    case "mimecast":
      return `<div class="bd-card">
    <div class="bd-card-title">How Mimecast sits in front of your mail platform</div>
    <div class="bd-card-body">
      <p class="tier-text">Mimecast is a cloud email security gateway. Inbound mail arrives at Mimecast's MX hostnames first, is filtered for spam and malware, and then forwarded to the actual mailbox platform (typically Microsoft 365 or Google Workspace) on a locked-down delivery path.</p>
      <p class="tier-text">Mimecast hostnames are regional: US customers use <code>us-smtp-inbound-*.mimecast.com</code>, EU customers use <code>eu-smtp-inbound-*.mimecast.com</code>, and so on. The specific hostname is assigned during account provisioning.</p>
      <p class="tier-text">Because Mimecast delivers inbound mail to your downstream platform, the downstream platform's MX and SPF records should be locked down — only Mimecast's delivery IPs should be accepted. Mimecast publishes an SPF record (<code>include:spf.mimecast.com</code>) that covers its sending IPs for outbound mail processed through the gateway.</p>
    </div>
  </div>`;

    case "proofpoint":
      return `<div class="bd-card">
    <div class="bd-card-title">Proofpoint Essentials vs. enterprise (pphosted.com vs. ppe-hosted.com)</div>
    <div class="bd-card-body">
      <p class="tier-text">Proofpoint operates two distinct products visible in MX records. The enterprise product uses <code>*.pphosted.com</code> hostnames; Proofpoint Essentials (the SMB offering) uses <code>*.ppe-hosted.com</code> hostnames. The architecture is similar — both are cloud gateways that filter inbound mail before delivering to your downstream platform — but the two product lines have separate infrastructure and support paths.</p>
      <p class="tier-text">Like Mimecast, Proofpoint deployments route inbound mail through the gateway first. This means the downstream Microsoft 365 or Google Workspace environment typically uses a Proofpoint-provided connector to only accept delivery from Proofpoint's IP ranges — the downstream MX is not advertised publicly.</p>
      <p class="tier-text">Proofpoint's outbound SPF range is covered by <code>include:pphosted.com</code> for enterprise and specific ranges for Essentials. Check Proofpoint's support documentation for the current include strings for your product tier.</p>
    </div>
  </div>`;

    case "fastmail":
      return `<div class="bd-card">
    <div class="bd-card-title">Why Fastmail uses messagingengine.com, not fastmail.com</div>
    <div class="bd-card-body">
      <p class="tier-text">Fastmail's inbound MX hostnames use the <code>messagingengine.com</code> domain, which is Fastmail's infrastructure domain, not the consumer-facing brand. This is normal — many email providers use a separate operational domain for DNS infrastructure to make hostname rotation easier without affecting the brand domain.</p>
      <p class="tier-text">A standard Fastmail custom-domain MX configuration uses two records at equal priority:</p>
      <pre class="learn-example"><code>10  in1-smtp.messagingengine.com.
20  in2-smtp.messagingengine.com.</code></pre>
      <p class="tier-text">Fastmail publishes SPF records for its outbound sending infrastructure. When using a custom domain with Fastmail, your SPF record should include <code>include:spf.messagingengine.com</code>. Fastmail supports DKIM signing for custom domains from the account settings panel.</p>
    </div>
  </div>`;

    case "zoho":
      return `<div class="bd-card">
    <div class="bd-card-title">Zoho Mail MX record setup</div>
    <div class="bd-card-body">
      <p class="tier-text">Zoho Mail requires three MX records in a specific priority order:</p>
      <pre class="learn-example"><code>10  mx.zoho.com.
20  mx2.zoho.com.
50  mx3.zoho.com.</code></pre>
      <p class="tier-text">All three hostnames are shared across all Zoho Mail customers — Zoho identifies the destination account from the SMTP envelope recipient address. The priority ladder means primary delivery goes to <code>mx.zoho.com</code>, with the others as progressively lower-priority fallbacks.</p>
      <p class="tier-text">Zoho also operates regional infrastructure in the EU and Australia under <code>*.zoho.eu</code> and <code>*.zoho.com.au</code> for data-residency compliance. If a domain uses these regional hostnames it means the account opted into a specific data region during signup.</p>
      <p class="tier-text">For outbound SPF, Zoho's include string is <code>include:zoho.com</code> (or the appropriate regional variant). Zoho supports DMARC-aligned DKIM signing for custom domains.</p>
    </div>
  </div>`;

    case "amazon-ses":
      return `<div class="bd-card">
    <div class="bd-card-title">How Amazon SES inbound email processing works</div>
    <div class="bd-card-body">
      <p class="tier-text">Amazon SES inbound uses a single MX record per AWS region. The hostname format is <code>inbound-smtp.&lt;region&gt;.amazonaws.com</code>. Common regions:</p>
      <pre class="learn-example"><code>inbound-smtp.us-east-1.amazonaws.com      # US East (N. Virginia)
inbound-smtp.us-west-2.amazonaws.com      # US West (Oregon)
inbound-smtp.eu-west-1.amazonaws.com      # Europe (Ireland)</code></pre>
      <p class="tier-text">Unlike a hosted mailbox service, SES inbound is a message-routing and processing service. Received messages are delivered to Amazon S3, Lambda, SNS, or WorkMail — the SES account owner configures the routing rules in the AWS Console. There is no built-in mailbox UI; SES inbound is typically used for automated mail processing pipelines, not human inboxes.</p>
      <p class="tier-text">SES inbound does not affect your outbound mail configuration. For outbound, SES provides dedicated sending IPs whose SPF ranges are published via <code>amazonses.com</code>. DKIM signing for outbound SES uses either Easy DKIM (AWS-managed key rotation) or BYODKIM (bring your own key).</p>
    </div>
  </div>`;

    case "cloudflare":
      return `<div class="bd-card">
    <div class="bd-card-title">How Cloudflare Email Routing works</div>
    <div class="bd-card-body">
      <p class="tier-text">Cloudflare Email Routing is a free service that lets you receive mail at a custom domain and forward it to another inbox (Gmail, Outlook, etc.). It is not a full mailbox — it is a forwarder. Mail sent to <code>you@yourdomain.com</code> is relayed to whichever destination address you configure in the Cloudflare dashboard.</p>
      <p class="tier-text">When Email Routing is enabled, Cloudflare automatically adds three MX records:</p>
      <pre class="learn-example"><code>10  route1.mx.cloudflare.net.
20  route2.mx.cloudflare.net.
30  route3.mx.cloudflare.net.</code></pre>
      <p class="tier-text">These records are added automatically when you enable Email Routing in the Cloudflare dashboard — you do not configure them manually. Cloudflare also adds an SPF record (<code>v=spf1 include:_spf.mx.cloudflare.net ~all</code>) to cover its forwarding IPs.</p>
      <p class="tier-text">Because Cloudflare forwards messages rather than delivering them to a mailbox, the final delivery DMARC check happens at the destination inbox (Gmail, Outlook), not at Cloudflare. Mail forwarded this way may fail DMARC at the destination if the original sender does not allow Cloudflare's forwarding IPs in their SPF or DKIM chain. ARC (Authenticated Received Chain) sealing mitigates this for providers that honor it.</p>
    </div>
  </div>`;

    default:
      return "";
  }
}

function dmarcContent(provider: MxProviderData): string {
  switch (provider.slug) {
    case "outlook":
      return `<p class="tier-text">Microsoft 365 handles DMARC evaluation for inbound mail at the Exchange Online layer before the message reaches a mailbox. If the sending domain has a DMARC policy of <code>p=reject</code>, Microsoft 365 will reject or quarantine failing messages according to the policy.</p>
      <p class="tier-text">For outbound, your SPF record must include <code>include:spf.protection.outlook.com</code> and Exchange Online must be configured as an approved sender. DKIM signing via Microsoft 365 uses the <code>*.domainkey.microsoft.com</code> CNAME chain — add the two CNAME records Microsoft provides in the Microsoft 365 admin center.</p>
      <p class="tier-text">DMARC aggregate reports (<code>rua=</code>) from domains that receive mail via Exchange Online are sent from Microsoft's report sender address. Check your DMARC report inbox for <code>@microsoft.com</code> aggregate reports if your domain receives mail sent by Microsoft 365 tenants.</p>`;

    case "google":
      return `<p class="tier-text">Google Workspace enforces DMARC for inbound mail. If the sending domain publishes <code>p=reject</code>, Google will reject failing messages. Google also sends DMARC aggregate reports for mail delivered to Workspace inboxes.</p>
      <p class="tier-text">For outbound DMARC alignment, add <code>include:_spf.google.com</code> to your SPF record and enable DKIM signing in the Google Admin console (Apps → Google Workspace → Gmail → Authenticate email). Google generates a 2048-bit RSA key by default; the CNAME record is added to your DNS zone.</p>
      <p class="tier-text">A common pitfall: if you use Google Groups for forwarding and the group re-sends mail externally, DMARC may fail at the final destination because Google does not DKIM-re-sign forwarded mail. Consider disabling external forwarding from groups or using ARC-aware receiving infrastructure.</p>`;

    case "mimecast":
      return `<p class="tier-text">With a Mimecast gateway, DMARC enforcement for inbound mail happens at Mimecast before the message reaches your platform. Mimecast's DMARC management module lets you configure per-domain policies and view aggregate data — this is separate from the DMARC record in your DNS.</p>
      <p class="tier-text">For outbound, Mimecast can apply DKIM signatures on behalf of your domain using its own key management infrastructure. You add a CNAME (or TXT) DKIM record that Mimecast provides, then enable signing in the Mimecast console. The signed mail will DMARC-align even if it passes through Mimecast's relay IPs.</p>
      <p class="tier-text">One nuance: mail delivered inbound by Mimecast to your downstream platform (Microsoft 365, Google) will appear to come from Mimecast's delivery IPs. Your downstream SPF policy should be locked to accept only those IPs. If the downstream SPF is wide open, the gateway provides less isolation than expected.</p>`;

    case "proofpoint":
      return `<p class="tier-text">Proofpoint Enterprise includes a DMARC reporting module (part of Proofpoint Email Fraud Defense / EFD). It aggregates DMARC rua= reports and provides a dashboard for visibility into senders. If you use Proofpoint, check whether your rua= address is configured to deliver reports to Proofpoint's parsing infrastructure or to a standalone inbox.</p>
      <p class="tier-text">For outbound DKIM signing, Proofpoint can sign on behalf of your domain as mail passes through the gateway. The DKIM public key is published as a CNAME or TXT record in your DNS zone, pointing to Proofpoint's key infrastructure.</p>
      <p class="tier-text">SPF: Proofpoint's outbound sending IPs must be included in your SPF record. Use <code>include:pphosted.com</code> for enterprise. Proofpoint Essentials customers should consult the Proofpoint Essentials SPF documentation for the correct include string.</p>`;

    case "fastmail":
      return `<p class="tier-text">Fastmail supports full DMARC alignment for custom domains. The setup requires: (1) adding <code>include:spf.messagingengine.com</code> to your SPF record to cover Fastmail's outbound IPs, and (2) enabling DKIM signing in Account Settings → Privacy &amp; Security → DKIM, which provides a TXT record to add to your DNS zone.</p>
      <p class="tier-text">Once both are in place, mail sent via Fastmail will pass both SPF and DKIM checks with alignment to your custom domain, satisfying DMARC. Fastmail enforces DMARC for inbound mail — if a sending domain publishes <code>p=reject</code>, Fastmail will reject failing messages.</p>
      <p class="tier-text">Fastmail also supports MTA-STS for inbound delivery security. If you publish an MTA-STS policy for your domain, senders that honor MTA-STS will require TLS when delivering to Fastmail's infrastructure.</p>`;

    case "zoho":
      return `<p class="tier-text">Zoho Mail supports DKIM signing for custom domains through the Zoho Admin Console (Mail Admin → Domains → your domain → Email Authentication). Zoho generates a 2048-bit key and provides a TXT record to add to your DNS zone. Once added, Zoho signs all outbound mail with this key.</p>
      <p class="tier-text">Add <code>include:zoho.com</code> to your SPF record to cover Zoho's outbound IPs (use <code>include:zoho.eu</code> or <code>include:zoho.com.au</code> for regional accounts). With SPF and DKIM both aligned, a DMARC policy of <code>p=reject</code> will protect your domain from spoofing even for mail transiting through Zoho's infrastructure.</p>
      <p class="tier-text">Zoho's DMARC report delivery: Zoho sends aggregate DMARC reports for inbound mail received at Zoho inboxes. These reports appear in your <code>rua=</code> inbox and identify senders failing DMARC for your domain's recipients.</p>`;

    case "amazon-ses":
      return `<p class="tier-text">Amazon SES supports two outbound DKIM approaches. Easy DKIM has AWS generate and rotate 2048-bit RSA keys automatically — you add three CNAME records to your DNS zone that point to AWS key infrastructure. BYODKIM (Bring Your Own DKIM) lets you provide an RSA or Ed25519 private key and manage rotation yourself.</p>
      <p class="tier-text">For SPF, SES outbound sending IPs are covered by the <code>amazonses.com</code> SPF record. Your domain's SPF record should include this via the MAIL FROM domain that SES assigns (e.g. <code>yourdomain.com.us-east-1.amazonses.com</code>), or use a custom MAIL FROM domain so SPF alignment matches your From: header domain.</p>
      <p class="tier-text">SES inbound mail processing does not perform DMARC enforcement by default — it delivers the message regardless of the sender's DMARC result and includes the DMARC disposition in the received headers. If you need DMARC-based rejection, implement it in your Lambda or S3 processing pipeline by inspecting the <code>Authentication-Results</code> header.</p>`;

    case "cloudflare":
      return `<p class="tier-text">Cloudflare Email Routing is a forwarding service, not a mailbox, which creates a specific DMARC complication. When Cloudflare forwards a message, the SMTP envelope sender (MAIL FROM) may or may not be rewritten. If the original sender's DMARC policy is <code>p=reject</code> and the destination inbox (Gmail, Outlook) checks DMARC, the forwarded message may fail because Cloudflare's forwarding IPs are not in the original sender's SPF record and the DKIM signature may break if the message is modified in transit.</p>
      <p class="tier-text">For your own domain's DMARC, the key question is about outbound mail — what SPF and DKIM records you publish for mail sent from your domain. Cloudflare Email Routing is inbound only; for outbound you use a separate mail service. Your DMARC record at <code>_dmarc.yourdomain.com</code> applies to mail sent by your domain, not to mail forwarded through Cloudflare.</p>
      <p class="tier-text">Cloudflare adds <code>v=spf1 include:_spf.mx.cloudflare.net ~all</code> to cover its forwarding IPs so that the Cloudflare forwarder appears authorized in SPF. However, this SPF record covers only the forwarding path, not any outbound senders you configure separately.</p>`;

    default:
      return `<p class="tier-text">Verify your domain's DMARC, SPF, and DKIM records are configured correctly for this provider by scanning your domain above.</p>`;
  }
}

export function renderMxHub(): string {
  const cards = MX_PROVIDERS.map(
    (p) =>
      `<li><a href="/mx/${esc(p.slug)}" class="learn-hub-card">
        <h2>${esc(p.name)}</h2>
        <p>${esc(p.description)}</p>
      </a></li>`,
  ).join("");

  const body = `<main class="breakdown learn">
  <nav class="report-nav" aria-label="Breadcrumb">
    <a href="/">${generateCreature("sm")} Home</a>
    <span class="breadcrumb-sep" aria-hidden="true">&rsaquo;</span>
    <span class="breadcrumb-current">MX Providers</span>
  </nav>
  <h1 class="rubric-title">What does this MX hostname mean?</h1>
  <p class="rubric-intro">Each email provider uses distinct MX hostnames. If you spotted an unfamiliar hostname in a DNS MX record — in a security tool, a search result, or a dmarcheck scan — these pages explain what it is, who operates it, and what it means for DMARC alignment.</p>
  <ul class="learn-hub-grid">${cards}</ul>
  <div class="bd-card">
    <div class="bd-card-title">Scan a domain</div>
    <div class="bd-card-body">
      <form action="/check" method="GET" class="learn-cta-form">
        <div class="search-box">
          <input type="text" name="domain" placeholder="Enter a domain to scan" aria-label="Enter a domain" autocapitalize="none" autocorrect="off" spellcheck="false" required>
          <button type="submit">Scan</button>
        </div>
      </form>
    </div>
  </div>
  ${MX_FOOTER}
</main>`;

  return page({
    title: "MX record providers — dmarcheck",
    path: "/mx",
    description:
      "What does this MX hostname mean? Identify Microsoft 365, Google Workspace, Mimecast, Proofpoint, Fastmail, Zoho, Amazon SES, and Cloudflare Email Routing from their MX records.",
    jsonLd: mxHubJsonLd(),
    body,
  });
}

export function renderMxProviderPage(slug: string): string | null {
  const provider = getMxProvider(slug);
  if (!provider) return null;

  const body = `<main class="breakdown learn">
  <nav class="report-nav" aria-label="Breadcrumb">
    <a href="/">${generateCreature("sm")} Home</a>
    <span class="breadcrumb-sep" aria-hidden="true">&rsaquo;</span>
    <a href="/mx">MX Providers</a>
    <span class="breadcrumb-sep" aria-hidden="true">&rsaquo;</span>
    <span class="breadcrumb-current">${esc(provider.name)}</span>
  </nav>
  <h1 class="rubric-title">${esc(provider.headline)}</h1>
  ${renderProviderBody(provider)}
  ${MX_FOOTER}
</main>`;

  return page({
    title: `${provider.name} MX records — dmarcheck`,
    path: `/mx/${provider.slug}`,
    description: provider.metaDescription,
    jsonLd: mxJsonLd(provider),
    body,
  });
}
