import type {
  BimiResult,
  DkimResult,
  DmarcResult,
  MtaStsResult,
  MxResult,
  ScanResult,
  SecurityTxtResult,
  SpfResult,
  TlsRptResult,
} from "../analyzers/types.js";
import { isIndexableScanDomain } from "../shared/indexable-domains.js";
import { CSS_PATH, JS_PATH } from "./assets.js";
import {
  dkimSelectorGrid,
  esc,
  generateCreature,
  gradeClass,
  lookupCounter,
  monitorSnapshotCard,
  mtaStsPolicyTable,
  mxTable,
  navLoginButton,
  protocolCard,
  protocolContributionGrid,
  rawRecord,
  rawRecordExpand,
  recommendationList,
  scoreSnippet,
  scoringFactorsTable,
  spfTree,
  tagGrid,
  themeToggle,
  tierExplanationCard,
  validationList,
} from "./components.js";

export const SITE_ORIGIN = "https://dmarc.mx";
export const DEFAULT_DESCRIPTION =
  "Free, open-source DNS email security analyzer. Check DMARC, SPF, DKIM, BIMI, and MTA-STS records for any domain.";

interface PageOptions {
  title: string;
  body: string;
  /** Absolute-path form, e.g. "/" or "/scoring" or "/check?domain=example.com". Defaults to "/". */
  path?: string;
  /** Overrides the default meta/og/twitter description. */
  description?: string;
  /** Pre-stringified JSON for a `<script type="application/ld+json">` block. */
  jsonLd?: string;
  /** When true, emits `<meta name="robots" content="noindex,follow">`. Used
   * for placeholder pages whose copy isn't final. */
  noindex?: boolean;
}

export function page(opts: PageOptions): string {
  const { title, body, path = "/", description = DEFAULT_DESCRIPTION } = opts;
  const canonical = `${SITE_ORIGIN}${path}`;
  const jsonLdBlock = opts.jsonLd
    ? `\n<script type="application/ld+json">${opts.jsonLd}</script>`
    : "";
  const robotsBlock = opts.noindex
    ? `\n<meta name="robots" content="noindex,follow">`
    : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#f97316">
<meta name="description" content="${esc(description)}">${robotsBlock}
<link rel="canonical" href="${esc(canonical)}">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:type" content="website">
<meta property="og:url" content="${esc(canonical)}">
<meta property="og:image" content="${SITE_ORIGIN}/og-image.png">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${esc(title)}">
<meta name="twitter:description" content="${esc(description)}">
<meta name="twitter:image" content="${SITE_ORIGIN}/og-image.png">
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/manifest.webmanifest">
<title>${esc(title)}</title>
<script>(function(){var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)})()</script>
<link rel="stylesheet" href="${CSS_PATH}">${jsonLdBlock}
</head>
<body>
${body}
${themeToggle()}
<script src="${JS_PATH}"></script>
</body>
</html>`;
}

const LANDING_JSON_LD = JSON.stringify({
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebSite",
      "@id": `${SITE_ORIGIN}/#website`,
      url: `${SITE_ORIGIN}/`,
      name: "dmarcheck",
      description: DEFAULT_DESCRIPTION,
      publisher: { "@id": `${SITE_ORIGIN}/#org` },
      potentialAction: {
        "@type": "SearchAction",
        target: {
          "@type": "EntryPoint",
          urlTemplate: `${SITE_ORIGIN}/check?domain={domain}`,
        },
        "query-input": "required name=domain",
      },
    },
    {
      "@type": "Organization",
      "@id": `${SITE_ORIGIN}/#org`,
      name: "dmarcheck",
      url: `${SITE_ORIGIN}/`,
      logo: `${SITE_ORIGIN}/logo.svg`,
    },
    {
      "@type": "SoftwareApplication",
      name: "dmarcheck",
      url: `${SITE_ORIGIN}/`,
      applicationCategory: "SecurityApplication",
      operatingSystem: "Any",
      description: DEFAULT_DESCRIPTION,
      offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
    },
  ],
});

export function renderLandingPage(): string {
  return page({
    title: "dmarcheck — DNS Email Security Analyzer",
    path: "/",
    jsonLd: LANDING_JSON_LD,
    body: `<main class="landing">
  <div class="landing-hero">
    <div class="landing-nav">${navLoginButton()}</div>
    <div class="landing-main">
      <div class="logo">${generateCreature("lg")}<span class="logo-text">dmar<span>check</span></span></div>
      <h1 class="tagline">DNS email security analyzer &mdash; DMARC, SPF, DKIM, BIMI &amp; MTA-STS</h1>
      <form action="/check" method="GET">
        <div class="search-box">
          <input type="text" name="domain" placeholder="Enter a domain (e.g., google.com)" aria-label="Enter a domain" autocapitalize="none" autocorrect="off" spellcheck="false" autofocus required>
          <button type="submit">Scan</button>
        </div>
        <details class="advanced-options">
          <summary>Advanced options</summary>
          <div class="advanced-body">
            <label for="selectors">Custom DKIM selectors</label>
            <input type="text" id="selectors" name="selectors"
                   placeholder="e.g. myselector, custom2"
                   autocomplete="off"
                   autocapitalize="none"
                   autocorrect="off"
                   spellcheck="false"
                   aria-describedby="selectors-help" />
            <small id="selectors-help">Comma-separated. These are checked in addition to the 38 common selectors.</small>
          </div>
        </details>
      </form>
      <div class="examples">
        Try: <a href="/check?domain=dmarc.mx">dmarc.mx</a> &middot;
        <a href="/check?domain=google.com">google.com</a> &middot;
        <a href="/check?domain=github.com">github.com</a>
      </div>
      <div class="learn-link">Analyze message headers: <a href="https://toolbox.googleapps.com/apps/messageheader/" target="_blank" rel="noopener">Google &#8599;</a> &middot; <a href="https://mha.azurewebsites.net/" target="_blank" rel="noopener">Microsoft &#8599;</a></div>
    </div>
    <div class="landing-footer">
      <div class="api-hint">
        <span>curl</span> https://dmarc.mx/api/check?domain=dmarc.mx
      </div>
      <div class="learn-link"><a href="/scoring">How is my score calculated?</a> &middot; <a href="https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/" target="_blank" rel="noopener">What is email security? &#8599;</a></div>
      <div class="learn-link"><a href="/pricing">Pricing</a> &middot; <a href="/legal/privacy">Privacy</a></div>
      <div class="foss-callout">
        <a href="https://github.com/schmug/dmarcheck" class="foss-link">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
          Free and open source &mdash; MIT License
        </a>
      </div>
      <div class="dmarcus-credit">Guarded by DMarcus ${generateCreature("sm", "content")}</div>
    </div>
  </div>
  <section class="landing-explainer" id="what-we-check" aria-labelledby="explainer-heading">
    <h2 id="explainer-heading">What dmarcheck checks</h2>
    <p>dmarcheck is a free DMARC, SPF, DKIM, BIMI, and MTA-STS checker for any domain. Enter a hostname and it pulls the live DNS records, validates them against the specs, and grades the overall posture from F to A+.</p>
    <dl class="explainer-grid">
      <div><dt><a href="/learn/dmarc">DMARC</a></dt><dd>The policy record that tells receivers how to treat unauthenticated mail and where to send aggregate reports.</dd></div>
      <div><dt><a href="/learn/spf">SPF</a></dt><dd>The list of hosts authorized to send on your behalf, including the 10-DNS-lookup budget.</dd></div>
      <div><dt><a href="/learn/dkim">DKIM</a></dt><dd>Per-selector signing keys and their key length, checked against 38 common selectors.</dd></div>
      <div><dt><a href="/learn/bimi">BIMI</a></dt><dd>The brand logo record that can render next to authenticated messages in supporting inboxes.</dd></div>
      <div><dt><a href="/learn/mta-sts">MTA-STS</a></dt><dd>The TLS enforcement policy that prevents downgrade attacks on inbound mail.</dd></div>
    </dl>
  </section>
</main>`,
  });
}

export function renderDmarcCard(dmarc: DmarcResult): string {
  const subtitle = dmarc.tags?.p ? `Policy: ${dmarc.tags.p}` : "No record";
  const raw = dmarc.tags
    ? rawRecord(dmarc.record)
    : rawRecordExpand(dmarc.record, "Show TXT records found");
  const body = tagGrid(dmarc.tags) + validationList(dmarc.validations) + raw;
  return protocolCard("DMARC", dmarc.status, subtitle, body, true, "dmarc");
}

export function renderSpfCard(spf: SpfResult): string {
  const subtitle = spf.record
    ? `${spf.lookups_used} of ${spf.lookup_limit} lookups used`
    : "No record";
  let body = "";
  if (spf.include_tree) {
    body += spfTree(spf.include_tree);
    body += lookupCounter(spf.lookups_used, spf.lookup_limit);
  }
  body += validationList(spf.validations);
  body += rawRecord(spf.record);
  return protocolCard("SPF", spf.status, subtitle, body, true, "spf");
}

export function renderDkimCard(dkim: DkimResult): string {
  const found = Object.values(dkim.selectors).filter((s) => s.found).length;
  const subtitle =
    found > 0
      ? `${found} selector${found > 1 ? "s" : ""} found`
      : "No selectors found";
  const body =
    dkimSelectorGrid(dkim.selectors) + validationList(dkim.validations);
  return protocolCard("DKIM", dkim.status, subtitle, body, false, "dkim");
}

export function renderBimiCard(bimi: BimiResult): string {
  const subtitle = bimi.record ? "Record found" : "No record found";
  const raw = bimi.tags
    ? rawRecord(bimi.record)
    : rawRecordExpand(bimi.record, "Show TXT records found");
  const logo = bimi.tags?.l?.startsWith("https://")
    ? `<div style="text-align:center;margin:1rem 0">
           <img src="${esc(bimi.tags.l)}" alt="BIMI logo" style="max-width:96px;max-height:96px;border-radius:8px;background:var(--clr-surface);padding:8px" onerror="this.style.display='none'">
         </div>`
    : "";
  const body =
    logo + tagGrid(bimi.tags) + validationList(bimi.validations) + raw;
  return protocolCard("BIMI", bimi.status, subtitle, body, false, "bimi");
}

export function renderMtaStsCard(mtaSts: MtaStsResult): string {
  const subtitle = mtaSts.policy
    ? `Mode: ${mtaSts.policy.mode}`
    : "Not configured";
  let body = "";
  if (mtaSts.policy) {
    body += mtaStsPolicyTable(mtaSts.policy);
  }
  body += validationList(mtaSts.validations);
  if (mtaSts.dns_record) {
    body += rawRecord(mtaSts.dns_record);
  }
  return protocolCard(
    "MTA-STS",
    mtaSts.status,
    subtitle,
    body,
    false,
    "mta-sts",
  );
}

export function renderSecurityTxtCard(s: SecurityTxtResult): string {
  const subtitle = s.fields
    ? `Found${s.signed ? " (signed)" : ""}`
    : "Not published";

  let body = "";
  if (s.fields) {
    const rows: string[] = [];
    if (s.fields.contact.length > 0) {
      rows.push(
        `<div><strong>Contact</strong></div><div>${s.fields.contact
          .map((v) => `<code>${esc(v)}</code>`)
          .join("<br>")}</div>`,
      );
    }
    if (s.fields.expires) {
      rows.push(
        `<div><strong>Expires</strong></div><div><code>${esc(s.fields.expires)}</code></div>`,
      );
    }
    if (s.fields.policy.length > 0) {
      rows.push(
        `<div><strong>Policy</strong></div><div>${s.fields.policy
          .map((v) => `<code>${esc(v)}</code>`)
          .join("<br>")}</div>`,
      );
    }
    if (s.fields.encryption.length > 0) {
      rows.push(
        `<div><strong>Encryption</strong></div><div>${s.fields.encryption
          .map((v) => `<code>${esc(v)}</code>`)
          .join("<br>")}</div>`,
      );
    }
    if (s.fields.preferred_languages) {
      rows.push(
        `<div><strong>Preferred-Languages</strong></div><div><code>${esc(s.fields.preferred_languages)}</code></div>`,
      );
    }
    if (rows.length > 0) {
      body += `<div class="tag-grid">${rows.join("")}</div>`;
    }
  }
  body += validationList(s.validations);
  if (s.source_url) {
    body += `<div class="raw-record"><a href="${esc(s.source_url)}" rel="nofollow noopener" target="_blank">${esc(s.source_url)} &nearr;</a></div>`;
  }
  return protocolCard(
    "security.txt",
    s.status,
    subtitle,
    body,
    false,
    "security-txt",
  );
}

export function renderTlsRptCard(t: TlsRptResult): string {
  const subtitle = t.record ? "Record found" : "Not configured";
  let body = "";
  if (t.tags?.rua) {
    const rows: string[] = [];
    rows.push(
      `<div><strong>rua</strong></div><div><code>${esc(t.tags.rua)}</code></div>`,
    );
    body += `<div class="tag-grid">${rows.join("")}</div>`;
  }
  body += validationList(t.validations);
  if (t.record) {
    body += rawRecord(t.record);
  }
  return protocolCard("TLS-RPT", t.status, subtitle, body, false, "tls-rpt");
}

export function renderMxCard(mx: MxResult): string {
  const subtitle =
    mx.records.length > 0
      ? `${mx.records.length} record${mx.records.length !== 1 ? "s" : ""}${mx.providers.length > 0 ? ` \u00b7 ${mx.providers.map((p) => p.name).join(", ")}` : ""}`
      : "No MX records";
  const body = mxTable(mx.records) + validationList(mx.validations);
  return protocolCard("MX", mx.status, subtitle, body);
}

function reportBody(result: ScanResult): string {
  const { mx, dmarc, spf, dkim, bimi, mta_sts, security_txt, tls_rpt } =
    result.protocols;

  return `<main class="report">
  <div class="report-nav">
    <a href="/">${generateCreature("sm")} dmarcheck</a>
    <span class="report-nav-spacer"></span>
    ${navLoginButton()}
  </div>
  <div class="report-header">
    <div class="overall-grade ${gradeClass(result.grade)}">${esc(result.grade)}</div>
    ${result.grade === "S" ? generateCreature("md", "celebrating", true) : ""}
    <h1 class="domain-name">${esc(result.domain)}</h1>
  </div>
  ${scoreSnippet(result)}
  <button class="confetti-toggle" data-grade="${esc(result.grade)}"
          aria-label="Toggle confetti" aria-pressed="false" title="Toggle confetti">&#127881;</button>
  <div class="report-meta">
    <time datetime="${esc(result.timestamp)}">Scanned ${esc(new Date(result.timestamp).toUTCString())}</time> &middot;
    <a href="/api/check?domain=${encodeURIComponent(result.domain)}">View JSON &nearr;</a> &middot;
    <a href="/check?domain=${encodeURIComponent(result.domain)}&format=csv" class="csv-download">Download CSV &darr;</a>
  </div>
  ${renderMxCard(mx)}
  ${renderDmarcCard(dmarc)}
  ${renderSpfCard(spf)}
  ${renderDkimCard(dkim)}
  ${renderBimiCard(bimi)}
  ${renderMtaStsCard(mta_sts)}
  ${security_txt ? renderSecurityTxtCard(security_txt) : ""}
  ${tls_rpt ? renderTlsRptCard(tls_rpt) : ""}
  ${monitorSnapshotCard(result)}
  <div class="learn-link" style="margin-top:2.5rem">Analyze message headers: <a href="https://toolbox.googleapps.com/apps/messageheader/" target="_blank" rel="noopener">Google &#8599;</a> &middot; <a href="https://mha.azurewebsites.net/" target="_blank" rel="noopener">Microsoft &#8599;</a></div>
  <div class="learn-link" style="margin-top:0.4rem;margin-bottom:1rem"><a href="/scoring">How is my score calculated?</a> &middot; <a href="https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/" target="_blank" rel="noopener">What is email security? &#8599;</a></div>
  <div class="foss-callout">
    <a href="https://github.com/schmug/dmarcheck" class="foss-link">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      Free and open source &mdash; MIT License
    </a>
  </div>
</main>`;
}

export function renderReport(result: ScanResult): string {
  return page({
    title: `${result.domain} DMARC report — Free check | dmarcheck`,
    path: `/check?domain=${encodeURIComponent(result.domain)}`,
    description: `Free, open-source DMARC, SPF, DKIM, BIMI, and MTA-STS check for ${result.domain}. See the current grade, records, and fixes. No signup, no email required.`,
    noindex: !isIndexableScanDomain(result.domain),
    body: reportBody(result),
  });
}

export function renderReportHeader(result: ScanResult): string {
  return `<div class="report-header">
    <div class="overall-grade ${gradeClass(result.grade)}">${esc(result.grade)}</div>
    ${result.grade === "S" ? generateCreature("md", "celebrating", true) : ""}
    <h1 class="domain-name">${esc(result.domain)}</h1>
  </div>
  ${scoreSnippet(result)}
  <button class="confetti-toggle" data-grade="${esc(result.grade)}"
          aria-label="Toggle confetti" aria-pressed="false" title="Toggle confetti">&#127881;</button>
  <div class="report-meta">
    <time datetime="${esc(result.timestamp)}">Scanned ${esc(new Date(result.timestamp).toUTCString())}</time> &middot;
    <a href="/api/check?domain=${encodeURIComponent(result.domain)}">View JSON &nearr;</a> &middot;
    <a href="/check?domain=${encodeURIComponent(result.domain)}&format=csv" class="csv-download">Download CSV &darr;</a>
  </div>`;
}

export function renderReportFooter(result: ScanResult): string {
  return `${monitorSnapshotCard(result)}
  <div class="learn-link" style="margin-top:2.5rem">Analyze message headers: <a href="https://toolbox.googleapps.com/apps/messageheader/" target="_blank" rel="noopener">Google &#8599;</a> &middot; <a href="https://mha.azurewebsites.net/" target="_blank" rel="noopener">Microsoft &#8599;</a></div>
  <div class="learn-link" style="margin-top:0.4rem;margin-bottom:1rem"><a href="/scoring">How is my score calculated?</a> &middot; <a href="https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/" target="_blank" rel="noopener">What is email security? &#8599;</a></div>
  <div class="foss-callout">
    <a href="https://github.com/schmug/dmarcheck" class="foss-link">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      Free and open source &mdash; MIT License
    </a>
  </div>`;
}

function skeletonCard(name: string, expanded: boolean): string {
  const bodyHtml = expanded
    ? `<div class="skel-body"><div class="skel-bar"></div><div class="skel-bar"></div><div class="skel-bar"></div></div>`
    : "";
  return `<div class="card-skeleton" data-protocol="${name.toLowerCase().replace("-", "_")}">
  <div class="card-header">
    <div class="skel-dot"></div>
    <div class="card-title">${esc(name)}</div>
    <div class="card-subtitle"><div class="skel-bar" style="width:100px;height:10px"></div></div>
  </div>
  ${bodyHtml}
</div>`;
}

export function renderStreamingLoading(
  domain: string,
  selectors: string,
): string {
  // `domain` and `selectors` are already validated by normalizeDomain /
  // parseSelectors at the route boundary, but we still avoid interpolating
  // them into JS string literals. Instead, the query string is emitted as an
  // HTML-escaped `data-qs` attribute and the inline script reads it from the
  // DOM — defense in depth against a future regression in input validation.
  // This replaces an earlier minimal fix (`.replace(/'/g, "%27")`) with a
  // structural solution that removes the injection point entirely.
  const qs = selectors
    ? `domain=${encodeURIComponent(domain)}&selectors=${encodeURIComponent(selectors)}`
    : `domain=${encodeURIComponent(domain)}`;

  return page({
    title: `${domain} DMARC report — Free check | dmarcheck`,
    path: `/check?domain=${encodeURIComponent(domain)}`,
    description: `Free, open-source DMARC, SPF, DKIM, BIMI, and MTA-STS check for ${domain}. See the current grade, records, and fixes. No signup, no email required.`,
    noindex: !isIndexableScanDomain(domain),
    body: `<main class="report" data-qs="${esc(qs)}">
  <div class="report-nav">
    <a href="/">${generateCreature("sm")} dmarcheck</a>
    <span class="report-nav-spacer"></span>
    ${navLoginButton()}
  </div>
  <div class="stream-header">
    <div class="grade-skeleton" style="margin:0 auto"></div>
    <h1 class="domain-name">${esc(domain)}</h1>
  </div>
  <div id="protocol-cards">
    ${skeletonCard("MX", false)}
    ${skeletonCard("DMARC", true)}
    ${skeletonCard("SPF", true)}
    ${skeletonCard("DKIM", false)}
    ${skeletonCard("BIMI", false)}
    ${skeletonCard("MTA-STS", false)}
  </div>
  <noscript><meta http-equiv="refresh" content="0;url=/check?${esc(qs)}&_direct=1"></noscript>
</main>
<script>
(function() {
  var root = document.querySelector('.report[data-qs]');
  var qs = root ? root.getAttribute('data-qs') : '';
  var source = new EventSource('/api/check/stream?' + qs);
  var container = document.getElementById('protocol-cards');
  var parser = new DOMParser();

  function parseFragment(html) {
    var doc = parser.parseFromString(html, 'text/html');
    return doc.body.firstElementChild;
  }

  source.addEventListener('protocol', function(e) {
    var data = JSON.parse(e.data);
    var skeleton = container.querySelector('[data-protocol="' + data.id + '"]');
    if (skeleton) {
      var el = parseFragment(data.html);
      if (el) {
        el.classList.add('loaded');
        el.setAttribute('data-protocol', data.id);
        skeleton.replaceWith(el);
      }
    }
  });

  source.addEventListener('done', function(e) {
    source.close();
    var data = JSON.parse(e.data);
    var header = document.querySelector('.stream-header');
    if (header) {
      var headerEl = parseFragment('<div>' + data.headerHtml + '</div>');
      if (headerEl) {
        while (headerEl.firstChild) {
          header.parentNode.insertBefore(headerEl.firstChild, header);
        }
        header.remove();
      }
    }
    if (data.footerHtml) {
      var cards = document.getElementById('protocol-cards');
      if (cards) {
        var footerDoc = parser.parseFromString(data.footerHtml, 'text/html');
        var nodes = footerDoc.body.childNodes;
        for (var i = 0; i < nodes.length; i++) {
          cards.parentNode.insertBefore(document.adoptNode(nodes[i].cloneNode(true)), cards.nextSibling);
        }
      }
    }
  });

  source.addEventListener('error', function() {
    source.close();
    window.location.href = '/check?' + qs + '&_direct=1';
  });
})();
</script>`,
  });
}

export function renderScoreBreakdown(result: ScanResult): string {
  const { breakdown } = result;
  const backUrl = `/check?domain=${encodeURIComponent(result.domain)}`;

  const body = `<main class="breakdown">
  <div class="report-nav">
    <a href="${backUrl}">${generateCreature("sm")} Back to results</a>
    <span class="report-nav-spacer"></span>
    ${navLoginButton()}
  </div>
  <div class="report-header">
    <div class="overall-grade ${gradeClass(result.grade)}">${esc(result.grade)}</div>
    ${result.grade === "S" ? generateCreature("md", "celebrating", true) : ""}
    <h1 class="domain-name">${esc(result.domain)}</h1>
  </div>
  <div class="report-meta">
    <time datetime="${esc(result.timestamp)}">Scanned ${esc(new Date(result.timestamp).toUTCString())}</time>
  </div>
  ${tierExplanationCard(breakdown.tier, breakdown.tierReason, breakdown.grade, breakdown.modifierLabel)}
  ${scoringFactorsTable(breakdown.factors, breakdown.modifier, breakdown.modifierLabel)}
  ${protocolContributionGrid(breakdown.protocolSummaries)}
  ${recommendationList(breakdown.recommendations)}
  <div class="learn-link" style="margin-top:2rem;margin-bottom:1rem"><a href="/scoring">How is my score calculated?</a> &middot; <a href="https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/" target="_blank" rel="noopener">What is email security? &#8599;</a></div>
</main>`;

  return page({
    title: `Scoring breakdown — ${result.domain} — dmarcheck`,
    path: `/check/score?domain=${encodeURIComponent(result.domain)}`,
    description: `Detailed scoring breakdown for ${result.domain}: tier, modifiers, and per-protocol contributions.`,
    body,
  });
}

const SCORING_JSON_LD = JSON.stringify({
  "@context": "https://schema.org",
  "@type": "FAQPage",
  mainEntity: [
    {
      "@type": "Question",
      name: "What is DMARC?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Domain-based Message Authentication, Reporting & Conformance. The policy layer that ties SPF and DKIM together and tells receivers what to do with unauthenticated mail. This is the most important factor in your grade.",
      },
    },
    {
      "@type": "Question",
      name: "What is SPF?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Sender Policy Framework. A DNS record listing which IP addresses are authorized to send mail for your domain. Receivers check the sending server's IP against this list.",
      },
    },
    {
      "@type": "Question",
      name: "What is DKIM?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "DomainKeys Identified Mail. Adds a cryptographic signature to outgoing messages, proving they haven't been tampered with in transit. Key strength of 2048 bits or more and multiple selectors improve your score.",
      },
    },
    {
      "@type": "Question",
      name: "What is BIMI?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Brand Indicators for Message Identification. Displays your brand logo next to authenticated messages in supporting email clients. Requires DMARC p=reject.",
      },
    },
    {
      "@type": "Question",
      name: "What is MTA-STS?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Mail Transfer Agent Strict Transport Security. Forces TLS encryption for inbound mail delivery, preventing downgrade attacks. Modes: testing (report only) and enforce (reject unencrypted).",
      },
    },
    {
      "@type": "Question",
      name: "How is the dmarcheck grade calculated?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "The grade has two parts: a base tier determined by your DMARC policy and authentication setup (F through A+), and modifiers that adjust the grade up (+) or down (-) based on reporting, SPF lookup budget, DKIM key length, BIMI, and MTA-STS.",
      },
    },
  ],
});

export function renderScoringRubric(): string {
  const body = `<main class="breakdown">
  <div class="report-nav">
    <a href="/">${generateCreature("sm")} Home</a>
  </div>
  <h1 class="rubric-title">Email Security Scoring</h1>
  <p class="rubric-intro">dmarcheck grades domains on five email authentication protocols. The grade is determined by a tier system based on your DMARC policy strength, then adjusted with modifiers from DMARC configuration quality, SPF, DKIM, and extras.</p>

  <div class="bd-card">
    <div class="bd-card-title">How the grade works</div>
    <div class="bd-card-body">
      <p class="tier-text">Your grade has two parts: a <strong>base tier</strong> determined by your DMARC policy and authentication setup, and <strong>modifiers</strong> that adjust the grade up (+) or down (&minus;) based on the quality of your configuration.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Grade tiers</div>
    <div class="bd-card-body">
      <table class="rubric-table">
        <thead><tr><th>Grade</th><th>Requirements</th></tr></thead>
        <tbody>
          <tr class="rubric-row-a">
            <td><span class="rubric-grade grade-a">A+</span></td>
            <td>DMARC p=reject + SPF within lookup limit + DKIM + <em>both</em> BIMI and MTA-STS (enforcing)</td>
          </tr>
          <tr class="rubric-row-a">
            <td><span class="rubric-grade grade-a">A</span></td>
            <td>DMARC p=reject + SPF within lookup limit + DKIM + at least one extra (BIMI or MTA-STS)</td>
          </tr>
          <tr class="rubric-row-b">
            <td><span class="rubric-grade grade-a">B</span></td>
            <td>DMARC p=reject + SPF passing + DKIM passing</td>
          </tr>
          <tr class="rubric-row-c">
            <td><span class="rubric-grade grade-c">C</span></td>
            <td>DMARC p=quarantine + SPF + DKIM passing (or p=reject with pct &lt; 10%)</td>
          </tr>
          <tr class="rubric-row-d">
            <td><span class="rubric-grade grade-c">D</span></td>
            <td>DMARC policy set but missing SPF or DKIM</td>
          </tr>
          <tr class="rubric-row-f">
            <td><span class="rubric-grade grade-f">F</span></td>
            <td>No DMARC record, DMARC validation failed, or policy set to none</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Modifiers</div>
    <div class="bd-card-body">
      <p class="tier-text" style="margin-bottom:12px">Grades C through A can receive a + or &minus; modifier based on configuration quality. The modifier is the sum of these factors:</p>
      <table class="rubric-table">
        <thead><tr><th>Factor</th><th>Effect</th></tr></thead>
        <tbody>
          <tr><td>DMARC aggregate reporting (rua) configured</td><td class="effect-plus">+1</td></tr>
          <tr><td>No DMARC reporting (rua/ruf) configured</td><td class="effect-minus">&minus;1</td></tr>
          <tr><td>DMARC pct &lt; 100% (partial enforcement)</td><td class="effect-minus">&minus;1</td></tr>
          <tr><td>SPF uses &le;5 DNS lookups</td><td class="effect-plus">+1</td></tr>
          <tr><td>Any DKIM key under 2048 bits</td><td class="effect-minus">&minus;1</td></tr>
          <tr><td>2 or more DKIM selectors found</td><td class="effect-plus">+1</td></tr>
          <tr><td>BIMI configured (B tier)</td><td class="effect-plus">+1</td></tr>
          <tr><td>MTA-STS configured (B tier)</td><td class="effect-plus">+1</td></tr>
          <tr><td>MTA-STS in testing mode</td><td class="effect-minus">&minus;1</td></tr>
        </tbody>
      </table>
      <p class="tier-text" style="margin-top:12px">If the total is +1 or higher, you get a +. If &minus;1 or lower, you get a &minus;. Zero means no modifier. SPF ~all and -all are treated equally when DMARC is enforced, per M3AAWG best practices.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">The five protocols</div>
    <div class="bd-card-body">
      <div class="rubric-protocol">
        <h3><a href="/learn/dmarc">DMARC</a></h3>
        <p>Domain-based Message Authentication, Reporting &amp; Conformance. The policy layer that ties SPF and DKIM together and tells receivers what to do with unauthenticated mail. This is the most important factor in your grade.</p>
      </div>
      <div class="rubric-protocol">
        <h3><a href="/learn/spf">SPF</a></h3>
        <p>Sender Policy Framework. A DNS record listing which IP addresses are authorized to send mail for your domain. Receivers check the sending server's IP against this list.</p>
      </div>
      <div class="rubric-protocol">
        <h3><a href="/learn/dkim">DKIM</a></h3>
        <p>DomainKeys Identified Mail. Adds a cryptographic signature to outgoing messages, proving they haven't been tampered with in transit. Key strength (2048+ bits) and multiple selectors improve your score.</p>
      </div>
      <div class="rubric-protocol">
        <h3><a href="/learn/bimi">BIMI</a></h3>
        <p>Brand Indicators for Message Identification. Displays your brand logo next to authenticated messages in supporting email clients. Requires DMARC p=reject.</p>
      </div>
      <div class="rubric-protocol">
        <h3><a href="/learn/mta-sts">MTA-STS</a></h3>
        <p>Mail Transfer Agent Strict Transport Security. Forces TLS encryption for inbound mail delivery, preventing downgrade attacks. Modes: testing (report only) and enforce (reject unencrypted).</p>
      </div>
    </div>
  </div>

  <div style="text-align:center;margin-top:2rem;margin-bottom:1rem">
    <a href="/" class="rubric-cta">Scan a domain &rarr;</a>
  </div>

  <div class="learn-link" style="text-align:center"><a href="/pricing">Pricing</a> &middot; <a href="/legal/privacy">Privacy</a></div>

  <div class="foss-callout">
    <a href="https://github.com/schmug/dmarcheck" class="foss-link">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      Free and open source &mdash; MIT License
    </a>
  </div>
</main>`;

  return page({
    title: "Email Security Scoring — dmarcheck",
    path: "/scoring",
    description:
      "How dmarcheck grades email security: DMARC policy tiers, SPF/DKIM requirements, and the modifiers that push grades up or down.",
    jsonLd: SCORING_JSON_LD,
    body,
  });
}

export function renderError(message: string): string {
  return page({
    title: "Error — dmarcheck",
    path: "/",
    body: `<main class="landing">
  <div class="landing-main">
    <div class="logo">${generateCreature("lg", "worried")}<span class="logo-text">dmar<span>check</span></span></div>
    <div class="error-box" role="alert">
      <h3>Error</h3>
      <p>${esc(message)}</p>
    </div>
    <a href="/">&larr; Try again</a>
  </div>
</main>`,
  });
}

export function renderApiDocs(): string {
  const body = `<main class="breakdown">
  <div class="report-nav">
    <a href="/">${generateCreature("sm")} Home</a>
  </div>
  <h1 class="rubric-title">dmarcheck API</h1>
  <p class="rubric-intro">Public, unauthenticated HTTP API for grading a domain's email-security DNS posture. Rate limited to 10 requests per minute per IP.</p>

  <div class="bd-card">
    <div class="bd-card-title">Discovery</div>
    <div class="bd-card-body">
      <ul>
        <li><a href="/.well-known/api-catalog"><code>/.well-known/api-catalog</code></a> — RFC 9727 linkset (<code>application/linkset+json</code>)</li>
        <li><a href="/openapi.json"><code>/openapi.json</code></a> — OpenAPI 3.1 service description</li>
        <li><a href="/health"><code>/health</code></a> — liveness probe</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">GET /api/check</div>
    <div class="bd-card-body">
      <p>Scan a domain and return the graded result as JSON.</p>
      <p><strong>Query params:</strong></p>
      <ul>
        <li><code>domain</code> <em>(required)</em> — <code>[a-z0-9.-]+</code></li>
        <li><code>selectors</code> <em>(optional)</em> — comma-separated extra DKIM selectors</li>
        <li><code>format</code> <em>(optional)</em> — <code>json</code> (default) or <code>csv</code></li>
      </ul>
      <p><strong>Example:</strong></p>
      <pre><code>curl -H 'Accept: application/json' '${SITE_ORIGIN}/api/check?domain=dmarc.mx'</code></pre>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">GET /api/check/stream</div>
    <div class="bd-card-body">
      <p>Same scan via Server-Sent Events. Emits a <code>protocol</code> event per analyzer, then a <code>done</code> event with header/footer HTML fragments.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">GET /check</div>
    <div class="bd-card-body">
      <p>Content-negotiated human endpoint.</p>
      <ul>
        <li>Default: HTML</li>
        <li><code>Accept: application/json</code> → JSON (same shape as <code>/api/check</code>)</li>
        <li><code>Accept: text/markdown</code> → markdown for agents</li>
        <li><code>format=csv</code> → CSV download</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Response shape</div>
    <div class="bd-card-body">
      <p>See <code>ScanResult</code> in <a href="/openapi.json">openapi.json</a>. Top-level keys: <code>domain</code>, <code>timestamp</code>, <code>grade</code>, <code>breakdown</code>, <code>summary</code>, <code>protocols</code> (<code>mx</code>, <code>dmarc</code>, <code>spf</code>, <code>dkim</code>, <code>bimi</code>, <code>mta_sts</code>, <code>security_txt</code>).</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Errors</div>
    <div class="bd-card-body">
      <ul>
        <li><code>400</code> — missing or invalid <code>domain</code> param</li>
        <li><code>429</code> — rate limit exceeded</li>
      </ul>
    </div>
  </div>

  <div class="foss-callout">
    <a href="https://github.com/schmug/dmarcheck" class="foss-link">Source on GitHub</a>
  </div>
</main>`;

  return page({
    title: "API — dmarcheck",
    path: "/docs/api",
    description:
      "dmarcheck public HTTP API: endpoints, parameters, response shape, and discovery (OpenAPI 3.1, RFC 9727 catalog).",
    body,
  });
}
