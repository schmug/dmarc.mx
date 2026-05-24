import type {
  ScanResult,
  SecurityTxtResult,
  TlsRptResult,
  Validation,
} from "../analyzers/types.js";
import {
  getMxProvider,
  MX_PROVIDERS,
  type MxProvider,
} from "../data/mx-providers.js";

// Markdown renderings for agent consumers that send `Accept: text/markdown`.
// Output is plain markdown with no HTML fragments — agents are expected to
// feed this straight into an LLM or a text diff.

const MD_SITE = "https://dmarc.mx";

function bullet(items: string[]): string {
  return items.length === 0 ? "" : items.map((s) => `- ${s}`).join("\n");
}

function validationLines(validations: Validation[]): string {
  if (validations.length === 0) return "- _(no findings)_";
  return validations.map((v) => `- **${v.status}** — ${v.message}`).join("\n");
}

function renderSecurityTxtMarkdown(s: SecurityTxtResult): string {
  if (!s.fields) {
    return `## security.txt — ${s.status}

_No security.txt published._

${validationLines(s.validations)}`;
  }
  const f = s.fields;
  const fieldLines: string[] = [];
  if (f.contact.length > 0)
    fieldLines.push(`- Contact: ${f.contact.join(", ")}`);
  if (f.expires) fieldLines.push(`- Expires: ${f.expires}`);
  if (f.policy.length > 0) fieldLines.push(`- Policy: ${f.policy.join(", ")}`);
  if (f.encryption.length > 0)
    fieldLines.push(`- Encryption: ${f.encryption.join(", ")}`);
  if (f.preferred_languages)
    fieldLines.push(`- Preferred-Languages: ${f.preferred_languages}`);
  return `## security.txt — ${s.status}

Source: <${s.source_url}>${s.signed ? " (PGP-signed)" : ""}

${fieldLines.join("\n")}

${validationLines(s.validations)}`;
}

function renderTlsRptMarkdown(t: TlsRptResult): string {
  if (!t.record) {
    return `## TLS-RPT — ${t.status}

_No TLS-RPT record found at _smtp._tls TXT._

${validationLines(t.validations)}`;
  }
  const ruaLine = t.tags?.rua ? `rua: ${t.tags.rua}` : "rua: _(missing)_";
  return `## TLS-RPT — ${t.status}

\`\`\`
${t.record}
\`\`\`

${ruaLine}

${validationLines(t.validations)}`;
}

export function renderLandingMarkdown(): string {
  return `# dmarcheck — DNS Email Security Analyzer

Free, open-source scanner that grades a domain's DMARC, SPF, DKIM, BIMI, and MTA-STS DNS posture.

## Scan a domain

\`\`\`
curl -H 'Accept: application/json' '${MD_SITE}/api/check?domain=example.com'
\`\`\`

Or render this page as a human report: <${MD_SITE}/check?domain=example.com>.

## API discovery

- Catalog: <${MD_SITE}/.well-known/api-catalog> (\`application/linkset+json\`, RFC 9727)
- OpenAPI 3.1: <${MD_SITE}/openapi.json>
- Human docs: <${MD_SITE}/docs/api>
- Health: <${MD_SITE}/health>

## Resources

- Scoring rubric: <${MD_SITE}/scoring>
- Learn: <${MD_SITE}/learn> (DMARC, SPF, DKIM, BIMI, MTA-STS)
- Source: <https://github.com/schmug/dmarcheck>

Rate limited to 10 requests per minute per IP.
`;
}

export function renderReportMarkdown(result: ScanResult): string {
  const { domain, timestamp, grade, breakdown, summary, protocols } = result;

  const recs = breakdown.recommendations
    .sort((a, b) => a.priority - b.priority)
    .map(
      (r) =>
        `- **P${r.priority} · ${r.protocol.toUpperCase()}** — ${r.title}. ${r.description} _(${r.impact})_`,
    )
    .join("\n");

  const factors = breakdown.factors
    .map(
      (f) =>
        `- ${f.protocol.toUpperCase()}: ${f.label} (${f.effect >= 0 ? "+" : ""}${f.effect})`,
    )
    .join("\n");

  return `# ${domain} — Grade ${grade}

_Scanned ${timestamp}_

**Tier:** ${breakdown.tier} — ${breakdown.tierReason}
**Modifier:** ${breakdown.modifierLabel} (${breakdown.modifier >= 0 ? "+" : ""}${breakdown.modifier})

## Summary

- MX records: ${summary.mx_records}${summary.mx_providers.length ? ` (${summary.mx_providers.join(", ")})` : ""}
- DMARC policy: ${summary.dmarc_policy ?? "_none_"}
- SPF: ${summary.spf_result} (${summary.spf_lookups})
- DKIM selectors found: ${summary.dkim_selectors_found}
- BIMI: ${summary.bimi_enabled ? "enabled" : "not configured"}
- MTA-STS mode: ${summary.mta_sts_mode ?? "_none_"}

## Recommendations

${recs || "- _(no recommendations — nicely done)_"}

## Scoring factors

${factors || "- _(no factors)_"}

## DMARC — ${protocols.dmarc.status}

${protocols.dmarc.record ? `\`\`\`\n${protocols.dmarc.record}\n\`\`\`` : "_No DMARC record found._"}

${validationLines(protocols.dmarc.validations)}

## SPF — ${protocols.spf.status}

${protocols.spf.record ? `\`\`\`\n${protocols.spf.record}\n\`\`\`` : "_No SPF record found._"}

Lookups used: ${protocols.spf.lookups_used} / ${protocols.spf.lookup_limit}

${validationLines(protocols.spf.validations)}

## DKIM — ${protocols.dkim.status}

${renderDkimSelectors(protocols.dkim.selectors)}

${validationLines(protocols.dkim.validations)}

## BIMI — ${protocols.bimi.status}

${protocols.bimi.record ? `\`\`\`\n${protocols.bimi.record}\n\`\`\`` : "_No BIMI record found._"}

${validationLines(protocols.bimi.validations)}

## MTA-STS — ${protocols.mta_sts.status}

${protocols.mta_sts.dns_record ? `\`\`\`\n${protocols.mta_sts.dns_record}\n\`\`\`` : "_No MTA-STS DNS record found._"}

${protocols.mta_sts.policy ? `Policy: mode=${protocols.mta_sts.policy.mode}, max_age=${protocols.mta_sts.policy.max_age}, mx=[${protocols.mta_sts.policy.mx.join(", ")}]` : ""}

${validationLines(protocols.mta_sts.validations)}

## MX — ${protocols.mx.status}

${bullet(protocols.mx.records.map((r) => `${r.priority} ${r.exchange}${r.provider ? ` _(${r.provider.name})_` : ""}`)) || "_No MX records found._"}

${validationLines(protocols.mx.validations)}

${protocols.security_txt ? renderSecurityTxtMarkdown(protocols.security_txt) : ""}

${protocols.tls_rpt ? renderTlsRptMarkdown(protocols.tls_rpt) : ""}

---

JSON: <${MD_SITE}/api/check?domain=${encodeURIComponent(domain)}>
`;
}

function renderDkimSelectors(
  selectors: ScanResult["protocols"]["dkim"]["selectors"],
): string {
  const entries = Object.entries(selectors);
  if (entries.length === 0) return "_No DKIM selectors probed._";
  return entries
    .map(([name, r]) => {
      if (!r.found) return `- \`${name}\` — not found`;
      const parts: string[] = [];
      if (r.key_type) parts.push(r.key_type);
      if (r.key_bits) parts.push(`${r.key_bits} bits`);
      if (r.testing) parts.push("testing");
      if (r.revoked) parts.push("revoked");
      return `- \`${name}\` — ${parts.join(", ") || "found"}`;
    })
    .join("\n");
}

export function renderApiDocsMarkdown(): string {
  return `# dmarcheck API

Public, unauthenticated HTTP API for grading a domain's email-security DNS posture.

**Base URL:** \`${MD_SITE}\`
**Rate limit:** 10 requests per minute per IP (see \`X-RateLimit-*\` response headers).

## Discovery

- **Catalog** (RFC 9727): \`GET /.well-known/api-catalog\` → \`application/linkset+json\`
- **OpenAPI 3.1**: \`GET /openapi.json\` → \`application/openapi+json\`
- **Health**: \`GET /health\` → \`{ "status": "ok", "timestamp": "..." }\`

## Endpoints

### \`GET /api/check\`

Scan a domain and return the graded result as JSON.

Query params:

- \`domain\` _(required)_ — \`[a-z0-9.-]+\`, e.g. \`example.com\`
- \`selectors\` _(optional)_ — comma-separated extra DKIM selectors
- \`format\` _(optional)_ — \`json\` (default) or \`csv\`

Example:

\`\`\`
curl -H 'Accept: application/json' '${MD_SITE}/api/check?domain=dmarc.mx'
\`\`\`

### \`GET /api/check/stream\`

Same scan but Server-Sent Events. Emits \`protocol\` events per analyzer, then a \`done\` event with header/footer HTML fragments.

### \`GET /check\`

Content-negotiated human endpoint.

- Default: HTML
- \`Accept: application/json\` → JSON (same shape as \`/api/check\`)
- \`Accept: text/markdown\` → this rendering, for agents
- \`format=csv\` → CSV download

## Response shape

See \`ScanResult\` in <${MD_SITE}/openapi.json>. Summary:

\`\`\`
{
  "domain": "example.com",
  "timestamp": "2026-04-17T12:00:00Z",
  "grade": "A",
  "breakdown": { "grade", "tier", "factors", "recommendations", ... },
  "summary": { "dmarc_policy", "spf_result", "dkim_selectors_found", ... },
  "protocols": {
    "mx":      { "status", "records", "providers", "validations" },
    "dmarc":   { "status", "record", "tags", "validations" },
    "spf":     { "status", "record", "lookups_used", "include_tree", ... },
    "dkim":    { "status", "selectors", "validations" },
    "bimi":    { "status", "record", "tags", "validations" },
    "mta_sts": { "status", "dns_record", "policy", "validations" },
    "security_txt": { "status", "source_url", "signed", "fields", "validations" }
  }
}
\`\`\`

## Errors

- \`400\` — missing or invalid \`domain\` param
- \`429\` — rate limit exceeded

## Source

<https://github.com/schmug/dmarcheck>
`;
}

export function renderScoringRubricMarkdown(): string {
  return `# dmarcheck scoring rubric

The grade (S, A+, A, B, C, D, F) is computed from a tier + modifier model. Full logic: <https://github.com/schmug/dmarcheck/blob/main/src/shared/scoring.ts>.

- **F** — domain has no DMARC record or DMARC \`p=none\`.
- **D / C** — DMARC present but weak; SPF/DKIM issues.
- **B** — DMARC enforced (quarantine/reject) with SPF + DKIM aligned.
- **A / A+** — Full DMARC enforcement, SPF + DKIM correct, MTA-STS enforced.
- **S** — All of the above plus BIMI with a valid VMC.

Run a scan: \`${MD_SITE}/check?domain=example.com\` (add \`Accept: text/markdown\` for this format).
`;
}

export function renderLearnHubMarkdown(): string {
  return `# Learn — email security DNS records

- [DMARC](${MD_SITE}/learn/dmarc) — policy layer on top of SPF + DKIM
- [SPF](${MD_SITE}/learn/spf) — authorized sending IPs
- [DKIM](${MD_SITE}/learn/dkim) — cryptographic signatures
- [BIMI](${MD_SITE}/learn/bimi) — brand logos in inboxes
- [MTA-STS](${MD_SITE}/learn/mta-sts) — TLS enforcement for inbound mail

Run a scan: ${MD_SITE}/check?domain=example.com
`;
}

export function renderPricingMarkdown(): string {
  return `# Nightly DMARC, SPF, DKIM, BIMI & MTA-STS monitoring

**$19/mo.** Free forever for one-off scans.

## Free — $0

Public scanner, no account needed.

- Unlimited on-demand scans from the web UI
- JSON API: \`GET /api/check?domain=example.com\`
- 10 requests per minute per IP
- All five analyzers: DMARC, SPF, DKIM, BIMI, MTA-STS
- Self-hostable (MIT) — <https://github.com/schmug/dmarcheck>

## Pro — $19/mo

Continuous monitoring for the domains you actually care about.

- Saved scan history with per-domain trend views
- Nightly rescans of your watchlist (up to 25 domains)
- Email alerts on grade drop or protocol regression
- Bulk scan: up to 100 domains per request
- API keys with a 60-request/hour rate limit (6× the anonymous ceiling)
- Cancel anytime via Stripe Customer Portal — access continues until the period ends
- 30-day refunds on request — email support@dmarc.mx

**Not in Pro (yet):** DMARC aggregate (RUA) report ingestion, team seats or SSO, white-label or custom domain.

**Start Pro:** <${MD_SITE}/dashboard/billing/subscribe> (requires a free account).

## FAQ

- **Does the free scanner stay free?** Yes. The scanner, all five analyzers, and the JSON API stay free and open source. Pro adds hosted features — history, monitoring, alerts — not the scan itself.
- **What counts as "nightly"?** Once every 24 hours, in the early-UTC-morning window. Every domain on your watchlist gets re-scanned; if the grade drops or a protocol regresses versus the previous scan, you get an email.
- **How do I cancel?** One click in the Stripe Customer Portal, linked from your account page. You keep access until the end of the current billing cycle and aren't charged again.
- **Refunds?** Yes — email support@dmarc.mx within 30 days of the charge for a full refund. After 30 days, cancel at period end.
- **Can I self-host the paid features?** Yes — the repo is MIT-licensed. Clone it, configure D1, WorkOS, and Stripe bindings, and run the same code with the same features.
- **Where's my data stored, and for how long?** Cloudflare D1 (US region). Scan results retained while your account is active; deleted on request or within 30 days of account closure. Full detail: <${MD_SITE}/legal/privacy>.
- **Pro API rate limits?** 60 requests/hour per API key. Anonymous IP limit stays at 10/min. Need more? Email support@dmarc.mx.

See [Privacy](${MD_SITE}/legal/privacy). Questions? support@dmarc.mx.
`;
}

export function renderPrivacyMarkdown(): string {
  return `# Privacy Policy

_Last updated: 2026-04-24_

## Who I am

DMarcus runs **dmarcheck** — the hosted email-security scanner at ${MD_SITE}. The self-hosted OSS project (<https://github.com/schmug/dmarcheck>) is yours to run under MIT; this policy covers the hosted service only.

## What I collect

When you use ${MD_SITE}:

- **The domain you scan** and its public DNS records.
- **Your IP address**, briefly, for rate limiting.
- **Your email address** — only if you have a Pro account. I need it to log you in, send alerts you asked for, and contact you about your account.
- **Your subscription state** from Stripe: subscription ID, plan, status, period end. Stripe holds the actual payment method; I never see your card number.
- **Scan history and watchlist** — only if you have a Pro account and added domains yourself.
- **Error telemetry** via Sentry, when the service crashes.
- **Anonymized page views** via Cloudflare Web Analytics — cookieless beacon, no cross-site tracking, no per-user profile. Skipped on \`/dashboard/*\`, \`/auth/*\`, and webhook endpoints.

## Why

- Scan → show you the result.
- IP address → stop one caller from drowning everyone.
- Email → log you in, send alerts you asked for, contact you about billing.
- Stripe subscription state → run Pro features, let you cancel.
- Scan history and watchlist → run the Pro features you paid for.
- Error telemetry → fix bugs.
- Page views → know which pages are worth improving.

## How long I keep it

- **Free, anonymous scans:** not stored after the scan completes.
- **Pro scan history and watchlist:** kept while your account is active. Deleted within 30 days of account closure or on request.
- **Account email:** same as above.
- **Stripe billing records:** Stripe retains these to comply with US financial-record law (typically 7 years). I delete my local copy on account closure.
- **Error telemetry:** 90 days, then purged by Sentry.
- **Page views (Cloudflare Web Analytics):** aggregated only, no per-user record to delete.

## Who I share it with

I use a short list of subprocessors to run the service. **I'm not using this to train AI, selling your data, or sending it to advertisers.**

- **Cloudflare** — hosting, DNS, edge compute, D1 database, Web Analytics
- **WorkOS** — account login
- **Stripe** — billing
- **Cloudflare Email Sending** — alerts, receipts, login links
- **Sentry** — error telemetry

If I add or swap a subprocessor, I'll update this list and email Pro users at least 14 days ahead.

## Your rights

- **Export your data** — email support@dmarc.mx and I'll send your scan history and watchlist as JSON within 30 days.
- **Delete your account** — one click from the dashboard. Everything I hold gets removed within 30 days. Stripe keeps its own billing records per law.
- **Stop getting emails** — unsubscribe from any email footer, or toggle alerts off in your dashboard.
- **Ask a question** — support@dmarc.mx.

If you're in the EU/UK, California, or any jurisdiction with statutory privacy rights (GDPR, UK GDPR, CCPA/CPRA, etc.), you have the full set of rights that law gives you. Nothing here overrides a statutory right.

## Cookies

- **Session cookie** when you log in (required).
- **Theme preference** (light/dark) in \`localStorage\`.

That's the whole list. No advertising cookies, no third-party tracking.

## Children

dmarcheck isn't aimed at anyone under 13. If you're under 13, please don't sign up.

## Changes

If I change how I handle your data in a way that affects you materially, I'll email Pro users at least 14 days ahead. The "Last updated" date tracks minor edits.

## Contact

support@dmarc.mx
`;
}

function mdStripHtml(html: string): string {
  // Page prose stores light HTML (<code>, <a>, etc.) for the HTML renderer.
  // For markdown we convert <code>x</code> to backticked `x`, strip remaining
  // tags, and decode the handful of HTML entities used in the catalog.
  return html
    .replace(/<code>([^<]*)<\/code>/g, (_, inner) => `\`${inner}\``)
    .replace(/<[^>]+>/g, "")
    .replace(/&rarr;/g, "→")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"');
}

function renderMxProviderBodyMarkdown(provider: MxProvider): string {
  const sections = provider.sections
    .map((section) => {
      const paragraphs = section.paragraphs.map(mdStripHtml).join("\n\n");
      const list = section.list
        ? `\n\n${section.list.map((item) => `- ${mdStripHtml(item)}`).join("\n")}`
        : "";
      return `## ${section.title}\n\n${paragraphs}${list}`;
    })
    .join("\n\n");
  const hostnames = provider.hostnameExamples
    .map((h) => `- \`${h}\``)
    .join("\n");
  const examples =
    provider.parentExamples.length > 0
      ? `## Scan an example tenant\n\n${provider.parentExamples
          .map(
            (d) =>
              `- [Scan ${d}](${MD_SITE}/check?domain=${encodeURIComponent(d)})`,
          )
          .join("\n")}\n\n`
      : "";
  return `# ${provider.headline}

${mdStripHtml(provider.intro)}

**Operator:** ${provider.operator}

## Hostnames in the catalog

${hostnames}

${sections}

${examples}---

More MX providers: <${MD_SITE}/mx>. Scan a domain: <${MD_SITE}/check?domain=example.com>.
`;
}

export function renderMxProviderMarkdown(slug: string): string | null {
  const provider = getMxProvider(slug);
  if (!provider) return null;
  return renderMxProviderBodyMarkdown(provider);
}

export function renderMxHubMarkdown(): string {
  const items = MX_PROVIDERS.map(
    (p) =>
      `- [${p.shortName}](${MD_SITE}/mx/${p.slug}) — \`${p.hostnameExamples[0] ?? ""}\``,
  ).join("\n");
  return `# MX provider reference — identify an MX hostname

If you've spotted an MX hostname in a DNS lookup or message header and want to know what runs it, start here. Each page covers what the service is, who operates it, how the MX hostname is structured, and which kinds of organisations use it.

${items}

Scan a domain: <${MD_SITE}/check?domain=example.com>.
`;
}

export function renderErrorMarkdown(message: string): string {
  return `# Error

${message}

Try again: <${MD_SITE}>
`;
}
