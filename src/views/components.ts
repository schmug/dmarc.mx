import type {
  DkimSelectorResult,
  EmailProvider,
  MtaStsPolicy,
  MxRecord,
  ScanResult,
  SpfIncludeNode,
  Status,
  Validation,
} from "../analyzers/types.js";
import { lookupMxProvider } from "../data/mx-providers.js";
import type { Recommendation, ScoringFactor } from "../shared/scoring.js";

const DMARC_TOOLTIPS: Record<string, string> = {
  v: "Version — must be DMARC1",
  p: "Policy — what to do with failing messages (none/quarantine/reject)",
  sp: "Subdomain policy — overrides p= for subdomains",
  rua: "Aggregate report URI — where to send daily XML reports",
  ruf: "Forensic report URI — where to send per-failure reports",
  pct: "Percentage — % of messages subject to the policy",
  adkim: "DKIM alignment — strict (s) or relaxed (r)",
  aspf: "SPF alignment — strict (s) or relaxed (r)",
  fo: "Failure options — when to generate forensic reports",
  ri: "Report interval — seconds between aggregate reports",
};

import { esc } from "../shared/escape.js";

export { esc };

export function gradeClass(grade: string): string {
  if (grade === "S") return "grade-s";
  const letter = grade.charAt(0).toUpperCase();
  if (letter === "A" || letter === "B") return "grade-a";
  if (letter === "C" || letter === "D") return "grade-c";
  return "grade-f";
}

export type CreatureSize = "lg" | "md" | "sm";
export type CreatureMood =
  | "celebrating"
  | "content"
  | "worried"
  | "scared"
  | "panicked";

export function generateCreature(
  size: CreatureSize,
  mood?: CreatureMood,
  partyHat?: boolean,
  walking?: boolean,
): string {
  const moodClass = mood ? ` creature-${mood}` : "";
  const hatClass = partyHat ? " creature-partying" : "";
  const walkClass = walking ? " creature-walking" : "";
  const hatHtml = partyHat ? '<div class="creature-hat"></div>' : "";
  return `<div class="creature creature-${size}${moodClass}${hatClass}${walkClass}" aria-hidden="true">
  ${hatHtml}<div class="creature-body">@<div class="creature-eyes"><div class="creature-eye"><div class="creature-pupil"></div></div><div class="creature-eye"><div class="creature-pupil"></div></div></div></div>
  <div class="creature-legs"><div class="creature-leg"></div><div class="creature-leg"></div><div class="creature-leg"></div></div>
</div>`;
}

export function themeToggle(): string {
  return '<button class="theme-toggle" aria-label="Toggle theme" title="Toggle theme"></button>';
}

// TODO: gate on session state once a request-scoped session helper exists
// outside src/auth/middleware.ts.
export function navLoginButton(): string {
  return `<a href="/auth/login" class="nav-login" aria-label="Log in to monitor a domain (free)">
  <span class="nav-login-avatar">${generateCreature("sm")}</span>
  <span class="nav-login-label">Log in to monitor</span>
  <span class="nav-login-arrow" aria-hidden="true">&#8599;</span>
</a>`;
}

export function monitorSnapshotCard(result: ScanResult): string {
  const { domain, protocols, timestamp } = result;
  const policy = protocols.dmarc.tags?.p;
  const dmarcOk = policy === "reject" || policy === "quarantine";
  const spfOk = protocols.spf.status === "pass";
  // ⚡ Bolt Optimization: Use a simple loop instead of Object.values().filter().length
  let dkimCount = 0;
  for (const name in protocols.dkim.selectors) {
    if (protocols.dkim.selectors[name].found) dkimCount++;
  }
  const bimiOk = !!protocols.bimi.tags;
  const nextUrl = `/auth/login?next=/dashboard&prompt=monitor:${encodeURIComponent(domain)}`;
  const stamp = new Date(timestamp).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });

  const row = (ok: boolean, label: string, value: string): string =>
    `<div class="snap-row${ok ? "" : " snap-row-muted"}">
      <span class="snap-mark">${ok ? "+" : "\u00b7"}</span>
      <span class="snap-label">${esc(label)}</span>
      <span class="snap-val">${esc(value)}</span>
    </div>`;

  const spfValue = protocols.spf.record
    ? `${protocols.spf.lookups_used}/${protocols.spf.lookup_limit} lookups`
    : "not set";
  const dkimValue =
    dkimCount > 0
      ? `${dkimCount} selector${dkimCount > 1 ? "s" : ""}`
      : "none found";
  const bimiValue = bimiOk ? "configured" : "not configured";
  const dmarcValue = policy ? `p=${policy}` : "not set";

  return `<section class="monitor-card" aria-labelledby="monitor-card-title">
  <div class="monitor-snap">
    <div class="monitor-eyebrow">Snapshot &middot; ${esc(stamp)}</div>
    <div id="monitor-card-title" class="monitor-snap-heading">We'd tell you if any of this changed:</div>
    <div class="snap-list">
      ${row(dmarcOk, "DMARC policy", dmarcValue)}
      ${row(spfOk, "SPF", spfValue)}
      ${row(dkimCount > 0, "DKIM", dkimValue)}
      ${row(bimiOk, "BIMI", bimiValue)}
    </div>
  </div>
  <div class="monitor-divider" aria-hidden="true"></div>
  <div class="monitor-pitch">
    <p class="monitor-pitch-lede">Monitor <strong>${esc(domain)}</strong> and we'll re-run this check every 24 hours. You'll get an email the moment anything drifts.</p>
    <div class="monitor-cta-row">
      <a href="${esc(nextUrl)}" class="monitor-cta">Start monitoring</a>
      <span class="monitor-cta-meta">free &middot; no card &middot; MIT open source</span>
    </div>
  </div>
</section>`;
}

export function gradeToMood(grade: string): CreatureMood {
  if (grade === "S") return "celebrating";
  const letter = grade.charAt(0).toUpperCase();
  if (letter === "A") return "celebrating";
  if (letter === "B") return "content";
  if (letter === "C") return "worried";
  if (letter === "D") return "scared";
  return "panicked";
}

export type StatCardStatus = "pass" | "warn" | "fail";

export function statCard(
  label: string,
  value: number | string,
  sub: string,
  status?: StatCardStatus,
): string {
  const tint = status ? ` stat-card-${status}` : "";
  return `<div class="stat-card${tint}">
    <div class="stat-card-label">${esc(label)}</div>
    <div class="stat-card-value">${esc(String(value))}</div>
    <div class="stat-card-sub">${esc(sub)}</div>
  </div>`;
}

export interface SparklineOptions {
  width?: number;
  height?: number;
  max?: number;
  min?: number;
  fill?: boolean;
  ariaLabel?: string;
}

export function sparkline(
  values: number[],
  color: string,
  opts: SparklineOptions = {},
): string {
  const width = opts.width ?? 80;
  const height = opts.height ?? 22;
  const max = opts.max ?? 12;
  const min = opts.min ?? 0;
  const range = Math.max(1, max - min);
  if (values.length === 0) {
    return `<svg class="dash-spark" width="${width}" height="${height}" aria-hidden="true"></svg>`;
  }
  const stepX = values.length > 1 ? width / (values.length - 1) : width;
  const points = values
    .map((v, i) => {
      const clamped = Math.max(min, Math.min(max, v));
      const x = i * stepX;
      const y = height - ((clamped - min) / range) * (height - 4) - 2;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const safeColor = esc(color);
  const area = opts.fill
    ? `<polygon points="0,${height} ${points} ${width},${height}" fill="${safeColor}" opacity="0.12" />`
    : "";
  const ariaAttrs = opts.ariaLabel
    ? ` role="img" aria-label="${esc(opts.ariaLabel)}"`
    : ' aria-hidden="true"';
  return `<svg class="dash-spark" width="${width}" height="${height}"${ariaAttrs}>${area}<polyline points="${points}" fill="none" stroke="${safeColor}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg>`;
}

export function singlePointTrendStub(): string {
  return `<span class="trend-stub" tabindex="0" aria-label="Just added — trend appears after the next scan">
    <svg width="80" height="22" aria-hidden="true">
      <line x1="4" y1="11" x2="76" y2="11" stroke="var(--clr-border-hover)" stroke-width="1" stroke-dasharray="2 3"/>
      <circle cx="72" cy="11" r="3" fill="var(--clr-accent)"/>
    </svg>
    <span class="trend-stub-label">new</span>
  </span>`;
}

export function statusDot(status: Status): string {
  const label =
    status === "pass"
      ? "Status: passing"
      : status === "warn"
        ? "Status: warning"
        : status === "info"
          ? "Status: informational"
          : "Status: failing";
  return `<div class="status-dot status-${status}" role="img" aria-label="${label}"></div>`;
}

export function validationList(validations: Validation[]): string {
  // ⚡ Bolt Optimization: Use a single-pass loop instead of .map().join("")
  // Reduces GC pressure on a hot rendering path by avoiding array allocations
  let items = "";
  for (const v of validations) {
    const icon =
      v.status === "pass"
        ? '<span class="icon-pass" aria-hidden="true">&#10003;</span>'
        : v.status === "warn"
          ? '<span class="icon-warn" aria-hidden="true">&#9888;</span>'
          : v.status === "info"
            ? '<span class="icon-info" aria-hidden="true">&#9432;</span>'
            : '<span class="icon-fail" aria-hidden="true">&#10007;</span>';
    items += `<li>${icon} ${esc(v.message)}</li>`;
  }
  return `<ul class="validation-list">${items}</ul>`;
}

export function rawRecord(record: string | null): string {
  if (!record) return "";
  return `<div class="record-raw"><code>${esc(record)}</code><button class="copy-btn" data-copy="${esc(record)}" aria-label="Copy DNS record">Copy</button></div>`;
}

export function rawRecordExpand(record: string | null, label: string): string {
  if (!record) return "";
  return `<details class="record-expand"><summary>${esc(label)}</summary><div class="record-raw"><code>${esc(record)}</code></div></details>`;
}

export function tagGrid(
  tags: Record<string, string> | null,
  tooltips: Record<string, string> = DMARC_TOOLTIPS,
): string {
  if (!tags) return "";
  let rows = "";
  // ⚡ Bolt Optimization: Use for...in instead of Object.entries().map()
  // Reduces GC pressure by avoiding array allocations on hot rendering paths
  for (const key in tags) {
    const value = tags[key];
    const tip = tooltips[key]
      ? `<span class="tooltip" tabindex="0" aria-label="${esc(key)}: ${esc(tooltips[key])}">${esc(key)}<span class="tooltip-text" aria-hidden="true">${esc(tooltips[key])}</span></span>`
      : esc(key);
    rows += `<span class="tag-name">${tip}</span><span class="tag-value">${esc(value)}</span>`;
  }
  return `<div class="tag-grid">${rows}</div>`;
}

export function protocolCard(
  name: string,
  status: Status,
  subtitle: string,
  body: string,
  expanded = false,
  learnSlug?: string,
): string {
  const safeId = name.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  const headerId = `card-header-${safeId}`;
  const bodyId = `card-body-${safeId}`;

  const learnLink = learnSlug
    ? `<div class="card-learn-link"><a href="/learn/${esc(learnSlug)}">Learn about ${esc(name)} &rarr;</a></div>`
    : "";
  return `<div class="card${expanded ? " expanded" : ""}">
  <div class="card-header" id="${headerId}" role="button" tabindex="0" aria-expanded="${expanded ? "true" : "false"}" aria-controls="${bodyId}">
    ${statusDot(status)}
    <div class="card-title">${esc(name)}</div>
    <div class="card-subtitle">${esc(subtitle)}</div>
    <div class="card-chevron" aria-hidden="true">&#9654;</div>
  </div>
  <div class="card-body" id="${bodyId}" role="region" aria-labelledby="${headerId}">${body}${learnLink}</div>
</div>`;
}

export function spfTree(node: SpfIncludeNode): string {
  // ⚡ Bolt Optimization: Use a single-pass loop instead of .map().filter().join("")
  // Reduces GC pressure on a hot rendering path by avoiding array allocations
  let items = "";
  for (const m of node.mechanisms) {
    const bare = m.replace(/^[+\-~?]/, "");
    if (!bare.startsWith("include:") && !bare.startsWith("redirect=")) {
      items += `<li><span class="spf-node mechanism">${esc(m)}</span></li>`;
    }
  }

  let includes = "";
  for (let i = 0; i < node.includes.length; i++) {
    const child = node.includes[i];
    const inner = spfTreeInner(child);
    const isExpandable = inner !== "";
    const safeId = child.domain.replace(/[^a-z0-9]+/g, "-");
    const listId = `spf-list-${safeId}-${i}`;
    const attrs = isExpandable
      ? ' role="button" tabindex="0" aria-expanded="true" aria-controls="' +
        listId +
        '"'
      : "";
    const innerWithId = isExpandable
      ? inner.replace("<ul>", `<ul id="${listId}">`)
      : inner;
    includes +=
      '<li><span class="spf-node include"' +
      attrs +
      ">" +
      esc(`include:${child.domain}`) +
      "</span>" +
      innerWithId +
      "</li>";
  }

  return `<div class="spf-tree"><ul>${items}${includes}</ul></div>`;
}

function spfTreeInner(node: SpfIncludeNode): string {
  if (!node.record) return "";

  // ⚡ Bolt Optimization: Use a single-pass loop instead of .map().filter().join("")
  let items = "";
  for (const m of node.mechanisms) {
    const bare = m.replace(/^[+\-~?]/, "");
    if (!bare.startsWith("include:") && !bare.startsWith("redirect=")) {
      items += `<li><span class="spf-node mechanism">${esc(m)}</span></li>`;
    }
  }

  let includes = "";
  for (let i = 0; i < node.includes.length; i++) {
    const child = node.includes[i];
    const inner = spfTreeInner(child);
    const isExpandable = inner !== "";
    const safeId = child.domain.replace(/[^a-z0-9]+/g, "-");
    const listId = `spf-list-${safeId}-${i}`;
    const attrs = isExpandable
      ? ' role="button" tabindex="0" aria-expanded="true" aria-controls="' +
        listId +
        '"'
      : "";
    const innerWithId = isExpandable
      ? inner.replace("<ul>", `<ul id="${listId}">`)
      : inner;
    includes +=
      '<li><span class="spf-node include"' +
      attrs +
      ">" +
      esc(`include:${child.domain}`) +
      "</span>" +
      innerWithId +
      "</li>";
  }

  if (!items && !includes) return "";
  return `<ul>${items}${includes}</ul>`;
}

export function lookupCounter(used: number, limit: number): string {
  const cls = used > limit ? "lookup-over" : "lookup-ok";
  return `<div class="lookup-count ${cls}">${used} / ${limit} DNS lookups used</div>`;
}

export function dkimSelectorGrid(
  selectors: Record<string, DkimSelectorResult>,
): string {
  // ⚡ Bolt Optimization: Use for...in instead of Object.entries().filter().map()
  // This single-pass approach avoids allocating and discarding multiple intermediate arrays
  // (entries, found array, notFound array, mapped strings array) on the hot rendering path,
  // significantly reducing GC pressure.
  let foundItems = "";
  let notFoundItems = "";
  let notFoundCount = 0;

  for (const name in selectors) {
    const info = selectors[name];
    if (info.found) {
      foundItems += `<div class="selector-item selector-found"><span class="icon-pass" style="font-size:0.7rem">&#10003;</span> ${esc(name)}${info.key_bits ? ` <span style="color:var(--clr-text-dim);font-size:0.7rem">${info.key_bits}bit</span>` : ""}</div>`;
    } else {
      if (notFoundCount < 6) {
        notFoundItems += `<div class="selector-item selector-not-found"><span style="font-size:0.7rem;color:var(--clr-text-faint)">&#10007;</span> ${esc(name)}</div>`;
      }
      notFoundCount++;
    }
  }

  const extra =
    notFoundCount > 6
      ? `<div class="selector-item selector-not-found" style="color:var(--clr-text-faint)">+${notFoundCount - 6} more not found</div>`
      : "";

  return `<div class="selector-grid">${foundItems}${notFoundItems}${extra}</div>`;
}

export function mtaStsPolicyTable(policy: MtaStsPolicy): string {
  return `<table class="policy-table">
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>version</td><td>${esc(policy.version)}</td></tr>
  <tr><td>mode</td><td>${esc(policy.mode)}</td></tr>
  <tr><td>mx</td><td>${policy.mx.map(esc).join(", ") || "—"}</td></tr>
  <tr><td>max_age</td><td>${policy.max_age.toLocaleString()}s</td></tr>
</table>`;
}

const CATEGORY_LABELS: Record<EmailProvider["category"], string> = {
  "security-gateway": "Gateway",
  "email-platform": "Platform",
  hosting: "Hosting",
};

export function providerBadge(provider: EmailProvider): string {
  const label = CATEGORY_LABELS[provider.category];
  return `<span class="provider-badge">${esc(provider.name)} <span class="badge-category">${label}</span></span>`;
}

export function mxTable(records: MxRecord[]): string {
  if (records.length === 0) return "";

  // ⚡ Bolt Optimization: Use a single-pass loop instead of .map().join("")
  // Reduces GC pressure on a hot rendering path by avoiding array allocations
  let rows = "";
  for (const r of records) {
    // The analyzer's PROVIDER_SIGNATURES (used for r.provider) is intentionally
    // stricter than this view's MX catalog — the catalog covers hostnames the
    // analyzer doesn't label (e.g. route*.mx.cloudflare.net, *.messagingengine.com).
    // Render a link whenever the catalog matches, regardless of analyzer label.
    const catalogged = lookupMxProvider(r.exchange);
    let providerCell = "";
    if (r.provider) {
      const badge = providerBadge(r.provider);
      providerCell = catalogged
        ? `<a class="mx-provider-link" href="/mx/${catalogged.slug}" title="What is ${esc(catalogged.shortName)}?">${badge}</a>`
        : badge;
    } else if (catalogged) {
      providerCell = `<a class="mx-provider-link" href="/mx/${catalogged.slug}" title="What is ${esc(catalogged.shortName)}?">${esc(catalogged.shortName)}</a>`;
    }
    rows += `<tr class="mx-row"><td class="mx-priority">${r.priority}</td><td class="mx-exchange">${esc(r.exchange)}</td><td class="mx-provider">${providerCell}</td></tr>`;
  }

  return `<table class="mx-table">
  <thead><tr><th>Priority</th><th>Exchange</th><th>Provider</th></tr></thead>
  <tbody>${rows}</tbody>
</table>`;
}

// ── Scoring breakdown components ───────────────────────────────

const PROTO_LABELS: Record<string, string> = {
  dmarc: "DMARC",
  spf: "SPF",
  dkim: "DKIM",
  bimi: "BIMI",
  mta_sts: "MTA-STS",
  security_txt: "security.txt",
  tls_rpt: "TLS-RPT",
  dnssec: "DNSSEC",
};

export function scoreSnippet(result: ScanResult): string {
  const { breakdown, domain } = result;
  const selectors = new URL(
    `https://x/check?domain=${encodeURIComponent(domain)}`,
  ).search;
  const scoreUrl = `/check/score${selectors}`;

  let dots = "";
  // ⚡ Bolt Optimization: Use for...in instead of Object.entries().map()
  // Reduces GC pressure by avoiding array allocations on hot rendering paths
  for (const key in breakdown.protocolSummaries) {
    const status = breakdown.protocolSummaries[key].status;
    dots += `<span class="snippet-proto"><span class="snippet-dot status-${status}"></span>${PROTO_LABELS[key] ?? key}</span>`;
  }

  const tierClass =
    breakdown.tier === "F"
      ? "tier-fail"
      : breakdown.tier === "D"
        ? "tier-warn"
        : "tier-pass";

  return `<div class="score-snippet">
  <div class="snippet-left">
    <div class="snippet-tier"><span class="${tierClass}">${esc(breakdown.tier)} tier</span> &mdash; ${esc(breakdown.tierReason)}</div>
    <div class="snippet-protocols">${dots}</div>
  </div>
  <a class="snippet-link" href="${scoreUrl}">View scoring breakdown &rarr;</a>
</div>`;
}

export function tierExplanationCard(
  tier: string,
  tierReason: string,
  grade: string,
  modifierLabel: string,
): string {
  const tierText =
    tier === "A+"
      ? `Your domain achieves a <span class="tier-pass">perfect score</span>. DMARC policy is set to reject, SPF and DKIM are strong, and both BIMI and MTA-STS are configured.`
      : tier === "F"
        ? `<span class="tier-fail">${esc(tierReason)}</span>. DMARC is the foundation of email authentication &mdash; without it, receivers have no policy for handling unauthenticated mail from your domain.`
        : `${esc(tierReason)} &mdash; this earns a <span class="tier-pass">${esc(tier)}-tier</span> base grade.${modifierLabel ? ` Scoring modifiers adjusted the final grade to <span class="tier-pass">${esc(grade)}</span>.` : ""}`;

  return `<div class="bd-card">
  <div class="bd-card-title">Why you got this grade</div>
  <div class="bd-card-body">
    <div class="tier-text">${tierText}</div>
  </div>
</div>`;
}

export function scoringFactorsTable(
  factors: ScoringFactor[],
  modifier: number,
  modifierLabel: string,
): string {
  if (factors.length === 0) {
    return "";
  }

  // ⚡ Bolt Optimization: Use a single-pass loop instead of .map().join("")
  // Reduces GC pressure on a hot rendering path by avoiding array allocations
  let rows = "";
  let netModifierStr = "";
  for (let i = 0; i < factors.length; i++) {
    const f = factors[i];
    const effectClass =
      f.effect > 0
        ? "effect-plus"
        : f.effect < 0
          ? "effect-minus"
          : "effect-neutral";
    const effectText = f.effect > 0 ? "+1" : f.effect < 0 ? "\u22121" : "0";
    rows += `<tr>
      <td class="factor-proto">${esc(PROTO_LABELS[f.protocol] ?? f.protocol)}</td>
      <td class="factor-label">${esc(f.label)}</td>
      <td class="factor-effect ${effectClass}">${effectText}</td>
    </tr>`;

    if (factors.length > 1) {
      if (i > 0) netModifierStr += " ";
      netModifierStr += effectText;
    }
  }

  const summary =
    factors.length > 1
      ? `<div class="modifier-summary">
      <span>Net modifier: ${netModifierStr} = ${modifier > 0 ? "+" : ""}${modifier}</span>
      <span class="modifier-result">&rarr; ${modifierLabel ? modifierLabel : "no change"}</span>
    </div>`
      : "";

  return `<div class="bd-card">
  <div class="bd-card-title">Scoring factors</div>
  <div class="bd-card-body">
    <table class="factors-table">
      ${rows}
    </table>
    ${summary}
  </div>
</div>`;
}

export function protocolContributionGrid(
  summaries: Record<string, { status: Status; summary: string }>,
): string {
  let cells = "";
  // ⚡ Bolt Optimization: Use for...in instead of Object.entries().map()
  // Reduces GC pressure by avoiding array allocations on hot rendering paths
  for (const key in summaries) {
    const { status, summary } = summaries[key];
    cells += `<div class="proto-cell">
      <div class="snippet-dot status-${status}" style="margin:0 auto 6px"></div>
      <div class="proto-name">${esc(PROTO_LABELS[key] ?? key)}</div>
      <div class="proto-summary">${esc(summary)}</div>
    </div>`;
  }

  return `<div class="bd-card">
  <div class="bd-card-title">Protocol contributions</div>
  <div class="bd-card-body">
    <div class="proto-grid">${cells}</div>
  </div>
</div>`;
}

export function recommendationList(recommendations: Recommendation[]): string {
  if (recommendations.length === 0) {
    return `<div class="bd-card">
  <div class="bd-card-title">How to improve</div>
  <div class="bd-card-body">
    <div class="tier-text">Nothing to improve &mdash; your email security configuration is fully optimized.</div>
  </div>
</div>`;
  }

  // ⚡ Bolt Optimization: Use a single-pass loop instead of .map().join("")
  // Reduces GC pressure on a hot rendering path by avoiding array allocations
  let items = "";
  for (const r of recommendations) {
    items += `<div class="rec-item">
      <div class="rec-priority priority-${r.priority}">P${r.priority}</div>
      <div class="rec-content">
        <div class="rec-title">${esc(r.title)}</div>
        <div class="rec-desc">${esc(r.description)}</div>
        <div class="rec-impact">${esc(r.impact)}</div>
      </div>
    </div>`;
  }

  return `<div class="bd-card">
  <div class="bd-card-title">How to improve</div>
  <div class="bd-card-body">${items}</div>
</div>`;
}
