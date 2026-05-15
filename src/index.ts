import * as Sentry from "@sentry/cloudflare";
import { type Context, Hono } from "hono";
import { cors } from "hono/cors";
import { csrf } from "hono/csrf";
import { streamSSE } from "hono/streaming";
import { dispatchPendingAlerts } from "./alerts/dispatcher.js";
import { validateUnsubscribeToken } from "./alerts/unsubscribe.js";
import type {
  BimiResult,
  DkimResult,
  DmarcResult,
  MtaStsResult,
  MxResult,
  ScanResult,
  SecurityTxtResult,
  SpfResult,
} from "./analyzers/types.js";
import {
  getAgentSkillsIndexJson,
  SCAN_DOMAIN_SKILL_MD,
} from "./api/agent-skills.js";
import { isValidGrade, renderBadgeSvg } from "./api/badge.js";
import {
  BULK_IN_BAND_CAP,
  isCapExceeded,
  processBulkScan,
} from "./api/bulk-scan.js";
import { API_CATALOG_JSON, CANONICAL_ORIGIN } from "./api/catalog.js";
import { clampHistoryLimit, fetchDomainHistory } from "./api/history.js";
import { LLMS_TXT } from "./api/llms-txt.js";
import { OPENAPI_JSON } from "./api/openapi.js";
import { accessJwtMiddleware } from "./auth/access-jwt.js";
import { type BearerIdentity, resolveBearer } from "./auth/api-key.js";
import { authRoutes } from "./auth/routes.js";
import { stripeWebhookRoutes } from "./billing/routes.js";
import { getCachedScan, setCachedScan } from "./cache.js";
import { runDueRescans } from "./cron/rescan.js";
import { generateCsv } from "./csv.js";
import { dashboardRoutes } from "./dashboard/routes.js";
import { getDomainByUserAndName } from "./db/domains.js";
import { recordScan } from "./db/scans.js";
import { getPlanForUser } from "./db/subscriptions.js";
import { setEmailAlertsEnabled } from "./db/users.js";
import type { Env } from "./env.js";
import type { ProtocolId, ProtocolResult } from "./orchestrator.js";
import { scan, scanStreaming } from "./orchestrator.js";
import {
  checkRateLimit,
  getRateLimitConfig,
  type RateLimitResult,
  rateLimitHeaders,
} from "./rate-limit.js";
import { normalizeDomain } from "./shared/domain.js";
import { listIndexableScanDomains } from "./shared/indexable-domains.js";
import { watchlistCapForPlan } from "./shared/limits.js";
import { CSS_PATH, JS_PATH } from "./views/assets.js";
import {
  APPLE_TOUCH_ICON_BASE64,
  FAVICON_ICO_BASE64,
  FAVICON_SVG,
  ICON_192_BASE64,
  ICON_512_BASE64,
  OG_IMAGE_PNG_BASE64,
  webManifest,
} from "./views/favicon.js";
import {
  renderApiDocs,
  renderBimiCard,
  renderDkimCard,
  renderDmarcCard,
  renderError,
  renderLandingPage,
  renderMtaStsCard,
  renderMxCard,
  renderReport,
  renderReportFooter,
  renderReportHeader,
  renderScoreBreakdown,
  renderScoringRubric,
  renderSecurityTxtCard,
  renderSpfCard,
  renderStreamingLoading,
} from "./views/html.js";
import {
  renderLearnBimi,
  renderLearnDkim,
  renderLearnDmarc,
  renderLearnHub,
  renderLearnMtaSts,
  renderLearnSpf,
} from "./views/learn.js";
import { renderPrivacyPage } from "./views/legal.js";
import {
  renderApiDocsMarkdown,
  renderErrorMarkdown,
  renderLandingMarkdown,
  renderLearnHubMarkdown,
  renderPricingMarkdown,
  renderPrivacyMarkdown,
  renderReportMarkdown,
  renderScoringRubricMarkdown,
} from "./views/markdown.js";
import { renderPricingPage } from "./views/pricing.js";
import { JS } from "./views/scripts.js";
import { CSS } from "./views/styles.js";
import { fireBulkScanWebhooks } from "./webhooks/triggers.js";

// The Hono app is exported for tests (which call `app.request(...)`).
// Runtime Workers use the Sentry-wrapped default export below, which adds
// cron (`scheduled`) alongside `fetch`.
export const app = new Hono<{ Bindings: Env }>();

// Set Sentry scope context for every request
app.use("*", async (c, next) => {
  const scope = Sentry.getCurrentScope();
  const domain = c.req.query("domain")?.trim().toLowerCase() || undefined;
  const format =
    c.req.query("format") ||
    (c.req.header("Accept")?.includes("application/json") ? "json" : "html");
  const selectors = c.req.query("selectors") || undefined;

  // Raw user input (not normalizeDomain) — shows what was actually typed, even for rejected requests
  if (domain) scope.setTag("domain", domain);
  scope.setTag("format", format);
  scope.setTag("path", c.req.path);
  scope.setContext("request", {
    selectors,
    method: c.req.method,
    path: c.req.path,
  });
  scope.setUser({
    ip_address: c.req.header("CF-Connecting-IP") || undefined,
  });

  await next();
});

// Cloudflare Access JWT enforcement for `*.workers.dev` preview-branch
// deploys. No-ops on the production custom domain (dmarc.mx). See
// src/auth/access-jwt.ts for the protected-host predicate and fail-CLOSED
// posture when ACCESS_AUD / ACCESS_TEAM_DOMAIN are missing.
app.use("*", accessJwtMiddleware());

// HSTS: 2 years + includeSubDomains. The 2-year max-age satisfies the
// hstspreload.org submission requirement, but `preload` is intentionally
// omitted — adding it is a one-way commitment that locks every current and
// future subdomain (including any short-lived `*.workers.dev` previews
// proxied behind a custom domain) into HTTPS forever. Submit to the preload
// list as a separate, deliberate change once we're confident.

// Content types that should be hidden from search engines. HTML is the opposite:
// it's the whole point of the site and must stay crawlable. Images/CSS/JS are
// skipped because noindex on subresources is a no-op for how Googlebot renders
// pages. XML (sitemap) and text/plain (robots.txt) need to stay crawlable.
const NOINDEX_CONTENT_TYPES = [
  "application/json",
  "application/manifest+json",
  "application/linkset+json",
  "application/openapi+json",
  "text/csv",
  "text/event-stream",
  "text/markdown",
];

// Link header (RFC 8288) pointing agents to discovery resources.
// Attached to HTML responses only — JSON/CSV/SSE consumers are already
// using the API directly.
const AGENT_DISCOVERY_LINK_HEADER = [
  '</.well-known/api-catalog>; rel="api-catalog"; type="application/linkset+json"',
  '</.well-known/agent-skills/index.json>; rel="https://agentskills.io/rel/index"; type="application/json"',
  '</openapi.json>; rel="service-desc"; type="application/openapi+json"',
  '</docs/api>; rel="service-doc"; type="text/html"',
  '</health>; rel="status"',
].join(", ");

// Origins permitted to embed the HTML report in an iframe. Anything not listed
// here (including subdomains) is blocked by the `frame-ancestors` directive
// below. X-Frame-Options is intentionally NOT set — older browsers honor it
// over `frame-ancestors`, which would defeat this allowlist.
const EMBED_ALLOWED_ORIGINS = ["https://cortech.online"];

// Paths that skip Cloudflare Web Analytics beacon injection. Dashboard and
// auth pages can expose user-specific URL patterns (e.g. domain names in
// the path); we deliberately keep those out of analytics even though the
// beacon itself is cookieless.
const ANALYTICS_SKIP_PATH_PREFIXES = ["/dashboard", "/auth", "/webhooks"];

// Cloudflare Web Analytics tokens are 32-char lowercase hex. Guard against
// a misconfigured env var injecting arbitrary strings into HTML.
const CF_ANALYTICS_TOKEN_RE = /^[a-f0-9]{32}$/;

app.use("*", async (c, next) => {
  await next();
  c.res.headers.set("X-Content-Type-Options", "nosniff");
  c.res.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  c.res.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  c.res.headers.set(
    "Strict-Transport-Security",
    "max-age=63072000; includeSubDomains",
  );

  const contentType = c.res.headers.get("content-type") ?? "";
  const isHtml = contentType.includes("text/html");
  if (isHtml) {
    const frameAncestors = ["'self'", ...EMBED_ALLOWED_ORIGINS].join(" ");
    c.res.headers.set(
      "Content-Security-Policy",
      `default-src 'none'; script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors ${frameAncestors}`,
    );
    if (!c.res.headers.has("Link")) {
      c.res.headers.set("Link", AGENT_DISCOVERY_LINK_HEADER);
    }
    // Short edge cache so Cloudflare can absorb landing/scoring/report traffic
    // without hitting the Worker on every request. Browsers still revalidate.
    if (!c.res.headers.has("Cache-Control")) {
      c.res.headers.set(
        "Cache-Control",
        "public, max-age=0, s-maxage=300, stale-while-revalidate=600",
      );
    }

    // Inject the Cloudflare Web Analytics beacon on public HTML pages.
    // Skipped when the token isn't configured (self-host default) and on
    // auth/dashboard/webhook paths whose URLs can carry user-specific detail.
    // Our HTML responses are already buffered strings (never streamed), so a
    // simple `</body>` replace is both correct and keeps tests in the Node
    // pool runnable without HTMLRewriter.
    const token = (c.env as Env | undefined)?.CF_ANALYTICS_TOKEN;
    const path = c.req.path;
    const isAnalyticsEligible =
      token &&
      CF_ANALYTICS_TOKEN_RE.test(token) &&
      !ANALYTICS_SKIP_PATH_PREFIXES.some((p) => path.startsWith(p));
    if (isAnalyticsEligible) {
      const beacon = `<script defer src="https://static.cloudflareinsights.com/beacon.min.js" data-cf-beacon='{"token":"${token}"}'></script>`;
      const body = await c.res.text();
      const injected = body.replace("</body>", `${beacon}</body>`);
      c.res = new Response(injected, {
        status: c.res.status,
        statusText: c.res.statusText,
        headers: c.res.headers,
      });
    }
  } else {
    // `frame-ancestors` does not inherit from `default-src`, so it must be
    // declared explicitly to keep JSON/CSV/SSE responses unframable.
    c.res.headers.set(
      "Content-Security-Policy",
      "default-src 'none'; frame-ancestors 'none'",
    );
  }

  // Keep the JSON API, CSV exports, the SSE stream, and the PWA manifest out
  // of Google's index. These showed up in Search Console as "Crawled - currently
  // not indexed" noise — no reason to spend crawl budget on them.
  if (NOINDEX_CONTENT_TYPES.some((t) => contentType.includes(t))) {
    c.res.headers.set("X-Robots-Tag", "noindex");
  }
});

// Safety net: capture any unhandled errors that bypass route catch blocks
app.onError((err, c) => {
  Sentry.captureException(err);
  const message = err instanceof Error ? err.message : "Internal error";
  const wantsJson =
    c.req.header("Accept")?.includes("application/json") ||
    c.req.query("format") === "json";
  if (wantsJson) {
    return c.json({ error: message }, 500);
  }
  return c.html(renderError(message), 500);
});

app.use("/api/*", cors());

// Auth routes (public) — login, WorkOS callback, logout
app.route("/auth", authRoutes);

// Dashboard routes (auth enforced inside dashboardRoutes via requireAuth)
app.use("/dashboard/*", csrf());
app.route("/dashboard", dashboardRoutes);

// Local-only dashboard fixture preview. Lets a developer eyeball every
// scenario (current / fire / allGreen / firstRun / free / zero) without
// going through WorkOS. Self-gated on the absence of WORKOS_API_KEY:
// production always has it set, `wrangler dev` (without a .dev.vars file)
// does not. If a self-host operator does set up local secrets, they can
// still hit the route via .dev.vars omission of this single key.
app.get("/_dev/dashboard", async (c) => {
  const apiKey = (c.env as { WORKOS_API_KEY?: string } | undefined)
    ?.WORKOS_API_KEY;
  if (apiKey && apiKey.length > 0) return c.text("Not Found", 404);
  const {
    renderDashboardFixture,
    renderDashboardFixtureIndex,
    DASHBOARD_FIXTURE_NAMES,
  } = await import("./views/dashboard.js");
  const fixture = c.req.query("fixture");
  if (!fixture) return c.html(renderDashboardFixtureIndex());
  if (!DASHBOARD_FIXTURE_NAMES.includes(fixture as never)) {
    return c.text(
      `Unknown fixture. Pick one of: ${DASHBOARD_FIXTURE_NAMES.join(", ")}`,
      404,
    );
  }
  return c.html(renderDashboardFixture(fixture as never));
});

// Stripe webhook (public — signature-verified). Self-gates on
// isBillingEnabled so self-host deploys without Stripe env still boot.
app.route("/webhooks", stripeWebhookRoutes);

function markdownResponse(c: Context, body: string, status = 200) {
  return c.body(body, status as 200, {
    "Content-Type": "text/markdown; charset=utf-8",
  });
}

// Returns true when the client explicitly asked for markdown (via `?format=md`
// or an `Accept` header that lists `text/markdown` before `text/html`). HTML
// stays the default for browsers that send wildcards like `*/*`.
function wantsMarkdown(c: Context): boolean {
  const format = c.req.query("format");
  if (format === "md" || format === "markdown") return true;
  const accept = c.req.header("Accept");
  if (!accept) return false;
  const types = accept.toLowerCase().split(",");
  const mdIndex = types.findIndex((t) => t.trim().startsWith("text/markdown"));
  if (mdIndex === -1) return false;
  const htmlIndex = types.findIndex((t) => t.trim().startsWith("text/html"));
  // Agents that send `Accept: text/markdown` (and nothing else, or markdown
  // first) get markdown. Browsers that prefer HTML keep getting HTML.
  return htmlIndex === -1 || mdIndex < htmlIndex;
}

function getClientIp(c: Context): string {
  const cfIp = c.req.header("CF-Connecting-IP");
  if (cfIp) return cfIp;

  return "unknown";
}

// Resolves rate-limit identity + config for a request. Pro-authed bearers
// lift to the per-user bucket (60/hour). Everyone else — anonymous callers,
// bearers whose subscription isn't active, free-plan bearers — falls through
// to the per-IP anon bucket (10/60s). Free-authed keeps on IP on purpose: a
// free bearer hitting from two IPs gets two anon buckets, which matches what
// anonymous scanners already see and avoids making a free account worse than
// no account. Bearer identity is stashed on context so downstream handlers
// (/api/check scan-history persistence) can read it without re-verifying.
export async function resolveRateLimitScope(c: Context): Promise<{
  identity: string;
  config: ReturnType<typeof getRateLimitConfig>;
}> {
  const bearer = await resolveBearer(c);
  if (bearer) {
    c.set("bearer" as never, bearer);
    const db = (c.env as { DB?: D1Database }).DB;
    if (db) {
      const plan = await getPlanForUser(db, bearer.userId);
      if (plan === "pro") {
        return {
          identity: `user:${bearer.userId}`,
          config: getRateLimitConfig("pro"),
        };
      }
    }
  }
  return {
    identity: `ip:${getClientIp(c)}`,
    config: getRateLimitConfig("free"),
  };
}

type RateLimitBlockedResponder = (
  c: Context,
  result: RateLimitResult,
  headers: Record<string, string>,
) => Response | Promise<Response>;

export function rateLimitMiddleware(onBlocked: RateLimitBlockedResponder) {
  return async (c: Context, next: () => Promise<void>) => {
    const { identity, config } = await resolveRateLimitScope(c);
    const result = await checkRateLimit(identity, config);
    if (result.pendingWrite) {
      c.executionCtx.waitUntil(result.pendingWrite.catch(() => {}));
    }

    const headers = rateLimitHeaders(result);

    if (!result.allowed) {
      return onBlocked(c, result, headers);
    }

    await next();
    // ⚡ Bolt Optimization: Use for...in instead of Object.entries() on hot paths.
    // Avoids allocating an array of key-value tuples for headers on every request,
    // reducing GC pressure for high-traffic middleware.
    for (const key in headers) {
      c.res.headers.set(key, headers[key]);
    }
  };
}

function blockedMessage(result: RateLimitResult): string {
  const waitSec = Math.max(1, result.resetAt - Math.floor(Date.now() / 1000));
  return `Rate limit exceeded. Try again in ${waitSec} seconds.`;
}

// Rate limit scan endpoints (not the landing page)
app.use(
  "/check",
  rateLimitMiddleware((c, result, headers) => {
    const format = c.req.query("format");
    const wantsJson =
      format === "json" || c.req.header("Accept")?.includes("application/json");

    if (wantsJson || format === "csv") {
      return c.json(
        { error: blockedMessage(result) },
        { status: 429, headers },
      );
    }
    return c.html(
      renderError(
        "Rate limit exceeded. Please wait a minute before scanning again.",
      ),
      { status: 429, headers },
    );
  }),
);

app.use(
  "/check/score",
  rateLimitMiddleware((_c, _result, headers) =>
    _c.html(
      renderError(
        "Rate limit exceeded. Please wait a minute before scanning again.",
      ),
      { status: 429, headers },
    ),
  ),
);

app.use(
  "/api/check",
  rateLimitMiddleware((c, result, headers) =>
    c.json({ error: blockedMessage(result) }, { status: 429, headers }),
  ),
);

// Bulk scan also runs N analyzers in-band per request — same rate-limit
// posture as /api/check (Pro bearer → user bucket; everyone else → IP).
// TODO(phase-4-pr3-followup): once per-plan limits expose a "weight" knob,
// charge bulk requests proportionally to the in-band scan count instead of
// counting as a single request.
app.use(
  "/api/bulk-scan",
  rateLimitMiddleware((c, result, headers) =>
    c.json({ error: blockedMessage(result) }, { status: 429, headers }),
  ),
);

// Per-domain API endpoints (currently only /api/domain/:name/history). Path
// prefix instead of exact-match so future per-domain endpoints inherit the
// same limiter without re-wiring. Hono matches `/api/domain/*` after the
// exact-match routes above, so /api/check and /api/bulk-scan aren't affected.
// This middleware is what populates `c.get("bearer")` via resolveRateLimitScope.
app.use(
  "/api/domain/*",
  rateLimitMiddleware((c, result, headers) =>
    c.json({ error: blockedMessage(result) }, { status: 429, headers }),
  ),
);

// The SSE streaming endpoint fans out ~50 DNS lookups per request and is
// bypassed by the `/api/check` middleware above (Hono matches exact paths).
// Give it its own limiter so it cannot be used as a DNS amplification vector.
app.use(
  "/api/check/stream",
  rateLimitMiddleware((c, result, headers) =>
    c.json({ error: blockedMessage(result) }, { status: 429, headers }),
  ),
);

// Badge endpoint runs a full scan on cache miss, so it gets the same
// per-IP limiter as /api/check. Cloudflare edge caches the SVG response
// (1h max-age), so README-embedded badges collapse to a small number of
// origin hits regardless of view volume.
app.use(
  "/badge",
  rateLimitMiddleware((c, _result, headers) =>
    // Even rate-limit responses must be SVG so embeds don't render a JSON
    // blob in place of the badge. "rate limited" is a fallback grade.
    c.body(renderBadgeSvg({ grade: "rate limited", color: "#737373" }), {
      status: 429,
      headers: { ...headers, "Content-Type": "image/svg+xml; charset=utf-8" },
    }),
  ),
);

const protocolRenderers: Record<
  ProtocolId,
  (result: ProtocolResult) => string
> = {
  mx: (r) => renderMxCard(r as MxResult),
  dmarc: (r) => renderDmarcCard(r as DmarcResult),
  spf: (r) => renderSpfCard(r as SpfResult),
  dkim: (r) => renderDkimCard(r as DkimResult),
  bimi: (r) => renderBimiCard(r as BimiResult),
  mta_sts: (r) => renderMtaStsCard(r as MtaStsResult),
  security_txt: (r) => renderSecurityTxtCard(r as SecurityTxtResult),
};

function tagScanResult(result: ScanResult): void {
  const scope = Sentry.getCurrentScope();
  scope.setTag("grade", result.grade);
  scope.setTag("dmarc.status", result.protocols.dmarc.status);
  scope.setTag("spf.status", result.protocols.spf.status);
  scope.setTag("dkim.status", result.protocols.dkim.status);
  scope.setTag("bimi.status", result.protocols.bimi.status);
  scope.setTag("mta_sts.status", result.protocols.mta_sts.status);
  // Optional access — older cached scans (pre-#40) may not include
  // security_txt. Drop the tag rather than crash the SSE replay.
  if (result.protocols.security_txt) {
    scope.setTag("security_txt.status", result.protocols.security_txt.status);
  }
}

app.get("/api/check/stream", async (c) => {
  const domain = normalizeDomain(c.req.query("domain"));
  if (!domain) {
    return c.json({ error: "Missing or invalid domain parameter" }, 400);
  }

  const selectors = parseSelectors(c.req.query("selectors"));
  const bearer =
    (c.get("bearer" as never) as BearerIdentity | undefined) ?? null;

  return streamSSE(c, async (stream) => {
    Sentry.addBreadcrumb({
      category: "scan.start",
      message: domain,
      data: { domain, selectors },
      level: "info",
    });
    const cached = await getCachedScan(domain, selectors);
    Sentry.addBreadcrumb({
      category: cached ? "cache.hit" : "cache.miss",
      message: domain,
      data: { domain },
      level: "info",
    });

    if (cached) {
      tagScanResult(cached);
      const protocolIds: ProtocolId[] = [
        "mx",
        "dmarc",
        "spf",
        "dkim",
        "bimi",
        "mta_sts",
        "security_txt",
      ];
      for (const id of protocolIds) {
        const protocolResult = cached.protocols[id];
        // Older cached scans (pre-#40) may lack security_txt; skip rather
        // than crashing the replay. Fresh scans always populate it.
        if (!protocolResult) continue;
        const html = protocolRenderers[id](protocolResult);
        await stream.writeSSE({
          event: "protocol",
          data: JSON.stringify({ id, html }),
        });
      }
      await stream.writeSSE({
        event: "done",
        data: JSON.stringify({
          grade: cached.grade,
          headerHtml: renderReportHeader(cached),
          footerHtml: renderReportFooter(cached),
        }),
      });
      return;
    }

    try {
      const result = await scanStreaming(
        domain,
        selectors,
        (id: ProtocolId, protocolResult: ProtocolResult) => {
          const html = protocolRenderers[id](protocolResult);
          stream.writeSSE({
            event: "protocol",
            data: JSON.stringify({ id, html }),
          });
        },
      );

      tagScanResult(result);
      const pendingCacheWrite = setCachedScan(domain, selectors, result);
      if (pendingCacheWrite) {
        c.executionCtx.waitUntil(pendingCacheWrite.catch(() => {}));
      }

      if (bearer) {
        persistBearerScanIfWatched(c, bearer.userId, domain, result);
      }

      await stream.writeSSE({
        event: "done",
        data: JSON.stringify({
          grade: result.grade,
          headerHtml: renderReportHeader(result),
          footerHtml: renderReportFooter(result),
        }),
      });
    } catch (err) {
      Sentry.captureException(err);
      await stream.writeSSE({
        event: "error",
        data: JSON.stringify({
          error: err instanceof Error ? err.message : "Scan failed",
        }),
      });
    }
  });
});

app.get("/logo.svg", (c) => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 512 512">
  <title>dmarcheck</title>
  <rect width="512" height="512" rx="64" fill="#0a0a0a"/>
  <text x="256" y="310" font-family="monospace" font-size="220" fill="#f97316" text-anchor="middle">@</text>
  <circle cx="210" cy="210" r="28" fill="white"/>
  <circle cx="302" cy="210" r="28" fill="white"/>
  <circle cx="216" cy="218" r="14" fill="#0a0a0f"/>
  <circle cx="308" cy="218" r="14" fill="#0a0a0f"/>
  <rect x="196" y="380" width="20" height="40" rx="8" fill="#ea580c"/>
  <rect x="246" y="380" width="20" height="32" rx="8" fill="#ea580c"/>
  <rect x="296" y="380" width="20" height="40" rx="8" fill="#ea580c"/>
</svg>`;
  return c.body(svg, 200, {
    "Content-Type": "image/svg+xml",
    "Cache-Control": "public, max-age=86400",
  });
});

app.get("/og-image.svg", (c) => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 630">
  <rect width="1200" height="630" fill="#0a0a0f"/>
  <!-- Creature -->
  <text x="340" y="310" font-family="monospace" font-size="180" fill="#f97316" text-anchor="middle">@</text>
  <circle cx="300" cy="220" r="22" fill="white"/>
  <circle cx="375" cy="220" r="22" fill="white"/>
  <circle cx="305" cy="226" r="11" fill="#0a0a0f"/>
  <circle cx="380" cy="226" r="11" fill="#0a0a0f"/>
  <rect x="290" y="370" width="16" height="32" rx="6" fill="#ea580c"/>
  <rect x="330" y="370" width="16" height="26" rx="6" fill="#ea580c"/>
  <rect x="370" y="370" width="16" height="32" rx="6" fill="#ea580c"/>
  <!-- Wordmark -->
  <text x="500" y="300" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif" font-weight="800" font-size="72">
    <tspan fill="#e4e4e7">dmar</tspan><tspan fill="#f97316">check</tspan>
  </text>
  <!-- Tagline -->
  <text x="500" y="350" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif" font-size="24" fill="#71717a">DNS Email Security Analyzer</text>
  <!-- BIMI badge -->
  <text x="500" y="400" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif" font-size="18" fill="#f97316">Meet DMarcus — your email security sidekick</text>
</svg>`;
  return c.body(svg, 200, {
    "Content-Type": "image/svg+xml",
    "Cache-Control": "public, max-age=86400",
  });
});

// Embeddable email-security badge for READMEs and dashboards. Always
// returns a 200 SVG (even for invalid input or scan errors) so a badge
// embed never renders as a broken image — error states are encoded into
// the badge text instead.
app.get("/badge", async (c) => {
  const domain = normalizeDomain(c.req.query("domain"));
  const svgHeaders = (): Record<string, string> => ({
    "Content-Type": "image/svg+xml; charset=utf-8",
    // 1h browser, 1h edge, generous SWR. Badges live on README pages —
    // they need to render fast and stay fresh-ish without re-scanning per
    // viewer. The scan itself is also cached for 5 minutes inside getCachedScan,
    // but that's a different layer; this header controls what GitHub
    // (and downstream image proxies like camo) see.
    "Cache-Control":
      "public, max-age=3600, s-maxage=3600, stale-while-revalidate=86400",
    // GitHub's image proxy (camo) won't show user-supplied SVGs unless
    // the response is a clean SVG with no embedded scripts. Our generator
    // emits no <script>, but reinforce with CSP.
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
  });

  if (!domain) {
    return c.body(renderBadgeSvg({ grade: "invalid", color: "#737373" }), 400, {
      ...svgHeaders(),
    });
  }

  try {
    const cached = await getCachedScan(domain, []);
    const result = cached ?? (await scan(domain, []));
    if (!cached) {
      const pendingCacheWrite = setCachedScan(domain, [], result);
      if (pendingCacheWrite) {
        c.executionCtx.waitUntil(pendingCacheWrite.catch(() => {}));
      }
    }
    const grade = isValidGrade(result.grade) ? result.grade : "unknown";
    return c.body(renderBadgeSvg({ grade }), 200, svgHeaders());
  } catch (err) {
    Sentry.captureException(err);
    return c.body(renderBadgeSvg({ grade: "error", color: "#737373" }), 200, {
      ...svgHeaders(),
      // Shorter cache on errors so a transient DNS failure doesn't lock
      // a domain into the error badge for an hour.
      "Cache-Control": "public, max-age=60",
    });
  }
});

app.get("/og-image.png", (c) => {
  const buf = Uint8Array.from(atob(OG_IMAGE_PNG_BASE64), (ch) =>
    ch.charCodeAt(0),
  );
  return c.body(buf, 200, {
    "Content-Type": "image/png",
    "Cache-Control": "public, max-age=86400",
  });
});

// Content-hashed static assets with immutable caching
app.get(CSS_PATH, (c) => {
  return c.body(CSS, 200, {
    "Content-Type": "text/css; charset=utf-8",
    "Cache-Control": "public, max-age=31536000, immutable",
  });
});

app.get(JS_PATH, (c) => {
  return c.body(JS, 200, {
    "Content-Type": "application/javascript; charset=utf-8",
    "Cache-Control": "public, max-age=31536000, immutable",
  });
});

app.get("/favicon.svg", (c) => {
  return c.body(FAVICON_SVG, 200, {
    "Content-Type": "image/svg+xml",
    "Cache-Control": "public, max-age=86400",
  });
});

app.get("/manifest.webmanifest", (c) => {
  return c.body(webManifest(), 200, {
    "Content-Type": "application/manifest+json",
    "Cache-Control": "public, max-age=86400",
  });
});

app.get("/favicon.ico", (c) => {
  const buf = Uint8Array.from(atob(FAVICON_ICO_BASE64), (ch) =>
    ch.charCodeAt(0),
  );
  return c.body(buf, 200, {
    "Content-Type": "image/x-icon",
    "Cache-Control": "public, max-age=86400",
  });
});

app.get("/apple-touch-icon.png", (c) => {
  const buf = Uint8Array.from(atob(APPLE_TOUCH_ICON_BASE64), (ch) =>
    ch.charCodeAt(0),
  );
  return c.body(buf, 200, {
    "Content-Type": "image/png",
    "Cache-Control": "public, max-age=86400",
  });
});

app.get("/icon-192.png", (c) => {
  const buf = Uint8Array.from(atob(ICON_192_BASE64), (ch) => ch.charCodeAt(0));
  return c.body(buf, 200, {
    "Content-Type": "image/png",
    "Cache-Control": "public, max-age=86400",
  });
});

app.get("/icon-512.png", (c) => {
  const buf = Uint8Array.from(atob(ICON_512_BASE64), (ch) => ch.charCodeAt(0));
  return c.body(buf, 200, {
    "Content-Type": "image/png",
    "Cache-Control": "public, max-age=86400",
  });
});

app.get("/health", (c) => {
  return c.json({ status: "ok", timestamp: new Date().toISOString() });
});

// RFC 9727 API catalog — agents discover this via the Link header on HTML
// pages or by fetching a well-known URI directly.
app.get("/.well-known/api-catalog", (c) => {
  return c.body(API_CATALOG_JSON, 200, {
    "Content-Type": "application/linkset+json",
    "Cache-Control": "public, max-age=3600",
  });
});

// Agent Skills discovery index — Cloudflare RFC v0.2.0.
// https://github.com/cloudflare/agent-skills-discovery-rfc
app.get("/.well-known/agent-skills/index.json", async (c) => {
  const json = await getAgentSkillsIndexJson();
  return c.body(json, 200, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

app.get("/.well-known/agent-skills/scan-domain/SKILL.md", (c) => {
  return c.body(SCAN_DOMAIN_SKILL_MD, 200, {
    "Content-Type": "text/markdown; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

app.get("/openapi.json", (c) => {
  return c.body(OPENAPI_JSON, 200, {
    "Content-Type": "application/openapi+json; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

app.get("/docs/api", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderApiDocsMarkdown());
  return c.html(renderApiDocs());
});

// llmstxt.org — vendor-neutral pointer to the canonical markdown URLs LLM
// clients should pull instead of scraping rendered HTML. See src/api/llms-txt.ts.
app.get("/llms.txt", (c) => {
  return c.body(LLMS_TXT, 200, {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

// Crawl guidance for search engines. Block the API namespace (Google was
// logging `/api/check?domain=dmarc.mx` as "Crawled - currently not indexed"
// noise) and point to the sitemap.
app.get("/robots.txt", (c) => {
  const body = `User-agent: *
Allow: /
Disallow: /api/
Sitemap: https://dmarc.mx/sitemap.xml
`;
  return c.body(body, 200, {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "public, max-age=86400",
  });
});

// Static URLs worth reinforcing to search engines. The /check entries are
// generated from the curated allowlist in src/shared/indexable-domains.ts —
// every domain listed there is also marked indexable on its scan page, so
// the sitemap and the per-page robots meta stay in sync.
const STATIC_SITEMAP_URLS: Array<{ loc: string; priority: string }> = [
  { loc: "https://dmarc.mx/", priority: "1.0" },
  { loc: "https://dmarc.mx/pricing", priority: "0.9" },
  { loc: "https://dmarc.mx/scoring", priority: "0.8" },
  { loc: "https://dmarc.mx/legal/privacy", priority: "0.3" },
  { loc: "https://dmarc.mx/learn", priority: "0.7" },
  { loc: "https://dmarc.mx/learn/dmarc", priority: "0.8" },
  { loc: "https://dmarc.mx/learn/spf", priority: "0.8" },
  { loc: "https://dmarc.mx/learn/dkim", priority: "0.7" },
  { loc: "https://dmarc.mx/learn/bimi", priority: "0.6" },
  { loc: "https://dmarc.mx/learn/mta-sts", priority: "0.7" },
  { loc: "https://dmarc.mx/llms.txt", priority: "0.2" },
];
const SITEMAP_LASTMOD = "2026-04-26";

function buildSitemapUrls(): Array<{ loc: string; priority: string }> {
  const scanUrls = listIndexableScanDomains().map((domain) => ({
    loc: `https://dmarc.mx/check?domain=${encodeURIComponent(domain)}`,
    priority: "0.6",
  }));
  return [...STATIC_SITEMAP_URLS, ...scanUrls];
}

app.get("/sitemap.xml", (c) => {
  const urls = buildSitemapUrls()
    .map(
      ({ loc, priority }) =>
        `  <url><loc>${loc}</loc><lastmod>${SITEMAP_LASTMOD}</lastmod><priority>${priority}</priority></url>`,
    )
    .join("\n");
  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>
`;
  return c.body(body, 200, {
    "Content-Type": "application/xml; charset=utf-8",
    "Cache-Control": "public, max-age=86400",
  });
});

app.get("/", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderLandingMarkdown());
  return c.html(renderLandingPage());
});

app.get("/scoring", (c) => {
  if (wantsMarkdown(c))
    return markdownResponse(c, renderScoringRubricMarkdown());
  return c.html(renderScoringRubric());
});

app.get("/learn", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderLearnHubMarkdown());
  return c.html(renderLearnHub());
});
app.get("/learn/dmarc", (c) => c.html(renderLearnDmarc()));
app.get("/learn/spf", (c) => c.html(renderLearnSpf()));
app.get("/learn/dkim", (c) => c.html(renderLearnDkim()));
app.get("/learn/bimi", (c) => c.html(renderLearnBimi()));
app.get("/learn/mta-sts", (c) => c.html(renderLearnMtaSts()));

app.get("/pricing", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderPricingMarkdown());
  return c.html(renderPricingPage());
});
app.get("/legal/privacy", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderPrivacyMarkdown());
  return c.html(renderPrivacyPage());
});

app.get("/api/check", async (c) => {
  const domain = normalizeDomain(c.req.query("domain"));
  if (!domain) {
    return c.json({ error: "Missing or invalid domain parameter" }, 400);
  }

  const selectors = parseSelectors(c.req.query("selectors"));
  const bearer =
    (c.get("bearer" as never) as BearerIdentity | undefined) ?? null;

  try {
    Sentry.addBreadcrumb({
      category: "scan.start",
      message: domain,
      data: { domain, selectors },
      level: "info",
    });
    const cached = await getCachedScan(domain, selectors);
    Sentry.addBreadcrumb({
      category: cached ? "cache.hit" : "cache.miss",
      message: domain,
      data: { domain },
      level: "info",
    });
    const result = cached ?? (await scan(domain, selectors));
    tagScanResult(result);
    if (!cached) {
      const pendingCacheWrite = setCachedScan(domain, selectors, result);
      if (pendingCacheWrite) {
        c.executionCtx.waitUntil(pendingCacheWrite.catch(() => {}));
      }
    }

    // Persist to scan_history only when the bearer's user already watches
    // this domain — mirrors the dashboard "Scan Now" contract and avoids
    // silently growing the watchlist on ad-hoc API requests.
    if (bearer) {
      persistBearerScanIfWatched(c, bearer.userId, domain, result);
    }

    if (c.req.query("format") === "csv") {
      return c.body(generateCsv(result), 200, {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${domain}-email-security.csv"`,
        ...(cached ? { "X-Cache": "HIT" } : {}),
      });
    }
    if (cached) {
      return c.json(result, { headers: { "X-Cache": "HIT" } });
    }
    return c.json(result);
  } catch (err) {
    Sentry.captureException(err);
    const message = err instanceof Error ? err.message : "Internal error";
    return c.json({ error: message }, 500);
  }
});

// Bulk scan — Pro-only, bearer-authenticated. Up to BULK_TOTAL_CAP submitted;
// the first BULK_IN_BAND_CAP are scanned synchronously in batches and the
// rest are queued by inserting `domains` rows for the next cron pickup. Per-
// entry results let the caller distinguish scanned/queued/invalid/error.
app.post("/api/bulk-scan", async (c) => {
  const bearer =
    (c.get("bearer" as never) as BearerIdentity | undefined) ?? null;
  if (!bearer) {
    return c.json(
      {
        error:
          "Bearer token required. Generate one at /dashboard/settings/api-keys.",
      },
      401,
    );
  }
  const db = (c.env as { DB?: D1Database }).DB;
  if (!db) {
    return c.json({ error: "Database not configured" }, 500);
  }
  const plan = await getPlanForUser(db, bearer.userId);
  if (plan !== "pro") {
    return c.json(
      {
        error: "Bulk scan requires a Pro plan.",
        upgrade: `${CANONICAL_ORIGIN}/dashboard/billing/subscribe`,
      },
      402,
    );
  }

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }
  const rawDomains = (body as { domains?: unknown })?.domains;
  if (!Array.isArray(rawDomains)) {
    return c.json({ error: "Body must be { domains: string[] }" }, 400);
  }
  if (!rawDomains.every((d): d is string => typeof d === "string")) {
    return c.json({ error: "All domains must be strings" }, 400);
  }

  const outcome = await processBulkScan({
    db,
    userId: bearer.userId,
    rawDomains,
    watchlistCap: watchlistCapForPlan(plan),
  });
  if (isCapExceeded(outcome)) {
    return c.json(
      {
        error: `Too many domains: ${outcome.submitted} > ${outcome.cap}`,
        cap: outcome.cap,
        in_band_cap: BULK_IN_BAND_CAP,
      },
      400,
    );
  }
  c.executionCtx.waitUntil(
    fireBulkScanWebhooks(db, bearer.userId, outcome.results, "bulk_api"),
  );
  return c.json(outcome);
});

// Scan history for a watched domain — Pro-only, bearer-authenticated. Thin
// wrapper around the same `getScanHistoryWithProtocols` helper the dashboard
// uses (src/dashboard/routes.ts `/dashboard/domain/:domain/history`), so the
// HTML view and the JSON API return the same rows. Check order is deliberate:
// auth → plan → domain validation → ownership. The ownership check must run
// after the plan check, otherwise a free-tier bearer could probe which
// domains belong to a pro user. It must also not echo anything about the
// domain on 404 — existence is not revealed.
app.get("/api/domain/:name/history", async (c) => {
  const bearer =
    (c.get("bearer" as never) as BearerIdentity | undefined) ?? null;
  if (!bearer) {
    return c.json(
      {
        error:
          "Bearer token required. Generate one at /dashboard/settings/api-keys.",
      },
      401,
    );
  }
  const db = (c.env as { DB?: D1Database }).DB;
  if (!db) {
    return c.json({ error: "Database not configured" }, 500);
  }
  const plan = await getPlanForUser(db, bearer.userId);
  if (plan !== "pro") {
    return c.json(
      {
        error: "Scan history requires a Pro plan.",
        upgrade: `${CANONICAL_ORIGIN}/dashboard/billing/subscribe`,
      },
      402,
    );
  }
  const domain = normalizeDomain(c.req.param("name"));
  if (!domain) {
    return c.json({ error: "Missing or invalid domain parameter" }, 400);
  }
  const limit = clampHistoryLimit(c.req.query("limit"));
  const resp = await fetchDomainHistory(db, bearer.userId, domain, limit);
  if (!resp) {
    return c.json({ error: "Domain not found" }, 404);
  }
  return c.json(resp);
});

// Fire-and-forget: look up the (user, domain) pair and record a scan_history
// row if the user watches this domain. The orchestrator result structure is
// the same shape consumed by dashboard "Scan Now".
function persistBearerScanIfWatched(
  c: Context,
  userId: string,
  domain: string,
  result: {
    grade: string;
    breakdown: { factors: unknown };
    protocols: unknown;
  },
): void {
  const db = (c.env as { DB?: D1Database }).DB;
  if (!db) return;
  const task = (async () => {
    const owned = await getDomainByUserAndName(db, userId, domain);
    if (!owned) return;
    await recordScan(db, {
      domainId: owned.id,
      grade: result.grade,
      scoreFactors: result.breakdown.factors,
      protocolResults: result.protocols,
    });
  })();
  c.executionCtx.waitUntil(task.catch(() => {}));
}

app.get("/check/score", async (c) => {
  const domain = normalizeDomain(c.req.query("domain"));
  if (!domain) {
    return c.html(renderError("Please provide a valid domain name."), 400);
  }

  const selectors = parseSelectors(c.req.query("selectors"));

  try {
    Sentry.addBreadcrumb({
      category: "scan.start",
      message: domain,
      data: { domain, selectors },
      level: "info",
    });
    const result = await scan(domain, selectors);
    tagScanResult(result);
    return c.html(renderScoreBreakdown(result));
  } catch (err) {
    Sentry.captureException(err);
    const message = err instanceof Error ? err.message : "Internal error";
    return c.html(renderError(message), 500);
  }
});

app.get("/check", async (c) => {
  const format = c.req.query("format");
  const wantsJson =
    format === "json" || c.req.header("Accept")?.includes("application/json");
  const wantsCsv = format === "csv";
  const wantsMd = !wantsJson && !wantsCsv && wantsMarkdown(c);

  const domain = normalizeDomain(c.req.query("domain"));
  if (!domain) {
    // API clients still get a structured error. Browsers get a 302 to `/` so
    // Google doesn't report `/check` (bare) as a crawl error — the human intent
    // of landing on `/check` with no query is "I want to scan something".
    if (wantsJson) {
      return c.json({ error: "Missing or invalid domain parameter" }, 400);
    }
    if (wantsCsv) {
      return c.body("error,Missing or invalid domain parameter\n", 400, {
        "Content-Type": "text/csv; charset=utf-8",
      });
    }
    if (wantsMd) {
      return markdownResponse(
        c,
        renderErrorMarkdown("Missing or invalid domain parameter"),
        400,
      );
    }
    return c.redirect("/", 302);
  }

  const selectors = parseSelectors(c.req.query("selectors"));

  if (wantsMd) {
    try {
      Sentry.addBreadcrumb({
        category: "scan.start",
        message: domain,
        data: { domain, selectors },
        level: "info",
      });
      const cached = await getCachedScan(domain, selectors);
      const result = cached ?? (await scan(domain, selectors));
      tagScanResult(result);
      if (!cached) {
        const pendingCacheWrite = setCachedScan(domain, selectors, result);
        if (pendingCacheWrite) {
          c.executionCtx.waitUntil(pendingCacheWrite.catch(() => {}));
        }
      }
      return markdownResponse(c, renderReportMarkdown(result));
    } catch (err) {
      Sentry.captureException(err);
      const message = err instanceof Error ? err.message : "Internal error";
      return markdownResponse(c, renderErrorMarkdown(message), 500);
    }
  }

  if (wantsJson) {
    try {
      Sentry.addBreadcrumb({
        category: "scan.start",
        message: domain,
        data: { domain, selectors },
        level: "info",
      });
      const result = await scan(domain, selectors);
      tagScanResult(result);
      return c.json(result);
    } catch (err) {
      Sentry.captureException(err);
      const message = err instanceof Error ? err.message : "Internal error";
      return c.json({ error: message }, 500);
    }
  }

  if (wantsCsv) {
    try {
      Sentry.addBreadcrumb({
        category: "scan.start",
        message: domain,
        data: { domain, selectors },
        level: "info",
      });
      const result = await scan(domain, selectors);
      tagScanResult(result);
      return c.body(generateCsv(result), 200, {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${domain}-email-security.csv"`,
      });
    } catch (err) {
      Sentry.captureException(err);
      const message = err instanceof Error ? err.message : "Internal error";
      return c.json({ error: message }, 500);
    }
  }

  // Fetch from loading page or noscript fallback — do the actual scan
  if (c.req.header("X-Scan-Fetch") === "1" || c.req.query("_direct") === "1") {
    try {
      Sentry.addBreadcrumb({
        category: "scan.start",
        message: domain,
        data: { domain, selectors },
        level: "info",
      });
      const cached = await getCachedScan(domain, selectors);
      Sentry.addBreadcrumb({
        category: cached ? "cache.hit" : "cache.miss",
        message: domain,
        data: { domain },
        level: "info",
      });
      const result = cached ?? (await scan(domain, selectors));
      tagScanResult(result);
      if (!cached) {
        const pendingCacheWrite = setCachedScan(domain, selectors, result);
        if (pendingCacheWrite) {
          c.executionCtx.waitUntil(pendingCacheWrite.catch(() => {}));
        }
      }
      return c.html(renderReport(result));
    } catch (err) {
      Sentry.captureException(err);
      const message = err instanceof Error ? err.message : "Internal error";
      return c.html(renderError(message), 500);
    }
  }

  // Default: return streaming loading page with skeleton cards, JS opens SSE.
  // Pass the sanitized selectors (re-joined from parseSelectors) rather than
  // the raw query string so the loader only ever sees validated characters.
  return c.html(renderStreamingLoading(domain, selectors.join(",")));
});

// Re-exported so long-standing callers (and tests) that import from
// `src/index.js` keep working. Canonical location: src/shared/domain.ts.
export { normalizeDomain };

// DKIM selector charset per RFC 6376 §3.1: sub-domain syntax, which is
// letters / digits / hyphens, with dot-separated labels. We also allow
// underscores since some providers use them in practice. Anything else
// is dropped silently — an invalid selector cannot match a real DKIM key.
const VALID_SELECTOR = /^[A-Za-z0-9._-]+$/;

export function parseSelectors(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && VALID_SELECTOR.test(s));
}

// Cron handler — runs nightly per the `[triggers] crons` entry in wrangler.toml.
// Rescans domains whose cadence has come due (monthly or weekly), persists
// results, and records grade_drop / protocol_regression alerts. Fails soft
// when DB is unbound so self-host deploys without D1 don't fault.
async function scheduled(
  _controller: ScheduledController,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  if (!env.DB) return;
  const work = (async () => {
    const rescanResult = await runDueRescans({
      db: env.DB,
      now: Math.floor(Date.now() / 1000),
    });
    const scope = Sentry.getCurrentScope();
    scope.setTag("cron.scanned", String(rescanResult.scanned));
    scope.setTag("cron.alerts", String(rescanResult.alerts));
    scope.setTag("cron.errors", String(rescanResult.errors));

    // Dispatch runs unconditionally — alerts from prior cron runs may still
    // be pending if the EMAIL binding was absent or failed previously.
    const dispatchResult = await dispatchPendingAlerts(env);
    scope.setTag("cron.emails_sent", String(dispatchResult.sent));
    scope.setTag("cron.emails_skipped", String(dispatchResult.skipped));
    scope.setTag("cron.emails_errors", String(dispatchResult.errors));
  })().catch((err) => {
    Sentry.captureException(err);
  });
  ctx.waitUntil(work);
}

// Public unsubscribe endpoint reached from email links. The token is the
// authentication — no session cookie required. Invalid / tampered tokens
// return a 400. Successful unsubscribe flips users.email_alerts_enabled to 0
// and renders a confirmation page.
app.get("/alerts/unsubscribe", async (c) => {
  const token = c.req.query("token");
  if (!token) {
    return c.html(renderError("Missing unsubscribe token."), 400);
  }
  const userId = await validateUnsubscribeToken(token, c.env.SESSION_SECRET);
  if (!userId) {
    return c.html(renderError("Invalid or expired unsubscribe link."), 400);
  }
  await setEmailAlertsEnabled(c.env.DB, userId, false);
  return c.html(
    `<!doctype html><html><head><meta charset="utf-8"><title>Unsubscribed</title></head><body style="font-family:system-ui;padding:32px;max-width:520px;margin:0 auto;line-height:1.5"><h1>Unsubscribed</h1><p>You will no longer receive grade-drop alerts from dmarc.mx.</p><p>You can re-enable alerts any time from <a href="/dashboard/settings">dashboard settings</a>.</p></body></html>`,
  );
});

const handler: ExportedHandler<Env> = {
  fetch: app.fetch.bind(app),
  scheduled,
};

export default Sentry.withSentry<Env>(
  (env) => ({
    dsn: env?.SENTRY_DSN ?? "",
    tracesSampler: (samplingContext: { parentSampled?: boolean }) => {
      if (samplingContext.parentSampled !== undefined)
        return samplingContext.parentSampled;
      return 0.3;
    },
  }),
  handler,
);
