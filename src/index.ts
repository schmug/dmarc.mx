import * as Sentry from "@sentry/cloudflare";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { csrf } from "hono/csrf";
import { sweepWorkosRetries } from "./account/workos-retry.js";
import { dispatchPendingAlerts } from "./alerts/dispatcher.js";
import { validateUnsubscribeToken } from "./alerts/unsubscribe.js";
import { renderBadgeSvg } from "./api/badge.js";
import { accessJwtMiddleware } from "./auth/access-jwt.js";
import { authRoutes } from "./auth/routes.js";
import { stripeWebhookRoutes } from "./billing/routes.js";
import { runDueRescans } from "./cron/rescan.js";
import { dashboardRoutes } from "./dashboard/routes.js";
import { isTransientD1Error } from "./db/retry.js";
import { setEmailAlertsEnabled } from "./db/users.js";
import type { Env } from "./env.js";
import { handleInboundEmail } from "./inbox/store.js";
import { agentDiscoveryRoutes } from "./routes/agent-discovery.js";
import { contentRoutes } from "./routes/content.js";
import { inboxRoutes } from "./routes/inbox.js";
import { scanRoutes } from "./routes/scan.js";
import { staticRoutes } from "./routes/static.js";
import {
  blockedMessage,
  bulkScanWeight,
  rateLimitMiddleware,
} from "./security/rate-limit-middleware.js";
import { scrubSentryEvent } from "./sentry-scrub.js";
import { normalizeDomain } from "./shared/domain.js";
import { parseScoringConfig } from "./shared/scoring-config.js";
import { renderError } from "./views/html.js";

// Durable Object class for the atomic rate limiter (GHSA-v7qc-7qh8-h69g).
// Must be re-exported from the Worker entry module so the `RATE_LIMITER`
// binding in wrangler.toml can resolve its `class_name`.
export { RateLimiterDO } from "./rate-limit-do.js";

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
  // DNS-AID agent metadata contract — the rel URI is the tracked IETF draft.
  '</.well-known/agent.json>; rel="https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid"; type="application/json"',
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
    // Per-request nonce eliminates 'unsafe-inline' from script-src. Scripts
    // with a matching nonce attribute execute; all others are blocked.
    const nonce = btoa(
      String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))),
    );
    c.res.headers.set(
      "Content-Security-Policy",
      `default-src 'none'; script-src 'nonce-${nonce}' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors ${frameAncestors}`,
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

    // Inject nonce into all <script> tags (excluding JSON-LD data blocks which
    // are not executable JS and don't fall under script-src).  Combine with the
    // optional Cloudflare Analytics beacon injection to avoid reading the body
    // twice — HTML responses are buffered strings, never true streams.
    const token = (c.env as Env | undefined)?.CF_ANALYTICS_TOKEN;
    const path = c.req.path;
    const isAnalyticsEligible =
      token &&
      CF_ANALYTICS_TOKEN_RE.test(token) &&
      !ANALYTICS_SKIP_PATH_PREFIXES.some((p) => path.startsWith(p));
    let body = (await c.res.text()).replace(
      /<script(?!\s+type=["']application\/ld\+json)/g,
      `<script nonce="${nonce}"`,
    );
    if (isAnalyticsEligible) {
      const beacon = `<script defer nonce="${nonce}" src="https://static.cloudflareinsights.com/beacon.min.js" data-cf-beacon='{"token":"${token}"}'></script>`;
      body = body.replace("</body>", `${beacon}</body>`);
    }
    c.res = new Response(body, {
      status: c.res.status,
      statusText: c.res.statusText,
      headers: c.res.headers,
    });
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

// A D1 blip that outlived `d1Read`'s retries is not the caller's fault and is
// not permanent, so it gets 503 + Retry-After rather than a 500 — that is what
// the API docs already tell clients and agents to back off on, and it keeps the
// raw `D1_ERROR: internal error; reference = <id>` out of the page (it is of no
// use to the visitor; Sentry has the full exception either way).
const D1_UNAVAILABLE_MESSAGE =
  "Our database is briefly unavailable. Please try again in a moment.";
const D1_RETRY_AFTER_SECONDS = "5";

// Safety net: capture any unhandled errors that bypass route catch blocks
app.onError((err, c) => {
  Sentry.captureException(err);
  const transientD1 = isTransientD1Error(err);
  const message = transientD1
    ? D1_UNAVAILABLE_MESSAGE
    : err instanceof Error
      ? err.message
      : "Internal error";
  const status = transientD1 ? 503 : 500;
  const headers = transientD1
    ? { "Retry-After": D1_RETRY_AFTER_SECONDS }
    : undefined;
  const wantsJson =
    c.req.header("Accept")?.includes("application/json") ||
    c.req.query("format") === "json";
  if (wantsJson) {
    return c.json({ error: message }, status, headers);
  }
  return c.html(renderError(message), status, headers);
});

app.use("/api/*", cors());

// Auth routes (public) — login, WorkOS callback, logout
// Logout is state-changing, so it gets the same Origin/CSRF check as
// /dashboard/* even though it lives outside that path prefix.
app.use("/auth/logout", csrf());
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

// Test-email address issuance (issue #417). Minting a token is also minting a
// routable address, so it gets the same per-identity limiter as a scan.
app.use(
  "/check/email",
  rateLimitMiddleware((_c, _result, headers) =>
    _c.html(
      renderError(
        "Rate limit exceeded. Please wait a minute before requesting another test address.",
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
// posture as /api/check (Pro bearer → user bucket; everyone else → IP), but
// charged proportionally to the in-band scan count rather than 1 token per
// request (issue #619), since a 30-domain request fans out ~30x the outbound
// DNS/fetch of a single scan.
app.use(
  "/api/bulk-scan",
  rateLimitMiddleware(
    (c, result, headers) =>
      c.json({ error: blockedMessage(result) }, { status: 429, headers }),
    bulkScanWeight,
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

// Inbox result SSE stream (issue #417). Polls KV (no DNS fan-out), but give it
// its own limiter so it can't be opened en masse on one identity.
app.use(
  "/api/check/email/stream",
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

// MCP endpoint runs a full scan on cache miss — same per-IP budget as /api/check.
app.use(
  "/mcp",
  rateLimitMiddleware((c, result, headers) =>
    c.json({ error: blockedMessage(result) }, { status: 429, headers }),
  ),
);

// INVARIANT: every sub-router mounted at "/" mounts AFTER the rate-limit block
// above. Hono runs handlers in registration order and `app.route()` copies the
// sub-router's handlers in at the point it is called, so a sub-router mounted
// above the block answers the request before its limiter ever runs
// (GHSA-j7p5-95v7-29v9: /mcp, /check/email and /api/check/email/stream were
// unmetered after #751 / #761). The /auth, /dashboard and /webhooks routers
// above serve no metered path. test/rate-limit-mount-order.test.ts asserts a
// 429 at the ceiling for each path this block meters; add a row there when
// adding a limiter here.
//
// Static assets, health check, and crawler-facing infrastructure (#661).
app.route("/", staticRoutes);
app.route("/", agentDiscoveryRoutes);
app.route("/", inboxRoutes);

// Core scan routes (#667). Mounted AFTER the rate-limit block above on purpose:
// Hono only runs middleware registered before a route is mounted, so moving
// this line above that block strips every scan endpoint of its limiter.
app.route("/", scanRoutes);

// Marketing/content pages (#666). Keep this mount below the rate-limit
// `app.use()` block: a sub-router mounted above an `app.use()` skips it.
app.route("/", contentRoutes);

// Re-exported so long-standing callers (and tests) that import from
// `src/index.js` keep working. Canonical location: src/shared/domain.ts.
export { normalizeDomain };

// Cron handler — runs nightly per the `[triggers] crons` entry in wrangler.toml.
// Rescans domains whose cadence has come due (monthly or weekly), persists
// results, and records grade_drop / protocol_regression alerts. Fails soft
// when DB is unbound so self-host deploys without D1 don't fault.
//
// The work is AWAITED, not handed to `ctx.waitUntil()`. Under waitUntil the
// handler returned in microseconds, so the Cron Trigger's reported duration
// measured nothing and its success/failure was decided before the rescan had
// done anything — the run that false-graded 147 domains (#700) was recorded as
// a success. Awaiting also puts the `cron.*` scope tags inside the live
// invocation rather than on a scope whose lifetime had already ended. Cron
// Triggers get 15 minutes of wall time and CPU, so awaiting the rescan does not
// risk the truncation waitUntil would have avoided. Do not revert to waitUntil.
async function scheduled(
  _controller: ScheduledController,
  env: Env,
  _ctx: ExecutionContext,
): Promise<void> {
  if (!env.DB) return;
  try {
    const rescanResult = await runDueRescans({
      db: env.DB,
      now: Math.floor(Date.now() / 1000),
      scoringConfig: parseScoringConfig(env.SCORING_CONFIG),
      dnsblKey: env.DNSBL_DQS_KEY,
    });
    const scope = Sentry.getCurrentScope();
    scope.setTag("cron.scanned", String(rescanResult.scanned));
    scope.setTag("cron.alerts", String(rescanResult.alerts));
    scope.setTag("cron.errors", String(rescanResult.errors));
    // #700 — due domains deferred to the next run by the per-invocation
    // ceiling or the resolver circuit breaker. Persistently non-zero means the
    // portfolio has outgrown one invocation's outbound subrequest allowance.
    scope.setTag("cron.skipped", String(rescanResult.skipped));

    // Dispatch runs unconditionally — alerts from prior cron runs may still
    // be pending if the EMAIL binding was absent or failed previously.
    const dispatchResult = await dispatchPendingAlerts(env);
    scope.setTag("cron.emails_sent", String(dispatchResult.sent));
    scope.setTag("cron.emails_skipped", String(dispatchResult.skipped));
    scope.setTag("cron.emails_errors", String(dispatchResult.errors));

    // Retry any WorkOS identity deletions that failed during account deletion.
    const workosResult = await sweepWorkosRetries(env.DB, env.WORKOS_API_KEY);
    scope.setTag("cron.workos_retried", String(workosResult.retried));
    scope.setTag("cron.workos_cleared", String(workosResult.cleared));
    scope.setTag("cron.workos_given_up", String(workosResult.givenUp));
  } catch (err) {
    Sentry.captureException(err);
    // Re-throw so the platform records a FAILED cron invocation. Swallowing
    // here (as the old `.catch()` did) left Sentry as the only place a bad run
    // was visible, and the trigger itself reported success unconditionally.
    // `Sentry.withSentry`'s scheduled wrapper re-throws after its own capture,
    // so this rejection reaches the runtime.
    throw err;
  }
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
  // Email Worker entry point for the `inbox@dmarc.mx` subaddressing rule (#417).
  // Reads the authentication verdict from the inbound message's headers and
  // stores it under the address token. Unknown/expired tokens and a message off
  // our subdomain are silent no-ops (handled in handleInboundEmail). Errors are
  // swallowed + reported so a transient KV failure never bounces legitimate
  // test mail.
  async email(message, env) {
    try {
      await handleInboundEmail(message, env.INBOX_TOKENS);
    } catch (err) {
      Sentry.captureException(err);
    }
  },
};

export default Sentry.withSentry<Env>(
  (env) => ({
    dsn: env?.SENTRY_DSN ?? "",
    tracesSampler: (samplingContext: { parentSampled?: boolean }) => {
      if (samplingContext.parentSampled !== undefined)
        return samplingContext.parentSampled;
      return 0.3;
    },
    // Registered on both hooks: beforeSend only covers error events, and the
    // SDK attaches request headers to transaction events too.
    beforeSend: scrubSentryEvent,
    beforeSendTransaction: scrubSentryEvent,
  }),
  handler,
);
