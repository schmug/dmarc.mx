import * as Sentry from "@sentry/cloudflare";
import { type Context, Hono } from "hono";
import { streamSSE } from "hono/streaming";
import type {
  BimiResult,
  DaneResult,
  DkimResult,
  DmarcResult,
  DnsblResult,
  DnssecResult,
  MtaStsResult,
  MxResult,
  ScanResult,
  SecurityTxtResult,
  SpfResult,
  TlsRptResult,
} from "../analyzers/types.js";
import { isValidGrade, renderBadgeSvg } from "../api/badge.js";
import {
  BULK_IN_BAND_CAP,
  isCapExceeded,
  processBulkScan,
} from "../api/bulk-scan.js";
import { CANONICAL_ORIGIN } from "../api/catalog.js";
import { clampHistoryLimit, fetchDomainHistory } from "../api/history.js";
import type { BearerIdentity } from "../auth/api-key.js";
import { getCachedScan, setCachedScan } from "../cache.js";
import { generateCsv } from "../csv.js";
import { getDomainByUserAndName } from "../db/domains.js";
import { recordScan } from "../db/scans.js";
import { getPlanForUser } from "../db/subscriptions.js";
import { getMaxDomainsOverrideForUser } from "../db/users.js";
import type { Env } from "../env.js";
import type { ProtocolId, ProtocolResult } from "../orchestrator.js";
import { scan, scanStreaming } from "../orchestrator.js";
import { parseSelectors } from "../security/selectors.js";
import {
  markdownResponse,
  wantsMarkdown,
} from "../shared/content-negotiation.js";
import { normalizeDomain } from "../shared/domain.js";
import { watchlistCapFor } from "../shared/limits.js";
import { parseScoringConfig } from "../shared/scoring-config.js";
import {
  renderBimiCard,
  renderDaneCard,
  renderDkimCard,
  renderDmarcCard,
  renderDnsblCard,
  renderDnssecCard,
  renderError,
  renderMtaStsCard,
  renderMxCard,
  renderReport,
  renderReportFooter,
  renderReportHeader,
  renderScoreBreakdown,
  renderSecurityTxtCard,
  renderSpfCard,
  renderStreamingLoading,
  renderTlsRptCard,
} from "../views/html.js";
import {
  renderErrorMarkdown,
  renderReportMarkdown,
} from "../views/markdown.js";
import { fireBulkScanWebhooks } from "../webhooks/triggers.js";

// Core scan HTTP surface (#667, part of #661): /check, /check/score, /badge,
// /api/check, /api/check/stream, /api/bulk-scan, /api/domain/:name/history.
//
// MOUNT ORDER IS LOAD-BEARING. Every route here is rate-limited by an
// `app.use(...)` in src/index.ts, and Hono only runs middleware registered
// BEFORE a route is mounted. `app.route("/", ...)` for this router must stay
// below the rate-limit block, or every scan endpoint silently loses its limiter
// (the #751 / #761 mistake for /mcp and /check/email). The limiter is also what
// stashes `c.get("bearer")`, which /api/check, /api/check/stream, /api/bulk-scan
// and /api/domain/:name/history read.
export const scanRoutes = new Hono<{ Bindings: Env }>();

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
  tls_rpt: (r) => renderTlsRptCard(r as TlsRptResult),
  dnssec: (r) => renderDnssecCard(r as DnssecResult),
  dane: (r) => renderDaneCard(r as DaneResult),
  dnsbl: (r) => renderDnsblCard(r as DnsblResult),
};

// Single chokepoint for env-derived scan inputs: the scoring rubric override
// and the optional Spamhaus DQS key (#587). Threading the key here (rather than
// at each route) keeps it on every scan path that warms the shared cache, so
// the DNSBL result is consistent regardless of which route ran the scan. The
// key is passed only to the analyzer's outbound query — never logged or cached.
function envScan(
  c: Context<{ Bindings: Env }>,
  domain: string,
  selectors: string[] = [],
): Promise<ScanResult> {
  return scan(
    domain,
    selectors,
    parseScoringConfig(c.env?.SCORING_CONFIG),
    undefined,
    c.env?.DNSBL_DQS_KEY,
  );
}

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

scanRoutes.get("/api/check/stream", async (c) => {
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
      // Derive the replay set from `protocolRenderers` keys, not a hand-listed
      // literal. `protocolRenderers` is `Record<ProtocolId, …>`, so adding a
      // protocol to the union forces a renderer key, which is iterated here —
      // no protocol can be silently dropped from the cache-hit path (#455).
      // Object insertion order matches the previous literal, so `done` still
      // comes last with no duplicate or reordered events.
      const protocolIds = Object.keys(protocolRenderers) as ProtocolId[];
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

      // Mirror GET /api/check: persist on cache hit too so bearer scans of
      // watched domains update scan_history even within the 5-minute TTL.
      if (bearer) {
        persistBearerScanIfWatched(c, bearer.userId, domain, cached);
      }
      return;
    }

    const protocolWrites: Promise<unknown>[] = [];
    const result = await scanStreaming(
      domain,
      selectors,
      (id: ProtocolId, protocolResult: ProtocolResult) => {
        const html = protocolRenderers[id](protocolResult);
        const pending = stream.writeSSE({
          event: "protocol",
          data: JSON.stringify({ id, html }),
        });
        if (pending) protocolWrites.push(pending);
      },
      parseScoringConfig(c.env?.SCORING_CONFIG),
      undefined,
      c.env?.DNSBL_DQS_KEY,
    );
    await Promise.all(protocolWrites);

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
  });
});

// Embeddable email-security badge for READMEs and dashboards. Always
// returns a 200 SVG (even for invalid input or scan errors) so a badge
// embed never renders as a broken image — error states are encoded into
// the badge text instead.
scanRoutes.get("/badge", async (c) => {
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
    const result = cached ?? (await envScan(c, domain, []));
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

scanRoutes.get("/api/check", async (c) => {
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
    const result = cached ?? (await envScan(c, domain, selectors));
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
scanRoutes.post("/api/bulk-scan", async (c) => {
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
  const [plan, override] = await Promise.all([
    getPlanForUser(db, bearer.userId),
    getMaxDomainsOverrideForUser(db, bearer.userId),
  ]);
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
    watchlistCap: watchlistCapFor(plan, override),
    scoringConfig: parseScoringConfig(c.env?.SCORING_CONFIG),
    dnsblKey: c.env?.DNSBL_DQS_KEY,
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
scanRoutes.get("/api/domain/:name/history", async (c) => {
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

scanRoutes.get("/check/score", async (c) => {
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
    const result = await envScan(c, domain, selectors);
    tagScanResult(result);
    return c.html(renderScoreBreakdown(result));
  } catch (err) {
    Sentry.captureException(err);
    const message = err instanceof Error ? err.message : "Internal error";
    return c.html(renderError(message), 500);
  }
});

scanRoutes.get("/check", async (c) => {
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
      const result = cached ?? (await envScan(c, domain, selectors));
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
      const result = await envScan(c, domain, selectors);
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
      const result = await envScan(c, domain, selectors);
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
      const result = cached ?? (await envScan(c, domain, selectors));
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
