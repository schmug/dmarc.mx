import { Hono } from "hono";
import {
  BULK_IN_BAND_CAP,
  BULK_TOTAL_CAP,
  isCapExceeded,
  processBulkScan,
} from "../api/bulk-scan.js";
import { generateApiKey } from "../auth/api-key.js";
import { requireAuth } from "../auth/middleware.js";
import type { SessionPayload } from "../auth/session.js";
import { dashboardBillingRoutes } from "../billing/routes.js";
import { escapeCsvField } from "../csv.js";
import {
  acknowledgeAlert,
  acknowledgeAllAlertsForUser,
  countUnacknowledgedByDomain,
  listUnacknowledgedForUser,
} from "../db/alerts.js";
import {
  createApiKey,
  listApiKeysByUser,
  revokeApiKey,
} from "../db/api-keys.js";
import {
  countDomainsByUser,
  createDomain,
  type DomainSortColumn,
  type DomainSortDirection,
  deleteDomain,
  getDomainByUserAndName,
  getDomainsByUser,
  listDomainsForUserPaged,
} from "../db/domains.js";
import {
  getDashboardExportRows,
  getPortfolioTrendForUser,
  getScanHistory,
  getScanHistoryWithProtocols,
  recordScan,
} from "../db/scans.js";
import { getPlanForUser } from "../db/subscriptions.js";
import {
  acknowledgeApiKeyRetirement,
  getUserById,
  setEmailAlertsEnabled,
  setNotifyOnChangeOnly,
} from "../db/users.js";
import { getRecentDeliveriesForUser } from "../db/webhook-deliveries.js";
import { scan } from "../orchestrator.js";
import { normalizeDomain } from "../shared/domain.js";
import { PRO_WATCHLIST_CAP, watchlistCapForPlan } from "../shared/limits.js";
import {
  computeGradeBreakdown,
  type ScoringConfig,
} from "../shared/scoring.js";
import { parseScoringConfig } from "../shared/scoring-config.js";
import { isAllowedWebhookUrl } from "../shared/ssrf.js";
import {
  renderAddDomainPage,
  renderApiKeysPage,
  renderBulkScanPage,
  renderDashboardPage,
  renderDomainDetailPage,
  renderDomainHistoryPage,
  renderDomainPanel,
  renderExportUpsellPage,
  renderSettingsPage,
  toApiKeyListEntry,
} from "../views/dashboard.js";
import { dispatchWebhook } from "../webhooks/dispatcher.js";
import {
  isWebhookFormat,
  type WebhookFormat,
} from "../webhooks/formats/index.js";
import {
  fireBulkScanWebhooks,
  fireScanCompletedWebhook,
} from "../webhooks/triggers.js";

const HISTORY_LIMIT_PRO = 30;
const HISTORY_LIMIT_FREE = 5;

// Page-size knobs for the Pro domain list. Cap is defensive: nothing in the
// product needs >100 rows at once, and the LIMIT bounds the worst-case D1
// scan even if a hostile query string asks for more.
const DOMAINS_PAGE_SIZE_DEFAULT = 25;
const DOMAINS_PAGE_SIZE_MAX = 100;
const DOMAINS_SEARCH_MAX = 60;

const VALID_GRADES = new Set([
  "A+",
  "A",
  "A-",
  "B+",
  "B",
  "B-",
  "C+",
  "C",
  "C-",
  "D+",
  "D",
  "D-",
  "F",
  "ungraded",
]);
const VALID_SORT_COLUMNS = new Set<DomainSortColumn>([
  "domain",
  "grade",
  "last_scanned",
  "created",
]);

// Powers the dashboard drawer's enriched payload: per-protocol summary lines
// + raw records, scoring recommendations, and a "what changed today" diff
// when the latest DMARC record drifted from the previous scan within 24h.
// All derivation is pure JSON parsing + a re-run of computeGradeBreakdown
// against the persisted protocol_results blob — no extra DB calls.
interface DrawerProtocolSummary {
  status: "pass" | "warn" | "fail" | "info" | null;
  summary: string;
  record: string | null;
}

interface DrawerDetail {
  protocols: {
    dmarc: DrawerProtocolSummary;
    spf: DrawerProtocolSummary;
    dkim: DrawerProtocolSummary;
    bimi: DrawerProtocolSummary;
    mta_sts: DrawerProtocolSummary;
  };
  recommendations: import("../shared/scoring.js").Recommendation[];
  diff: {
    change: string;
    previous: string;
    current: string;
  } | null;
}

const EMPTY_PROTOCOL: DrawerProtocolSummary = {
  status: null,
  summary: "no data yet",
  record: null,
};

function asProtocolStatus(
  v: unknown,
): "pass" | "warn" | "fail" | "info" | null {
  return v === "pass" || v === "warn" || v === "fail" || v === "info"
    ? v
    : null;
}

function buildDrawerDetail(
  rawScanRows: import("../db/scans.js").ScanHistoryRow[],
  config: Partial<ScoringConfig>,
): DrawerDetail {
  const empty: DrawerDetail = {
    protocols: {
      dmarc: EMPTY_PROTOCOL,
      spf: EMPTY_PROTOCOL,
      dkim: EMPTY_PROTOCOL,
      bimi: EMPTY_PROTOCOL,
      mta_sts: EMPTY_PROTOCOL,
    },
    recommendations: [],
    diff: null,
  };
  if (rawScanRows.length === 0) return empty;

  const latest = rawScanRows[0];
  const parsed = safeParseProtocols(latest.protocol_results);
  if (!parsed) return empty;

  // Stringly-typed reach into the parsed JSON: D1 stored what the orchestrator
  // wrote, but TypeScript can't follow it through the JSON round-trip.
  const dmarc = parsed.dmarc as
    | { status?: unknown; record?: unknown; tags?: Record<string, unknown> }
    | undefined;
  const spf = parsed.spf as
    | {
        status?: unknown;
        record?: unknown;
        lookups_used?: unknown;
        lookup_limit?: unknown;
      }
    | undefined;
  const dkim = parsed.dkim as
    | {
        status?: unknown;
        selectors?: Record<
          string,
          { found?: unknown; key_bits?: unknown; key_type?: unknown }
        >;
      }
    | undefined;
  const bimi = parsed.bimi as
    | { status?: unknown; record?: unknown; tags?: Record<string, unknown> }
    | undefined;
  const mta = parsed.mta_sts as
    | {
        status?: unknown;
        dns_record?: unknown;
        policy?: { mode?: unknown } | null;
      }
    | undefined;

  const dmarcPolicy = typeof dmarc?.tags?.p === "string" ? dmarc.tags.p : null;
  const spfLookupsUsed =
    typeof spf?.lookups_used === "number" ? spf.lookups_used : null;
  const spfLookupLimit =
    typeof spf?.lookup_limit === "number" ? spf.lookup_limit : 10;
  const dkimSelectors = dkim?.selectors ?? {};
  const dkimFound = Object.values(dkimSelectors).filter(
    (s) => s?.found === true,
  );
  const dkimKeyBits = dkimFound
    .map((s) => (typeof s.key_bits === "number" ? s.key_bits : 0))
    .filter((n) => n > 0);
  const bimiConfigured = !!(bimi?.tags && Object.keys(bimi.tags).length > 0);
  const mtaMode =
    typeof mta?.policy?.mode === "string" ? mta.policy.mode : null;
  const mtaConfigured = !!(mta?.dns_record || mta?.policy);

  const protocols: DrawerDetail["protocols"] = {
    dmarc: {
      status: asProtocolStatus(dmarc?.status),
      summary: dmarcPolicy ? `policy: p=${dmarcPolicy}` : "no policy",
      record: typeof dmarc?.record === "string" ? dmarc.record : null,
    },
    spf: {
      status: asProtocolStatus(spf?.status),
      summary:
        spfLookupsUsed !== null
          ? `${spfLookupsUsed}/${spfLookupLimit} DNS lookups`
          : "not set",
      record: typeof spf?.record === "string" ? spf.record : null,
    },
    dkim: {
      status: asProtocolStatus(dkim?.status),
      summary:
        dkimFound.length > 0
          ? `${dkimFound.length} selector${dkimFound.length === 1 ? "" : "s"}` +
            (dkimKeyBits.length ? ` · ${Math.min(...dkimKeyBits)}-bit` : "")
          : "no selectors found",
      record: null,
    },
    bimi: {
      status: asProtocolStatus(bimi?.status),
      summary: bimiConfigured ? "configured" : "not configured",
      record: typeof bimi?.record === "string" ? bimi.record : null,
    },
    mta_sts: {
      status: asProtocolStatus(mta?.status),
      summary: mtaConfigured
        ? `configured${mtaMode ? ` · mode=${mtaMode}` : ""}`
        : "not configured",
      record: typeof mta?.dns_record === "string" ? mta.dns_record : null,
    },
  };

  // Recommendations are derived on the fly so we don't have to migrate the
  // scan_history schema. computeGradeBreakdown is pure — given the persisted
  // protocol blobs it produces the same recommendation list the orchestrator
  // would have at scan time.
  let recommendations: import("../shared/scoring.js").Recommendation[] = [];
  try {
    const breakdown = computeGradeBreakdown(
      parsed as Parameters<typeof computeGradeBreakdown>[0],
      config,
    );
    recommendations = breakdown.recommendations;
  } catch {
    recommendations = [];
  }

  // Diff: surface only when DMARC drifted within ~26h (slack on 24h cron) and
  // the previous record was non-empty. SPF/DKIM diffs add noise — DMARC is
  // the field most worth a "you broke this, paste this back" prompt.
  let diff: DrawerDetail["diff"] = null;
  if (rawScanRows.length >= 2 && protocols.dmarc.record) {
    const prev = rawScanRows[1];
    const prevParsed = safeParseProtocols(prev.protocol_results);
    const prevDmarcRecord =
      typeof (prevParsed?.dmarc as { record?: unknown } | undefined)?.record ===
      "string"
        ? ((prevParsed?.dmarc as { record: string }).record ?? null)
        : null;
    const ageSec = latest.scanned_at - prev.scanned_at;
    if (
      prevDmarcRecord &&
      prevDmarcRecord !== protocols.dmarc.record &&
      ageSec < 26 * 3600
    ) {
      diff = {
        change: dmarcPolicy
          ? `DMARC record changed (now p=${dmarcPolicy})`
          : "DMARC record changed",
        previous: prevDmarcRecord,
        current: protocols.dmarc.record,
      };
    }
  }

  return { protocols, recommendations, diff };
}

function safeParseProtocols(
  json: string | null,
): Record<string, unknown> | null {
  if (!json) return null;
  try {
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === "object"
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

interface DomainListQuery {
  search: string;
  grade: string | null;
  frequency: "weekly" | "monthly" | null;
  sort: DomainSortColumn;
  direction: DomainSortDirection;
  page: number;
  pageSize: number;
}

function parseDomainListQuery(url: URL): DomainListQuery {
  const params = url.searchParams;
  const rawSearch = (params.get("q") ?? "").trim().slice(0, DOMAINS_SEARCH_MAX);
  const grade = params.get("grade");
  const frequencyRaw = params.get("frequency");
  const sortRaw = params.get("sort");
  const dirRaw = params.get("dir");
  const pageRaw = Number.parseInt(params.get("page") ?? "1", 10);
  const pageSizeRaw = Number.parseInt(params.get("pageSize") ?? "", 10);
  return {
    search: rawSearch,
    grade: grade && VALID_GRADES.has(grade) ? grade : null,
    frequency:
      frequencyRaw === "weekly" || frequencyRaw === "monthly"
        ? frequencyRaw
        : null,
    sort:
      sortRaw && VALID_SORT_COLUMNS.has(sortRaw as DomainSortColumn)
        ? (sortRaw as DomainSortColumn)
        : "domain",
    direction: dirRaw === "desc" ? "desc" : "asc",
    page: Number.isFinite(pageRaw) && pageRaw > 0 ? pageRaw : 1,
    pageSize:
      Number.isFinite(pageSizeRaw) && pageSizeRaw > 0
        ? Math.min(pageSizeRaw, DOMAINS_PAGE_SIZE_MAX)
        : DOMAINS_PAGE_SIZE_DEFAULT,
  };
}

export const dashboardRoutes = new Hono();

// All dashboard routes require auth
dashboardRoutes.use("*", requireAuth);

// Billing sub-routes (upgrade / portal). Self-gates on isBillingEnabled so a
// self-host deploy without Stripe env vars still 404s these cleanly.
dashboardRoutes.route("/billing", dashboardBillingRoutes);

// Domain list. Surfaces nightly-detected regressions ("Needs attention" section)
// above the table so logged-in users see them between cron fires without having
// to wait for the email.
dashboardRoutes.get("/", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const plan = await getPlanForUser(db, session.sub);

  const [alerts, unackCounts, portfolioTrend, user] = await Promise.all([
    listUnacknowledgedForUser(db, session.sub, 20),
    countUnacknowledgedByDomain(db, session.sub),
    getPortfolioTrendForUser(db, session.sub, 30),
    getUserById(db, session.sub),
  ]);

  // First-run = the user signed up within the last 24 hours and has exactly
  // one domain (the one auto-provisioned from their email suffix). The hero's
  // welcome banner only fires while both are true; after either window passes
  // it disappears for good without needing a separate "dismissed" flag.
  const ageSeconds = user
    ? Math.floor(Date.now() / 1000) - user.created_at
    : Number.POSITIVE_INFINITY;
  const isFirstRun = ageSeconds < 24 * 3600;

  const alertsView = alerts.map((a) => ({
    id: a.id,
    domain: a.domain,
    alertType: a.alert_type,
    previousValue: a.previous_value,
    newValue: a.new_value,
    createdAt: a.created_at,
  }));

  // Free-tier accounts cap out at a handful of domains, so we skip the
  // search/sort/page UI for them entirely and serve the simple list.
  if (plan !== "pro") {
    const domains = await getDomainsByUser(db, session.sub);
    return c.html(
      renderDashboardPage({
        email: session.email,
        plan,
        alerts: alertsView,
        portfolioTrend,
        isFirstRun,
        domains: domains.map((d) => ({
          domain: d.domain,
          grade: d.last_grade ?? "—",
          frequency: d.scan_frequency,
          lastScanned: d.last_scanned_at
            ? new Date(d.last_scanned_at * 1000).toLocaleDateString()
            : null,
          isFree: d.is_free === 1,
          unacknowledgedAlerts: unackCounts.get(d.id) ?? 0,
        })),
        controls: null,
        usage: {
          plan,
          current: domains.length,
          cap: watchlistCapForPlan(plan),
        },
      }),
    );
  }

  const query = parseDomainListQuery(new URL(c.req.url));
  const offset = (query.page - 1) * query.pageSize;
  // Unfiltered watchlist count, separate from `page.total` (which respects
  // the search/grade/frequency filters). The toolbar usage hint reflects
  // the user's full watchlist regardless of what's currently filtered.
  const [page, totalForUser] = await Promise.all([
    listDomainsForUserPaged(db, {
      userId: session.sub,
      search: query.search || undefined,
      grade: query.grade ?? undefined,
      frequency: query.frequency ?? undefined,
      sort: query.sort,
      direction: query.direction,
      limit: query.pageSize,
      offset,
    }),
    countDomainsByUser(db, session.sub),
  ]);

  // Clamp out-of-range pages so a deep-linked stale URL doesn't render an
  // empty table when results exist.
  const totalPages = Math.max(1, Math.ceil(page.total / query.pageSize));
  const currentPage = Math.min(query.page, totalPages);

  return c.html(
    renderDashboardPage({
      email: session.email,
      plan,
      alerts: alertsView,
      portfolioTrend,
      isFirstRun,
      domains: page.rows.map((d) => ({
        domain: d.domain,
        grade: d.last_grade ?? "—",
        frequency: d.scan_frequency,
        lastScanned: d.last_scanned_at
          ? new Date(d.last_scanned_at * 1000).toLocaleDateString()
          : null,
        isFree: d.is_free === 1,
        unacknowledgedAlerts: unackCounts.get(d.id) ?? 0,
      })),
      controls: {
        search: query.search,
        grade: query.grade,
        frequency: query.frequency,
        sort: query.sort,
        direction: query.direction,
        page: currentPage,
        pageSize: query.pageSize,
        totalPages,
        total: page.total,
      },
      usage: {
        plan,
        current: totalForUser,
        cap: watchlistCapForPlan(plan),
      },
    }),
  );
});

// Dismiss a regression alert. IDOR-safe via SQL: acknowledgeAlert only updates
// rows whose domain belongs to the session user. Returns 404 (not 500, not 303)
// for invalid / cross-user / already-acked ids so the caller can distinguish.
// Live-search fragment endpoint for the Pro domain list. Returns only the
// `#domain-panel` markup (toolbar + table + pagination) so the client can
// swap it in place when the user types or changes a filter — no full page
// reload, no flicker, no focus loss. Free users get 404 because their
// dashboard skips the search UI entirely; the full page already does the
// right thing for them.
dashboardRoutes.get("/domains", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const plan = await getPlanForUser(db, session.sub);
  if (plan !== "pro") return c.notFound();

  const query = parseDomainListQuery(new URL(c.req.url));
  const offset = (query.page - 1) * query.pageSize;
  const [page, unackCounts] = await Promise.all([
    listDomainsForUserPaged(db, {
      userId: session.sub,
      search: query.search || undefined,
      grade: query.grade ?? undefined,
      frequency: query.frequency ?? undefined,
      sort: query.sort,
      direction: query.direction,
      limit: query.pageSize,
      offset,
    }),
    countUnacknowledgedByDomain(db, session.sub),
  ]);

  const totalPages = Math.max(1, Math.ceil(page.total / query.pageSize));
  const currentPage = Math.min(query.page, totalPages);

  const html = renderDomainPanel({
    domains: page.rows.map((d) => ({
      domain: d.domain,
      grade: d.last_grade ?? "—",
      frequency: d.scan_frequency,
      lastScanned: d.last_scanned_at
        ? new Date(d.last_scanned_at * 1000).toLocaleDateString()
        : null,
      isFree: d.is_free === 1,
      unacknowledgedAlerts: unackCounts.get(d.id) ?? 0,
    })),
    controls: {
      search: query.search,
      grade: query.grade,
      frequency: query.frequency,
      sort: query.sort,
      direction: query.direction,
      page: currentPage,
      pageSize: query.pageSize,
      totalPages,
      total: page.total,
    },
  });

  // no-store keeps a CDN from caching one user's domain list and serving it
  // to another. The route is auth-required, but belt-and-suspenders.
  return c.html(html, 200, { "Cache-Control": "no-store" });
});

// Dashboard export — Pro only. Serves the user's full watchlist + most-recent
// scan result for every domain as either CSV or JSON, depending on ?format=.
// Strictly reads from the existing scan_history table — no fresh DNS lookups,
// so this is fast and never hits the rate limiter.
//
// Future work (out of scope): historical bulk-export (all scans over time),
// scheduled/emailed exports, PDF reports. See issue #194 for context.
dashboardRoutes.get("/export", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const plan = await getPlanForUser(db, session.sub);

  // Gate on Pro — but return a 402 upsell page, not 404, so the URL is stable
  // and can appear in docs/pricing without breaking for non-Pro visitors.
  if (plan !== "pro") {
    return c.html(renderExportUpsellPage({ email: session.email }), 402);
  }

  const rows = await getDashboardExportRows(db, session.sub);
  const formatParam = new URL(c.req.url).searchParams.get("format");
  const format = formatParam === "json" ? "json" : "csv";

  const dateStr = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

  if (format === "json") {
    const payload = rows.map((row) => {
      let protocols: Record<string, unknown> | null = null;
      if (row.protocol_results) {
        try {
          protocols = JSON.parse(row.protocol_results) as Record<
            string,
            unknown
          >;
        } catch {
          protocols = null;
        }
      }
      return {
        domain: row.domain,
        last_scanned_at: row.last_scanned_at,
        grade: row.last_grade,
        protocols,
      };
    });

    return new Response(JSON.stringify(payload, null, 2), {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Disposition": `attachment; filename="dmarcheck-dashboard-${dateStr}.json"`,
        "Cache-Control": "no-store",
      },
    });
  }

  // CSV: one row per domain with flat protocol-status columns
  const CSV_HEADERS = [
    "domain",
    "last_scanned_at",
    "grade",
    "score",
    "dmarc_status",
    "spf_status",
    "dkim_status",
    "bimi_status",
    "mta_sts_status",
    "mx_status",
  ];

  // Grade → numeric score (0–12), mirroring the GRADE_SCORE table in scans.ts
  const GRADE_SCORE: Record<string, number> = {
    S: 12,
    "A+": 11,
    A: 10,
    "A-": 9,
    "B+": 8,
    B: 7,
    "B-": 6,
    "C+": 5,
    C: 4,
    "C-": 3,
    "D+": 2,
    D: 1,
    "D-": 1,
    F: 0,
  };

  function extractStatus(
    protocols: Record<string, unknown> | null,
    key: string,
  ): string {
    const proto = protocols?.[key] as { status?: unknown } | undefined | null;
    const s = proto?.status;
    return typeof s === "string" ? s : "";
  }

  const csvRows: string[] = [];
  // BOM so Excel auto-detects UTF-8
  csvRows.push(`﻿${CSV_HEADERS.map(escapeCsvField).join(",")}`);

  for (const row of rows) {
    let protocols: Record<string, unknown> | null = null;
    if (row.protocol_results) {
      try {
        protocols = JSON.parse(row.protocol_results) as Record<string, unknown>;
      } catch {
        protocols = null;
      }
    }

    const lastScannedIso = row.last_scanned_at
      ? new Date(row.last_scanned_at * 1000).toISOString()
      : "";
    const grade = row.last_grade ?? "";
    const score = grade ? String(GRADE_SCORE[grade] ?? "") : "";

    const fields = [
      row.domain,
      lastScannedIso,
      grade,
      score,
      extractStatus(protocols, "dmarc"),
      extractStatus(protocols, "spf"),
      extractStatus(protocols, "dkim"),
      extractStatus(protocols, "bimi"),
      extractStatus(protocols, "mta_sts"),
      extractStatus(protocols, "mx"),
    ];
    csvRows.push(fields.map(escapeCsvField).join(","));
  }

  const csv = `${csvRows.join("\r\n")}\r\n`;

  return new Response(csv, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="dmarcheck-dashboard-${dateStr}.csv"`,
      "Cache-Control": "no-store",
    },
  });
});

// Bulk-acknowledge route — registered BEFORE /alerts/:id/acknowledge so Hono
// does not treat "acknowledge-all" as the :id param.
dashboardRoutes.post("/alerts/acknowledge-all", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  await acknowledgeAllAlertsForUser(db, session.sub);
  return c.redirect("/dashboard", 303);
});

dashboardRoutes.post("/alerts/:id/acknowledge", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const idParam = c.req.param("id");
  const alertId = Number.parseInt(idParam, 10);
  if (!Number.isFinite(alertId) || alertId <= 0) {
    return c.text("Invalid alert id", 400);
  }
  const ok = await acknowledgeAlert(db, session.sub, alertId);
  if (!ok) {
    return c.text("Alert not found", 404);
  }
  return c.redirect("/dashboard", 303);
});

// Add-domain form. Simple GET → form; POST → validate + insert.
// `/domain/add` is matched before `/domain/:domain` because Hono picks routes
// in registration order for literal-vs-param collisions.
dashboardRoutes.get("/domain/add", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const [plan, current] = await Promise.all([
    getPlanForUser(db, session.sub),
    countDomainsByUser(db, session.sub),
  ]);
  return c.html(
    renderAddDomainPage({
      email: session.email,
      error: null,
      usage: { plan, current, cap: watchlistCapForPlan(plan) },
    }),
  );
});

dashboardRoutes.post("/domain/add", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const body = await c.req.parseBody();
  const normalized = normalizeDomain(body.domain as string | undefined);
  const [plan, currentCount] = await Promise.all([
    getPlanForUser(db, session.sub),
    countDomainsByUser(db, session.sub),
  ]);
  const cap = watchlistCapForPlan(plan);
  const usage = { plan, current: currentCount, cap };
  if (!normalized) {
    return c.html(
      renderAddDomainPage({
        email: session.email,
        error: "Enter a valid domain (e.g. example.com).",
        usage,
      }),
      400,
    );
  }

  // Prevent duplicates per-user cleanly rather than surfacing the raw
  // UNIQUE(user_id, domain) constraint violation from D1. Re-submits
  // bypass the cap check below — they don't consume a new slot.
  const existing = await getDomainByUserAndName(db, session.sub, normalized);
  if (existing) {
    return c.redirect(
      `/dashboard/domain/${encodeURIComponent(normalized)}`,
      303,
    );
  }

  if (currentCount >= cap) {
    const overCap = currentCount > cap;
    const error =
      plan === "pro"
        ? overCap
          ? `Pro plan includes ${cap} domains and you already have ${currentCount} (grandfathered). Email support@dmarc.mx to add more.`
          : `You've reached the Pro plan limit of ${cap} domains. Email support@dmarc.mx if you need more.`
        : `Free plan limit reached (${cap} domains). Upgrade to Pro for up to ${PRO_WATCHLIST_CAP}.`;
    return c.html(
      renderAddDomainPage({ email: session.email, error, usage }),
      400,
    );
  }

  await createDomain(db, {
    userId: session.sub,
    domain: normalized,
    isFree: false,
  });
  return c.redirect(`/dashboard/domain/${encodeURIComponent(normalized)}`, 303);
});

// Bulk scan (Pro). The route is reachable for free users so the upgrade CTA
// has somewhere to land — same gate-the-payload-not-the-route pattern as the
// scan-history page from PR #153.
dashboardRoutes.get("/bulk", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const plan = await getPlanForUser(db, session.sub);
  return c.html(
    renderBulkScanPage({
      email: session.email,
      plan,
      submitted: null,
      results: null,
      error: null,
      totalCap: BULK_TOTAL_CAP,
      inBandCap: BULK_IN_BAND_CAP,
    }),
  );
});

dashboardRoutes.post("/bulk", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const plan = await getPlanForUser(db, session.sub);
  if (plan !== "pro") {
    return c.html(
      renderBulkScanPage({
        email: session.email,
        plan,
        submitted: null,
        results: null,
        error: "Bulk scan is a Pro feature.",
        totalCap: BULK_TOTAL_CAP,
        inBandCap: BULK_IN_BAND_CAP,
      }),
      402,
    );
  }
  const body = await c.req.parseBody();
  const raw = typeof body.domains === "string" ? body.domains : "";
  const lines = raw
    .split(/[\r\n,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const outcome = await processBulkScan({
    db,
    userId: session.sub,
    rawDomains: lines,
    watchlistCap: watchlistCapForPlan(plan),
    scoringConfig: parseScoringConfig(
      (c.env as { SCORING_CONFIG?: string }).SCORING_CONFIG,
    ),
  });
  if (isCapExceeded(outcome)) {
    return c.html(
      renderBulkScanPage({
        email: session.email,
        plan,
        submitted: lines.length,
        results: null,
        error: `Too many domains: ${outcome.submitted} submitted, max ${outcome.cap}.`,
        totalCap: BULK_TOTAL_CAP,
        inBandCap: BULK_IN_BAND_CAP,
      }),
      400,
    );
  }
  c.executionCtx.waitUntil(
    fireBulkScanWebhooks(db, session.sub, outcome.results, "dashboard"),
  );

  return c.html(
    renderBulkScanPage({
      email: session.email,
      plan,
      submitted: lines.length,
      results: outcome,
      error: null,
      totalCap: BULK_TOTAL_CAP,
      inBandCap: BULK_IN_BAND_CAP,
    }),
  );
});

// JSON sibling of /domain/:domain. Powers the dashboard drawer so a row
// click loads detail in-place without a full navigation. Same auth + same
// IDOR protection as the HTML route — getDomainByUserAndName only returns
// rows owned by session.sub. Registered BEFORE /domain/:domain so the
// `.json` suffix isn't swallowed by the greedy :domain match.
dashboardRoutes.get("/domain/:domain{.+\\.json}", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const raw = c.req.param("domain");
  const domainName = raw?.endsWith(".json") ? raw.slice(0, -5) : raw;
  if (!domainName) return c.json({ error: "Domain not found" }, 404);
  const domain = await getDomainByUserAndName(db, session.sub, domainName);
  if (!domain) return c.json({ error: "Domain not found" }, 404);
  const plan = await getPlanForUser(db, session.sub);
  const limit = plan === "pro" ? HISTORY_LIMIT_PRO : HISTORY_LIMIT_FREE;
  const [withStatus, rawRows] = await Promise.all([
    getScanHistoryWithProtocols(db, domain.id, limit),
    getScanHistory(db, domain.id, 2),
  ]);
  const detail = buildDrawerDetail(
    rawRows,
    parseScoringConfig((c.env as { SCORING_CONFIG?: string }).SCORING_CONFIG),
  );
  return c.json({
    domain: domain.domain,
    grade: domain.last_grade ?? "—",
    lastScannedAt: domain.last_scanned_at,
    scanFrequency: domain.scan_frequency,
    isFree: domain.is_free === 1,
    plan,
    protocols: detail.protocols,
    recommendations: detail.recommendations,
    diff: detail.diff,
    history: withStatus.map((row) => ({
      scannedAt: row.scannedAt,
      grade: row.grade,
      protocols: row.protocols,
    })),
  });
});

// Domain detail
dashboardRoutes.get("/domain/:domain", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const domainName = c.req.param("domain");
  const domain = await getDomainByUserAndName(db, session.sub, domainName);
  if (!domain) {
    return c.text("Domain not found", 404);
  }
  const history = await db
    .prepare(
      "SELECT grade, scanned_at FROM scan_history WHERE domain_id = ? ORDER BY scanned_at DESC LIMIT 12",
    )
    .bind(domain.id)
    .all<{ grade: string; scanned_at: number }>();
  return c.html(
    renderDomainDetailPage({
      email: session.email,
      domain: domain.domain,
      grade: domain.last_grade ?? "—",
      lastScanned: domain.last_scanned_at
        ? new Date(domain.last_scanned_at * 1000).toLocaleDateString()
        : null,
      isFree: domain.is_free === 1,
      scanFrequency: domain.scan_frequency,
      scanHistory: history.results.map((r) => ({
        date: new Date(r.scanned_at * 1000).toLocaleDateString(),
        grade: r.grade,
      })),
    }),
  );
});

// Full scan history for a domain. Pro users see up to 30 entries with a
// sparkline + protocol-drift matrix; free users get a 5-entry teaser + an
// upgrade CTA. Route is not hidden for free users — we gate the payload, not
// the URL, so the upgrade prompt has somewhere to land.
dashboardRoutes.get("/domain/:domain/history", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const domainName = c.req.param("domain");
  const domain = await getDomainByUserAndName(db, session.sub, domainName);
  if (!domain) {
    return c.text("Domain not found", 404);
  }
  const plan = await getPlanForUser(db, session.sub);
  const limit = plan === "pro" ? HISTORY_LIMIT_PRO : HISTORY_LIMIT_FREE;
  const rows = await getScanHistoryWithProtocols(db, domain.id, limit);
  return c.html(
    renderDomainHistoryPage({
      email: session.email,
      domain: domain.domain,
      plan,
      history: rows.map((row) => ({
        date: new Date(row.scannedAt * 1000).toLocaleDateString(),
        scannedAt: row.scannedAt,
        grade: row.grade,
        protocols: row.protocols,
      })),
    }),
  );
});

// Manual scan trigger — runs the orchestrator for a user-owned domain and
// persists the result to scan_history + domains.last_*. Rate-limiting comes
// from the session cookie gating this path (plus D1 write volume per user).
dashboardRoutes.post("/domain/:domain/scan", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const domainName = c.req.param("domain");

  const owned = await getDomainByUserAndName(db, session.sub, domainName);
  if (!owned) {
    return c.text("Domain not found", 404);
  }

  const result = await scan(
    owned.domain,
    [],
    parseScoringConfig((c.env as { SCORING_CONFIG?: string }).SCORING_CONFIG),
  );
  await recordScan(db, {
    domainId: owned.id,
    grade: result.grade,
    scoreFactors: result.breakdown.factors,
    protocolResults: result.protocols,
  });

  c.executionCtx.waitUntil(
    fireScanCompletedWebhook(db, session.sub, {
      domain: owned.domain,
      grade: result.grade,
      scanId: owned.id,
      trigger: "dashboard",
    }),
  );

  return c.redirect(`/dashboard/domain/${encodeURIComponent(domainName)}`, 303);
});

// Delete monitored domain. POST-only (no idempotent DELETE since HTML forms
// can't send DELETE without JS). Ownership check is inherent: the SQL WHERE
// clause in deleteDomain keys on user_id, so one user can't delete another's
// row even if they guess the domain name.
dashboardRoutes.post("/domain/:domain/delete", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const domainName = c.req.param("domain");
  await deleteDomain(db, session.sub, domainName);
  return c.redirect("/dashboard", 303);
});

// Settings page
dashboardRoutes.get("/settings", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const user = await getUserById(db, session.sub);
  if (!user) {
    return c.redirect("/auth/logout");
  }
  const webhook = await db
    .prepare("SELECT url, format FROM webhooks WHERE user_id = ?")
    .bind(session.sub)
    .first<{ url: string; format: WebhookFormat }>();
  const plan = await getPlanForUser(db, session.sub);
  const env = c.env as { STRIPE_SECRET_KEY?: string };
  const deliveries = await getRecentDeliveriesForUser(db, session.sub, 10);
  const testParam = c.req.query("test");
  let testFlash: {
    ok: boolean;
    statusCode: number | null;
    error: string | null;
  } | null = null;
  if (testParam === "ok" || testParam === "fail") {
    // Latest delivery row for this user is always the test we just ran (POST
    // /webhook/test always inserts one). Pull it back so the flash carries the
    // real status code without us needing to round-trip query params.
    const latest = deliveries[0] ?? null;
    if (latest) {
      testFlash = {
        ok: latest.ok === 1,
        statusCode: latest.status_code,
        error: latest.error,
      };
    }
  }
  return c.html(
    renderSettingsPage({
      email: user.email,
      webhookUrl: webhook?.url ?? null,
      webhookFormat: webhook?.format ?? "raw",
      plan,
      billingEnabled: Boolean(env.STRIPE_SECRET_KEY),
      emailAlertsEnabled: user.email_alerts_enabled === 1,
      notifyOnChangeOnly: user.notify_on_change_only === 1,
      showRetirementBanner: user.api_key_retirement_acknowledged_at === null,
      recentDeliveries: deliveries.map((row) => ({
        eventType: row.event_type,
        ok: row.ok === 1,
        statusCode: row.status_code,
        error: row.error,
        attemptedAt: row.attempted_at,
      })),
      testFlash,
    }),
  );
});

// Toggle email alert preference. Presence of a "enabled" form field means on,
// absence means off (standard checkbox semantics from HTML forms).
dashboardRoutes.post("/settings/email-alerts", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const body = await c.req.parseBody();
  const enabled = body.enabled === "on" || body.enabled === "1";
  await setEmailAlertsEnabled(db, session.sub, enabled);
  return c.redirect("/dashboard/settings");
});

// Toggle notify-on-change-only preference. Same checkbox semantics as email-alerts.
dashboardRoutes.post("/settings/notify-on-change", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const body = await c.req.parseBody();
  const enabled = body.enabled === "on" || body.enabled === "1";
  await setNotifyOnChangeOnly(db, session.sub, enabled);
  return c.redirect("/dashboard/settings");
});

// API keys: list / generate / revoke. The cleartext `POST /settings/api-key`
// handler from Phase 1 is intentionally gone — keys are now hashed server-side
// and the raw value is surfaced only at generation time on this page.
dashboardRoutes.get("/settings/api-keys", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const user = await getUserById(db, session.sub);
  if (!user) {
    return c.redirect("/auth/logout");
  }
  const showRetirementBanner = user.api_key_retirement_acknowledged_at === null;
  // First visit dismisses the banner — the user has now seen the explanation
  // and can generate a replacement on this same page.
  if (showRetirementBanner) {
    c.executionCtx.waitUntil(
      acknowledgeApiKeyRetirement(db, session.sub).catch(() => {}),
    );
  }
  const rows = await listApiKeysByUser(db, session.sub);
  const justCreated =
    c.req.query("created") === "1" ? (c.req.query("raw") ?? null) : null;
  return c.html(
    renderApiKeysPage({
      email: user.email,
      keys: rows.map(toApiKeyListEntry),
      justCreated,
      showRetirementBanner,
    }),
  );
});

dashboardRoutes.post("/settings/api-keys/generate", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const body = await c.req.parseBody();
  const nameRaw =
    typeof body.name === "string" ? body.name.trim().slice(0, 60) : "";
  const name = nameRaw.length > 0 ? nameRaw : null;

  const generated = await generateApiKey();
  const id = crypto.randomUUID();
  await createApiKey(db, {
    id,
    userId: session.sub,
    name,
    prefix: generated.prefix,
    hash: generated.hash,
  });

  // Shuttle the raw value through a redirect URL so the GET renders it once.
  // Anyone capable of reading the user's browser history already owns the key,
  // so this is no weaker than rendering it inline after the POST.
  const params = new URLSearchParams({
    created: "1",
    raw: generated.raw,
  });
  return c.redirect(`/dashboard/settings/api-keys?${params.toString()}`, 303);
});

dashboardRoutes.post("/settings/api-keys/revoke", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const body = await c.req.parseBody();
  const id = typeof body.id === "string" ? body.id : null;
  if (id) {
    await revokeApiKey(db, id, session.sub);
  }
  return c.redirect("/dashboard/settings/api-keys", 303);
});

// Fires a synthetic `webhook.test` event through the dispatcher so the user
// can verify their receiver + signing without waiting for a real scan. Awaits
// the result (rather than waitUntil) so we can flash the outcome on redirect.
dashboardRoutes.post("/settings/webhook/test", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const result = await dispatchWebhook(db, session.sub, {
    type: "webhook.test",
    data: { message: "Hello from dmarcheck" },
  });
  if (!result) {
    return c.redirect("/dashboard/settings");
  }
  return c.redirect(
    `/dashboard/settings?test=${result.ok ? "ok" : "fail"}`,
    303,
  );
});

// Save webhook URL + format
dashboardRoutes.post("/settings/webhook", async (c) => {
  const session = c.get("user" as never) as SessionPayload;
  const db = (c.env as { DB: D1Database }).DB;
  const body = await c.req.parseBody();
  const url = body.webhookUrl as string;

  // Validate URL: must be a public https host. The host guard blocks SSRF to
  // internal/reserved addresses (loopback, link-local/metadata, RFC1918, ULA)
  // and internal-only names. The dispatcher re-checks at fetch time and uses
  // redirect: "manual" so a 3xx can't pivot past this.
  if (!isAllowedWebhookUrl(url)) {
    return c.redirect("/dashboard/settings");
  }

  // Missing `format` (older submissions) means the legacy signed-JSON path.
  // Unknown values are rejected with a no-save redirect to match the URL
  // validation above — silent coercion would hide typos in the receiver UI.
  const rawFormat = body.format;
  const formatCandidate =
    typeof rawFormat === "string" && rawFormat !== "" ? rawFormat : "raw";
  if (!isWebhookFormat(formatCandidate)) {
    return c.redirect("/dashboard/settings");
  }
  const format: WebhookFormat = formatCandidate;

  const existing = await db
    .prepare("SELECT id FROM webhooks WHERE user_id = ?")
    .bind(session.sub)
    .first<{ id: number }>();
  if (existing) {
    await db
      .prepare("UPDATE webhooks SET url = ?, format = ? WHERE user_id = ?")
      .bind(url, format, session.sub)
      .run();
  } else {
    const secret = crypto.randomUUID();
    await db
      .prepare(
        "INSERT INTO webhooks (user_id, url, secret, format) VALUES (?, ?, ?, ?)",
      )
      .bind(session.sub, url, secret, format)
      .run();
  }
  return c.redirect("/dashboard/settings");
});
