import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";
import { createSessionToken } from "../src/auth/session.js";
import { dashboardRoutes } from "../src/dashboard/routes.js";

vi.mock("../src/orchestrator.js", () => ({
  scan: vi.fn(async (domain: string) => ({
    domain,
    timestamp: "2026-04-19T00:00:00.000Z",
    grade: "B",
    breakdown: {
      grade: "B",
      tier: "B",
      tierReason: "test",
      modifier: 0,
      modifierLabel: "",
      factors: [{ name: "dmarc", status: "pass", weight: 1 }],
      recommendations: [],
      protocolSummaries: {},
    },
    summary: {
      mx_records: 0,
      mx_providers: [],
      dmarc_policy: "none",
    },
    protocols: {
      mx: { status: "info" },
      dmarc: { status: "pass" },
      spf: { status: "pass" },
      dkim: { status: "pass" },
      bimi: { status: "pass" },
      mta_sts: { status: "pass" },
    },
  })),
}));

const SECRET = "test-session-secret";

// Mirrors the dynamic WHERE clause emitted by listDomainsForUserPaged. Used by
// both the SELECT * paged listing and the SELECT COUNT(*) total query, so the
// mock keeps the two consistent.
function filterPagedDomains(
  sql: string,
  bindings: unknown[],
  rows: Array<{
    id: number;
    user_id: string;
    domain: string;
    is_free: number;
    scan_frequency: string;
    last_scanned_at: number | null;
    last_grade: string | null;
    created_at: number;
  }>,
) {
  let cursor = 0;
  const userId = bindings[cursor++] as string;
  let out = rows.filter((r) => r.user_id === userId);
  if (/LOWER\(domain\) LIKE \?/i.test(sql)) {
    const like = bindings[cursor++] as string;
    const inner = like.slice(1, -1).replace(/\\([\\%_])/g, "$1");
    out = out.filter((r) => r.domain.toLowerCase().includes(inner));
  }
  if (/last_grade IS NULL/i.test(sql)) {
    out = out.filter((r) => r.last_grade === null);
  } else if (/last_grade = \?/i.test(sql)) {
    const grade = bindings[cursor++] as string;
    out = out.filter((r) => r.last_grade === grade);
  }
  if (/scan_frequency = \?/i.test(sql)) {
    const freq = bindings[cursor++] as string;
    out = out.filter((r) => r.scan_frequency === freq);
  }
  // Default sort matches the route's default (sort=domain asc).
  return [...out].sort((a, b) => a.domain.localeCompare(b.domain));
}

// Minimal D1-like mock that routes calls to in-memory data
function createMockDB(data: {
  domains?: Array<{
    id: number;
    user_id: string;
    domain: string;
    is_free: number;
    scan_frequency: string;
    last_scanned_at: number | null;
    last_grade: string | null;
    created_at: number;
  }>;
  users?: Array<{
    id: string;
    email: string;
    email_domain: string;
    stripe_customer_id: string | null;
    email_alerts_enabled: number;
    api_key_retirement_acknowledged_at: number | null;
    created_at: number;
  }>;
  scanHistory?: Array<{
    grade: string;
    scanned_at: number;
    protocol_results?: string | null;
    score_factors?: string | null;
    id?: number;
    domain_id?: number;
  }>;
  subscriptions?: Array<{
    user_id: string;
    status: string;
  }>;
  webhooks?: Array<{
    id: number;
    user_id: string;
    url: string;
    secret: string;
    format?: "raw" | "slack" | "google_chat";
  }>;
  apiKeys?: Array<{
    id: string;
    user_id: string;
    name: string | null;
    prefix: string;
    hash: string;
    created_at: number;
    last_used_at: number | null;
    revoked_at: number | null;
  }>;
  alerts?: Array<{
    id: number;
    domain_id: number;
    alert_type: string;
    previous_value: string | null;
    new_value: string | null;
    notified_via: string | null;
    acknowledged_at: number | null;
    created_at: number;
  }>;
  writes?: Array<{ sql: string; bindings: unknown[] }>;
}) {
  const domains = data.domains ?? [];
  const users = data.users ?? [];
  const scanHistory = data.scanHistory ?? [];
  const webhooks = data.webhooks ?? [];
  const apiKeys = data.apiKeys ?? [];
  const subscriptions = data.subscriptions ?? [];
  const alerts = data.alerts ?? [];
  const writes = data.writes;

  const makeStatement = (sql: string, bindings: unknown[]) => ({
    bind: (...args: unknown[]) => makeStatement(sql, args),
    first: async <T>() => {
      if (sql.includes("SELECT * FROM users WHERE id")) {
        return (users.find((u) => u.id === bindings[0]) ?? null) as T | null;
      }
      if (sql.includes("SELECT * FROM users WHERE email")) {
        return (users.find((u) => u.email === bindings[0]) ?? null) as T | null;
      }
      if (sql.includes("SELECT * FROM domains WHERE user_id = ? AND domain")) {
        return (domains.find(
          (d) => d.user_id === bindings[0] && d.domain === bindings[1],
        ) ?? null) as T | null;
      }
      if (sql.includes("SELECT url, format FROM webhooks WHERE user_id")) {
        const wh = webhooks.find((w) => w.user_id === bindings[0]);
        return (
          wh ? { url: wh.url, format: wh.format ?? "raw" } : null
        ) as T | null;
      }
      if (sql.includes("SELECT id FROM webhooks WHERE user_id")) {
        const wh = webhooks.find((w) => w.user_id === bindings[0]);
        return (wh ? { id: wh.id } : null) as T | null;
      }
      if (sql.includes("SELECT status FROM subscriptions")) {
        const sub = subscriptions.find((s) => s.user_id === bindings[0]);
        return (sub ? { status: sub.status } : null) as T | null;
      }
      if (/^\s*SELECT COUNT\(\*\) AS n FROM domains/i.test(sql)) {
        const rows = filterPagedDomains(sql, bindings, domains);
        return { n: rows.length } as T;
      }
      // getWorstGradedDomainForUser: lowest-graded domain across the watchlist,
      // tie-broken alphabetically, ungraded excluded, S treated as best.
      if (
        /last_grade IS NOT NULL/i.test(sql) &&
        /ORDER BY/i.test(sql) &&
        /LIMIT 1/i.test(sql)
      ) {
        const [userId] = bindings as [string];
        const score: Record<string, number> = {
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
        const graded = domains.filter(
          (d) => d.user_id === userId && d.last_grade !== null,
        );
        if (graded.length === 0) return null;
        graded.sort((a, b) => {
          const ra = score[a.last_grade as string] ?? 0;
          const rb = score[b.last_grade as string] ?? 0;
          return ra !== rb ? ra - rb : a.domain.localeCompare(b.domain);
        });
        return { domain: graded[0].domain, grade: graded[0].last_grade } as T;
      }
      return null as T | null;
    },
    all: async <T>() => {
      // Dashboard export query — correlated subquery form emitted by
      // getDashboardExportRows. Matches before the generic domains handler.
      if (sql.includes("FROM domains d") && sql.includes("d.user_id = ?")) {
        const userId = bindings[0] as string;
        const userDomains = [...domains]
          .filter((d) => d.user_id === userId)
          .sort((a, b) => a.domain.localeCompare(b.domain));
        // Build a lookup from domain_id → most-recent protocol_results
        const latestProtocol = new Map<number, string | null>();
        for (const d of userDomains) {
          const latest = [...scanHistory]
            .filter((sh) => (sh.domain_id ?? 1) === d.id)
            .sort((a, b) => b.scanned_at - a.scanned_at)[0];
          latestProtocol.set(d.id, latest?.protocol_results ?? null);
        }
        return {
          results: userDomains.map((d) => ({
            domain: d.domain,
            last_scanned_at: d.last_scanned_at,
            last_grade: d.last_grade,
            protocol_results: latestProtocol.get(d.id) ?? null,
          })) as T[],
        };
      }
      if (sql.includes("SELECT * FROM domains WHERE user_id")) {
        // Paged listing path (used by Pro dashboard) — applies search / grade
        // / frequency filters + LIMIT/OFFSET. The simpler unpaged select used
        // by the free path still falls through here with no LIMIT/OFFSET, in
        // which case the slice is a no-op.
        const filtered = filterPagedDomains(sql, bindings, domains);
        if (/LIMIT \? OFFSET \?/i.test(sql)) {
          const limit = bindings[bindings.length - 2] as number;
          const offset = bindings[bindings.length - 1] as number;
          return { results: filtered.slice(offset, offset + limit) as T[] };
        }
        return { results: filtered as T[] };
      }
      if (sql.includes("SELECT grade, scanned_at FROM scan_history")) {
        return { results: scanHistory as T[] };
      }
      if (sql.includes("SELECT * FROM scan_history")) {
        const [, limit] = bindings as [number, number];
        const sorted = [...scanHistory].sort(
          (a, b) => b.scanned_at - a.scanned_at,
        );
        return {
          results: sorted.slice(0, limit).map((r, i) => ({
            id: r.id ?? i + 1,
            domain_id: r.domain_id ?? 1,
            grade: r.grade,
            score_factors: r.score_factors ?? null,
            protocol_results: r.protocol_results ?? null,
            scanned_at: r.scanned_at,
          })) as T[],
        };
      }
      if (sql.includes("SELECT * FROM api_keys WHERE user_id")) {
        return {
          results: apiKeys.filter((k) => k.user_id === bindings[0]) as T[],
        };
      }
      if (
        /acknowledged_at IS NULL[\s\S]*ORDER BY a\.created_at DESC/i.test(sql)
      ) {
        const [userId, limit] = bindings as [string, number];
        const ownedDomainIds = new Set(
          domains.filter((d) => d.user_id === userId).map((d) => d.id),
        );
        const rows = alerts
          .filter(
            (a) =>
              a.acknowledged_at === null && ownedDomainIds.has(a.domain_id),
          )
          .sort((a, b) => b.created_at - a.created_at)
          .slice(0, limit)
          .map((a) => ({
            ...a,
            domain: domains.find((d) => d.id === a.domain_id)?.domain ?? "",
          }));
        return { results: rows as T[] };
      }
      if (/GROUP BY a\.domain_id/i.test(sql)) {
        const [userId] = bindings as [string];
        const ownedDomainIds = new Set(
          domains.filter((d) => d.user_id === userId).map((d) => d.id),
        );
        const counts = new Map<number, number>();
        for (const a of alerts) {
          if (a.acknowledged_at !== null) continue;
          if (!ownedDomainIds.has(a.domain_id)) continue;
          counts.set(a.domain_id, (counts.get(a.domain_id) ?? 0) + 1);
        }
        const rows = [...counts.entries()].map(([domain_id, count]) => ({
          domain_id,
          count,
        }));
        return { results: rows as T[] };
      }
      // getGradeDistributionForUser: GROUP BY last_grade counts for the whole
      // watchlist, scoped to the user.
      if (/GROUP BY last_grade/i.test(sql)) {
        const [userId] = bindings as [string];
        const counts = new Map<string | null, number>();
        for (const d of domains) {
          if (d.user_id !== userId) continue;
          counts.set(d.last_grade, (counts.get(d.last_grade) ?? 0) + 1);
        }
        const rows = [...counts.entries()].map(([grade, count]) => ({
          grade,
          count,
        }));
        return { results: rows as T[] };
      }
      return { results: [] as T[] };
    },
    run: async () => {
      writes?.push({ sql, bindings });
      // Phase 4b — IDOR-scoped acknowledge UPDATE that the route's POST flow
      // sends. The mock applies it only when the alert's owning domain
      // belongs to the supplied user_id, mirroring the SQL.
      if (/^\s*UPDATE alerts\s+SET acknowledged_at/i.test(sql)) {
        const [now, alertId, userId] = bindings as [number, number, string];
        const alert = alerts.find((a) => a.id === alertId);
        if (!alert || alert.acknowledged_at !== null) {
          return { success: true, meta: { changes: 0 } };
        }
        const owner = domains.find((d) => d.id === alert.domain_id);
        if (!owner || owner.user_id !== userId) {
          return { success: true, meta: { changes: 0 } };
        }
        alert.acknowledged_at = now;
        return { success: true, meta: { changes: 1 } };
      }
      // Phase 4c — apply INSERT INTO domains so processBulkScan's "create
      // then re-fetch" pattern (avoids relying on last_row_id) finds the new
      // row when it does the SELECT lookup right after.
      if (/^INSERT INTO domains/i.test(sql)) {
        const [userId, domain, isFree, frequency] = bindings as [
          string,
          string,
          number,
          string,
        ];
        domains.push({
          id:
            domains.length > 0 ? Math.max(...domains.map((d) => d.id)) + 1 : 1,
          user_id: userId,
          domain,
          is_free: isFree,
          scan_frequency: frequency,
          last_scanned_at: null,
          last_grade: null,
          created_at: 1700000000,
        });
      }
      return { success: true, meta: { changes: 1 } };
    },
  });

  return {
    prepare: (sql: string) => makeStatement(sql, []),
    batch: async (
      stmts: Array<{ run: () => Promise<{ success: boolean }> }>,
    ) => {
      const out = [];
      for (const stmt of stmts) {
        out.push(await stmt.run());
      }
      return out;
    },
  };
}

function createTestApp(db: ReturnType<typeof createMockDB>) {
  const app = new Hono();
  app.route("/dashboard", dashboardRoutes);
  // Inject the mock DB into requests via env
  return {
    request: (url: string, init?: RequestInit) =>
      app.request(
        url,
        init,
        { SESSION_SECRET: SECRET, DB: db },
        // Stub ExecutionContext so handlers that fire-and-forget writes via
        // `c.executionCtx.waitUntil(...)` don't blow up in tests.
        {
          waitUntil: () => {},
          passThroughOnException: () => {},
        } as ExecutionContext,
      ),
  };
}

async function makeSessionCookie(sub: string, email: string): Promise<string> {
  const token = await createSessionToken({ sub, email }, SECRET);
  return `session=${token}`;
}

describe("dashboard/routes", () => {
  describe("GET /dashboard (domain list)", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard");
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("returns 200 and contains Dashboard with valid session", async () => {
      const db = createMockDB({
        users: [
          {
            id: "user_1",
            email: "alice@example.com",
            email_domain: "example.com",
            stripe_customer_id: null,
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 1,
            scan_frequency: "monthly",
            last_scanned_at: null,
            last_grade: null,
            created_at: 1700000000,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("Your Domains");
    });

    it("shows domain names in the list", async () => {
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 1,
            scan_frequency: "monthly",
            last_scanned_at: null,
            last_grade: "A",
            created_at: 1700000000,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      expect(body).toContain("example.com");
    });

    it("shows empty state when user has no domains", async () => {
      const db = createMockDB({ domains: [] });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      expect(body).toContain("No domains");
    });

    it("does not render the search toolbar for free-plan users", async () => {
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 1,
            scan_frequency: "monthly",
            last_scanned_at: null,
            last_grade: "A",
            created_at: 1700000000,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      expect(body).not.toContain('<form class="domain-toolbar"');
    });

    it("renders search toolbar + pagination for Pro-plan users", async () => {
      const proDomains = Array.from({ length: 30 }, (_, i) => ({
        id: i + 1,
        user_id: "user_pro",
        domain: `domain-${String(i + 1).padStart(2, "0")}.com`,
        is_free: 0,
        scan_frequency: "weekly",
        last_scanned_at: 1700000000 + i,
        last_grade: i % 3 === 0 ? "A" : i % 3 === 1 ? "B" : "F",
        created_at: 1700000000 + i,
      }));
      const db = createMockDB({
        users: [
          {
            id: "user_pro",
            email: "pro@example.com",
            email_domain: "example.com",
            stripe_customer_id: "cus_x",
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
        subscriptions: [{ user_id: "user_pro", status: "active" }],
        domains: proDomains,
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_pro", "pro@example.com");
      const res = await app.request("/dashboard", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain('<form class="domain-toolbar"');
      // Default page size is 25, so 30 domains span two pages.
      expect(body).toContain("Showing 1–25 of 30");
      expect(body).toContain('rel="next"');
      // First-page rows, last-page rows excluded.
      expect(body).toContain("domain-01.com");
      expect(body).toContain("domain-25.com");
      expect(body).not.toContain("domain-26.com");
    });

    it("computes the scoreboard from the whole watchlist, not the visible page", async () => {
      // 30 domains: page 1 (domain-01..25, sorted asc) is all healthy A's, and
      // every failure lives on page 2 (domain-26..30 = F). If the scoreboard
      // read only the visible page it would show 0 failures and party-hat;
      // portfolio-wide it must surface 5 failures and triage the worst.
      const proDomains = Array.from({ length: 30 }, (_, i) => ({
        id: i + 1,
        user_id: "user_pro",
        domain: `domain-${String(i + 1).padStart(2, "0")}.com`,
        is_free: 0,
        scan_frequency: "weekly" as const,
        last_scanned_at: 1700000000 + i,
        last_grade: i < 25 ? "A" : "F",
        created_at: 1700000000 + i,
      }));
      const db = createMockDB({
        users: [
          {
            id: "user_pro",
            email: "pro@example.com",
            email_domain: "example.com",
            stripe_customer_id: "cus_x",
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
        subscriptions: [{ user_id: "user_pro", status: "active" }],
        domains: proDomains,
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_pro", "pro@example.com");
      const res = await app.request("/dashboard", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      // The headline symptom: the "Domains" stat card shows the full watchlist
      // size (30), not the visible page size (25). The stat-card-value anchor
      // avoids colliding with the "Showing 1–25 of 30" pagination string.
      expect(body).toMatch(/stat-card-value">30</);
      // On-fire banner + hero reflect all 5 portfolio failures.
      expect(body).toContain("5 domains failing");
      expect(body).toContain("5 domains are failing");
      // The worst domain (page 2, not in the visible table) is triaged.
      expect(body).toContain("domain-26.com");
      // A failing portfolio must not celebrate just because page 1 is green.
      // Anchor on the rendered creature element so the CSS rule of the same
      // name (always inlined) doesn't trip the assertion.
      expect(body).not.toMatch(/<div class="creature[^"]*creature-partying/);
    });

    it("names the top failure among failing domains, not the watchlist-wide protocol tally", async () => {
      // Regression: MTA-STS reports status "fail" on most healthy domains too
      // (no _mta-sts record), so a watchlist-wide tally produced banners like
      // "MTA-STS is the top issue — 342 of 199 failing domains". The numerator
      // must come from the same failing-grade bucket as the denominator.
      const proDomains = Array.from({ length: 30 }, (_, i) => ({
        id: i + 1,
        user_id: "user_pro",
        domain: `domain-${String(i + 1).padStart(2, "0")}.com`,
        is_free: 0,
        scan_frequency: "weekly" as const,
        last_scanned_at: 1700000000 + i,
        last_grade: i < 25 ? "A" : "F",
        created_at: 1700000000 + i,
      }));
      // Healthy domains fail MTA-STS only; F domains fail DMARC (and most
      // also fail MTA-STS, like real portfolios).
      const scanHistory = proDomains.map((d, i) => ({
        id: i + 1,
        domain_id: d.id,
        grade: d.last_grade,
        scanned_at: 1700000000 + i,
        score_factors: null,
        protocol_results: JSON.stringify(
          i < 25
            ? { dmarc: { status: "pass" }, mta_sts: { status: "fail" } }
            : {
                dmarc: { status: "fail" },
                mta_sts: { status: i < 29 ? "fail" : "pass" },
              },
        ),
      }));
      const db = createMockDB({
        users: [
          {
            id: "user_pro",
            email: "pro@example.com",
            email_domain: "example.com",
            stripe_customer_id: "cus_x",
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
        subscriptions: [{ user_id: "user_pro", status: "active" }],
        domains: proDomains,
        scanHistory,
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_pro", "pro@example.com");
      const res = await app.request("/dashboard", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      // DMARC fails on all 5 failing domains; MTA-STS only on 4 of them. The
      // 25 healthy MTA-STS failures must not be counted.
      expect(body).toContain("<strong>DMARC</strong> is the top issue");
      expect(body).toContain("5 of 5 failing domains");
      expect(body).not.toContain("MTA-STS</strong> is the top issue");
      expect(body).not.toContain("29 of 5");
    });

    it("filters by search query for Pro users", async () => {
      const db = createMockDB({
        users: [
          {
            id: "user_pro",
            email: "pro@example.com",
            email_domain: "example.com",
            stripe_customer_id: "cus_x",
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
        subscriptions: [{ user_id: "user_pro", status: "active" }],
        domains: [
          {
            id: 1,
            user_id: "user_pro",
            domain: "alpha.example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: "A",
            created_at: 1700000000,
          },
          {
            id: 2,
            user_id: "user_pro",
            domain: "beta.io",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: "B",
            created_at: 1700000001,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_pro", "pro@example.com");
      const res = await app.request("/dashboard?q=alpha", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      expect(body).toContain("alpha.example.com");
      expect(body).not.toContain("beta.io");
      expect(body).toContain("Showing 1–1 of 1");
    });

    it("renders 'no matches' empty state when filters yield zero rows", async () => {
      const db = createMockDB({
        users: [
          {
            id: "user_pro",
            email: "pro@example.com",
            email_domain: "example.com",
            stripe_customer_id: "cus_x",
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
        subscriptions: [{ user_id: "user_pro", status: "active" }],
        domains: [
          {
            id: 1,
            user_id: "user_pro",
            domain: "alpha.example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: "A",
            created_at: 1700000000,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_pro", "pro@example.com");
      const res = await app.request("/dashboard?q=zzz", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      expect(body).toContain("No domains match these filters");
    });
  });

  describe("GET /dashboard/domains (live-search fragment)", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/domains");
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("returns 404 for free-plan users (Pro-only endpoint)", async () => {
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 1,
            scan_frequency: "monthly",
            last_scanned_at: null,
            last_grade: null,
            created_at: 1700000000,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domains", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(404);
    });

    it("returns the panel fragment (no <html> shell) for Pro users", async () => {
      const db = createMockDB({
        users: [
          {
            id: "user_pro",
            email: "pro@example.com",
            email_domain: "example.com",
            stripe_customer_id: "cus_x",
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
        subscriptions: [{ user_id: "user_pro", status: "active" }],
        domains: [
          {
            id: 1,
            user_id: "user_pro",
            domain: "alpha.example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: "A",
            created_at: 1700000000,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_pro", "pro@example.com");
      const res = await app.request("/dashboard/domains", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      const body = await res.text();
      // Fragment, not a full page.
      expect(body).not.toContain("<!DOCTYPE");
      expect(body).not.toContain("<html");
      expect(body).not.toContain("dashboard-nav");
      // But it does include the live-search-aware wrapper + toolbar + table.
      expect(body).toContain('id="domain-panel"');
      expect(body).toContain('data-pro="1"');
      expect(body).toContain('<form class="domain-toolbar"');
      expect(body).toContain("alpha.example.com");
    });

    it("honors the q filter so the fragment matches the full-page result", async () => {
      const db = createMockDB({
        users: [
          {
            id: "user_pro",
            email: "pro@example.com",
            email_domain: "example.com",
            stripe_customer_id: "cus_x",
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
        subscriptions: [{ user_id: "user_pro", status: "active" }],
        domains: [
          {
            id: 1,
            user_id: "user_pro",
            domain: "alpha.example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: "A",
            created_at: 1700000000,
          },
          {
            id: 2,
            user_id: "user_pro",
            domain: "beta.io",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: "B",
            created_at: 1700000001,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_pro", "pro@example.com");
      const res = await app.request("/dashboard/domains?q=alpha", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("alpha.example.com");
      expect(body).not.toContain("beta.io");
      expect(body).toContain("Showing 1–1 of 1");
    });
  });

  describe("GET /dashboard/domain/:domain", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/domain/example.com");
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("returns 404 when domain does not belong to the user", async () => {
      const db = createMockDB({ domains: [] });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/notmine.com", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(404);
    });

    it("returns 200 and contains domain name with valid session", async () => {
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: 1700000000,
            last_grade: "B",
            created_at: 1700000000,
          },
        ],
        scanHistory: [{ grade: "B", scanned_at: 1700000000 }],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/example.com", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("example.com");
    });

    it("shows grade history section", async () => {
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: null,
            created_at: 1700000000,
          },
        ],
        scanHistory: [],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/example.com", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      expect(body).toContain("Grade History");
    });
  });

  describe("GET /dashboard/domain/:domain.json (drawer endpoint)", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/domain/example.com.json");
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("returns 404 JSON when the domain doesn't belong to the user", async () => {
      const db = createMockDB({ domains: [] });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/notmine.com.json", {
        headers: { Cookie: cookie, Accept: "application/json" },
      });
      expect(res.status).toBe(404);
      const body = (await res.json()) as { error?: string };
      expect(body.error).toBe("Domain not found");
    });

    it("returns the drawer payload for an owned domain", async () => {
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: 1700000000,
            last_grade: "B",
            created_at: 1700000000,
          },
        ],
        scanHistory: [{ grade: "B", scanned_at: 1700000000 }],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/example.com.json", {
        headers: { Cookie: cookie, Accept: "application/json" },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("application/json");
      const body = (await res.json()) as {
        domain: string;
        grade: string;
        lastScannedAt: number | null;
        scanFrequency: string;
        history: { scannedAt: number; grade: string }[];
      };
      expect(body.domain).toBe("example.com");
      expect(body.grade).toBe("B");
      expect(body.scanFrequency).toBe("weekly");
      expect(body.lastScannedAt).toBe(1700000000);
      expect(body.history).toHaveLength(1);
      expect(body.history[0].grade).toBe("B");
    });

    it("surfaces enriched protocol summaries from the latest scan blob", async () => {
      const protocolBlob = JSON.stringify({
        mx: { status: "info", records: [], providers: [], validations: [] },
        dmarc: {
          status: "pass",
          record: "v=DMARC1; p=reject; rua=mailto:rua@example.com",
          tags: { v: "DMARC1", p: "reject", rua: "mailto:rua@example.com" },
          validations: [],
        },
        spf: {
          status: "pass",
          record: "v=spf1 include:_spf.google.com ~all",
          lookups_used: 4,
          lookup_limit: 10,
          include_tree: null,
          validations: [],
        },
        dkim: {
          status: "pass",
          selectors: {
            google: { found: true, key_type: "rsa", key_bits: 2048 },
            other: { found: false },
          },
          validations: [],
        },
        bimi: { status: "fail", record: null, tags: null, validations: [] },
        mta_sts: {
          status: "fail",
          dns_record: null,
          policy: null,
          validations: [],
        },
      });
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: 1700000000,
            last_grade: "A",
            created_at: 1700000000,
          },
        ],
        scanHistory: [
          {
            grade: "A",
            scanned_at: 1700000000,
            protocol_results: protocolBlob,
            score_factors: "[]",
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/example.com.json", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        protocols: {
          dmarc: { status: string; record: string | null; summary: string };
          spf: { status: string; record: string | null; summary: string };
          dkim: { status: string; record: string | null; summary: string };
          bimi: { status: string; record: string | null; summary: string };
          mta_sts: { status: string; record: string | null; summary: string };
        };
        recommendations: { priority: number; title: string }[];
        diff: unknown | null;
      };
      expect(body.protocols.dmarc.status).toBe("pass");
      expect(body.protocols.dmarc.record).toContain("v=DMARC1");
      expect(body.protocols.dmarc.summary).toBe("policy: p=reject");
      expect(body.protocols.spf.summary).toBe("4/10 DNS lookups");
      expect(body.protocols.dkim.summary).toContain("1 selector");
      expect(body.protocols.dkim.summary).toContain("2048-bit");
      expect(body.protocols.bimi.summary).toBe("not configured");
      expect(body.protocols.mta_sts.summary).toBe("not configured");
      // recommendations is whatever computeGradeBreakdown returns; we just
      // assert the field is present and is an array — content varies with
      // scoring tweaks.
      expect(Array.isArray(body.recommendations)).toBe(true);
      // No diff with a single history row.
      expect(body.diff).toBeNull();
    });

    it("emits a diff when DMARC drifted within 26h of the previous scan", async () => {
      const previous = JSON.stringify({
        dmarc: {
          status: "pass",
          record: "v=DMARC1; p=quarantine; pct=100",
          tags: { p: "quarantine" },
        },
        spf: { status: "pass", lookups_used: 3 },
        dkim: { status: "pass", selectors: {} },
        bimi: { status: "fail" },
        mta_sts: { status: "fail" },
      });
      const current = JSON.stringify({
        dmarc: {
          status: "warn",
          record: "v=DMARC1; p=none",
          tags: { p: "none" },
        },
        spf: { status: "pass", lookups_used: 3 },
        dkim: { status: "pass", selectors: {} },
        bimi: { status: "fail" },
        mta_sts: { status: "fail" },
      });
      const now = 1700000000;
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 0,
            scan_frequency: "daily",
            last_scanned_at: now,
            last_grade: "F",
            created_at: now - 86400 * 30,
          },
        ],
        scanHistory: [
          { grade: "F", scanned_at: now, protocol_results: current },
          {
            grade: "B",
            scanned_at: now - 12 * 3600,
            protocol_results: previous,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/example.com.json", {
        headers: { Cookie: cookie },
      });
      const body = (await res.json()) as {
        diff: {
          change: string;
          previous: string;
          current: string;
        } | null;
      };
      expect(body.diff).not.toBeNull();
      expect(body.diff?.previous).toContain("p=quarantine");
      expect(body.diff?.current).toContain("p=none");
      expect(body.diff?.change).toContain("p=none");
    });

    it("does not emit a diff when the previous scan is older than 26h", async () => {
      const blob = (policy: string) =>
        JSON.stringify({
          dmarc: {
            status: "pass",
            record: `v=DMARC1; p=${policy}`,
            tags: { p: policy },
          },
          spf: { status: "pass", lookups_used: 3 },
          dkim: { status: "pass", selectors: {} },
          bimi: { status: "fail" },
          mta_sts: { status: "fail" },
        });
      const now = 1700000000;
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: now,
            last_grade: "B",
            created_at: now - 86400 * 30,
          },
        ],
        scanHistory: [
          { grade: "B", scanned_at: now, protocol_results: blob("none") },
          // 5 days ago — outside the 26h diff window.
          {
            grade: "A",
            scanned_at: now - 5 * 86400,
            protocol_results: blob("reject"),
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/example.com.json", {
        headers: { Cookie: cookie },
      });
      const body = (await res.json()) as { diff: unknown };
      expect(body.diff).toBeNull();
    });
  });

  describe("GET /dashboard/domain/:domain/history", () => {
    const domainFixture = {
      id: 1,
      user_id: "user_1",
      domain: "example.com",
      is_free: 0,
      scan_frequency: "weekly",
      last_scanned_at: 1700000000,
      last_grade: "B",
      created_at: 1700000000,
    };

    const makeScan = (
      at: number,
      grade: string,
      statuses: Record<string, string>,
    ) => ({
      grade,
      scanned_at: at,
      protocol_results: JSON.stringify(
        Object.fromEntries(
          Object.entries(statuses).map(([k, v]) => [k, { status: v }]),
        ),
      ),
    });

    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/domain/example.com/history");
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("returns 404 when the domain does not belong to the user", async () => {
      const db = createMockDB({ domains: [] });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/notmine.com/history", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(404);
    });

    it("renders the full 30-row table and no upgrade prompt for Pro users", async () => {
      const scans = Array.from({ length: 12 }, (_, i) =>
        makeScan(1_700_000_000 + i * 86_400, "B", {
          dmarc: "pass",
          spf: "pass",
          dkim: "pass",
          bimi: "warn",
          mta_sts: "pass",
        }),
      );
      const db = createMockDB({
        domains: [domainFixture],
        scanHistory: scans,
        subscriptions: [{ user_id: "user_1", status: "active" }],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/example.com/history", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("History — example.com");
      expect(body).toContain("Protocol drift");
      expect(body).toContain("Grade trend");
      expect(body).not.toContain("Upgrade to see the full history");
      // Should render a sparkline SVG
      expect(body).toContain("sparkline-line");
      // All 12 scans show up (there's at least 12 distinct status-pass dots
      // since every scan has multiple pass protocols).
      const rowCount = (body.match(/class="drift-date"/g) || []).length;
      expect(rowCount).toBe(12);
    });

    it("shows an upgrade prompt for free users", async () => {
      const scans = Array.from({ length: 10 }, (_, i) =>
        makeScan(1_700_000_000 + i * 86_400, "C", {
          dmarc: "warn",
          spf: "pass",
          dkim: "pass",
          bimi: "fail",
          mta_sts: "pass",
        }),
      );
      const db = createMockDB({
        domains: [domainFixture],
        scanHistory: scans,
        // no subscriptions row → free plan
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/example.com/history", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("Upgrade to see the full history");
      expect(body).toContain("/dashboard/billing/subscribe");
      // Free users get only 5 rows even when 10 scans exist.
      const rowCount = (body.match(/class="drift-date"/g) || []).length;
      expect(rowCount).toBe(5);
    });

    it("treats a cancelled subscription as free", async () => {
      const db = createMockDB({
        domains: [domainFixture],
        scanHistory: [
          makeScan(1_700_000_000, "A", {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass",
            bimi: "pass",
            mta_sts: "pass",
          }),
        ],
        subscriptions: [{ user_id: "user_1", status: "canceled" }],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/example.com/history", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("Upgrade to see the full history");
    });

    it("handles domains with no scans yet without crashing", async () => {
      const db = createMockDB({
        domains: [domainFixture],
        scanHistory: [],
        subscriptions: [{ user_id: "user_1", status: "active" }],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/example.com/history", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("No scans yet to chart");
      expect(body).toContain("No scans yet.");
    });

    it("marks protocol-status transitions with drift-changed", async () => {
      const db = createMockDB({
        domains: [domainFixture],
        scanHistory: [
          // newest first: dmarc regressed pass→fail between the two scans
          makeScan(1_700_000_100, "F", {
            dmarc: "fail",
            spf: "pass",
            dkim: "pass",
            bimi: "pass",
            mta_sts: "pass",
          }),
          makeScan(1_700_000_000, "A", {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass",
            bimi: "pass",
            mta_sts: "pass",
          }),
        ],
        subscriptions: [{ user_id: "user_1", status: "active" }],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/example.com/history", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      expect(body).toContain("drift-changed");
      expect(body).toContain('title="changed from pass"');
    });
  });

  describe("GET /dashboard/settings", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/settings");
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("returns 200 and contains email and Settings with valid session", async () => {
      const db = createMockDB({
        users: [
          {
            id: "user_1",
            email: "alice@example.com",
            email_domain: "example.com",
            stripe_customer_id: null,
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/settings", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("Settings");
      expect(body).toContain("alice@example.com");
    });

    it("links to the API keys management page (hashed-key flow)", async () => {
      const db = createMockDB({
        users: [
          {
            id: "user_1",
            email: "alice@example.com",
            email_domain: "example.com",
            stripe_customer_id: null,
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/settings", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      expect(body).toContain("/dashboard/settings/api-keys");
      expect(body).toContain("Manage API Keys");
    });

    it("renders the retirement banner when the user has not acked", async () => {
      const db = createMockDB({
        users: [
          {
            id: "user_1",
            email: "alice@example.com",
            email_domain: "example.com",
            stripe_customer_id: null,
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: null,
            created_at: 1700000000,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/settings", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      expect(body).toContain("API key was retired");
    });

    it("shows webhook URL when one is configured", async () => {
      const db = createMockDB({
        users: [
          {
            id: "user_1",
            email: "alice@example.com",
            email_domain: "example.com",
            stripe_customer_id: null,
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
        webhooks: [
          {
            id: 1,
            user_id: "user_1",
            url: "https://hooks.example.com/notify",
            secret: "sec",
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/settings", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      expect(body).toContain("https://hooks.example.com/notify");
    });

    it("redirects to logout when user record is missing", async () => {
      const db = createMockDB({ users: [] });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("ghost_user", "ghost@example.com");
      const res = await app.request("/dashboard/settings", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/logout");
    });
  });

  describe("GET /dashboard/settings/api-keys", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/settings/api-keys");
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("lists existing keys by prefix and omits raw values on a normal visit", async () => {
      const db = createMockDB({
        users: [
          {
            id: "user_1",
            email: "alice@example.com",
            email_domain: "example.com",
            stripe_customer_id: null,
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
        apiKeys: [
          {
            id: "k1",
            user_id: "user_1",
            name: "ci-pipeline",
            prefix: "dmk_abcd1234",
            hash: "a".repeat(64),
            created_at: 1700000000,
            last_used_at: null,
            revoked_at: null,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/settings/api-keys", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("ci-pipeline");
      expect(body).toContain("dmk_abcd1234");
      expect(body).toContain("Active");
      expect(body).not.toContain("Save this key now");
    });

    it("shows the raw key banner only on the created=1 redirect", async () => {
      const db = createMockDB({
        users: [
          {
            id: "user_1",
            email: "alice@example.com",
            email_domain: "example.com",
            stripe_customer_id: null,
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
        apiKeys: [],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const raw = `dmk_${"a".repeat(32)}`;
      const res = await app.request(
        `/dashboard/settings/api-keys?created=1&raw=${encodeURIComponent(raw)}`,
        { headers: { Cookie: cookie } },
      );
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("Save this key now");
      expect(body).toContain(raw);
    });

    it("acks the retirement banner via waitUntil on first visit", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({
        users: [
          {
            id: "user_1",
            email: "alice@example.com",
            email_domain: "example.com",
            stripe_customer_id: null,
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: null,
            created_at: 1700000000,
          },
        ],
        writes,
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/settings/api-keys", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("old API key was retired");
      // Ack is scheduled via waitUntil; in tests we can observe the write.
      const ack = writes.find((w) =>
        w.sql.includes("UPDATE users SET api_key_retirement_acknowledged_at"),
      );
      expect(ack).toBeDefined();
    });
  });

  describe("POST /dashboard/settings/api-keys/generate", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/settings/api-keys/generate", {
        method: "POST",
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("creates an api_keys row and redirects with the raw key in the query string (shown once)", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");

      const res = await app.request("/dashboard/settings/api-keys/generate", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "name=ci-pipeline",
      });

      expect(res.status).toBe(303);
      const loc = res.headers.get("Location") ?? "";
      expect(loc.startsWith("/dashboard/settings/api-keys?")).toBe(true);
      expect(loc).toContain("created=1");
      expect(loc).toContain("raw=dmk_");

      const insert = writes.find((w) => w.sql.includes("INSERT INTO api_keys"));
      expect(insert).toBeDefined();
      // bindings: id, userId, name, prefix, hash
      expect(insert?.bindings[1]).toBe("user_1");
      expect(insert?.bindings[2]).toBe("ci-pipeline");
      expect(String(insert?.bindings[3] ?? "")).toMatch(/^dmk_.{8}$/);
      expect(String(insert?.bindings[4] ?? "")).toMatch(/^[0-9a-f]{64}$/);
    });

    it("stores name as null when the form field is blank", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");

      const res = await app.request("/dashboard/settings/api-keys/generate", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "name=",
      });
      expect(res.status).toBe(303);

      const insert = writes.find((w) => w.sql.includes("INSERT INTO api_keys"));
      expect(insert?.bindings[2]).toBeNull();
    });
  });

  describe("POST /dashboard/settings/api-keys/revoke", () => {
    it("writes UPDATE api_keys SET revoked_at keyed on id + user_id", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");

      const res = await app.request("/dashboard/settings/api-keys/revoke", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "id=some-key-id",
      });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/dashboard/settings/api-keys");

      const update = writes.find(
        (w) =>
          w.sql.includes("UPDATE api_keys") && w.sql.includes("revoked_at"),
      );
      expect(update).toBeDefined();
      expect(update?.bindings).toEqual(["some-key-id", "user_1"]);
    });
  });

  describe("POST /dashboard/domain/:domain/scan", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/domain/example.com/scan", {
        method: "POST",
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("returns 404 when domain does not belong to the user", async () => {
      const db = createMockDB({ domains: [] });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/notmine.com/scan", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(404);
    });

    it("runs the scan, persists history, and 303-redirects to the detail page", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({
        domains: [
          {
            id: 7,
            user_id: "user_1",
            domain: "example.com",
            is_free: 1,
            scan_frequency: "monthly",
            last_scanned_at: null,
            last_grade: null,
            created_at: 1700000000,
          },
        ],
        writes,
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");

      const res = await app.request("/dashboard/domain/example.com/scan", {
        method: "POST",
        headers: { Cookie: cookie },
      });

      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/dashboard/domain/example.com");

      const insertSql = writes.find((w) =>
        w.sql.includes("INSERT INTO scan_history"),
      );
      expect(insertSql).toBeDefined();
      expect(insertSql?.bindings[0]).toBe(7); // domain_id
      expect(insertSql?.bindings[1]).toBe("B"); // grade

      const updateSql = writes.find((w) =>
        w.sql.includes("UPDATE domains SET last_grade"),
      );
      expect(updateSql).toBeDefined();
      expect(updateSql?.bindings[0]).toBe("B");
    });
  });

  describe("POST /dashboard/settings/email-alerts", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/settings/email-alerts", {
        method: "POST",
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("flips email_alerts_enabled to 0 when checkbox is unchecked", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");

      const res = await app.request("/dashboard/settings/email-alerts", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "",
      });

      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/dashboard/settings");
      const update = writes.find((w) =>
        w.sql.includes("UPDATE users SET email_alerts_enabled"),
      );
      expect(update?.bindings[0]).toBe(0);
    });

    it("flips email_alerts_enabled to 1 when checkbox is checked", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");

      const res = await app.request("/dashboard/settings/email-alerts", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "enabled=on",
      });

      expect(res.status).toBe(302);
      const update = writes.find((w) =>
        w.sql.includes("UPDATE users SET email_alerts_enabled"),
      );
      expect(update?.bindings[0]).toBe(1);
    });
  });

  describe("POST /dashboard/settings/webhook", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/settings/webhook", {
        method: "POST",
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("redirects to /dashboard/settings after saving webhook", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ webhooks: [], writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const body = new URLSearchParams({
        webhookUrl: "https://example.com/hook",
        format: "slack",
      });
      const res = await app.request("/dashboard/settings/webhook", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/dashboard/settings");

      const insert = writes.find((w) => /^INSERT INTO webhooks/i.test(w.sql));
      expect(insert).toBeDefined();
      // (user_id, url, secret, format) — format lands in position 4.
      expect(insert?.bindings[3]).toBe("slack");
    });

    it("rejects an unknown format with a no-save redirect", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ webhooks: [], writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const body = new URLSearchParams({
        webhookUrl: "https://example.com/hook",
        format: "borked",
      });
      const res = await app.request("/dashboard/settings/webhook", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/dashboard/settings");
      expect(
        writes.find((w) => /INSERT INTO webhooks/i.test(w.sql)),
      ).toBeUndefined();
      expect(
        writes.find((w) => /UPDATE webhooks/i.test(w.sql)),
      ).toBeUndefined();
    });

    it("defaults missing format to raw", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ webhooks: [], writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const body = new URLSearchParams({
        webhookUrl: "https://example.com/hook",
      });
      const res = await app.request("/dashboard/settings/webhook", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(302);
      const insert = writes.find((w) => /^INSERT INTO webhooks/i.test(w.sql));
      expect(insert?.bindings[3]).toBe("raw");
    });
  });

  describe("GET /dashboard/domain/add", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/domain/add");
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("renders the add-domain form with a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/add", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("Add Domain");
      expect(body).toContain('name="domain"');
    });
  });

  describe("POST /dashboard/domain/add", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/domain/add", {
        method: "POST",
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("rejects an invalid domain with 400 and re-renders the form", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const body = new URLSearchParams({ domain: "not a domain" });
      const res = await app.request("/dashboard/domain/add", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(400);
      const html = await res.text();
      expect(html).toContain("valid domain");
    });

    it("creates the domain and 303-redirects to the detail page", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const body = new URLSearchParams({ domain: "example.com" });
      const res = await app.request("/dashboard/domain/add", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/dashboard/domain/example.com");
      const inserted = writes.find((w) =>
        w.sql.includes("INSERT INTO domains"),
      );
      expect(inserted).toBeDefined();
      expect(inserted?.bindings).toEqual([
        "user_1",
        "example.com",
        0, // isFree=false → 0
        "weekly",
      ]);
    });

    it("does not create a duplicate when the user already owns the domain", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: null,
            created_at: 1_700_000_000,
          },
        ],
        writes,
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const body = new URLSearchParams({ domain: "example.com" });
      const res = await app.request("/dashboard/domain/add", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/dashboard/domain/example.com");
      const inserted = writes.find((w) =>
        w.sql.includes("INSERT INTO domains"),
      );
      expect(inserted).toBeUndefined();
    });

    it("normalizes protocol-prefixed input to a bare domain", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const body = new URLSearchParams({
        domain: "https://Example.COM/path",
      });
      const res = await app.request("/dashboard/domain/add", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/dashboard/domain/example.com");
      const inserted = writes.find((w) =>
        w.sql.includes("INSERT INTO domains"),
      );
      expect(inserted?.bindings[1]).toBe("example.com");
    });

    it("rejects net-new domain with 400 when a free user is at the cap", async () => {
      const seedDomains = Array.from({ length: 3 }, (_, i) => ({
        id: i + 1,
        user_id: "user_1",
        domain: `seed${i}.example`,
        is_free: 0,
        scan_frequency: "weekly",
        last_scanned_at: null,
        last_grade: null,
        created_at: 1_700_000_000,
      }));
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ domains: seedDomains, writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const body = new URLSearchParams({ domain: "newdomain.example" });
      const res = await app.request("/dashboard/domain/add", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(400);
      const html = await res.text();
      expect(html).toMatch(/Free plan limit reached/);
      expect(html).toMatch(/Upgrade to Pro/);
      const inserted = writes.find((w) =>
        w.sql.includes("INSERT INTO domains"),
      );
      expect(inserted).toBeUndefined();
    });

    it("rejects net-new domain with 400 when a Pro user is at the cap", async () => {
      // Pro user already at the cap of 25.
      const seedDomains = Array.from({ length: 25 }, (_, i) => ({
        id: i + 1,
        user_id: "user_1",
        domain: `seed${i}.example`,
        is_free: 0,
        scan_frequency: "weekly",
        last_scanned_at: null,
        last_grade: null,
        created_at: 1_700_000_000,
      }));
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({
        domains: seedDomains,
        subscriptions: [{ user_id: "user_1", status: "active" }],
        writes,
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const body = new URLSearchParams({ domain: "overflow.example" });
      const res = await app.request("/dashboard/domain/add", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(400);
      const html = await res.text();
      expect(html).toMatch(/Pro plan limit of 25 domains/);
      expect(html).toContain("support@dmarc.mx");
      const inserted = writes.find((w) =>
        w.sql.includes("INSERT INTO domains"),
      );
      expect(inserted).toBeUndefined();
    });

    it("still redirects to the existing domain detail page for a duplicate even when at cap", async () => {
      // Grandfather: a free user already over cap can still re-visit
      // existing domains via the duplicate-redirect path. Net-new is what
      // gets blocked.
      const seedDomains = Array.from({ length: 5 }, (_, i) => ({
        id: i + 1,
        user_id: "user_1",
        domain: `seed${i}.example`,
        is_free: 0,
        scan_frequency: "weekly",
        last_scanned_at: null,
        last_grade: null,
        created_at: 1_700_000_000,
      }));
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ domains: seedDomains, writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const body = new URLSearchParams({ domain: "seed0.example" });
      const res = await app.request("/dashboard/domain/add", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe(
        "/dashboard/domain/seed0.example",
      );
      const inserted = writes.find((w) =>
        w.sql.includes("INSERT INTO domains"),
      );
      expect(inserted).toBeUndefined();
    });

    it("renders a grandfathered usage hint when a Pro user is over the cap", async () => {
      const seedDomains = Array.from({ length: 30 }, (_, i) => ({
        id: i + 1,
        user_id: "user_1",
        domain: `seed${i}.example`,
        is_free: 0,
        scan_frequency: "weekly",
        last_scanned_at: null,
        last_grade: null,
        created_at: 1_700_000_000,
      }));
      const db = createMockDB({
        domains: seedDomains,
        subscriptions: [{ user_id: "user_1", status: "active" }],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/add", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toMatch(/30 domains tracked/);
      expect(html).toMatch(/Pro plan includes 25/);
      expect(html).toMatch(/grandfathered/);
      // No "X of N used" framing for over-cap accounts.
      expect(html).not.toMatch(/30 of 25/);
    });

    it("returns a grandfathered error message when an over-cap Pro user POSTs a net-new domain", async () => {
      const seedDomains = Array.from({ length: 30 }, (_, i) => ({
        id: i + 1,
        user_id: "user_1",
        domain: `seed${i}.example`,
        is_free: 0,
        scan_frequency: "weekly",
        last_scanned_at: null,
        last_grade: null,
        created_at: 1_700_000_000,
      }));
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({
        domains: seedDomains,
        subscriptions: [{ user_id: "user_1", status: "active" }],
        writes,
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const body = new URLSearchParams({ domain: "overflow.example" });
      const res = await app.request("/dashboard/domain/add", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(400);
      const html = await res.text();
      expect(html).toMatch(/Pro plan includes 25 domains/);
      expect(html).toMatch(/already have 30/);
      expect(html).toMatch(/grandfathered/);
      const inserted = writes.find((w) =>
        w.sql.includes("INSERT INTO domains"),
      );
      expect(inserted).toBeUndefined();
    });

    it("renders the add-domain form with usage hint for a free user under cap", async () => {
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "first.example",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: null,
            created_at: 1_700_000_000,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/add", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toMatch(/1 of 3 Free domains used/);
    });
  });

  describe("POST /dashboard/domain/:domain/delete", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/domain/example.com/delete", {
        method: "POST",
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("deletes the domain and 303-redirects to /dashboard", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({ writes });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/domain/example.com/delete", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/dashboard");
      const deleted = writes.find((w) => w.sql.includes("DELETE FROM domains"));
      expect(deleted).toBeDefined();
      expect(deleted?.bindings).toEqual(["user_1", "example.com"]);
    });
  });

  describe("GET /dashboard alerts surface", () => {
    const userDomain = {
      id: 1,
      user_id: "user_1",
      domain: "example.com",
      is_free: 0,
      scan_frequency: "weekly",
      last_scanned_at: 1700000000,
      last_grade: "C",
      created_at: 1700000000,
    };

    it("renders the Needs attention section when the user has unacknowledged alerts", async () => {
      const db = createMockDB({
        domains: [userDomain],
        alerts: [
          {
            id: 11,
            domain_id: 1,
            alert_type: "grade_drop",
            previous_value: "A",
            new_value: "C",
            notified_via: null,
            acknowledged_at: null,
            created_at: 1_700_000_500,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("Needs attention");
      expect(body).toContain("Grade dropped from A to C");
      expect(body).toContain("/dashboard/alerts/11/acknowledge");
      expect(body).toContain("badge-alert");
      expect(body).toContain("1 alert");
    });

    it("omits the Needs attention section when no alerts exist", async () => {
      const db = createMockDB({
        domains: [userDomain],
        alerts: [],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      expect(body).not.toContain("Needs attention");
      // Markup-level usage; .badge-alert exists in DASHBOARD_CSS unconditionally.
      expect(body).not.toContain('class="badge-alert"');
    });

    it("does not surface another user's alerts", async () => {
      const db = createMockDB({
        domains: [
          userDomain,
          {
            id: 2,
            user_id: "user_2",
            domain: "other.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: null,
            created_at: 1700000000,
          },
        ],
        alerts: [
          {
            id: 22,
            domain_id: 2,
            alert_type: "grade_drop",
            previous_value: "A",
            new_value: "F",
            notified_via: null,
            acknowledged_at: null,
            created_at: 1_700_000_500,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard", {
        headers: { Cookie: cookie },
      });
      const body = await res.text();
      expect(body).not.toContain("Needs attention");
      expect(body).not.toContain("/dashboard/alerts/22/acknowledge");
    });
  });

  describe("POST /dashboard/alerts/:id/acknowledge", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/alerts/1/acknowledge", {
        method: "POST",
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("returns 400 when the id is not numeric", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/alerts/abc/acknowledge", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(400);
    });

    it("303-redirects to /dashboard for the user's own alert and persists the ack", async () => {
      const writes: Array<{ sql: string; bindings: unknown[] }> = [];
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: "C",
            created_at: 1700000000,
          },
        ],
        alerts: [
          {
            id: 42,
            domain_id: 1,
            alert_type: "grade_drop",
            previous_value: "A",
            new_value: "C",
            notified_via: null,
            acknowledged_at: null,
            created_at: 1_700_000_500,
          },
        ],
        writes,
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/alerts/42/acknowledge", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/dashboard");
      const ack = writes.find((w) =>
        /UPDATE alerts\s+SET acknowledged_at/i.test(w.sql),
      );
      expect(ack).toBeDefined();
      expect(ack?.bindings[1]).toBe(42); // alertId
      expect(ack?.bindings[2]).toBe("user_1"); // userId
    });

    it("returns 404 for another user's alert id (IDOR)", async () => {
      const db = createMockDB({
        domains: [
          {
            id: 2,
            user_id: "user_2",
            domain: "other.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: null,
            created_at: 1700000000,
          },
        ],
        alerts: [
          {
            id: 99,
            domain_id: 2,
            alert_type: "grade_drop",
            previous_value: "A",
            new_value: "F",
            notified_via: null,
            acknowledged_at: null,
            created_at: 1_700_000_500,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/alerts/99/acknowledge", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(404);
    });

    it("returns 404 for a nonexistent alert id (no 500, no redirect to dashboard)", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/alerts/99999/acknowledge", {
        method: "POST",
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(404);
    });
  });

  describe("GET /dashboard/bulk", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/bulk");
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("renders an upgrade prompt for free users", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/bulk", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("Pro feature");
      expect(body).toContain("Upgrade to Pro");
      expect(body).toContain("/dashboard/billing/subscribe");
      // Form must NOT render for free users.
      expect(body).not.toContain('name="domains"');
    });

    it("renders the bulk-scan textarea for Pro users", async () => {
      const db = createMockDB({
        subscriptions: [{ user_id: "user_1", status: "active" }],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/bulk", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain("Bulk Scan");
      expect(body).toContain('name="domains"');
      expect(body).not.toContain("Pro feature");
    });
  });

  describe("POST /dashboard/bulk", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/bulk", { method: "POST" });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("returns 402 for free users (gates the action, not the route)", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/bulk", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "domains=example.com",
      });
      expect(res.status).toBe(402);
      const body = await res.text();
      expect(body).toContain("Bulk scan is a Pro feature.");
    });

    it("renders results with status badges for a Pro submission", async () => {
      const db = createMockDB({
        subscriptions: [{ user_id: "user_1", status: "active" }],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      // 27 valid domains, Pro cap = 25 → 25 scanned, 2 over-cap rejected.
      // Stays under inBandCap (30) so we don't mix with queued behavior.
      const inputDomains = Array.from(
        { length: 27 },
        (_, i) => `d${i}.example`,
      ).join("\n");
      const body = new URLSearchParams({ domains: inputDomains });
      const res = await app.request("/dashboard/bulk", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('class="bulk-status scanned"');
      expect(html).toContain("Results");
      expect(html).toMatch(/27 submitted/);
      expect(html).toContain("Watchlist limit reached");
    });

    it("returns 400 when more than 100 domains are submitted", async () => {
      const db = createMockDB({
        subscriptions: [{ user_id: "user_1", status: "active" }],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const inputDomains = Array.from(
        { length: 101 },
        (_, i) => `d${i}.example`,
      ).join("\n");
      const body = new URLSearchParams({ domains: inputDomains });
      const res = await app.request("/dashboard/bulk", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      expect(res.status).toBe(400);
      const html = await res.text();
      expect(html).toContain("Too many domains");
    });
  });

  describe("GET /dashboard/export", () => {
    it("redirects to /auth/login without a session cookie", async () => {
      const db = createMockDB({});
      const app = createTestApp(db);
      const res = await app.request("/dashboard/export");
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/auth/login");
    });

    it("returns 402 with upsell page for free users", async () => {
      const db = createMockDB({
        domains: [
          {
            id: 1,
            user_id: "user_1",
            domain: "example.com",
            is_free: 1,
            scan_frequency: "monthly",
            last_scanned_at: null,
            last_grade: null,
            created_at: 1700000000,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_1", "alice@example.com");
      const res = await app.request("/dashboard/export", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(402);
      const body = await res.text();
      expect(body).toContain("Pro feature");
      expect(body).toContain("Upgrade to Pro");
    });

    it("returns CSV with expected columns for a Pro user", async () => {
      const protocolResults = JSON.stringify({
        dmarc: { status: "pass" },
        spf: { status: "warn" },
        dkim: { status: "pass" },
        bimi: { status: "fail" },
        mta_sts: { status: "pass" },
        mx: { status: "info" },
      });
      const db = createMockDB({
        subscriptions: [{ user_id: "user_pro", status: "active" }],
        domains: [
          {
            id: 1,
            user_id: "user_pro",
            domain: "example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: 1700000000,
            last_grade: "B",
            created_at: 1700000000,
          },
        ],
        scanHistory: [
          {
            id: 1,
            domain_id: 1,
            grade: "B",
            scanned_at: 1700000000,
            protocol_results: protocolResults,
            score_factors: null,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_pro", "pro@example.com");
      const res = await app.request("/dashboard/export", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toContain("text/csv");
      expect(res.headers.get("Content-Disposition")).toMatch(
        /filename="dmarcheck-dashboard-\d{4}-\d{2}-\d{2}\.csv"/,
      );
      const text = await res.text();
      // Header row must contain all required columns
      const lines = text.trim().split(/\r?\n/);
      // First line is BOM + headers; strip BOM for comparison
      const headerLine = lines[0].replace(/^﻿/, "");
      expect(headerLine).toBe(
        "domain,last_scanned_at,grade,score,dmarc_status,spf_status,dkim_status,bimi_status,mta_sts_status,mx_status",
      );
      // Data row
      expect(lines.length).toBe(2); // header + 1 domain
      const dataLine = lines[1];
      expect(dataLine).toContain("example.com");
      expect(dataLine).toContain("pass"); // dmarc_status
      expect(dataLine).toContain("warn"); // spf_status
      expect(dataLine).toContain("fail"); // bimi_status
    });

    it("returns header-only CSV for a Pro user with an empty watchlist", async () => {
      const db = createMockDB({
        subscriptions: [{ user_id: "user_pro", status: "active" }],
        domains: [],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_pro", "pro@example.com");
      const res = await app.request("/dashboard/export", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toContain("text/csv");
      const text = await res.text();
      const lines = text.trim().split(/\r?\n/);
      expect(lines.length).toBe(1); // header only
      const headerLine = lines[0].replace(/^﻿/, "");
      expect(headerLine).toBe(
        "domain,last_scanned_at,grade,score,dmarc_status,spf_status,dkim_status,bimi_status,mta_sts_status,mx_status",
      );
    });

    it("returns JSON array with domain and protocols for ?format=json", async () => {
      const protocolResults = JSON.stringify({
        dmarc: { status: "pass" },
        spf: { status: "pass" },
        dkim: { status: "pass" },
        bimi: { status: "fail" },
        mta_sts: { status: "pass" },
        mx: { status: "info" },
      });
      const db = createMockDB({
        subscriptions: [{ user_id: "user_pro", status: "active" }],
        domains: [
          {
            id: 1,
            user_id: "user_pro",
            domain: "alpha.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: 1700000000,
            last_grade: "A",
            created_at: 1700000000,
          },
          {
            id: 2,
            user_id: "user_pro",
            domain: "beta.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: null,
            created_at: 1700000001,
          },
        ],
        scanHistory: [
          {
            id: 1,
            domain_id: 1,
            grade: "A",
            scanned_at: 1700000000,
            protocol_results: protocolResults,
            score_factors: null,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_pro", "pro@example.com");
      const res = await app.request("/dashboard/export?format=json", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toContain("application/json");
      expect(res.headers.get("Content-Disposition")).toMatch(
        /filename="dmarcheck-dashboard-\d{4}-\d{2}-\d{2}\.json"/,
      );
      const payload = (await res.json()) as Array<{
        domain: string;
        last_scanned_at: number | null;
        grade: string | null;
        protocols: Record<string, unknown> | null;
      }>;
      expect(Array.isArray(payload)).toBe(true);
      expect(payload).toHaveLength(2);
      // Sorted by domain alphabetically
      expect(payload[0].domain).toBe("alpha.com");
      expect(payload[0].grade).toBe("A");
      expect(payload[0].protocols).not.toBeNull();
      // beta.com has no scan yet
      expect(payload[1].domain).toBe("beta.com");
      expect(payload[1].grade).toBeNull();
      expect(payload[1].protocols).toBeNull();
    });

    it("renders an Export button in the dashboard toolbar for Pro users", async () => {
      const db = createMockDB({
        subscriptions: [{ user_id: "user_pro", status: "active" }],
        users: [
          {
            id: "user_pro",
            email: "pro@example.com",
            email_domain: "example.com",
            stripe_customer_id: "cus_x",
            email_alerts_enabled: 1,
            api_key_retirement_acknowledged_at: 1700000000,
            created_at: 1700000000,
          },
        ],
        domains: [
          {
            id: 1,
            user_id: "user_pro",
            domain: "example.com",
            is_free: 0,
            scan_frequency: "weekly",
            last_scanned_at: null,
            last_grade: "A",
            created_at: 1700000000,
          },
        ],
      });
      const app = createTestApp(db);
      const cookie = await makeSessionCookie("user_pro", "pro@example.com");
      const res = await app.request("/dashboard", {
        headers: { Cookie: cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).toContain('href="/dashboard/export"');
      expect(body).toContain("Export");
    });
  });
});
