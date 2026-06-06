import { describe, expect, it } from "vitest";
import {
  renderApiKeysPage,
  renderDashboardPage,
  renderDomainDetailPage,
  renderSettingsPage,
} from "../src/views/dashboard";

describe("renderDashboardPage", () => {
  it("renders empty state when no domains", () => {
    const html = renderDashboardPage({
      email: "user@example.com",
      domains: [],
    });
    expect(html).toContain("No domains");
  });

  it("renders domain rows when domains are provided", () => {
    const html = renderDashboardPage({
      email: "user@example.com",
      domains: [
        {
          domain: "example.com",
          grade: "A",
          frequency: "daily",
          lastScanned: "2026-04-01",
          isFree: true,
        },
      ],
    });
    expect(html).toContain("example.com");
    expect(html).toContain("grade-a");
    expect(html).toContain("badge-free");
    expect(html).toContain("Free");
    expect(html).toContain("daily");
  });

  it("renders multiple domains", () => {
    const html = renderDashboardPage({
      email: "user@example.com",
      domains: [
        {
          domain: "alpha.com",
          grade: "B",
          frequency: "weekly",
          lastScanned: null,
          isFree: false,
        },
        {
          domain: "beta.com",
          grade: "F",
          frequency: "monthly",
          lastScanned: "2026-03-15",
          isFree: true,
        },
      ],
    });
    expect(html).toContain("alpha.com");
    expect(html).toContain("beta.com");
    expect(html).toContain("grade-a"); // B maps to grade-a class
    expect(html).toContain("grade-f");
    expect(html).toContain("Never");
  });

  it("escapes domain names containing special characters", () => {
    const html = renderDashboardPage({
      email: "user@example.com",
      domains: [
        {
          domain: "<script>alert(1)</script>",
          grade: "F",
          frequency: "daily",
          lastScanned: null,
          isFree: false,
        },
      ],
    });
    // The escaped form must appear in the body content
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("includes nav links and email", () => {
    const html = renderDashboardPage({
      email: "test@example.com",
      domains: [],
    });
    expect(html).toContain("test@example.com");
    expect(html).toContain("Domains");
    expect(html).toContain("Settings");
    expect(html).toContain("Logout");
  });

  it("links to domain detail pages", () => {
    const html = renderDashboardPage({
      email: "user@example.com",
      domains: [
        {
          domain: "example.com",
          grade: "A",
          frequency: "daily",
          lastScanned: null,
          isFree: false,
        },
      ],
    });
    expect(html).toContain("/dashboard/domain/");
    expect(html).toContain("example.com");
  });

  it("does not render search/filter controls when controls is omitted", () => {
    const html = renderDashboardPage({
      email: "user@example.com",
      domains: [],
    });
    // The class lives in the always-included CSS, so the markup-level check
    // looks for the actual <form> the toolbar renders into.
    expect(html).not.toContain('<form class="domain-toolbar"');
    expect(html).not.toContain("Search domains…");
  });

  it("renders search/filter controls and pagination when controls are provided", () => {
    const html = renderDashboardPage({
      email: "user@example.com",
      plan: "pro",
      domains: [
        {
          domain: "alpha.com",
          grade: "A",
          frequency: "weekly",
          lastScanned: "2026-04-01",
          isFree: false,
        },
      ],
      controls: {
        search: "",
        grade: null,
        frequency: null,
        sort: "domain",
        direction: "asc",
        page: 1,
        pageSize: 25,
        totalPages: 1,
        total: 1,
      },
    });
    expect(html).toContain("domain-toolbar");
    expect(html).toContain('placeholder="Search domains');
    expect(html).toContain("All grades");
    expect(html).toContain("All frequencies");
    expect(html).toContain("Showing 1–1 of 1");
  });

  it("preserves search/filter state in sort header links", () => {
    const html = renderDashboardPage({
      email: "user@example.com",
      plan: "pro",
      domains: [
        {
          domain: "alpha.com",
          grade: "A",
          frequency: "weekly",
          lastScanned: null,
          isFree: false,
        },
      ],
      controls: {
        search: "alpha",
        grade: "A",
        frequency: "weekly",
        sort: "domain",
        direction: "asc",
        page: 1,
        pageSize: 25,
        totalPages: 1,
        total: 1,
      },
    });
    expect(html).toContain("q=alpha");
    expect(html).toContain("grade=A");
    expect(html).toContain("frequency=weekly");
    expect(html).toContain("sort=grade");
  });

  it("renders prev/next pagination links spanning multiple pages", () => {
    const html = renderDashboardPage({
      email: "user@example.com",
      plan: "pro",
      domains: [
        {
          domain: "p2-domain.com",
          grade: "B",
          frequency: "weekly",
          lastScanned: null,
          isFree: false,
        },
      ],
      controls: {
        search: "",
        grade: null,
        frequency: null,
        sort: "domain",
        direction: "asc",
        page: 2,
        pageSize: 25,
        totalPages: 4,
        total: 80,
      },
    });
    expect(html).toContain("Showing 26–50 of 80");
    // Prev jumps to page 1 (rendered as bare /dashboard since page=1 is the
    // default and we drop default-valued params for clean URLs). Next jumps
    // to page 3.
    expect(html).toContain('href="/dashboard" rel="prev"');
    expect(html).toContain("page=3");
    expect(html).toContain('rel="next"');
  });

  it("disables prev on first page and next on last page", () => {
    const lastPage = renderDashboardPage({
      email: "user@example.com",
      plan: "pro",
      domains: [
        {
          domain: "tail.com",
          grade: "B",
          frequency: "weekly",
          lastScanned: null,
          isFree: false,
        },
      ],
      controls: {
        search: "",
        grade: null,
        frequency: null,
        sort: "domain",
        direction: "asc",
        page: 3,
        pageSize: 25,
        totalPages: 3,
        total: 51,
      },
    });
    expect(lastPage).toContain("page-disabled");
    expect(lastPage).not.toContain('rel="next"');
  });

  it("shows a 'no matches' empty state when filters are active and no results", () => {
    const html = renderDashboardPage({
      email: "user@example.com",
      plan: "pro",
      domains: [],
      controls: {
        search: "nope",
        grade: null,
        frequency: null,
        sort: "domain",
        direction: "asc",
        page: 1,
        pageSize: 25,
        totalPages: 1,
        total: 0,
      },
    });
    expect(html).toContain("No domains match these filters");
    expect(html).toContain("Clear filters");
    // Must not show the new-account empty state copy.
    expect(html).not.toContain("Add your first domain");
  });

  it("escapes hostile search input in the toolbar value", () => {
    const html = renderDashboardPage({
      email: "user@example.com",
      plan: "pro",
      domains: [],
      controls: {
        search: '"><script>alert(1)</script>',
        grade: null,
        frequency: null,
        sort: "domain",
        direction: "asc",
        page: 1,
        pageSize: 25,
        totalPages: 1,
        total: 0,
      },
    });
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });

  describe("hero + banners + stat strip", () => {
    const sample = (
      grade: string,
      domain = "example.com",
    ): {
      domain: string;
      grade: string;
      frequency: string;
      lastScanned: string | null;
      isFree: boolean;
    } => ({
      domain,
      grade,
      frequency: "daily",
      lastScanned: "2026-04-25",
      isFree: false,
    });

    // Bare class names appear inside the inlined CSS too, so assertions
    // target the rendered element/attribute pattern instead. `class="…"`
    // matches per-element, not per-stylesheet rule.
    const hasSection = (html: string, className: string): boolean =>
      html.includes(`class="${className}`) ||
      html.includes(`class="dashboard-banner ${className}`) ||
      html.includes(`class="stat-card ${className}`);

    it("renders an empty-portfolio hero with a prompt to add a domain", () => {
      const html = renderDashboardPage({
        email: "user@example.com",
        domains: [],
      });
      expect(html).toContain('class="dashboard-hero"');
      expect(html).toContain("Add a domain");
      // No stat strip when zero domains.
      expect(html).not.toContain('class="stat-strip"');
    });

    it("renders the stat strip with derived counts", () => {
      const html = renderDashboardPage({
        email: "user@example.com",
        domains: [
          sample("A", "a.com"),
          sample("B", "b.com"),
          sample("C", "c.com"),
          sample("D", "d.com"),
          sample("F", "f.com"),
        ],
      });
      expect(html).toContain('class="stat-strip"');
      expect(hasSection(html, "stat-card-pass")).toBe(true); // 2 healthy
      expect(hasSection(html, "stat-card-warn")).toBe(true); // 2 drifting
      expect(hasSection(html, "stat-card-fail")).toBe(true); // 1 failing
    });

    it("derives the scoreboard from the explicit stats override, not the page rows", () => {
      // The Pro dashboard passes one paginated page of rows but portfolio-wide
      // stats/worst. The scoreboard, on-fire banner, and hero "triage" line
      // must reflect the whole watchlist, not just the visible page.
      const html = renderDashboardPage({
        email: "u@x.com",
        plan: "pro",
        // Page rows are all healthy A's — if the scoreboard read these, it would
        // show 2 healthy / 0 failing and party-hat.
        domains: [sample("A", "page-a.com"), sample("A", "page-b.com")],
        stats: {
          total: 344,
          healthy: 300,
          drifting: 32,
          failing: 12,
          ungraded: 0,
        },
        worst: { domain: "worst-in-portfolio.example", grade: "F" },
      });
      // "Domains" card shows the full watchlist size, not the 2 visible rows.
      expect(html).toContain("344");
      // Failing card + on-fire banner reflect the 12 portfolio-wide failures.
      expect(hasSection(html, "stat-card-fail")).toBe(true);
      expect(hasSection(html, "dashboard-banner-fire")).toBe(true);
      expect(html).toContain("12 domains failing");
      // Hero triages the portfolio-wide worst domain, which isn't on this page.
      expect(html).toContain("12 domains are failing");
      expect(html).toContain("worst-in-portfolio.example");
      // A failing portfolio must never party-hat, even though the page is green.
      expect(html).not.toMatch(/<div class="creature[^"]*creature-partying/);
    });

    it("falls back to deriving stats from domains when no override is given", () => {
      // Free tier and fixtures pass the full list as `domains` and omit the
      // override — the derived path must keep working unchanged.
      const html = renderDashboardPage({
        email: "u@x.com",
        domains: [sample("A", "a.com"), sample("F", "b.com")],
      });
      expect(html).toContain('class="stat-strip"');
      expect(hasSection(html, "stat-card-pass")).toBe(true); // 1 healthy
      expect(hasSection(html, "stat-card-fail")).toBe(true); // 1 failing
      expect(html).toContain("b.com"); // worst derived from the list
    });

    it("renders the free-tier banner only when plan=free", () => {
      const free = renderDashboardPage({
        email: "u@x.com",
        plan: "free",
        domains: [sample("A")],
      });
      expect(hasSection(free, "dashboard-banner-free")).toBe(true);
      expect(free).toContain("$19/mo");
      expect(free).toContain("/pricing");
      const pro = renderDashboardPage({
        email: "u@x.com",
        plan: "pro",
        domains: [sample("A")],
      });
      expect(hasSection(pro, "dashboard-banner-free")).toBe(false);
    });

    it("renders the first-run banner only when isFirstRun and exactly one domain", () => {
      const html = renderDashboardPage({
        email: "u@x.com",
        domains: [sample("A", "auto-provisioned.example")],
        isFirstRun: true,
      });
      expect(hasSection(html, "dashboard-banner-firstrun")).toBe(true);
      expect(html).toContain("auto-provisioned.example");
      const noBanner = renderDashboardPage({
        email: "u@x.com",
        domains: [sample("A", "a.com"), sample("B", "b.com")],
        isFirstRun: true,
      });
      expect(hasSection(noBanner, "dashboard-banner-firstrun")).toBe(false);
    });

    it("renders the on-fire banner when 3+ domains are failing", () => {
      const html = renderDashboardPage({
        email: "u@x.com",
        domains: [
          sample("F", "x.com"),
          sample("F", "y.com"),
          sample("F", "z.com"),
        ],
      });
      expect(hasSection(html, "dashboard-banner-fire")).toBe(true);
      expect(html).toContain("3 domains failing");
      const tame = renderDashboardPage({
        email: "u@x.com",
        domains: [sample("F", "x.com"), sample("F", "y.com")],
      });
      expect(hasSection(tame, "dashboard-banner-fire")).toBe(false);
    });

    it("renders the portfolio sparkline only when 2+ trend points", () => {
      const withTrend = renderDashboardPage({
        email: "u@x.com",
        domains: [sample("A")],
        portfolioTrend: [8, 9, 10, 11, 12],
      });
      expect(withTrend).toContain('<svg class="dash-spark"');
      const noTrend = renderDashboardPage({
        email: "u@x.com",
        domains: [sample("A")],
        portfolioTrend: [10],
      });
      expect(noTrend).not.toContain('<svg class="dash-spark"');
    });

    it("escapes domain names in the hero voice line", () => {
      const html = renderDashboardPage({
        email: "u@x.com",
        domains: [sample("F", "<script>x</script>.com")],
      });
      expect(html).not.toContain("<script>x</script>");
      expect(html).toContain("&lt;script&gt;");
    });

    it("celebrates with party hat when no failures and no drift", () => {
      const html = renderDashboardPage({
        email: "u@x.com",
        domains: [sample("A", "a.com"), sample("S", "b.com")],
      });
      expect(html).toContain("creature-partying");
      expect(html).toMatch(/Everything('|&#39;)s green/);
    });

    it("does not panic or party when the only domain is ungraded", () => {
      // A fresh user with one not-yet-scanned domain. Bug we're guarding:
      // gradeToMood('—') used to fall through to 'panicked', so DMarcus
      // screamed at a user who hadn't received their first scan back. The
      // hero should be neutral and the voice line should acknowledge the
      // scan-in-progress state.
      const html = renderDashboardPage({
        email: "u@x.com",
        domains: [sample("—", "fresh.example")],
      });
      expect(html).not.toMatch(/<div class="creature[^"]*creature-panicked/);
      expect(html).not.toMatch(/<div class="creature[^"]*creature-partying/);
      expect(html).toContain("Scanning your");
    });

    it("picks the worst graded domain even when an ungraded one comes first", () => {
      // worstDomain bug we're guarding: when seeded with an ungraded entry,
      // the prior implementation could promote a healthy domain to "worst"
      // and let DMarcus celebrate while another domain was failing.
      const html = renderDashboardPage({
        email: "u@x.com",
        domains: [
          sample("—", "fresh.example"),
          sample("F", "broken.example"),
          sample("A", "good.example"),
        ],
      });
      expect(html).toContain("broken.example");
      expect(html).not.toMatch(/good\.example<\/code> is failing/);
      // Failing portfolio must not party-hat regardless of insertion order.
      expect(html).not.toMatch(/<div class="creature[^"]*creature-partying/);
    });

    it("does not party-hat a 100% ungraded portfolio", () => {
      const html = renderDashboardPage({
        email: "u@x.com",
        domains: [sample("—", "a.com"), sample("—", "b.com")],
      });
      expect(html).not.toMatch(/<div class="creature[^"]*creature-partying/);
      expect(html).toContain("Scanning your 2 domains");
    });

    it("renders the drawer + wizard shells with data hooks but hidden", () => {
      const html = renderDashboardPage({
        email: "u@x.com",
        domains: [sample("A")],
      });
      // Drawer shell present and hidden by default
      expect(html).toContain('id="domain-drawer"');
      expect(html).toContain('role="dialog"');
      expect(html).toContain('aria-modal="true"');
      expect(html).toMatch(/<aside[^>]+id="domain-drawer"[^>]+hidden/);
      expect(html).toContain("data-drawer-close");
      // Wizard shell present and hidden by default
      expect(html).toContain('id="add-wizard"');
      expect(html).toMatch(/<div[^>]+id="add-wizard"[^>]+hidden/);
      expect(html).toContain("data-wizard-form");
      expect(html).toContain('action="/dashboard/domain/add"');
      expect(html).toContain("Step 1 of 3");
      // Add-domain trigger button rendered next to the table heading
      expect(html).toContain("data-wizard-open");
      // Each table row carries data-domain so the drawer JS knows what to load
      expect(html).toContain('data-domain="example.com"');
      expect(html).toContain("data-drawer-link");
    });

    it("preserves the existing alerts section markup above the table", () => {
      const html = renderDashboardPage({
        email: "u@x.com",
        domains: [sample("F", "broken.com")],
        alerts: [
          {
            id: 1,
            domain: "broken.com",
            alertType: "grade_drop",
            previousValue: "B",
            newValue: "F",
            createdAt: Math.floor(Date.now() / 1000) - 60,
          },
        ],
      });
      expect(html).toContain("alerts-needs-attention");
      expect(html).toContain("Grade dropped from B to F");
    });
  });
});

describe("renderDomainDetailPage", () => {
  const baseProps = {
    email: "user@example.com",
    domain: "example.com",
    grade: "B+",
    lastScanned: "2026-04-01",
    isFree: false,
    scanFrequency: "daily",
    scanHistory: [
      { date: "2026-04-01", grade: "B+" },
      { date: "2026-03-25", grade: "B" },
    ],
  };

  it("renders domain name", () => {
    const html = renderDomainDetailPage(baseProps);
    expect(html).toContain("example.com");
  });

  it("renders grade", () => {
    const html = renderDomainDetailPage(baseProps);
    expect(html).toContain("B+");
  });

  it("renders Scan Now button", () => {
    const html = renderDomainDetailPage(baseProps);
    expect(html).toContain("Scan Now");
  });

  it("renders Grade History section", () => {
    const html = renderDomainDetailPage(baseProps);
    expect(html).toContain("Grade History");
  });

  it("renders scan history entries", () => {
    const html = renderDomainDetailPage(baseProps);
    expect(html).toContain("2026-04-01");
    expect(html).toContain("2026-03-25");
  });

  it("links to full report", () => {
    const html = renderDomainDetailPage(baseProps);
    expect(html).toContain("/check?domain=");
    expect(html).toContain("View Full Report");
  });

  it("shows free badge when isFree is true", () => {
    const html = renderDomainDetailPage({ ...baseProps, isFree: true });
    expect(html).toContain("badge-free");
    expect(html).toContain("Free");
  });

  it("shows no-history message when scanHistory is empty", () => {
    const html = renderDomainDetailPage({ ...baseProps, scanHistory: [] });
    expect(html).toContain("No scan history yet");
  });

  it("limits grade history to 12 entries", () => {
    const history = Array.from({ length: 20 }, (_, i) => ({
      date: `2026-01-${String(i + 1).padStart(2, "0")}`,
      grade: "A",
    }));
    const html = renderDomainDetailPage({ ...baseProps, scanHistory: history });
    // Only 12 entries should appear — count list items inside the history list
    // Each entry renders as a <li> with class history-date span
    const matches = html.match(/<li>\s*<span class="history-date">/g);
    expect(matches).not.toBeNull();
    expect((matches ?? []).length).toBe(12);
  });

  it("includes scan form posting to correct URL", () => {
    const html = renderDomainDetailPage(baseProps);
    expect(html).toContain('method="POST"');
    expect(html).toContain("/scan");
  });
});

describe("renderSettingsPage", () => {
  const defaults = {
    email: "user@example.com",
    webhookUrl: null,
    plan: "free" as const,
    billingEnabled: true,
    emailAlertsEnabled: true,
    showRetirementBanner: false,
  };

  it("links to the API Keys page instead of rendering the raw key inline", () => {
    const html = renderSettingsPage(defaults);
    expect(html).toContain("/dashboard/settings/api-keys");
    expect(html).toContain("Manage API Keys");
    // No `.api-key-display` element on this page — the shared CSS class still
    // appears in the <style> block, but it shouldn't be used in the body.
    expect(html).not.toContain('class="api-key-display"');
  });

  it("renders email in account section", () => {
    const html = renderSettingsPage({
      ...defaults,
      email: "admin@example.com",
    });
    expect(html).toContain("admin@example.com");
    expect(html).toContain("Account");
  });

  it("renders webhook input with existing URL prefilled", () => {
    const html = renderSettingsPage({
      ...defaults,
      webhookUrl: "https://hooks.example.com/dmarc",
    });
    expect(html).toContain("https://hooks.example.com/dmarc");
    expect(html).toContain("Webhook");
  });

  it("renders a format <select> with all three options, raw selected by default", () => {
    const html = renderSettingsPage(defaults);
    expect(html).toContain('name="format"');
    expect(html).toContain('value="raw"');
    expect(html).toContain('value="slack"');
    expect(html).toContain('value="google_chat"');
    // Default value is "raw", which the template pre-selects.
    expect(html).toMatch(/value="raw" selected/);
  });

  it("pre-selects slack when webhookFormat is slack", () => {
    const html = renderSettingsPage({
      ...defaults,
      webhookUrl: "https://hooks.slack.com/services/T/B/X",
      webhookFormat: "slack",
    });
    expect(html).toMatch(/value="slack" selected/);
    expect(html).not.toMatch(/value="raw" selected/);
  });

  it("renders the Pro badge and Manage Billing link for pro users", () => {
    const html = renderSettingsPage({ ...defaults, plan: "pro" });
    expect(html).toContain("Manage Billing");
    expect(html).toContain("<strong>Pro</strong>");
  });

  it("renders the Free badge and an Upgrade link for free users", () => {
    const html = renderSettingsPage(defaults);
    expect(html).toContain("<strong>Free</strong>");
    expect(html).toContain("Upgrade to Pro");
  });

  it("shows a 'not configured' message when billing is disabled on this deployment", () => {
    const html = renderSettingsPage({ ...defaults, billingEnabled: false });
    expect(html).toContain("not configured");
    expect(html).not.toContain("Upgrade to Pro");
  });

  it("renders the retirement banner when showRetirementBanner is true", () => {
    const html = renderSettingsPage({
      ...defaults,
      showRetirementBanner: true,
    });
    expect(html).toContain("API key was retired");
  });

  it("omits the retirement banner by default", () => {
    const html = renderSettingsPage(defaults);
    expect(html).not.toContain("API key was retired");
  });

  it("renders the email-alerts section with the checkbox checked when enabled", () => {
    const html = renderSettingsPage(defaults);
    expect(html).toContain("Email Alerts");
    expect(html).toContain('name="enabled" checked');
    expect(html).toContain("/dashboard/settings/email-alerts");
  });

  it("renders the checkbox unchecked when email alerts are disabled", () => {
    const html = renderSettingsPage({
      ...defaults,
      emailAlertsEnabled: false,
    });
    expect(html).toContain('name="enabled" >');
    expect(html).not.toContain('name="enabled" checked');
  });
});

describe("renderApiKeysPage", () => {
  const baseProps = {
    email: "user@example.com",
    keys: [],
    justCreated: null as string | null,
    showRetirementBanner: false,
  };

  it("renders an empty-state message when the user has no keys", () => {
    const html = renderApiKeysPage(baseProps);
    expect(html).toContain("No API keys yet");
    expect(html).toContain("Generate API Key");
  });

  it("lists keys by prefix + name + status", () => {
    const html = renderApiKeysPage({
      ...baseProps,
      keys: [
        {
          id: "k1",
          name: "ci-pipeline",
          prefix: "dmk_abcd1234",
          createdAt: "2026-04-01",
          lastUsedAt: "2026-04-18",
          revoked: false,
        },
      ],
    });
    expect(html).toContain("ci-pipeline");
    expect(html).toContain("dmk_abcd1234");
    expect(html).toContain("Active");
    expect(html).toContain("Revoke");
  });

  it("renders revoked keys without a Revoke button", () => {
    const html = renderApiKeysPage({
      ...baseProps,
      keys: [
        {
          id: "k1",
          name: null,
          prefix: "dmk_abcd1234",
          createdAt: "2026-04-01",
          lastUsedAt: null,
          revoked: true,
        },
      ],
    });
    expect(html).toContain("Revoked");
    expect(html).not.toContain("/api-keys/revoke");
  });

  it("shows the just-created banner only when justCreated is set", () => {
    const raw = `dmk_${"x".repeat(32)}`;
    const html = renderApiKeysPage({ ...baseProps, justCreated: raw });
    expect(html).toContain("Save this key now");
    expect(html).toContain(raw);
  });

  it("escapes the raw key in the banner to prevent HTML injection", () => {
    const raw = "dmk_<script>";
    const html = renderApiKeysPage({ ...baseProps, justCreated: raw });
    expect(html).toContain("dmk_&lt;script&gt;");
  });

  it("renders the retirement banner when showRetirementBanner is true", () => {
    const html = renderApiKeysPage({
      ...baseProps,
      showRetirementBanner: true,
    });
    expect(html).toContain("old API key was retired");
  });
});
