import { Hono } from "hono";
import type { Env } from "../env.js";
import {
  markdownResponse,
  wantsMarkdown,
} from "../shared/content-negotiation.js";
import { parseScoringConfig } from "../shared/scoring-config.js";
import { renderLandingPage, renderScoringRubric } from "../views/html.js";
import {
  learnCta,
  renderLearnBimi,
  renderLearnDane,
  renderLearnDkim,
  renderLearnDmarc,
  renderLearnDnssec,
  renderLearnHub,
  renderLearnMtaSts,
  renderLearnPage,
  renderLearnSecurityTxt,
  renderLearnSpf,
  renderLearnTlsRpt,
} from "../views/learn.js";
import { FIX_PAGES, type FixPage } from "../views/learn-fixes.js";
import { renderSenderRequirementsPage } from "../views/learn-senders.js";
import { renderSpfLookupsPage } from "../views/learn-spf-lookups.js";
import { renderPrivacyPage, renderTermsPage } from "../views/legal.js";
import {
  renderLandingMarkdown,
  renderLearnHubMarkdown,
  renderMxHubMarkdown,
  renderMxProviderMarkdown,
  renderPricingMarkdown,
  renderPrivacyMarkdown,
  renderScoringRubricMarkdown,
} from "../views/markdown.js";
import { renderMxHub, renderMxProviderPage } from "../views/mx.js";
import { renderPricingPage } from "../views/pricing.js";

// Marketing and content pages — mounted at "/" by src/index.ts (#666). Each
// handler renders a fixed page (HTML, or markdown when `wantsMarkdown`); none
// runs a scan, so none is rate-limited. The only request input read is the
// `/mx/:slug` param, which is a lookup key into a fixed provider table.
export const contentRoutes = new Hono<{ Bindings: Env }>();

contentRoutes.get("/", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderLandingMarkdown());
  return c.html(renderLandingPage());
});

contentRoutes.get("/scoring", (c) => {
  if (wantsMarkdown(c))
    return markdownResponse(
      c,
      renderScoringRubricMarkdown(parseScoringConfig(c.env?.SCORING_CONFIG)),
    );
  return c.html(renderScoringRubric(parseScoringConfig(c.env?.SCORING_CONFIG)));
});

contentRoutes.get("/learn", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderLearnHubMarkdown());
  return c.html(renderLearnHub());
});
contentRoutes.get("/learn/dmarc", (c) => c.html(renderLearnDmarc()));
contentRoutes.get("/learn/spf", (c) => c.html(renderLearnSpf()));
contentRoutes.get("/learn/dkim", (c) => c.html(renderLearnDkim()));
contentRoutes.get("/learn/bimi", (c) => c.html(renderLearnBimi()));
contentRoutes.get("/learn/mta-sts", (c) => c.html(renderLearnMtaSts()));
contentRoutes.get("/learn/security-txt", (c) =>
  c.html(renderLearnSecurityTxt()),
);
contentRoutes.get("/learn/tls-rpt", (c) => c.html(renderLearnTlsRpt()));
contentRoutes.get("/learn/dnssec", (c) => c.html(renderLearnDnssec()));
contentRoutes.get("/learn/dane", (c) => c.html(renderLearnDane()));
contentRoutes.get("/learn/sender-requirements", (c) =>
  c.html(renderSenderRequirementsPage()),
);
contentRoutes.get("/learn/spf-too-many-lookups", (c) =>
  c.html(renderSpfLookupsPage()),
);

function renderFixPage(page: FixPage): string {
  return renderLearnPage({
    protocol: page.protocol,
    slug: page.slug,
    title: page.title,
    headline: page.headline,
    description: page.description,
    body: `${page.body}
  ${learnCta(page.cta)}
  <p class="tier-text" style="margin-top:12px">Records drift when vendors or admins change things. Pro rechecks up to 25 domains nightly and emails you when a grade drops &mdash; <a href="/pricing">$9/mo</a>.</p>`,
  });
}

for (const page of FIX_PAGES) {
  contentRoutes.get(`/learn/${page.slug}`, (c) => c.html(renderFixPage(page)));
}

contentRoutes.get("/mx", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderMxHubMarkdown());
  return c.html(renderMxHub());
});
contentRoutes.get("/mx/:slug", (c) => {
  const slug = c.req.param("slug");
  if (wantsMarkdown(c)) {
    const md = renderMxProviderMarkdown(slug);
    if (!md) return c.notFound();
    return markdownResponse(c, md);
  }
  const html = renderMxProviderPage(slug);
  if (!html) return c.notFound();
  return c.html(html);
});

contentRoutes.get("/pricing", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderPricingMarkdown());
  return c.html(renderPricingPage());
});
contentRoutes.get("/legal/privacy", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderPrivacyMarkdown());
  return c.html(renderPrivacyPage());
});
contentRoutes.get("/legal/terms", (c) => c.html(renderTermsPage()));
