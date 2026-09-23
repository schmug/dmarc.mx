import { Hono } from "hono";
import type { Env } from "../env.js";
import {
  markdownResponse,
  wantsMarkdown,
} from "../shared/content-negotiation.js";
import { parseScoringConfig } from "../shared/scoring-config.js";
import { renderLandingPage, renderScoringRubric } from "../views/html.js";
import {
  renderLearnBimi,
  renderLearnDane,
  renderLearnDkim,
  renderLearnDmarc,
  renderLearnDnssec,
  renderLearnHub,
  renderLearnMtaSts,
  renderLearnSecurityTxt,
  renderLearnSpf,
  renderLearnTlsRpt,
} from "../views/learn.js";
import { renderPrivacyPage } from "../views/legal.js";
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
