import { generateCreature } from "./components.js";
import { page } from "./html.js";

const PRICING_JSON_LD = JSON.stringify({
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Product",
      name: "dmarcheck Pro",
      description:
        "Nightly email-security monitoring for your domains — DMARC, SPF, DKIM, BIMI, MTA-STS, and more. Saved history, grade-drop email alerts, bulk scan, and a higher-rate API key.",
      brand: { "@type": "Brand", name: "dmarcheck" },
      offers: {
        "@type": "Offer",
        url: "https://dmarc.mx/pricing",
        price: "19",
        priceCurrency: "USD",
        availability: "https://schema.org/InStock",
        priceSpecification: {
          "@type": "UnitPriceSpecification",
          price: "19",
          priceCurrency: "USD",
          billingDuration: "P1M",
          unitCode: "MON",
        },
      },
    },
    {
      "@type": "FAQPage",
      mainEntity: [
        {
          "@type": "Question",
          name: "Does the free scanner stay free?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. The scanner, all its analyzers, and the JSON API stay free and open source. Pro adds hosted features — history, monitoring, alerts — not the scan itself.",
          },
        },
        {
          "@type": "Question",
          name: "What counts as nightly?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Once every 24 hours, in the early-UTC-morning window. Every domain on your watchlist gets re-scanned; if the grade drops or a protocol regresses versus the previous scan, you get an email.",
          },
        },
        {
          "@type": "Question",
          name: "How do I cancel?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "One click in the Stripe Customer Portal, linked from your account page. You keep access until the end of the current billing cycle and aren't charged again.",
          },
        },
        {
          "@type": "Question",
          name: "Do you offer refunds?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Email support@dmarc.mx within 30 days of the charge for a full refund. After 30 days, cancel at period end via the Customer Portal.",
          },
        },
        {
          "@type": "Question",
          name: "Can I self-host the paid features?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. The repo is MIT-licensed. Clone it, configure D1, WorkOS, and Stripe bindings, and run the same code with the same features. The hosted tier exists for people who'd rather pay than run it.",
          },
        },
      ],
    },
  ],
});

export function renderPricingPage(): string {
  const body = `<main class="breakdown">
  <div class="report-nav">
    <a href="/">${generateCreature("sm")} Home</a>
  </div>

  <h1 class="rubric-title">Nightly email-security monitoring &mdash; DMARC, SPF, DKIM &amp; more</h1>
  <p class="rubric-intro"><strong>$19/mo.</strong> Free forever for one-off scans.</p>

  <div class="bd-card">
    <div class="bd-card-title">Free &mdash; $0</div>
    <div class="bd-card-body">
      <p class="tier-text">Public scanner, no account needed.</p>
      <ul>
        <li>Unlimited on-demand scans from the web UI</li>
        <li>JSON API: <code>GET /api/check?domain=example.com</code></li>
        <li>10 requests per minute per IP</li>
        <li>All analyzers: DMARC, SPF, DKIM, BIMI, MTA-STS, MX, security.txt, TLS-RPT, DNSSEC, DANE</li>
        <li>Self-hostable &mdash; MIT-licensed, <a href="https://github.com/schmug/dmarcheck">clone &amp; run your own</a></li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Pro &mdash; $19/mo</div>
    <div class="bd-card-body">
      <p class="tier-text">Continuous monitoring for the domains you actually care about.</p>
      <ul>
        <li>Saved scan history with per-domain trend views</li>
        <li>Nightly rescans of your watchlist (up to 25 domains)</li>
        <li>Email alerts on grade drop or protocol regression</li>
        <li>Bulk scan: up to 100 domains per request</li>
        <li>API keys with a 60-request/hour rate limit (6&times; the anonymous ceiling)</li>
        <li>Cancel anytime via Stripe Customer Portal &mdash; access continues until the period ends</li>
        <li>30-day refunds on request &mdash; email <a href="mailto:support@dmarc.mx">support@dmarc.mx</a></li>
      </ul>
      <p class="tier-text" style="margin-top:12px"><strong>Not in Pro (yet):</strong> DMARC aggregate (RUA) report ingestion, team seats or SSO, white-label or custom domain.</p>
      <div style="text-align:center;margin-top:1.25rem;margin-bottom:0.5rem">
        <a href="/dashboard/billing/subscribe" class="rubric-cta">Start Pro &mdash; $19/mo</a>
      </div>
      <p class="tier-text" style="text-align:center;font-size:0.9em;margin-top:0.5rem">Requires a free account. You can sign up and kick the tires before upgrading.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">FAQ</div>
    <div class="bd-card-body">
      <div class="rubric-protocol">
        <h3>Does the free scanner stay free?</h3>
        <p>Yes. The scanner, all its analyzers, and the JSON API stay free and open source. Pro adds hosted features &mdash; history, monitoring, alerts &mdash; not the scan itself.</p>
      </div>
      <div class="rubric-protocol">
        <h3>What counts as "nightly"?</h3>
        <p>Once every 24 hours, in the early-UTC-morning window. Every domain on your watchlist gets re-scanned; if the grade drops or a protocol regresses versus the previous scan, you get an email.</p>
      </div>
      <div class="rubric-protocol">
        <h3>How do I cancel?</h3>
        <p>One click in the Stripe Customer Portal, linked from your account page. You keep access until the end of the current billing cycle and aren't charged again.</p>
      </div>
      <div class="rubric-protocol">
        <h3>Do you offer refunds?</h3>
        <p>Yes &mdash; email <a href="mailto:support@dmarc.mx">support@dmarc.mx</a> within 30 days of the charge for a full refund. After 30 days, cancel at period end via the Customer Portal.</p>
      </div>
      <div class="rubric-protocol">
        <h3>Can I self-host the paid features?</h3>
        <p>Yes. The repo is <a href="https://github.com/schmug/dmarcheck">MIT-licensed</a>. Clone it, configure D1, WorkOS, and Stripe bindings, and run the same code with the same features. The hosted tier exists for people who'd rather pay than run it.</p>
      </div>
      <div class="rubric-protocol">
        <h3>Where's my data stored, and for how long?</h3>
        <p>Cloudflare D1 (US region). Scan results are retained while your account is active and deleted on request or within 30 days of account closure. See the <a href="/legal/privacy">Privacy Policy</a> for full detail.</p>
      </div>
      <div class="rubric-protocol">
        <h3>What about Pro API rate limits?</h3>
        <p>60 requests per hour per API key, versus 10 requests per minute per IP for anonymous callers. If you have a real reason to need more, email <a href="mailto:support@dmarc.mx">support@dmarc.mx</a>.</p>
      </div>
    </div>
  </div>

  <div style="text-align:center;margin-top:2rem;margin-bottom:1rem">
    <a href="/" class="rubric-cta">Scan a domain &rarr;</a>
  </div>

  <div class="learn-link" style="text-align:center">See <a href="/legal/privacy">Privacy</a>. Questions? <a href="mailto:support@dmarc.mx">support@dmarc.mx</a></div>
</main>`;

  return page({
    title: "Pricing — dmarcheck",
    path: "/pricing",
    description:
      "Nightly email-security monitoring (DMARC, SPF, DKIM, BIMI, MTA-STS and more) for $19/mo. Free forever for one-off scans. Cancel anytime via Stripe.",
    jsonLd: PRICING_JSON_LD,
    body,
  });
}
