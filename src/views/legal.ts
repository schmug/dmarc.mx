import { LEGAL_ENTITY, venueText } from "../shared/legal-entity.js";
import { generateCreature } from "./components.js";
import { page } from "./html.js";

// Voice: first person ("I") throughout. DMarcus is used as the operator
// placeholder until the LLC is formed; at that point "DMarcus"/"I" flip to
// the entity name and "we".

const LAST_UPDATED = "2026-06-15";

export function renderPrivacyPage(): string {
  const body = `<main class="breakdown">
  <div class="report-nav">
    <a href="/">${generateCreature("sm")} Home</a>
  </div>
  <h1 class="rubric-title">Privacy Policy</h1>
  <p class="rubric-intro"><em>Last updated: ${LAST_UPDATED}</em></p>

  <div class="bd-card">
    <div class="bd-card-title">Who I am</div>
    <div class="bd-card-body">
      <p class="tier-text">DMarcus runs <strong>dmarcheck</strong> &mdash; the hosted email-security scanner at <code>dmarc.mx</code>. The self-hosted OSS project (<a href="https://github.com/schmug/dmarcheck">github.com/schmug/dmarcheck</a>) is yours to run under MIT; this policy covers the hosted service only.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">What I collect</div>
    <div class="bd-card-body">
      <p class="tier-text">When you use <code>dmarc.mx</code>:</p>
      <ul>
        <li><strong>The domain you scan</strong> and its public DNS records.</li>
        <li><strong>Your IP address</strong>, briefly, for rate limiting.</li>
        <li><strong>Your email address</strong> &mdash; only if you have a Pro account. I need it to log you in, send alerts you asked for, and contact you about your account.</li>
        <li><strong>Your subscription state</strong> from Stripe: subscription ID, plan, status, period end. Stripe holds the actual payment method; I never see your card number.</li>
        <li><strong>Scan history and watchlist</strong> &mdash; only if you have a Pro account and added domains yourself.</li>
        <li><strong>Error telemetry</strong> via Sentry, when the service crashes.</li>
        <li><strong>Anonymized page views</strong> via Cloudflare Web Analytics &mdash; cookieless beacon, no cross-site tracking, no per-user profile. Skipped on <code>/dashboard/*</code>, <code>/auth/*</code>, and webhook endpoints.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Why</div>
    <div class="bd-card-body">
      <ul>
        <li>Scan &rarr; show you the result.</li>
        <li>IP address &rarr; stop one caller from drowning everyone.</li>
        <li>Email &rarr; log you in, send alerts you asked for, contact you about billing.</li>
        <li>Stripe subscription state &rarr; run Pro features, let you cancel.</li>
        <li>Scan history and watchlist &rarr; run the Pro features you paid for.</li>
        <li>Error telemetry &rarr; fix bugs.</li>
        <li>Page views &rarr; know which pages are worth improving.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">How long I keep it</div>
    <div class="bd-card-body">
      <ul>
        <li><strong>Free, anonymous scans:</strong> not stored after the scan completes.</li>
        <li><strong>Pro scan history and watchlist:</strong> kept while your account is active. Deleted immediately when you close your account, or within 30 days on request.</li>
        <li><strong>Account email:</strong> same as above.</li>
        <li><strong>Stripe billing records:</strong> Stripe retains these to comply with US financial-record law (typically 7 years). I delete my local copy on account closure.</li>
        <li><strong>Error telemetry:</strong> 90 days, then purged by Sentry.</li>
        <li><strong>Page views (Cloudflare Web Analytics):</strong> aggregated only, no per-user record to delete.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Who I share it with</div>
    <div class="bd-card-body">
      <p class="tier-text">I use a short list of subprocessors to run the service. <strong>I'm not using this to train AI, selling your data, or sending it to advertisers.</strong></p>
      <ul>
        <li><strong>Cloudflare</strong> &mdash; hosting, DNS, edge compute, D1 database, Web Analytics</li>
        <li><strong>WorkOS</strong> &mdash; account login</li>
        <li><strong>Stripe</strong> &mdash; billing</li>
        <li><strong>Cloudflare Email Sending</strong> &mdash; alerts, receipts, login links</li>
        <li><strong>Sentry</strong> &mdash; error telemetry</li>
      </ul>
      <p class="tier-text" style="margin-top:12px">If I add or swap a subprocessor, I'll update this list and email Pro users at least 14 days ahead.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Your rights</div>
    <div class="bd-card-body">
      <ul>
        <li><strong>Export your data</strong> &mdash; email <a href="mailto:support@dmarc.mx">support@dmarc.mx</a> and I'll send your scan history and watchlist as JSON within 30 days.</li>
        <li><strong>Delete your account</strong> &mdash; from your dashboard settings. After you re-confirm your login and type a confirmation, I erase everything I hold <strong>immediately</strong>: your watchlist, scan history, alerts, API keys, webhooks, and your WorkOS login identity. Any active subscription is cancelled. There is no grace period &mdash; it cannot be undone. Stripe keeps its own billing records per law.</li>
        <li><strong>Stop getting emails</strong> &mdash; unsubscribe from any email footer, or toggle alerts off in your dashboard.</li>
        <li><strong>Ask a question</strong> &mdash; <a href="mailto:support@dmarc.mx">support@dmarc.mx</a>.</li>
      </ul>
      <p class="tier-text" style="margin-top:12px">If you're in the EU/UK, California, or any jurisdiction with statutory privacy rights (GDPR, UK GDPR, CCPA/CPRA, etc.), you have the full set of rights that law gives you. Nothing here overrides a statutory right.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Cookies</div>
    <div class="bd-card-body">
      <ul>
        <li><strong>Session cookie</strong> when you log in (required).</li>
        <li><strong>Theme preference</strong> (light/dark) in <code>localStorage</code>.</li>
      </ul>
      <p class="tier-text" style="margin-top:12px">That's the whole list. No advertising cookies, no third-party tracking.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Children</div>
    <div class="bd-card-body">
      <p class="tier-text">dmarcheck isn't aimed at anyone under 13. If you're under 13, please don't sign up.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Changes</div>
    <div class="bd-card-body">
      <p class="tier-text">If I change how I handle your data in a way that affects you materially, I'll email Pro users at least 14 days ahead. The "Last updated" date tracks minor edits.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Contact</div>
    <div class="bd-card-body">
      <p class="tier-text"><a href="mailto:support@dmarc.mx">support@dmarc.mx</a></p>
    </div>
  </div>

  <div style="text-align:center;margin-top:2rem;margin-bottom:1rem">
    <a href="/" class="rubric-cta">Scan a domain &rarr;</a>
  </div>
</main>`;

  return page({
    title: "Privacy Policy — dmarcheck",
    path: "/legal/privacy",
    description:
      "How dmarcheck collects, uses, and retains your data. Short, first-person, no dark patterns.",
    body,
  });
}

const TERMS_EFFECTIVE_DATE = "2026-10-03";

export function renderTermsPage(): string {
  const { operatorName, entityType, governingState } = LEGAL_ENTITY;
  const card = (title: string, inner: string) => `  <div class="bd-card">
    <div class="bd-card-title">${title}</div>
    <div class="bd-card-body">
      ${inner}
    </div>
  </div>`;

  const body = `<main class="breakdown">
  <div class="report-nav">
    <a href="/">${generateCreature("sm")} Home</a>
  </div>
  <h1 class="rubric-title">Terms of Service</h1>
  <p class="rubric-intro"><em>Effective date: ${TERMS_EFFECTIVE_DATE}</em></p>

${card(
  "Who operates the service",
  `<p class="tier-text"><strong>dmarcheck</strong> at <code>dmarc.mx</code> is operated by ${operatorName}, a ${entityType} (&ldquo;I&rdquo;). By using the hosted service you agree to these Terms. The self-hosted OSS project is licensed separately under MIT; these Terms cover the hosted service only. How I handle your data is in the <a href="/legal/privacy">Privacy Policy</a>.</p>`,
)}

${card(
  "Acceptable use",
  `<p class="tier-text">You may scan any domain, because the DNS records I read are public. Don't abuse the service: no evading or circumventing rate limits, no attacks on the service or its infrastructure, no using it to harass others, and no automated use beyond the documented API and your plan's limits. I may block traffic that does.</p>`,
)}

${card(
  "Availability",
  `<p class="tier-text">The free tier is provided as-is, with no SLA. Pro is best-effort: I aim to keep it running and rescans on schedule, but I don't promise uninterrupted service.</p>`,
)}

${card(
  "Pro subscription",
  `<p class="tier-text">Pro costs $9/mo, billed monthly through Stripe. Cancel anytime in the Stripe Customer Portal; access continues until the end of the paid period. For a full refund within 30 days of a charge, email <a href="mailto:support@dmarc.mx">support@dmarc.mx</a>. See <a href="/pricing">Pricing</a>.</p>`,
)}

${card(
  "Account termination",
  `<p class="tier-text">You can close your account at any time from your dashboard settings. I may suspend or terminate an account for abuse or non-payment.</p>`,
)}

${card(
  "Disclaimer of warranties",
  `<p class="tier-text">The service and its scan results are provided &ldquo;as is&rdquo; and &ldquo;as available,&rdquo; without warranties of any kind, express or implied, including merchantability, fitness for a particular purpose, accuracy, and non-infringement. Scan grades are informational and not a guarantee of email deliverability or security.</p>`,
)}

${card(
  "Limitation of liability",
  `<p class="tier-text">To the maximum extent permitted by law, my total liability for any claim relating to the service is limited to the fees you paid me in the 12 months before the claim arose.</p>`,
)}

${card(
  "Governing law",
  `<p class="tier-text">These Terms are governed by the laws of the State of ${governingState}, United States. Any dispute will be brought in ${venueText()}.</p>`,
)}

${card(
  "Changes",
  `<p class="tier-text">If I change these Terms, I'll post the new version here with an updated effective date.</p>`,
)}

${card(
  "Contact",
  `<p class="tier-text"><a href="mailto:support@dmarc.mx">support@dmarc.mx</a> &middot; <a href="/legal/privacy">Privacy Policy</a></p>`,
)}

  <div style="text-align:center;margin-top:2rem;margin-bottom:1rem">
    <a href="/" class="rubric-cta">Scan a domain &rarr;</a>
  </div>
</main>`;

  return page({
    title: "Terms of Service — dmarcheck",
    path: "/legal/terms",
    description:
      "Terms of Service for the dmarcheck hosted service at dmarc.mx. Short, first-person, plain language.",
    body,
  });
}
