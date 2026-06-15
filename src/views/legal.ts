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
