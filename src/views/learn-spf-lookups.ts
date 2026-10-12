import { learnCta, renderLearnPage } from "./learn.js";

const TITLE = "SPF PermError: too many DNS lookups — how to fix it";
const DESCRIPTION =
  "Your SPF record exceeds the 10 DNS lookup limit in RFC 7208 and returns permerror. Learn what counts, why it happens, and how to fix it.";

export function renderSpfLookupsPage(): string {
  const body = `
  <p class="rubric-intro">If a receiver reports <code>permerror</code> for your SPF record, the most common cause is the 10 DNS lookup limit. I wrote this page to explain exactly what counts toward the limit and how to get back under it.</p>

  <div class="bd-card">
    <div class="bd-card-title">The rule: 10 lookups, counted recursively</div>
    <div class="bd-card-body">
      <p class="tier-text">RFC 7208 section 4.6.4 allows at most 10 DNS-querying terms while evaluating an SPF record. The terms that count are <code>include</code>, <code>a</code>, <code>mx</code>, <code>ptr</code>, <code>exists</code>, and the <code>redirect</code> modifier. The count is recursive: every term inside an included record counts too, so one <code>include</code> can cost several lookups.</p>
      <p class="tier-text">The <code>ip4</code>, <code>ip6</code>, and <code>all</code> mechanisms do not count. They need no DNS query.</p>
      <p class="tier-text">The RFC also sets a limit of 2 void lookups: queries that return no records or NXDOMAIN. A record that points at two dead hostnames can fail even when it is under 10 lookups.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">What happens when you go over</div>
    <div class="bd-card-body">
      <p class="tier-text">Exceeding either limit makes SPF evaluation return <code>permerror</code>. Most receivers treat a permerror as an SPF fail. Since SPF cannot pass, DMARC can then only pass through an aligned DKIM signature. If a sender does not sign with DKIM, its mail fails DMARC.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Common causes</div>
    <div class="bd-card-body">
      <ul>
        <li><strong>Stacked SaaS includes.</strong> Google Workspace, Microsoft 365, marketing platforms, and helpdesk tools each add an <code>include</code>, and many of them nest further includes.</li>
        <li><strong>Old vendors.</strong> Includes for services you stopped using still count.</li>
        <li><strong><code>mx</code> and <code>a</code> mechanisms.</strong> Each costs a lookup, and <code>mx</code> can cost more because the MX hosts are resolved too.</li>
        <li><strong><code>ptr</code>.</strong> It is deprecated by RFC 7208, slow, and counts against the limit. Remove it.</li>
      </ul>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">How to fix it, in order of preference</div>
    <div class="bd-card-body">
      <ol class="learn-steps">
        <li><strong>Remove includes for services you no longer use.</strong> This is free and often enough.</li>
        <li><strong>Move bulk and marketing senders to a subdomain</strong> such as <code>mail.example.com</code> with its own SPF record. Each domain gets its own budget of 10.</li>
        <li><strong>Replace <code>a</code> and <code>mx</code> with <code>ip4</code>/<code>ip6</code></strong> where the IPs are stable and you control them.</li>
        <li><strong>Rely on DKIM-aligned DMARC</strong> for vendors that sign your mail, and drop their SPF include.</li>
        <li><strong>Flatten as a last resort.</strong> Flattening replaces includes with the IPs they resolve to. It works, but it breaks silently when a vendor changes its IPs, which is why flattened records need watching.</li>
      </ol>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">How dmarcheck helps</div>
    <div class="bd-card-body">
      <p class="tier-text">dmarcheck counts the lookups in your full include tree and shows which include costs what, so you know where to cut. For background on SPF itself, read the <a href="/learn/spf">SPF guide</a>.</p>
    </div>
  </div>

  ${learnCta("Count your SPF lookups")}
  <p class="tier-text" style="margin-top:12px"><a href="/">Count your SPF lookups</a>. Vendors change their SPF without telling you. Pro rechecks up to 25 domains nightly and emails you when something changes &mdash; <a href="/pricing">$9/mo</a>.</p>`;

  return renderLearnPage({
    protocol: "SPF lookups",
    slug: "spf-too-many-lookups",
    title: TITLE,
    headline: "SPF PermError: too many DNS lookups",
    description: DESCRIPTION,
    body,
  });
}
