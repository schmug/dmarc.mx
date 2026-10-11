import { learnCta, renderLearnPage } from "./learn.js";

const TITLE = "Gmail, Yahoo & Outlook sender requirements — check your domain";
const DESCRIPTION =
  "What Gmail, Yahoo, and Outlook.com require from bulk senders: SPF, DKIM, DMARC, one-click unsubscribe, and a spam rate under 0.3%. Check your domain.";

export function renderSenderRequirementsPage(): string {
  const body = `
  <p class="rubric-intro">If you send email to people with Gmail, Yahoo, or Outlook.com addresses, those providers now publish rules your domain has to meet. I wrote this page to lay the rules out plainly and show which dmarcheck check verifies each one.</p>

  <div class="bd-card">
    <div class="bd-card-title">Gmail and Yahoo (since February 2024)</div>
    <div class="bd-card-body">
      <p class="tier-text">The strictest rules apply if you send roughly 5,000 or more messages a day to their users. For those bulk senders:</p>
      <ul>
        <li>Set up both SPF and DKIM for your sending domain.</li>
        <li>Publish a DMARC record with a policy of at least <code>p=none</code>.</li>
        <li>Align the From domain with the domain that passes SPF or DKIM.</li>
        <li>Support one-click unsubscribe (RFC 8058) on marketing and subscribed mail.</li>
        <li>Keep your spam rate under 0.3%.</li>
        <li>Use valid forward and reverse DNS (a PTR record) for your sending IPs.</li>
        <li>Send over a TLS connection.</li>
      </ul>
      <p class="tier-text">Every sender, whatever the volume, needs SPF or DKIM authentication and a valid PTR record on its sending IPs.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Microsoft Outlook.com (since May 2025)</div>
    <div class="bd-card-body">
      <p class="tier-text">For the same 5,000+ messages a day volume, Outlook.com requires SPF, DKIM, and DMARC with a policy of at least <code>p=none</code>, with the From domain aligned with SPF or DKIM.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Why p=none meets the rule but is not enough</div>
    <div class="bd-card-body">
      <p class="tier-text">A <code>p=none</code> policy satisfies the providers' minimum, but it only asks receivers to report failures. It does not ask them to block anything, so anyone can still send mail that spoofs your domain. That is why dmarcheck grades <code>p=none</code> an F.</p>
      <p class="tier-text">The fix is to read your DMARC reports, fix the legitimate sources that fail, then move to <code>p=quarantine</code> and finally <code>p=reject</code>. The <a href="/learn/dmarc">DMARC guide</a> walks through each step.</p>
    </div>
  </div>

  <div class="bd-card">
    <div class="bd-card-title">Requirement checklist</div>
    <div class="bd-card-body">
      <table class="learn-table">
        <thead><tr><th>Requirement</th><th>dmarcheck check</th></tr></thead>
        <tbody>
          <tr><td>SPF record</td><td><a href="/learn/spf">SPF</a></td></tr>
          <tr><td>DKIM signing</td><td><a href="/learn/dkim">DKIM</a></td></tr>
          <tr><td>DMARC record, at least <code>p=none</code></td><td><a href="/learn/dmarc">DMARC</a></td></tr>
          <tr><td>From domain aligned with SPF or DKIM</td><td>DMARC (alignment tags) with SPF and DKIM</td></tr>
          <tr><td>TLS for mail delivery</td><td>MX (inbound TLS support)</td></tr>
          <tr><td>Valid PTR on sending IPs</td><td>Not checked yet</td></tr>
          <tr><td>One-click unsubscribe and spam rate under 0.3%</td><td>Not DNS-checkable; see your mailbox provider's postmaster tools</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  ${learnCta("Check your domain against these rules")}
  <p class="tier-text" style="margin-top:12px"><a href="/">Check your domain against these rules</a>. Records drift. Pro rechecks up to 25 domains nightly and emails you when something changes &mdash; <a href="/pricing">$9/mo</a>.</p>`;

  return renderLearnPage({
    protocol: "Sender requirements",
    slug: "sender-requirements",
    title: TITLE,
    headline: "Gmail, Yahoo & Outlook sender requirements",
    description: DESCRIPTION,
    body,
  });
}
