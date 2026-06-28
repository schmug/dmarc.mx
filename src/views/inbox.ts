// HTML for inbound test-email scanning (issue #417).
//
// Two surfaces: the issuance page (GET /check/email), which shows the one-time
// address + send instructions and opens the SSE result stream, and the verdict
// card pushed over that stream when the message arrives. Every dynamic value —
// including the fully attacker-controlled message headers — goes through esc().

import type { VerdictRecord } from "../inbox/store.js";
import { inboxAddress } from "../inbox/tokens.js";
import { esc, generateCreature, navLoginButton } from "./components.js";
import { page } from "./html.js";

// Maps a verdict keyword to a status class for colouring. Unknown/absent values
// fall back to a neutral class.
function verdictClass(value: string | null): string {
  if (value === "pass") return "inbox-v-pass";
  if (value === "fail" || value === "permerror") return "inbox-v-fail";
  if (!value || value === "none") return "inbox-v-none";
  return "inbox-v-warn";
}

function verdictRow(label: string, value: string | null): string {
  return `<div class="inbox-verdict-row"><span class="inbox-verdict-label">${esc(label)}</span><span class="inbox-verdict-value ${verdictClass(value)}">${esc(value ?? "unknown")}</span></div>`;
}

/**
 * The verdict card rendered when a test message arrives. Pushed (pre-escaped)
 * inside the SSE `result` event's `html` field; the client inserts it via
 * DOMParser, so escaping here is the XSS boundary for the attacker-controlled
 * header values.
 */
export function renderInboxVerdict(rec: VerdictRecord): string {
  const selector = rec.dkim_selector
    ? `<div class="inbox-verdict-row"><span class="inbox-verdict-label">DKIM selector</span><span class="inbox-verdict-value">${esc(rec.dkim_selector)}${
        rec.dkim_domain ? esc(` (${rec.dkim_domain})`) : ""
      }</span></div>`
    : "";
  const fromLine = rec.from
    ? `<p class="inbox-verdict-from">From: <code>${esc(rec.from)}</code> <span class="inbox-verdict-hint">(envelope sender — spoofable)</span></p>`
    : "";
  const raw = rec.auth_results
    ? `<details class="inbox-verdict-raw"><summary>Authentication-Results header</summary><pre>${esc(rec.auth_results)}</pre></details>`
    : "";
  return `<div class="inbox-verdict-card">
  <h2>Message received ${generateCreature("sm", "content")}</h2>
  ${fromLine}
  <div class="inbox-verdict-grid">
    ${verdictRow("SPF", rec.spf)}
    ${verdictRow("DKIM", rec.dkim)}
    ${verdictRow("DMARC", rec.dmarc)}
    ${verdictRow("Alignment", rec.alignment)}
    ${selector}
  </div>
  ${raw}
  <p class="inbox-verdict-time">Received ${esc(rec.received_at)}</p>
  <p class="inbox-verdict-note">We trust Cloudflare's upstream authentication check for this verdict. Cryptographic DKIM re-verification is not yet performed.</p>
  <a href="/check/email" class="inbox-again">Test another message →</a>
</div>`;
}

const INBOX_BOUNCE_NOTE = `If the domain you're testing publishes DMARC <code>p=reject</code> and your message hard-fails authentication, Cloudflare may reject it at the mail server before it reaches us — so a badly-misconfigured domain can bounce instead of showing a "fail" here.`;

// Static client bootstrap. Reads the token from a data-* attribute (never
// interpolated into this script string) and streams the verdict. The token is
// strict hex, but the data-attribute pattern keeps user-derived values out of
// inline script regardless — matching renderStreamingLoading.
const INBOX_STREAM_SCRIPT = `
(function() {
  var root = document.querySelector('[data-inbox-token]');
  if (!root) return;
  var token = root.getAttribute('data-inbox-token');
  if (!token) return;
  var statusEl = document.getElementById('inbox-status');
  var resultEl = document.getElementById('inbox-result');
  var parser = new DOMParser();

  function setStatus(text) {
    if (!statusEl) return;
    var p = statusEl.querySelector('p');
    if (p) p.textContent = text;
  }
  function stopSpinner() {
    if (!statusEl) return;
    var sp = statusEl.querySelector('.spinner');
    if (sp) sp.style.display = 'none';
  }

  var source = new EventSource('/api/check/email/stream?token=' + encodeURIComponent(token));

  source.addEventListener('waiting', function() {
    setStatus('Waiting for your message…');
  });

  source.addEventListener('result', function(e) {
    source.close();
    if (statusEl) statusEl.style.display = 'none';
    var data;
    try { data = JSON.parse(e.data); } catch (err) { return; }
    if (resultEl && data.html) {
      var doc = parser.parseFromString(data.html, 'text/html');
      var node = doc.body.firstElementChild;
      if (node) resultEl.appendChild(node);
    }
  });

  source.addEventListener('closed', function(e) {
    source.close();
    stopSpinner();
    var data = {};
    try { data = JSON.parse(e.data); } catch (err) {}
    if (data.status === 'timeout') {
      setStatus('No message arrived within 30 minutes. Refresh to get a new address.');
    } else {
      setStatus('This test address has expired. Refresh to get a new one.');
    }
  });

  source.addEventListener('error', function() {
    setStatus('Connection interrupted. Refresh to try again.');
  });
})();
`;

/** The GET /check/email issuance page for a freshly-minted token. */
export function renderInboxScanPage(token: string): string {
  const address = inboxAddress(token);
  const body = `<main class="report" data-inbox-token="${esc(token)}">
  <div class="report-nav">
    <a href="/">${generateCreature("sm")} dmarcheck</a>
    <span class="report-nav-spacer"></span>
    ${navLoginButton()}
  </div>
  <div class="stream-header">
    <h1 class="domain-name">Test a real message</h1>
    <p class="inbox-intro">Send an email to this one-time address and we'll show you exactly how your message authenticated — the real SPF, DKIM, and DMARC results, including the actual DKIM selector your mail server used.</p>
  </div>
  <div class="inbox-address-card">
    <label for="inbox-address">Your test address — valid for 30 minutes</label>
    <div class="inbox-address-row">
      <code id="inbox-address" class="inbox-address">${esc(address)}</code>
      <button type="button" class="copy-btn" data-copy="${esc(address)}">Copy</button>
    </div>
  </div>
  <ol class="inbox-steps">
    <li>Send a normal email <strong>from the domain you want to test</strong> to the address above.</li>
    <li>Keep this page open — the result appears automatically when your message arrives.</li>
  </ol>
  <div class="inbox-status" id="inbox-status" role="status" aria-live="polite">
    <div class="spinner" aria-hidden="true"></div>
    <p>Waiting for your message…</p>
  </div>
  <div id="inbox-result"></div>
  <div class="inbox-note">
    <p><strong>Heads up:</strong> ${INBOX_BOUNCE_NOTE}</p>
    <p>Inbound messages are used only to read the authentication verdict, then expire within 30 minutes. We never publish or index them. This address is a one-time capability — don't share it.</p>
  </div>
</main>
<script>${INBOX_STREAM_SCRIPT}</script>`;

  return page({
    title: "Test a real message — dmarcheck",
    path: "/check/email",
    description:
      "Send a real test email and see the actual SPF, DKIM, and DMARC authentication results for your message, including the DKIM selector used.",
    noindex: true,
    body,
  });
}
