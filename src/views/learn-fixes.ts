export const FIX_MODIFIED = "2026-10-25";

export interface FixPage {
  slug: string;
  protocol: string;
  blurb: string;
  title: string;
  headline: string;
  description: string;
  cta: string;
  body: string;
}

const card = (title: string, html: string): string => `
  <div class="bd-card">
    <div class="bd-card-title">${title}</div>
    <div class="bd-card-body">${html}</div>
  </div>`;

const p = (html: string): string => `<p class="tier-text">${html}</p>`;

export const FIX_PAGES: FixPage[] = [
  {
    slug: "no-dmarc-record",
    protocol: "No DMARC record",
    blurb: "Publish your first DMARC record safely.",
    title: "No DMARC record found — how to add one",
    headline: "No DMARC record found",
    description:
      "Your domain has no DMARC record at _dmarc. Learn what that means for spoofing and deliverability, and publish a safe first record.",
    cta: "Check your DMARC record",
    body: `
  <p class="rubric-intro">Without a DMARC record, receivers have no instruction from you about mail that fails SPF and DKIM, and you get no reports about who is sending as your domain. dmarcheck grades a missing record as an F.</p>
  ${card("Where the record lives", p("DMARC is a TXT record at <code>_dmarc.example.com</code>, not at the bare domain. A record published at the apex is ignored. There must be exactly one record starting with <code>v=DMARC1</code>."))}
  ${card("A safe first record", `${p("Start in monitoring mode so nothing is blocked while you learn who sends for you:")}<pre class="learn-example"><code>_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"</code></pre>${p("The <code>rua</code> address receives daily aggregate reports from large mailbox providers. If the address is on another domain, that domain must authorize it with a <code>example.com._report._dmarc</code> TXT record.")}`)}
  ${card("Then move to enforcement", p('<code>p=none</code> only watches. Once the reports show your real senders passing, move to <code>p=quarantine</code> and then <code>p=reject</code>. The next step is covered in <a href="/learn/dmarc-p-none">DMARC p=none: moving to enforcement</a>.'))}`,
  },
  {
    slug: "dmarc-p-none",
    protocol: "DMARC p=none",
    blurb: "Move from monitoring to quarantine and reject.",
    title: "DMARC p=none — why it still fails and how to enforce",
    headline: "DMARC p=none: moving to enforcement",
    description:
      "A DMARC policy of p=none asks receivers to take no action, so your domain can still be spoofed. A step-by-step path to p=quarantine and p=reject.",
    cta: "Check your DMARC policy",
    body: `
  <p class="rubric-intro"><code>p=none</code> tells receivers to deliver mail that fails DMARC as if nothing happened. It is useful for collecting reports, but it does not stop anyone spoofing your domain. That is why dmarcheck grades it an F, even though it satisfies the bulk-sender rules at Gmail and Yahoo.</p>
  ${card("Before you enforce", `<ol class="learn-steps"><li><strong>Read your aggregate reports</strong> (<code>rua</code>) for at least a few weeks. List every service that sends as your domain.</li><li><strong>Make each one pass with alignment.</strong> Usually that means DKIM signing with your domain, or SPF with a return-path on your domain. See <a href="/learn/dmarc-alignment">DMARC alignment</a>.</li><li><strong>Fix or retire the rest.</strong> Unknown sources that fail are what enforcement is meant to block.</li></ol>`)}
  ${card(
    "Roll out gradually",
    `${p("The <code>pct</code> tag applies the policy to a share of failing mail. A common path:")}<pre class="learn-example"><code>v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-reports@example.com
v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com
v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com</code></pre>${p("Keep the <code>rua</code> reports flowing at every step, and watch them after each change.")}`,
  )}
  ${card("Subdomains", p("Without an <code>sp</code> tag, subdomains inherit <code>p</code>. If you are not ready to enforce on subdomains, set <code>sp=none</code> explicitly and revisit it later."))}`,
  },
  {
    slug: "dmarc-alignment",
    protocol: "DMARC alignment",
    blurb: "Why DMARC fails when SPF and DKIM pass.",
    title: "DMARC fails but SPF and DKIM pass — alignment explained",
    headline: "DMARC fails even though SPF and DKIM pass",
    description:
      "DMARC needs SPF or DKIM to pass for a domain that matches the visible From address. Learn how alignment works and how to fix third-party senders.",
    cta: "Check your domain",
    body: `
  <p class="rubric-intro">A passing SPF or DKIM check only counts for DMARC when it passes for the same domain as the From address people see. This is called alignment, and it is the most common reason a third-party sender fails DMARC.</p>
  ${card("What has to match", `<ul class="learn-pitfalls"><li><strong>SPF</strong> checks the envelope sender (return-path). It aligns only if that domain matches the From domain.</li><li><strong>DKIM</strong> checks the <code>d=</code> domain in the signature. It aligns only if <code>d=</code> matches the From domain.</li></ul>${p("DMARC passes if either one aligns. With the default relaxed mode, <code>mail.example.com</code> aligns with <code>example.com</code>. With <code>aspf=s</code> or <code>adkim=s</code> the domains must match exactly.")}`)}
  ${card("The usual cause", p("An email platform sends with its own return-path and signs with its own domain, for example <code>d=vendor-mail.com</code>. Both checks pass, but for the vendor's domain, not yours, so DMARC fails."))}
  ${card("How to fix it", `<ol class="learn-steps"><li><strong>Set up custom DKIM</strong> in the vendor's settings. They give you CNAME or TXT records so they can sign as <code>d=example.com</code>. This is the most robust fix.</li><li><strong>Set a custom return-path</strong> (often called a bounce or MAIL FROM domain) on a subdomain you own, so SPF aligns too.</li><li><strong>Check the result</strong> in your DMARC aggregate reports, or send a test message to the <a href="/check/email">email check</a>.</li></ol>`)}`,
  },
  {
    slug: "spf-plus-all",
    protocol: "SPF +all",
    blurb: "Why +all authorizes every server on the internet.",
    title: "SPF +all — why it is dangerous and what to use instead",
    headline: "SPF +all authorizes everyone",
    description:
      "An SPF record ending in +all lets any server on the internet pass SPF for your domain. Learn the difference between +all, ?all, ~all and -all.",
    cta: "Check your SPF record",
    body: `
  <p class="rubric-intro">The <code>all</code> mechanism decides what happens to every sender your record does not list. With <code>+all</code>, the answer is pass: any server anywhere can send as your domain and pass SPF.</p>
  ${card("The four qualifiers", `<ul class="learn-pitfalls"><li><code>-all</code> &mdash; fail. Unlisted senders are not authorized. The strongest setting.</li><li><code>~all</code> &mdash; softfail. Unlisted senders are suspicious. Common and acceptable when DMARC is enforced.</li><li><code>?all</code> &mdash; neutral. No statement at all, so it gives no protection.</li><li><code>+all</code> (or a bare <code>all</code>) &mdash; pass. Every sender is authorized.</li></ul>`)}
  ${card("How to fix it", `${p("List your real senders, then end the record with <code>~all</code> or <code>-all</code>:")}<pre class="learn-example"><code>example.com.  TXT  "v=spf1 include:_spf.google.com -all"</code></pre>${p('If you are not sure who sends for you, publish a DMARC record with reports first (<a href="/learn/no-dmarc-record">how</a>) and use the reports to build the list.')}`)}
  ${card("One record, at the end", p('<code>all</code> must be the last term. Anything after it is ignored. See also <a href="/learn/multiple-spf-records">multiple SPF records</a> and <a href="/learn/spf-too-many-lookups">too many DNS lookups</a>.'))}`,
  },
  {
    slug: "multiple-spf-records",
    protocol: "Multiple SPF records",
    blurb: "Merge duplicate v=spf1 records into one.",
    title: "Multiple SPF records found — how to merge them",
    headline: "Multiple SPF records: permerror",
    description:
      "Publishing more than one v=spf1 TXT record makes SPF return permerror under RFC 7208. Learn how to merge them into a single valid record.",
    cta: "Check your SPF record",
    body: `
  <p class="rubric-intro">RFC 7208 section 4.5 is strict: if a domain has more than one TXT record starting with <code>v=spf1</code>, SPF evaluation returns <code>permerror</code>. This often happens when a new vendor's setup guide says "add this SPF record" and it gets added next to the old one.</p>
  ${card(
    "How to merge",
    `${p("Combine the mechanisms into one record, keep a single <code>v=spf1</code> at the start and a single <code>all</code> at the end:")}<pre class="learn-example"><code>Before:
"v=spf1 include:_spf.google.com ~all"
"v=spf1 include:sendgrid.net ~all"

After:
"v=spf1 include:_spf.google.com include:sendgrid.net ~all"</code></pre>`,
  )}
  ${card("Watch the lookup budget", p('Merging adds the includes together, and the 10-lookup limit still applies. If the merged record goes over, read <a href="/learn/spf-too-many-lookups">SPF too many DNS lookups</a>.'))}
  ${card("Other TXT records are fine", p("Only records that start with <code>v=spf1</code> count. Verification strings for other services can sit alongside your SPF record."))}`,
  },
  {
    slug: "dkim-record-not-found",
    protocol: "DKIM not found",
    blurb: "Find your DKIM selector and publish the key.",
    title: "DKIM record not found — finding your selector",
    headline: "DKIM record not found",
    description:
      "DKIM keys live at selector._domainkey. Learn how to find the selector your mail provider uses, publish the key, and confirm signing works.",
    cta: "Check your DKIM",
    body: `
  <p class="rubric-intro">DKIM public keys are published at <code>&lt;selector&gt;._domainkey.example.com</code>. There is no way to list every selector from DNS, so checkers, dmarcheck included, try common ones. "Not found" can mean DKIM is missing, or that your provider uses a selector nobody guessed.</p>
  ${card("Find your selector", `<ol class="learn-steps"><li><strong>Open a message you sent</strong> and view the original headers.</li><li><strong>Find the <code>DKIM-Signature</code> header.</strong> The <code>s=</code> tag is the selector and <code>d=</code> is the signing domain.</li><li><strong>Or send a message to the <a href="/check/email">email check</a></strong>, which reads the signature for you.</li></ol>`)}
  ${card("Turn signing on", p('Most providers do not sign with your domain until you enable it. Google Workspace and Microsoft 365 both have a DKIM setting in the admin console that gives you the record to publish (a TXT key or CNAMEs). Third-party senders have a similar "domain authentication" step.'))}
  ${card("Why it matters", p('DKIM survives forwarding, where SPF often breaks, so an aligned DKIM signature is the most reliable way to pass DMARC. See <a href="/learn/dmarc-alignment">DMARC alignment</a>.'))}`,
  },
  {
    slug: "mta-sts-policy-missing",
    protocol: "MTA-STS missing",
    blurb: "Publish an MTA-STS policy in testing mode first.",
    title: "MTA-STS policy not found — how to set it up",
    headline: "MTA-STS policy not found",
    description:
      "MTA-STS tells sending servers to require TLS when delivering to you. Set up the _mta-sts TXT record and policy file, starting in testing mode.",
    cta: "Check your MTA-STS",
    body: `
  <p class="rubric-intro">Without MTA-STS (RFC 8461), a sending server will usually fall back to plain text if TLS to your MX fails, which an attacker on the path can force. MTA-STS lets you publish a policy that says "only deliver over valid TLS".</p>
  ${card(
    "The two parts",
    `${p("A TXT record that announces the policy and its version:")}<pre class="learn-example"><code>_mta-sts.example.com.  TXT  "v=STSv1; id=20261025"</code></pre>${p("And a policy file served over HTTPS at <code>https://mta-sts.example.com/.well-known/mta-sts.txt</code>, with a valid certificate:")}<pre class="learn-example"><code>version: STSv1
mode: testing
mx: mail.example.com
max_age: 86400</code></pre>`,
  )}
  ${card("Roll it out", `<ol class="learn-steps"><li><strong>Start with <code>mode: testing</code></strong> and add a <a href="/learn/tls-rpt">TLS-RPT</a> record so you get failure reports.</li><li><strong>Make sure every <code>mx:</code> line matches</strong> your MX hosts and that their certificates are valid.</li><li><strong>Switch to <code>mode: enforce</code></strong> and raise <code>max_age</code> (a week or more). Change the <code>id</code> in the TXT record whenever the file changes.</li></ol>`)}
  ${card("More detail", p('The <a href="/learn/mta-sts">MTA-STS guide</a> covers each field and common mistakes.'))}`,
  },
];
