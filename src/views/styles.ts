export const CSS = `
* { margin: 0; padding: 0; box-sizing: border-box; }
:root {
  color-scheme: light dark;
  --clr-bg: #f4f4f5;
  --clr-surface: #ffffff;
  --clr-border: #e4e4e7;
  --clr-border-subtle: rgba(228,228,231,0.25);
  --clr-border-hover: #d4d4d8;
  --clr-text: #18181b;
  --clr-text-secondary: #27272a;
  --clr-text-muted: #52525b;
  --clr-text-dim: #52525b;
  --clr-text-faint: #a1a1aa;
  --clr-accent: #c2410c;
  --clr-accent-hover: #c2410c;
  --clr-on-accent: #ffffff;
  --clr-pass: #16a34a;
  --clr-pass-glow: rgba(22,163,74,0.25);
  --clr-pass-bg: #dcfce7;
  --clr-pass-bg-alpha: rgba(220,252,231,0.5);
  --clr-pass-border: #86efac;
  --clr-warn: #d97706;
  --clr-warn-glow: rgba(217,119,6,0.25);
  --clr-warn-bg: #fef3c7;
  --clr-warn-bg-alpha: rgba(254,243,199,0.5);
  --clr-warn-border: #fcd34d;
  --clr-fail: #dc2626;
  --clr-fail-glow: rgba(220,38,38,0.25);
  --clr-fail-bg: #fee2e2;
  --clr-fail-border: #fca5a5;
  --clr-info: #2563eb;
  --clr-info-bg: #dbeafe;
  --clr-info-glow: rgba(37,99,235,0.25);
  --clr-shadow: rgba(0,0,0,0.12);
  --clr-accent-glow: rgba(234,88,12,0.2);
  --clr-accent-muted: rgba(194,65,12,0.08);
  --clr-surface-muted: #f4f4f5;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --clr-bg: #0a0a0f;
    --clr-surface: #18181b;
    --clr-border: #27272a;
    --clr-border-subtle: rgba(39,39,42,0.25);
    --clr-border-hover: #3f3f46;
    --clr-text: #e4e4e7;
    --clr-text-secondary: #d4d4d8;
    --clr-text-muted: #a1a1aa;
    --clr-text-dim: #a1a1aa;
    --clr-text-faint: #52525b;
    --clr-accent: #f97316;
    --clr-accent-hover: #ea580c;
    --clr-pass: #22c55e;
    --clr-pass-glow: rgba(34,197,94,0.25);
    --clr-pass-bg: #052e16;
    --clr-pass-bg-alpha: rgba(5,46,22,0.5);
    --clr-pass-border: #166534;
    --clr-warn: #f59e0b;
    --clr-warn-glow: rgba(245,158,11,0.25);
    --clr-warn-bg: #451a03;
    --clr-warn-bg-alpha: rgba(69,26,3,0.5);
    --clr-warn-border: #92400e;
    --clr-fail: #ef4444;
    --clr-fail-glow: rgba(239,68,68,0.25);
    --clr-fail-bg: #450a0a;
    --clr-fail-border: #991b1b;
    --clr-info: #3b82f6;
    --clr-info-bg: #1e3a5f;
    --clr-info-glow: rgba(59,130,246,0.25);
    --clr-shadow: rgba(0,0,0,0.3);
    --clr-accent-glow: rgba(249,115,22,0.3);
    --clr-accent-muted: rgba(249,115,22,0.08);
    --clr-surface-muted: #1f1f23;
  }
}
[data-theme="dark"] {
  color-scheme: dark;
  --clr-bg: #0a0a0f;
  --clr-surface: #18181b;
  --clr-border: #27272a;
  --clr-border-subtle: rgba(39,39,42,0.25);
  --clr-border-hover: #3f3f46;
  --clr-text: #e4e4e7;
  --clr-text-secondary: #d4d4d8;
  --clr-text-muted: #a1a1aa;
  --clr-text-dim: #a1a1aa;
  --clr-text-faint: #52525b;
  --clr-accent: #f97316;
  --clr-accent-hover: #ea580c;
  --clr-pass: #22c55e;
  --clr-pass-glow: rgba(34,197,94,0.25);
  --clr-pass-bg: #052e16;
  --clr-pass-bg-alpha: rgba(5,46,22,0.5);
  --clr-pass-border: #166534;
  --clr-warn: #f59e0b;
  --clr-warn-glow: rgba(245,158,11,0.25);
  --clr-warn-bg: #451a03;
  --clr-warn-bg-alpha: rgba(69,26,3,0.5);
  --clr-warn-border: #92400e;
  --clr-fail: #ef4444;
  --clr-fail-glow: rgba(239,68,68,0.25);
  --clr-fail-bg: #450a0a;
  --clr-fail-border: #991b1b;
  --clr-info: #3b82f6;
  --clr-info-bg: #1e3a5f;
  --clr-info-glow: rgba(59,130,246,0.25);
  --clr-shadow: rgba(0,0,0,0.3);
  --clr-accent-glow: rgba(249,115,22,0.3);
  --clr-accent-muted: rgba(249,115,22,0.08);
  --clr-surface-muted: #1f1f23;
}
[data-theme="light"] { color-scheme: light; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  background: var(--clr-bg); color: var(--clr-text); min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--clr-accent); text-decoration: none; }
a:hover { text-decoration: underline; }
a:focus-visible, button:focus-visible, summary:focus-visible {
  outline: 2px solid var(--clr-accent);
  outline-offset: 2px;
  border-radius: 4px;
}
button:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}
code { font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; font-size: 0.9em; }

/* Landing */
.landing { display: block; }
.landing-hero {
  display: flex; flex-direction: column; align-items: center;
  min-height: 100vh;
  min-height: 100dvh;
  padding: 2rem;
  position: relative;
}
.landing-nav {
  position: absolute; top: 1.25rem; right: 1.5rem;
  z-index: 2;
}

/* Persistent login pill (landing + report nav) */
.nav-login {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 5px 12px 5px 5px;
  background: var(--clr-surface);
  border: 1px solid var(--clr-border);
  border-radius: 999px;
  color: var(--clr-text);
  font-size: 0.82rem; font-weight: 500;
  text-decoration: none;
  transition: background 0.15s, border-color 0.15s;
}
.nav-login:hover {
  background: var(--clr-bg);
  border-color: var(--clr-border-hover);
  text-decoration: none;
}
.nav-login:focus-visible {
  outline: 2px solid var(--clr-accent);
  outline-offset: 2px;
}
.nav-login-avatar {
  display: inline-flex; align-items: center; justify-content: center;
  flex-direction: column;
  width: 26px; height: 26px;
  border-radius: 50%;
  background: var(--clr-bg);
  overflow: hidden;
  flex-shrink: 0;
}
.nav-login-avatar .creature { transform: scale(0.72); transform-origin: center; }
.nav-login-arrow {
  color: var(--clr-text-faint); font-size: 0.75rem;
  transition: color 0.15s, transform 0.15s;
}
.nav-login:hover .nav-login-arrow {
  color: var(--clr-accent);
  transform: translate(1px, -1px);
}
@media (max-width: 480px) {
  .nav-login-label { display: none; }
  .nav-login { padding: 4px; }
  .landing-nav { top: 0.75rem; right: 0.75rem; }
}
.landing-main {
  flex: 1; display: flex; flex-direction: column; align-items: center;
  justify-content: center;
}
.landing-footer {
  display: flex; flex-direction: column; align-items: center;
  padding-bottom: 1rem;
}
.logo { font-size: 2.8rem; font-weight: 800; letter-spacing: -0.5px; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 12px; justify-content: center; }
.logo-text span { color: var(--clr-accent); }
h1.tagline, .tagline { color: var(--clr-text-dim); font-size: 1.1rem; font-weight: 400; margin: 0 0 2.5rem; text-align: center; }

/* Landing explainer (SEO / intro copy — sits below the hero viewport) */
.landing-explainer {
  max-width: 860px; margin: 0 auto; padding: 3.5rem 1.5rem 3rem;
  border-top: 1px solid var(--clr-border);
  color: var(--clr-text-muted); font-size: 0.92rem; line-height: 1.55;
  scroll-margin-top: 1rem;
}
.landing-explainer h2 {
  margin: 0 0 0.5rem; text-align: center;
  font-size: 1.15rem; font-weight: 700; color: var(--clr-text);
  letter-spacing: -0.01em;
}
.landing-explainer > p {
  margin: 0 auto 1.75rem; max-width: 680px;
  text-align: center; color: var(--clr-text-dim);
}
.landing-explainer > p.explainer-note {
  margin: -0.75rem auto 1.25rem; max-width: 620px;
  font-size: 0.82rem; color: var(--clr-text-muted);
}
.explainer-grid {
  display: grid; gap: 0.85rem; grid-template-columns: repeat(3, 1fr);
  margin: 0;
}
.explainer-grid > div {
  margin: 0; padding: 14px 16px;
  background: var(--clr-surface);
  border: 1px solid var(--clr-border);
  border-left: 3px solid var(--clr-accent);
  border-radius: 8px;
}
.explainer-grid dt {
  font-weight: 700; color: var(--clr-text); font-size: 0.85rem;
  letter-spacing: 0.04em; text-transform: uppercase; margin-bottom: 0.25rem;
}
.explainer-grid dd { margin: 0; color: var(--clr-text-dim); font-size: 0.88rem; line-height: 1.5; }

.search-box {
  display: flex; width: 100%; max-width: 560px;
  background: var(--clr-surface); border: 1px solid var(--clr-border); border-radius: 12px;
  overflow: hidden; transition: border-color 0.2s;
}
.search-box:focus-within { border-color: var(--clr-accent); }
.search-box input {
  flex: 1; padding: 16px 20px; background: transparent; border: none;
  color: var(--clr-text); font-size: 1.1rem; outline: none;
}
.search-box input::placeholder { color: var(--clr-text-faint); }
.search-box button {
  padding: 16px 28px; background: var(--clr-accent); color: var(--clr-on-accent); border: none;
  font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.2s;
}
.search-box button:hover { background: var(--clr-accent-hover); }

/* Advanced options */
.advanced-options {
  width: 100%; max-width: 560px; margin-top: 0.75rem;
}
.advanced-options summary {
  color: var(--clr-text-dim); font-size: 0.8rem; cursor: pointer; text-align: right;
  list-style: none;
}
.advanced-options summary::-webkit-details-marker { display: none; }
.advanced-options summary::before { content: '\\25B8 '; }
.advanced-options[open] summary::before { content: '\\25BE '; }
.advanced-options summary:hover { color: var(--clr-accent); }
.advanced-body {
  margin-top: 0.5rem; padding: 12px 16px; background: var(--clr-surface);
  border: 1px solid var(--clr-border); border-radius: 8px;
}
.advanced-body label {
  display: block; font-size: 0.8rem; color: var(--clr-text-muted); margin-bottom: 4px;
}
.advanced-body input {
  width: 100%; padding: 10px 12px; background: var(--clr-bg); border: 1px solid var(--clr-border);
  border-radius: 6px; color: var(--clr-text); font-size: 0.9rem; outline: none;
  transition: border-color 0.2s;
}
.advanced-body input:focus { border-color: var(--clr-accent); }
.advanced-body input::placeholder { color: var(--clr-text-faint); }
.advanced-body small { display: block; margin-top: 6px; color: var(--clr-text-faint); font-size: 0.75rem; }

.learn-link { margin-top: 1.5rem; text-align: center; font-size: 0.85rem; color: var(--clr-text-dim); }
.learn-link a { text-decoration: underline; text-underline-offset: 2px; }
.landing-footer .learn-link { margin-top: 0; margin-bottom: 0.75rem; }
.landing-footer .api-hint { margin-top: 0; margin-bottom: 0.75rem; }
.landing-footer .foss-callout { margin-top: 0; }
.examples { margin-top: 2rem; color: var(--clr-text-dim); font-size: 0.85rem; }
.api-hint {
  margin-top: 1.5rem; padding: 10px 16px; background: var(--clr-surface); border: 1px solid var(--clr-border);
  border-radius: 8px; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.78rem; color: var(--clr-text-dim);
}
.api-hint span { color: var(--clr-accent); }
.foss-callout { margin-top: 1.5rem; text-align: center; }
.foss-link {
  display: inline-flex; align-items: center; gap: 6px;
  color: var(--clr-text-dim); font-size: 0.8rem; text-decoration: none;
}
.foss-link:hover { color: var(--clr-text-muted); text-decoration: none; }
.foss-link:hover svg { fill: var(--clr-text-muted); }
.dmarcus-credit {
  margin-top: 0.75rem; text-align: center; font-size: 0.75rem;
  color: var(--clr-text-dim); display: inline-flex; align-items: center; gap: 4px;
  width: 100%; justify-content: center; opacity: 0.8;
}
.dmarcus-credit:hover { opacity: 1; transition: opacity 0.3s; }
.footer-creature { margin-bottom: 0.75rem; opacity: 0.6; }
.footer-creature:hover { opacity: 1; transition: opacity 0.3s; }
.logo-text { display: inline; }
.creature-loading { display: inline-flex; }

/* Report */
.report { max-width: 800px; margin: 0 auto; padding: 2rem; }
.report-nav {
  display: flex; align-items: center; gap: 12px; margin-bottom: 2rem;
}
.report-nav a { font-size: 0.85rem; display: inline-flex; align-items: center; gap: 6px; }
.report-nav-spacer { flex: 1; }
.report-nav .nav-login { font-size: 0.82rem; }
.report-header { display: flex; align-items: center; gap: 1rem; margin-bottom: 0.5rem; }
.report-header .creature { margin-left: 8px; }
h1.domain-name, .domain-name { font-size: 1.5rem; font-weight: 700; margin: 0; }
.overall-grade {
  display: inline-flex; align-items: center; justify-content: center;
  width: 44px; height: 44px; border-radius: 10px; font-weight: 800; font-size: 1.2rem;
}
.grade-a { background: var(--clr-pass-bg); color: var(--clr-pass); border: 1px solid var(--clr-pass-border); }
.grade-b { background: var(--clr-pass-bg); color: var(--clr-pass); border: 1px solid var(--clr-pass-border); }
.grade-c { background: var(--clr-warn-bg); color: var(--clr-warn); border: 1px solid var(--clr-warn-border); }
.grade-d { background: var(--clr-warn-bg); color: var(--clr-warn); border: 1px solid var(--clr-warn-border); }
.grade-f { background: var(--clr-fail-bg); color: var(--clr-fail); border: 1px solid var(--clr-fail-border); }
.grade-s {
  background: linear-gradient(135deg, #fde68a, #f59e0b, #facc15);
  color: #78350f; border: 1px solid #f59e0b;
  animation: grade-s-glow 2s ease-in-out infinite;
}
@keyframes grade-s-glow {
  0%, 100% { box-shadow: 0 0 8px rgba(245, 158, 11, 0.4); }
  50% { box-shadow: 0 0 20px rgba(245, 158, 11, 0.7); }
}
.confetti-toggle {
  position: fixed; bottom: 1rem; left: 1rem; z-index: 100;
  display: inline-flex; align-items: center; justify-content: center;
  width: 28px; height: 28px; border-radius: 6px;
  background: var(--clr-border); border: 1px solid var(--clr-border-hover);
  cursor: pointer; transition: background 0.15s, opacity 0.15s;
  font-size: 0.8rem; line-height: 1; padding: 0;
}
.confetti-toggle:hover { background: var(--clr-border-hover); }
.confetti-toggle.disabled { opacity: 0.4; }
.theme-toggle {
  position: fixed; bottom: 1rem; right: 1rem; z-index: 100;
  display: inline-flex; align-items: center; justify-content: center;
  width: 28px; height: 28px; border-radius: 6px;
  background: var(--clr-border); border: 1px solid var(--clr-border-hover);
  color: var(--clr-text-dim); cursor: pointer; transition: background 0.15s, color 0.15s;
  padding: 0; line-height: 1;
}
.theme-toggle:hover { background: var(--clr-border-hover); color: var(--clr-text); }
.report-meta { color: var(--clr-text-dim); font-size: 0.85rem; margin-bottom: 2rem; }
.csv-download {
  padding: 2px 8px; background: var(--clr-border); border-radius: 4px;
  font-size: 0.8rem; text-decoration: none; color: var(--clr-text-muted);
  transition: background 0.15s, color 0.15s;
}
.csv-download:hover { background: var(--clr-accent); color: var(--clr-on-accent); }

/* Cards */
.card {
  background: var(--clr-surface); border: 1px solid var(--clr-border); border-radius: 12px;
  margin-bottom: 12px; overflow: hidden; transition: border-color 0.2s;
}
.card:hover { border-color: var(--clr-border-hover); }
.card-header {
  display: flex; align-items: center; padding: 16px 20px; cursor: pointer; gap: 14px;
}
.card-header:focus-visible {
  outline: 2px solid var(--clr-accent);
  outline-offset: -2px;
  border-radius: 12px;
}
.status-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.status-pass { background: var(--clr-pass); box-shadow: 0 0 8px var(--clr-pass-glow); }
.status-warn { background: var(--clr-warn); box-shadow: 0 0 8px var(--clr-warn-glow); }
.status-fail { background: var(--clr-fail); box-shadow: 0 0 8px var(--clr-fail-glow); }
.status-info { background: var(--clr-info); box-shadow: 0 0 8px var(--clr-info-glow); }
.card-title { font-weight: 600; flex: 1; }
.card-subtitle { color: var(--clr-text-dim); font-size: 0.85rem; }
.card-chevron { color: var(--clr-text-faint); transition: transform 0.2s; font-size: 0.8rem; }
.card-body { padding: 0 20px 20px; border-top: 1px solid var(--clr-border); display: none; }
.card.expanded .card-body { display: block; }
.card.expanded .card-chevron { transform: rotate(90deg); }
.card-learn-link { margin-top: 16px; padding-top: 12px; border-top: 1px dashed var(--clr-border); font-size: 0.85rem; }
.card-learn-link a { color: var(--clr-text-dim); text-decoration: underline; text-underline-offset: 2px; }
.card-learn-link a:hover { color: var(--clr-accent); }
.validation-learn-link { white-space: nowrap; font-size: 0.85rem; color: var(--clr-text-dim); text-decoration: underline; text-underline-offset: 2px; }
.validation-learn-link:hover { color: var(--clr-accent); }

/* Tag grid */
.tag-grid {
  display: grid; grid-template-columns: auto 1fr; gap: 6px 16px;
  margin-top: 12px; font-size: 0.9rem;
}
.tag-name { font-family: monospace; color: var(--clr-accent); font-weight: 600; }
.tag-value { color: var(--clr-text-secondary); }

/* Validation list */
.validation-list { margin-top: 12px; list-style: none; }
.validation-list li {
  padding: 6px 0; display: flex; align-items: flex-start; gap: 8px; font-size: 0.85rem;
}
.icon-pass { color: var(--clr-pass); flex-shrink: 0; }
.icon-warn { color: var(--clr-warn); flex-shrink: 0; }
.icon-fail { color: var(--clr-fail); flex-shrink: 0; }
.icon-info { color: var(--clr-info); flex-shrink: 0; }

/* MX table */
.mx-table { width: 100%; margin-top: 12px; border-collapse: collapse; }
.mx-table th {
  text-align: left; padding: 8px 12px; font-size: 0.75rem; text-transform: uppercase;
  color: var(--clr-text-dim); border-bottom: 1px solid var(--clr-border); font-weight: 500;
}
.mx-table th:first-child { text-align: center; width: 60px; }
.mx-table td { padding: 8px 12px; font-size: 0.85rem; border-bottom: 1px solid var(--clr-border); }
.mx-priority { font-family: monospace; color: var(--clr-accent); text-align: center; }
.mx-exchange { font-family: monospace; }
.provider-badge {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 2px 10px; background: var(--clr-bg); border: 1px solid var(--clr-border);
  border-radius: 16px; font-size: 0.78rem; white-space: nowrap;
}
.badge-category { color: var(--clr-text-faint); font-size: 0.7rem; }

/* Raw record */
.record-raw {
  background: var(--clr-bg); padding: 12px 16px; border-radius: 8px;
  font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem;
  color: var(--clr-text-muted); margin-top: 12px; overflow-x: auto; white-space: pre-wrap;
  word-break: break-all; display: flex; align-items: flex-start; gap: 12px;
}
.record-raw code { flex: 1; min-width: 0; }
.copy-btn {
  flex-shrink: 0; padding: 4px 10px; background: var(--clr-border); color: var(--clr-text-muted);
  border: 1px solid var(--clr-border-hover); border-radius: 6px; font-size: 0.75rem;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  cursor: pointer; transition: background 0.15s, color 0.15s, border-color 0.15s;
  white-space: nowrap;
}
.copy-btn:hover { background: var(--clr-accent); color: var(--clr-on-accent); border-color: var(--clr-accent); }
.record-expand { margin-top: 12px; }
.record-expand summary {
  cursor: pointer; color: var(--clr-text-muted); font-size: 0.8rem;
  user-select: none; list-style: revert;
}
.record-expand summary:hover { color: var(--clr-text-secondary); }
.record-expand .record-raw { margin-top: 8px; }

/* SPF tree */
.spf-tree { margin-top: 12px; }
.spf-tree ul { list-style: none; padding-left: 20px; }
.spf-tree > ul { padding-left: 0; }
.spf-tree li { padding: 4px 0; font-size: 0.85rem; }
.spf-node {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 2px 8px; background: var(--clr-border); border-radius: 4px;
  font-family: monospace; font-size: 0.8rem;
}
.spf-node.mechanism { color: var(--clr-accent); }
.spf-node.include { color: var(--clr-info); cursor: pointer; }
.spf-node.include:hover { background: var(--clr-info-bg); }
.spf-node.include:focus-visible { outline: 2px solid var(--clr-info); outline-offset: 2px; }
.lookup-count {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 0.75rem; font-weight: 600; margin-top: 8px;
}
.lookup-ok { background: var(--clr-pass-bg); color: var(--clr-pass); }
.lookup-over { background: var(--clr-fail-bg); color: var(--clr-fail); }

/* DKIM selectors */
.selector-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 8px; margin-top: 12px;
}
.selector-item {
  padding: 8px 12px; background: var(--clr-bg); border-radius: 8px;
  font-family: monospace; font-size: 0.8rem; display: flex; align-items: center; gap: 8px;
}
.selector-found { border: 1px solid var(--clr-pass-border); }
.selector-not-found { border: 1px solid var(--clr-border); color: var(--clr-text-faint); }

/* MTA-STS policy table */
.policy-table { width: 100%; margin-top: 12px; border-collapse: collapse; }
.policy-table th {
  text-align: left; padding: 8px 12px; background: var(--clr-bg);
  font-size: 0.8rem; color: var(--clr-text-dim); font-weight: 500; border-bottom: 1px solid var(--clr-border);
}
.policy-table td {
  padding: 8px 12px; font-size: 0.85rem; border-bottom: 1px solid var(--clr-border);
}
.policy-table td:first-child { font-family: monospace; color: var(--clr-accent); }

/* Tooltip */
.tooltip {
  position: relative; cursor: help; border-bottom: 1px dotted var(--clr-accent);
}
.tooltip .tooltip-text {
  visibility: hidden; opacity: 0; position: absolute; bottom: 125%; left: 0;
  background: var(--clr-border); color: var(--clr-text);
  padding: 8px 12px; border-radius: 8px; font-size: 0.75rem; font-weight: 400;
  width: max-content; max-width: 220px; z-index: 10; transition: opacity 0.15s;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  box-shadow: 0 4px 12px var(--clr-shadow);
}
.tooltip:hover .tooltip-text, .tooltip:focus-visible .tooltip-text { visibility: visible; opacity: 1; }
.tooltip:focus-visible {
  outline: 2px solid var(--clr-accent); outline-offset: 4px; border-radius: 2px;
}

/* Error */
.error-box {
  background: var(--clr-fail-bg); border: 1px solid var(--clr-fail-border); border-radius: 12px;
  padding: 20px; margin: 2rem auto; max-width: 560px; text-align: center;
}
.error-box h3 { color: var(--clr-fail); margin-bottom: 0.5rem; }
.error-box p { color: var(--clr-text-muted); font-size: 0.9rem; }

/* Loading */
.scan-loading {
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  min-height: 60vh;
}
.loading { text-align: center; padding: 4rem 2rem; }
.loading .spinner {
  display: inline-block; width: 32px; height: 32px; border: 3px solid var(--clr-border);
  border-top-color: var(--clr-accent); border-radius: 50%; animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.loading p { color: var(--clr-text-dim); margin-top: 1rem; font-size: 0.9rem; }

/* Score snippet (inline on results page) */
.score-snippet {
  background: var(--clr-surface); border: 1px solid var(--clr-border); border-radius: 10px;
  padding: 14px 18px; margin: 12px 0 20px 0;
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  flex-wrap: wrap;
}
.snippet-left { display: flex; flex-direction: column; gap: 6px; }
.snippet-tier { font-size: 0.85rem; color: var(--clr-text); }
.tier-pass { color: var(--clr-pass); font-weight: 600; }
.tier-warn { color: var(--clr-warn); font-weight: 600; }
.tier-fail { color: var(--clr-fail); font-weight: 600; }
.snippet-protocols { display: flex; gap: 12px; align-items: center; }
.snippet-proto {
  display: flex; align-items: center; gap: 4px;
  font-size: 0.7rem; color: var(--clr-text-muted);
}
.snippet-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.snippet-link {
  color: var(--clr-accent); font-size: 0.8rem; text-decoration: none; font-weight: 500;
  white-space: nowrap;
}
.snippet-link:hover { text-decoration: underline; }

/* Post-scan monitor upsell */
.monitor-card {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 1px minmax(0, 1.1fr);
  gap: 22px;
  align-items: stretch;
  margin: 1.75rem 0 1rem;
  padding: 18px 22px;
  background: var(--clr-surface);
  border: 1px solid var(--clr-border);
  border-radius: 12px;
}
.monitor-snap { min-width: 0; }
.monitor-eyebrow {
  font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1.5px;
  color: var(--clr-text-faint); font-family: 'SF Mono', 'Fira Code', monospace;
}
.monitor-snap-heading {
  font-size: 0.95rem; font-weight: 600; color: var(--clr-text);
  margin-top: 4px;
}
.snap-list {
  margin-top: 10px;
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 0.78rem; line-height: 1.65;
  color: var(--clr-text-muted);
}
.snap-row { display: grid; grid-template-columns: 14px auto 1fr; gap: 6px; }
.snap-row-muted { opacity: 0.55; }
.snap-mark { color: var(--clr-pass); font-weight: 700; text-align: center; }
.snap-row-muted .snap-mark { color: var(--clr-text-faint); }
.snap-label { color: var(--clr-text-dim); }
.snap-val { color: var(--clr-text); }
.monitor-divider { background: var(--clr-border); }
.monitor-pitch {
  display: flex; flex-direction: column; justify-content: center;
  gap: 12px; min-width: 0;
}
.monitor-pitch-lede {
  margin: 0;
  font-size: 0.92rem; line-height: 1.5;
  color: var(--clr-text);
}
.monitor-pitch-lede strong { color: var(--clr-accent); font-weight: 600; }
.monitor-cta-row {
  display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
}
.monitor-cta {
  display: inline-flex; align-items: center;
  padding: 9px 16px;
  background: var(--clr-accent); color: var(--clr-on-accent);
  border-radius: 8px;
  font-size: 0.86rem; font-weight: 600;
  text-decoration: none;
  transition: background 0.15s;
}
.monitor-cta:hover { background: var(--clr-accent-hover); text-decoration: none; }
.monitor-cta-meta {
  font-size: 0.72rem; color: var(--clr-text-faint);
  font-family: 'SF Mono', 'Fira Code', monospace;
}
@media (max-width: 640px) {
  .monitor-card {
    grid-template-columns: 1fr;
    gap: 16px;
  }
  .monitor-divider { display: none; }
}

/* Scoring breakdown page */
.breakdown { max-width: 700px; margin: 0 auto; padding: 2rem; }
.breakdown .report-nav { margin-bottom: 1.5rem; }
.breakdown .report-header { margin-bottom: 0.5rem; }
.breakdown .report-meta { margin-bottom: 1.5rem; }

.bd-card {
  background: var(--clr-surface); border: 1px solid var(--clr-border); border-radius: 10px;
  margin-bottom: 16px; overflow: hidden;
}
.bd-card-title {
  font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
  letter-spacing: 1px; color: var(--clr-text-muted); padding: 14px 18px 0;
  margin: 0;
}
.bd-card-body { padding: 12px 18px 16px; }
.tier-text { font-size: 0.9rem; line-height: 1.6; color: var(--clr-text); }

/* Factors table */
.factors-table { width: 100%; border-collapse: collapse; }
.factors-table td {
  padding: 8px 0; font-size: 0.8rem; border-bottom: 1px solid var(--clr-border-subtle);
  vertical-align: middle;
}
.factors-table tr:last-child td { border-bottom: none; }
.factor-proto {
  color: var(--clr-text-muted); font-weight: 500; width: 70px;
  font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.5px;
}
.factor-label { color: var(--clr-text); }
.factor-effect {
  text-align: right; font-weight: 700; font-size: 0.8rem; width: 40px;
  font-family: 'SF Mono', 'Fira Code', monospace;
}
.effect-plus { color: var(--clr-pass); }
.effect-minus { color: var(--clr-fail); }
.effect-neutral { color: var(--clr-text-muted); }
.modifier-summary {
  margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--clr-border);
  font-size: 0.8rem; color: var(--clr-text-muted);
  display: flex; justify-content: space-between;
}
.modifier-result { color: var(--clr-pass); font-weight: 600; }

/* Protocol contribution grid */
.proto-grid {
  display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px;
}
.proto-cell {
  text-align: center; padding: 12px 6px; border-radius: 8px; background: var(--clr-bg);
}
.proto-name {
  font-size: 0.7rem; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.5px; color: var(--clr-text); margin-bottom: 4px;
}
.proto-summary { font-size: 0.65rem; color: var(--clr-text-muted); line-height: 1.3; }

/* Recommendations */
.rec-item {
  display: flex; gap: 12px; padding: 12px 0;
  border-bottom: 1px solid var(--clr-border-subtle);
}
.rec-item:last-child { border-bottom: none; }
.rec-priority {
  width: 28px; height: 28px; border-radius: 6px;
  display: flex; align-items: center; justify-content: center;
  font-size: 0.7rem; font-weight: 700; flex-shrink: 0; margin-top: 2px;
}
.priority-1 { background: var(--clr-pass-bg-alpha); color: var(--clr-pass); border: 1px solid var(--clr-pass-glow); }
.priority-2 { background: var(--clr-warn-bg-alpha); color: var(--clr-warn); border: 1px solid var(--clr-warn-glow); }
.priority-3 { background: var(--clr-surface); color: var(--clr-text-muted); border: 1px solid var(--clr-border); }
.rec-content { flex: 1; }
.rec-title { font-size: 0.85rem; font-weight: 500; color: var(--clr-text); margin-bottom: 3px; }
.rec-desc { font-size: 0.78rem; color: var(--clr-text-muted); line-height: 1.4; }
.rec-impact { font-size: 0.7rem; color: var(--clr-accent); margin-top: 4px; font-weight: 500; }

/* Scoring rubric page */
.rubric-title { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.5rem; }
.rubric-intro { color: var(--clr-text-muted); font-size: 0.9rem; line-height: 1.6; margin-bottom: 1.5rem; }
.rubric-table { width: 100%; border-collapse: collapse; }
.rubric-table th {
  text-align: left; padding: 8px 12px; background: var(--clr-bg);
  font-size: 0.75rem; color: var(--clr-text-dim); font-weight: 500; text-transform: uppercase;
  letter-spacing: 0.5px; border-bottom: 1px solid var(--clr-border);
}
.rubric-table td {
  padding: 10px 12px; font-size: 0.85rem; border-bottom: 1px solid var(--clr-border-subtle);
  vertical-align: middle;
}
.rubric-grade {
  display: inline-flex; align-items: center; justify-content: center;
  width: 36px; height: 28px; border-radius: 6px; font-weight: 700; font-size: 0.85rem;
}
.rubric-subhead {
  margin: 4px 0 6px; font-size: 0.82rem; font-weight: 600;
  color: var(--clr-text-dim);
}
.rubric-subhead:not(:first-child) { margin-top: 18px; }
.rubric-protocol { padding: 10px 0; border-bottom: 1px solid var(--clr-border-subtle); }
.rubric-protocol:last-child { border-bottom: none; }
.rubric-protocol h3 { font-size: 0.9rem; font-weight: 600; color: var(--clr-accent); margin-bottom: 4px; }
.rubric-protocol h3 a { color: inherit; text-decoration: none; }
.rubric-protocol h3 a:hover { text-decoration: underline; text-underline-offset: 3px; }
.rubric-protocol p { font-size: 0.82rem; color: var(--clr-text-muted); line-height: 1.5; }
.rubric-cta {
  display: inline-block; padding: 10px 24px; background: var(--clr-accent); color: var(--clr-on-accent);
  border-radius: 8px; font-weight: 600; font-size: 0.9rem; text-decoration: none;
  transition: background 0.2s;
}
.rubric-cta:hover { background: var(--clr-accent-hover); text-decoration: none; }

/* @ Creature easter egg */
.at-creature {
  position: fixed; z-index: 9998; cursor: pointer;
  display: flex; flex-direction: column; align-items: center;
  user-select: none; outline: none;
  will-change: transform, left, top;
  transition: left 0s linear, top 0s linear;
}
.at-creature .creature-body {
  font-size: 48px; font-family: monospace; color: var(--clr-accent); line-height: 1;
  text-shadow: 0 4px 12px var(--clr-accent-glow);
  position: relative; transition: transform 0.15s;
}
.at-creature .creature-eyes {
  position: absolute; top: 6px; left: 12px;
  display: flex; gap: 6px; pointer-events: none;
}
.at-creature .creature-eye {
  width: 10px; height: 10px; background: white; border-radius: 50%;
  position: relative; overflow: hidden; box-shadow: 0 0 0 1.5px var(--clr-accent-hover);
}
.at-creature .creature-pupil {
  width: 5px; height: 5px; background: #0a0a0f; border-radius: 50%;
  position: absolute; top: 3px; left: 3px;
  transition: left 0.15s, top 0.15s;
}
.at-creature .creature-legs {
  display: flex; gap: 6px; margin-top: -4px; pointer-events: none;
}
.at-creature .creature-leg {
  width: 6px; height: 12px; background: var(--clr-accent-hover); border-radius: 0 0 3px 3px;
}
.at-creature.walking .creature-leg:nth-child(odd) {
  animation: creature-walk 0.3s ease-in-out infinite alternate;
}
.at-creature.walking .creature-leg:nth-child(even) {
  animation: creature-walk 0.3s ease-in-out infinite alternate-reverse;
}
.at-creature .creature-body.chomping {
  animation: creature-chomp 0.3s ease-in-out;
}
.at-creature.panicking .creature-eye {
  transform: scale(1.4);
}
.at-creature.panicking .creature-pupil {
  width: 3px; height: 3px; top: 4px; left: 4px;
}
.at-creature.panicking .creature-leg {
  animation-duration: 0.12s !important;
}
@keyframes creature-walk {
  from { height: 12px; }
  to { height: 6px; }
}
@keyframes creature-chomp {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.2) rotate(-5deg); }
}
/* Static creature (brand mascot) */
.creature {
  display: inline-flex; flex-direction: column; align-items: center;
  vertical-align: middle;
}
.creature .creature-body {
  font-family: 'SF Mono', 'Fira Code', monospace; color: var(--clr-accent); line-height: 1;
  text-shadow: 0 2px 8px var(--clr-accent-glow);
  position: relative;
}
.creature .creature-eyes {
  position: absolute; display: flex; pointer-events: none;
}
.creature .creature-eye {
  background: white; border-radius: 50%; position: relative; overflow: hidden; box-shadow: 0 0 0 1.5px var(--clr-accent-hover);
}
.creature .creature-pupil {
  background: #0a0a0f; border-radius: 50%; position: absolute;
}
.creature .creature-legs {
  display: flex; pointer-events: none;
}
.creature .creature-leg {
  background: var(--clr-accent-hover); border-radius: 0 0 3px 3px;
}

/* Sizes */
.creature-lg .creature-body { font-size: 48px; }
.creature-lg .creature-eyes { top: 6px; left: 12px; gap: 6px; }
.creature-lg .creature-eye { width: 10px; height: 10px; }
.creature-lg .creature-pupil { width: 5px; height: 5px; top: 3px; left: 3px; }
.creature-lg .creature-legs { gap: 6px; margin-top: -4px; }
.creature-lg .creature-leg { width: 6px; height: 12px; }

.creature-md .creature-body { font-size: 30px; }
.creature-md .creature-eyes { top: 4px; left: 7px; gap: 4px; }
.creature-md .creature-eye { width: 7px; height: 7px; }
.creature-md .creature-pupil { width: 3px; height: 3px; top: 2px; left: 2px; }
.creature-md .creature-legs { gap: 4px; margin-top: -3px; }
.creature-md .creature-leg { width: 4px; height: 8px; }

.creature-sm .creature-body { font-size: 20px; }
.creature-sm .creature-eyes { top: 3px; left: 5px; gap: 3px; }
.creature-sm .creature-eye { width: 5px; height: 5px; }
.creature-sm .creature-pupil { width: 2px; height: 2px; top: 2px; left: 2px; }
.creature-sm .creature-legs { gap: 3px; margin-top: -2px; }
.creature-sm .creature-leg { width: 3px; height: 6px; }

/* Moods — pupil position changes */
.creature-celebrating .creature-pupil { top: 1px; left: 1px; }
.creature-content .creature-pupil { /* default centered — no change */ }
.creature-worried .creature-pupil { top: 4px; }
.creature-worried .creature-eye:first-child .creature-pupil { left: 1px; }
.creature-scared .creature-eye { transform: scale(1.2); }
.creature-scared .creature-pupil { width: 3px; height: 3px; top: 3px; left: 3px; }
.creature-panicked .creature-eye { transform: scale(1.4); }
.creature-panicked .creature-pupil { width: 2px; height: 2px; top: 4px; left: 4px; }

/* Party hat variant */
.creature-partying {
  position: relative;
  animation: creature-dance 1.2s ease-in-out infinite;
  transform-origin: bottom center;
}
.creature-partying .creature-leg:nth-child(1) {
  animation: creature-kick 0.6s ease-in-out infinite alternate;
}
.creature-partying .creature-leg:nth-child(3) {
  animation: creature-kick 0.6s ease-in-out infinite alternate-reverse;
}
@keyframes creature-dance {
  0%, 100% { transform: translateY(0) rotate(0deg); }
  25% { transform: translateY(-3px) rotate(-4deg); }
  50% { transform: translateY(0) rotate(0deg); }
  75% { transform: translateY(-3px) rotate(4deg); }
}
@keyframes creature-kick {
  0% { transform: rotate(-12deg); }
  100% { transform: rotate(12deg); }
}
.creature-hat {
  position: absolute; top: -12px; left: 50%;
  transform: translateX(-50%) rotate(8deg);
  width: 0; height: 0;
  border-left: 7px solid transparent;
  border-right: 7px solid transparent;
  border-bottom: 14px solid #f59e0b;
  z-index: 1; filter: drop-shadow(0 1px 2px rgba(0,0,0,0.15));
}
.creature-hat::after {
  content: ''; position: absolute;
  top: 12px; left: -9px;
  width: 18px; height: 4px;
  background: repeating-linear-gradient(90deg, #ef4444, #ef4444 3px, #22c55e 3px, #22c55e 6px, #3b82f6 6px, #3b82f6 9px);
  border-radius: 2px;
}
.creature-hat::before {
  content: ''; position: absolute;
  top: -4px; left: -1px;
  width: 4px; height: 4px;
  background: #facc15; border-radius: 50%;
}
.creature-lg .creature-hat { top: -16px; border-left-width: 10px; border-right-width: 10px; border-bottom-width: 20px; }
.creature-lg .creature-hat::after { top: 17px; left: -13px; width: 26px; height: 5px; }
.creature-lg .creature-hat::before { top: -5px; left: -1px; width: 5px; height: 5px; }
.creature-sm .creature-hat { top: -8px; border-left-width: 5px; border-right-width: 5px; border-bottom-width: 10px; }
.creature-sm .creature-hat::after { top: 8px; left: -6px; width: 12px; height: 3px; }
.creature-sm .creature-hat::before { top: -3px; left: -1px; width: 3px; height: 3px; }

/* Loading / walking creature — leg animation */
.creature-loading .creature-leg:nth-child(odd),
.creature-walking .creature-leg:nth-child(odd) {
  animation: creature-walk 0.3s ease-in-out infinite alternate;
}
.creature-loading .creature-leg:nth-child(even),
.creature-walking .creature-leg:nth-child(even) {
  animation: creature-walk 0.3s ease-in-out infinite alternate-reverse;
}
@media (prefers-reduced-motion: reduce) {
  .at-creature { display: none !important; }
  .creature-loading .creature-leg,
  .creature-walking .creature-leg { animation: none !important; }
  .grade-s { animation: none; }
  .creature-partying { animation: none; }
  .creature-partying .creature-leg { animation: none; }
}

/* Skeleton loading cards */
.card-skeleton {
  background: var(--clr-surface); border: 1px solid var(--clr-border); border-radius: 12px;
  margin-bottom: 12px; overflow: hidden;
}
.card-skeleton .card-header {
  display: flex; align-items: center; padding: 16px 20px; gap: 14px;
  cursor: default;
}
.card-skeleton .skel-dot {
  width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
  background: var(--clr-border);
}
.card-skeleton .card-title { font-weight: 600; flex: 1; }
.card-skeleton .card-subtitle { color: transparent; font-size: 0.85rem; }
.card-skeleton .skel-bar {
  height: 12px; border-radius: 6px; background: var(--clr-border);
  animation: shimmer 1.5s ease-in-out infinite;
}
.card-skeleton .skel-body {
  padding: 16px 20px; border-top: 1px solid var(--clr-border);
  display: flex; flex-direction: column; gap: 10px;
}
@keyframes shimmer {
  0%, 100% { opacity: 0.4; }
  50% { opacity: 1; }
}
.card-skeleton .skel-bar:nth-child(1) { width: 80%; }
.card-skeleton .skel-bar:nth-child(2) { width: 60%; }
.card-skeleton .skel-bar:nth-child(3) { width: 45%; }
.grade-skeleton {
  width: 80px; height: 80px; border-radius: 50%; background: var(--clr-border);
  animation: shimmer 1.5s ease-in-out infinite;
}
.stream-header { text-align: center; margin-bottom: 1.5rem; }
.stream-header .domain-name { margin-top: 0.5rem; }
[data-protocol] { transition: opacity 0.3s ease; }
[data-protocol].loaded { animation: fadeSlideIn 0.3s ease; }
@keyframes fadeSlideIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}
@media (prefers-reduced-motion: reduce) {
  .card-skeleton .skel-bar { animation: none; opacity: 0.6; }
  .grade-skeleton { animation: none; opacity: 0.6; }
  [data-protocol].loaded { animation: none; }
}

/* Responsive */
@media (max-width: 640px) {
  .logo { font-size: 2rem; }
  .landing-hero { padding: 1.5rem 1rem; }
  .landing-explainer { padding: 2.5rem 1rem 2rem; }
  .explainer-grid { grid-template-columns: repeat(2, 1fr); gap: 0.75rem; }
  .explainer-grid > div:nth-child(odd):last-child { grid-column: 1 / -1; }
  .search-box { flex-direction: column; border-radius: 12px; }
  .search-box button { padding: 14px; }
  .report { padding: 1rem; }
  .breakdown { padding: 1rem; }
  .selector-grid { grid-template-columns: 1fr; }
  .proto-grid { grid-template-columns: repeat(3, 1fr); }
  .score-snippet { flex-direction: column; align-items: flex-start; }
  .logo > .creature .creature-body { font-size: 36px; }
  .logo > .creature .creature-eyes { top: 4px; left: 9px; gap: 4px; }
  .logo > .creature .creature-eye { width: 8px; height: 8px; }
  .logo > .creature .creature-pupil { width: 4px; height: 4px; top: 2px; left: 2px; }
  .logo > .creature .creature-legs { gap: 4px; margin-top: -3px; }
  .logo > .creature .creature-leg { width: 5px; height: 9px; }
  .report-header .creature { display: none; }
  .mx-table thead { display: none; }
  .mx-table, .mx-table tbody { display: block; }
  .mx-row { display: block; padding: 8px 0; border-bottom: 1px solid var(--clr-border); }
  .mx-row:last-child { border-bottom: none; }
  .mx-priority { display: inline; text-align: left; padding: 0; border: none; }
  .mx-priority::after { content: " "; }
  .mx-exchange { display: inline; padding: 0; border: none; }
  .mx-provider { display: block; padding: 4px 0 0; border: none; }
}
`;
