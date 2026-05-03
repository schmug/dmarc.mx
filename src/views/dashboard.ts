import type { WebhookFormat } from "../webhooks/formats/index.js";
import {
  esc,
  generateCreature,
  gradeClass,
  gradeToMood,
  sparkline,
  statCard,
  themeToggle,
} from "./components.js";
import { JS } from "./scripts.js";
import { CSS } from "./styles.js";

const DASHBOARD_CSS = `
.dashboard-nav {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  padding: 0.75rem 1.5rem;
  background: var(--clr-surface);
  border-bottom: 1px solid var(--clr-border);
  flex-wrap: wrap;
}
.dashboard-nav .nav-logo {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  text-decoration: none;
  color: var(--clr-text);
  font-weight: 700;
  font-size: 1rem;
}
.dashboard-nav .nav-links {
  display: flex;
  align-items: center;
  gap: 1rem;
  flex: 1;
}
.dashboard-nav .nav-links a {
  color: var(--clr-text-muted);
  text-decoration: none;
  font-size: 0.875rem;
}
.dashboard-nav .nav-links a:hover {
  color: var(--clr-accent);
}
.dashboard-nav .nav-user {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-left: auto;
  font-size: 0.875rem;
  color: var(--clr-text-muted);
}
.dashboard-nav .nav-user a {
  color: var(--clr-text-muted);
  text-decoration: none;
}
.dashboard-nav .nav-user a:hover {
  color: var(--clr-accent);
}
.dashboard-body {
  max-width: 900px;
  margin: 2rem auto;
  padding: 0 1.5rem;
}
.dashboard-title {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--clr-text);
  margin-bottom: 1.5rem;
}
.domain-table {
  width: 100%;
  border-collapse: collapse;
  background: var(--clr-surface);
  border: 1px solid var(--clr-border);
  border-radius: 8px;
  overflow: hidden;
}
.domain-table th {
  text-align: left;
  padding: 0.75rem 1rem;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--clr-text-muted);
  background: var(--clr-bg);
  border-bottom: 1px solid var(--clr-border);
}
.domain-table td {
  padding: 0.875rem 1rem;
  border-bottom: 1px solid var(--clr-border);
  color: var(--clr-text);
  font-size: 0.9rem;
}
.domain-table tr:last-child td {
  border-bottom: none;
}
.domain-table tr:hover td {
  background: var(--clr-bg);
}
.domain-table a {
  color: var(--clr-accent);
  text-decoration: none;
  font-weight: 500;
}
.domain-table a:hover {
  text-decoration: underline;
}
.badge-free {
  display: inline-block;
  padding: 0.1rem 0.45rem;
  background: var(--clr-accent-glow);
  color: var(--clr-accent);
  border: 1px solid var(--clr-accent);
  border-radius: 4px;
  font-size: 0.65rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-left: 0.4rem;
  vertical-align: middle;
}
.badge-alert {
  display: inline-block;
  padding: 0.1rem 0.45rem;
  background: var(--clr-fail);
  color: white;
  border-radius: 4px;
  font-size: 0.65rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-left: 0.4rem;
  vertical-align: middle;
}
.alerts-needs-attention {
  background: var(--clr-surface);
  border: 1px solid var(--clr-fail);
  border-radius: 8px;
  padding: 1rem 1.25rem;
  margin-bottom: 1.5rem;
}
.alerts-needs-attention h2 {
  margin: 0 0 0.75rem 0;
  font-size: 1rem;
  font-weight: 700;
  color: var(--clr-fail);
}
.alerts-needs-attention ul {
  list-style: none;
  margin: 0;
  padding: 0;
}
.alerts-needs-attention li {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 0;
  border-top: 1px solid var(--clr-border);
  font-size: 0.875rem;
  flex-wrap: wrap;
}
.alerts-needs-attention li:first-child {
  border-top: none;
}
.alerts-needs-attention .alert-domain {
  font-weight: 600;
}
.alerts-needs-attention .alert-domain a {
  color: var(--clr-accent);
  text-decoration: none;
}
.alerts-needs-attention .alert-domain a:hover {
  text-decoration: underline;
}
.alerts-needs-attention .alert-message {
  color: var(--clr-text);
  flex: 1;
  min-width: 200px;
}
.alerts-needs-attention .alert-time {
  color: var(--clr-text-muted);
  font-size: 0.75rem;
}
.alerts-needs-attention form {
  margin: 0;
}
.alerts-needs-attention .btn-dismiss {
  background: transparent;
  border: 1px solid var(--clr-border);
  color: var(--clr-text-muted);
  padding: 0.25rem 0.6rem;
  border-radius: 4px;
  font-size: 0.75rem;
  cursor: pointer;
}
.alerts-needs-attention .btn-dismiss:hover {
  border-color: var(--clr-fail);
  color: var(--clr-fail);
}
.grade-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 3rem;
  height: 3rem;
  border-radius: 50%;
  font-size: 1.25rem;
  font-weight: 800;
  border: 3px solid currentColor;
}
.grade-badge.grade-a { color: var(--clr-pass); border-color: var(--clr-pass); }
.grade-badge.grade-c { color: var(--clr-warn); border-color: var(--clr-warn); }
.grade-badge.grade-f { color: var(--clr-fail); border-color: var(--clr-fail); }
.domain-detail-header {
  display: flex;
  align-items: center;
  gap: 1.25rem;
  margin-bottom: 1.5rem;
  flex-wrap: wrap;
}
.domain-detail-name {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--clr-text);
}
.domain-detail-meta {
  background: var(--clr-surface);
  border: 1px solid var(--clr-border);
  border-radius: 8px;
  padding: 1rem 1.25rem;
  margin-bottom: 1.5rem;
  font-size: 0.875rem;
  color: var(--clr-text-muted);
  display: flex;
  gap: 1.5rem;
  flex-wrap: wrap;
}
.domain-detail-meta strong {
  color: var(--clr-text);
}
.btn {
  display: inline-block;
  padding: 0.5rem 1rem;
  background: var(--clr-accent);
  color: #fff;
  border: none;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
  transition: background 0.15s;
}
.btn:hover { background: var(--clr-accent-hover); }
.btn-secondary {
  background: var(--clr-surface);
  color: var(--clr-text);
  border: 1px solid var(--clr-border);
}
.btn-secondary:hover {
  background: var(--clr-bg);
  border-color: var(--clr-border-hover);
}
.btn-danger {
  background: var(--clr-fail);
  color: #fff;
}
.btn-danger:hover { opacity: 0.85; }
.history-list {
  list-style: none;
  padding: 0;
  margin: 0;
}
.history-list li {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.6rem 1rem;
  border-bottom: 1px solid var(--clr-border);
  font-size: 0.875rem;
}
.history-list li:last-child { border-bottom: none; }
.history-list .history-date {
  color: var(--clr-text-muted);
  flex: 1;
}
.settings-section {
  background: var(--clr-surface);
  border: 1px solid var(--clr-border);
  border-radius: 8px;
  padding: 1.25rem 1.5rem;
  margin-bottom: 1.5rem;
}
.settings-section h2 {
  font-size: 1rem;
  font-weight: 700;
  color: var(--clr-text);
  margin-bottom: 0.75rem;
}
.settings-section p {
  font-size: 0.875rem;
  color: var(--clr-text-muted);
  margin-bottom: 0.75rem;
}
.api-key-display {
  font-family: monospace;
  font-size: 0.85rem;
  background: var(--clr-bg);
  border: 1px solid var(--clr-border);
  border-radius: 6px;
  padding: 0.5rem 0.75rem;
  color: var(--clr-text);
  word-break: break-all;
  margin-bottom: 0.75rem;
}
.settings-input {
  display: block;
  width: 100%;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--clr-border);
  border-radius: 6px;
  background: var(--clr-bg);
  color: var(--clr-text);
  font-size: 0.875rem;
  margin-bottom: 0.75rem;
  box-sizing: border-box;
}
.settings-input:focus {
  outline: 2px solid var(--clr-accent);
  outline-offset: 1px;
  border-color: var(--clr-accent);
}
.empty-state {
  text-align: center;
  padding: 3rem 1rem;
  color: var(--clr-text-muted);
  font-size: 0.95rem;
}
.empty-state p { margin-bottom: 1.25rem; }
.inline-grade {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.8rem;
  font-weight: 700;
}
.inline-grade.grade-a { color: var(--clr-pass); background: var(--clr-pass-bg); }
.inline-grade.grade-c { color: var(--clr-warn); background: var(--clr-warn-bg); }
.inline-grade.grade-f { color: var(--clr-fail); background: var(--clr-fail-bg); }
.section-card {
  background: var(--clr-surface);
  border: 1px solid var(--clr-border);
  border-radius: 8px;
  padding: 1.25rem 1.5rem;
  margin-bottom: 1.5rem;
}
.section-card h2 {
  font-size: 1rem;
  font-weight: 700;
  color: var(--clr-text);
  margin-bottom: 1rem;
}
.action-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-top: 0.5rem;
  flex-wrap: wrap;
}
.bulk-textarea {
  display: block;
  width: 100%;
  min-height: 12rem;
  padding: 0.75rem;
  border: 1px solid var(--clr-border);
  border-radius: 6px;
  background: var(--clr-bg);
  color: var(--clr-text);
  font-family: monospace;
  font-size: 0.875rem;
  box-sizing: border-box;
  resize: vertical;
}
.bulk-results-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}
.bulk-results-table th,
.bulk-results-table td {
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--clr-border);
  text-align: left;
}
.bulk-results-table tr:last-child td {
  border-bottom: none;
}
.bulk-status {
  display: inline-block;
  padding: 0.1rem 0.5rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.bulk-status.scanned { color: var(--clr-pass); background: var(--clr-pass-bg); }
.bulk-status.queued { color: var(--clr-text-muted); background: var(--clr-bg); border: 1px solid var(--clr-border); }
.bulk-status.invalid { color: var(--clr-warn); background: var(--clr-warn-bg); }
.bulk-status.error { color: var(--clr-fail); background: var(--clr-fail-bg); }
.bulk-summary {
  font-size: 0.875rem;
  color: var(--clr-text-muted);
  margin-bottom: 1rem;
}
.bulk-error {
  background: var(--clr-fail-bg);
  color: var(--clr-fail);
  border: 1px solid var(--clr-fail);
  border-radius: 6px;
  padding: 0.75rem 1rem;
  margin-bottom: 1rem;
  font-size: 0.875rem;
}
.sparkline {
  width: 100%;
  height: 80px;
  display: block;
}
.sparkline .sparkline-line {
  fill: none;
  stroke: var(--clr-accent);
  stroke-width: 2;
  stroke-linecap: round;
  stroke-linejoin: round;
}
.sparkline .sparkline-dot {
  fill: var(--clr-accent);
}
.sparkline .sparkline-grid {
  stroke: var(--clr-border);
  stroke-width: 1;
  stroke-dasharray: 2 4;
}
.drift-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.8125rem;
}
.drift-table th,
.drift-table td {
  padding: 0.5rem 0.6rem;
  border-bottom: 1px solid var(--clr-border);
  text-align: left;
}
.drift-table th {
  font-weight: 600;
  color: var(--clr-text-muted);
  text-transform: uppercase;
  font-size: 0.7rem;
  letter-spacing: 0.05em;
  background: var(--clr-bg);
}
.drift-table td.drift-date {
  color: var(--clr-text-muted);
  white-space: nowrap;
}
.drift-cell {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
}
.drift-dot {
  display: inline-block;
  width: 0.6rem;
  height: 0.6rem;
  border-radius: 50%;
  background: var(--clr-text-muted);
}
.drift-dot.status-pass { background: var(--clr-pass); }
.drift-dot.status-warn { background: var(--clr-warn); }
.drift-dot.status-fail { background: var(--clr-fail); }
.drift-dot.status-info { background: var(--clr-text-muted); }
.drift-changed {
  border-left: 2px solid var(--clr-accent);
  padding-left: 0.5rem;
}
.upgrade-prompt {
  background: var(--clr-surface);
  border: 1px solid var(--clr-accent);
  border-radius: 8px;
  padding: 1.25rem 1.5rem;
  margin-top: 1.5rem;
  text-align: center;
}
.upgrade-prompt h2 {
  color: var(--clr-accent);
  font-size: 1rem;
  font-weight: 700;
  margin-bottom: 0.5rem;
}
.upgrade-prompt p {
  color: var(--clr-text-muted);
  font-size: 0.875rem;
  margin-bottom: 1rem;
}
.domain-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem 0.75rem;
  align-items: stretch;
  margin-bottom: 0.75rem;
}
.domain-toolbar input,
.domain-toolbar select {
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--clr-border);
  border-radius: 6px;
  background: var(--clr-bg);
  color: var(--clr-text);
  font-size: 0.875rem;
  font-family: inherit;
  box-sizing: border-box;
}
.domain-toolbar input:focus,
.domain-toolbar select:focus {
  outline: 2px solid var(--clr-accent);
  outline-offset: 1px;
  border-color: var(--clr-accent);
}
.domain-toolbar .toolbar-search {
  flex: 1 1 220px;
  min-width: 180px;
}
.domain-toolbar .toolbar-actions {
  display: flex;
  gap: 0.5rem;
  margin-left: auto;
}
.domain-meta-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
  font-size: 0.8125rem;
  color: var(--clr-text-muted);
}
.domain-table th a.sort-link {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  color: var(--clr-text-muted);
  text-decoration: none;
  font: inherit;
  text-transform: inherit;
  letter-spacing: inherit;
}
.domain-table th a.sort-link:hover {
  color: var(--clr-accent);
}
.domain-table th a.sort-link.active {
  color: var(--clr-text);
}
.domain-table th .sort-arrow {
  font-size: 0.7rem;
  opacity: 0.7;
}
.domain-pagination {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  margin-top: 1rem;
  font-size: 0.875rem;
  color: var(--clr-text-muted);
}
.domain-pagination .pagination-links {
  display: flex;
  gap: 0.4rem;
  align-items: center;
}
.domain-pagination a,
.domain-pagination span.page-current,
.domain-pagination span.page-disabled {
  display: inline-block;
  padding: 0.35rem 0.65rem;
  border: 1px solid var(--clr-border);
  border-radius: 4px;
  background: var(--clr-surface);
  color: var(--clr-text-muted);
  text-decoration: none;
  font-size: 0.8125rem;
  min-width: 1.75rem;
  text-align: center;
}
.domain-pagination a:hover {
  border-color: var(--clr-accent);
  color: var(--clr-accent);
  text-decoration: none;
}
.domain-pagination span.page-current {
  background: var(--clr-accent);
  color: #fff;
  border-color: var(--clr-accent);
  font-weight: 600;
}
.domain-pagination span.page-disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

/* ============================================================
   Dashboard refresh — banners, hero, stat strip
   Scoped under .dashboard-body so report/landing styles stay clean.
   ============================================================ */
.dashboard-banner {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.85rem 1.1rem;
  border-radius: 10px;
  margin-bottom: 1rem;
  font-size: 0.9rem;
  flex-wrap: wrap;
}
.dashboard-banner-text { flex: 1; min-width: 220px; line-height: 1.45; }
.dashboard-banner-text strong { font-weight: 600; }
.dashboard-banner-cta {
  display: inline-flex;
  align-items: center;
  padding: 0.5rem 0.95rem;
  background: var(--clr-accent);
  color: var(--clr-on-accent);
  border-radius: 6px;
  font-size: 0.85rem;
  font-weight: 600;
  text-decoration: none;
  white-space: nowrap;
  transition: background 0.15s;
}
.dashboard-banner-cta:hover { background: var(--clr-accent-hover); text-decoration: none; }
.dashboard-banner-free {
  background: var(--clr-accent-muted);
  border: 1px solid var(--clr-accent);
  color: var(--clr-text);
}
.dashboard-banner-firstrun {
  background: var(--clr-pass-bg);
  border: 1px solid var(--clr-pass-border);
  color: var(--clr-text);
}
.dashboard-banner-fire {
  background: var(--clr-fail-bg);
  border: 1px solid var(--clr-fail-border);
  color: var(--clr-text);
}

.dashboard-hero {
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 1.25rem;
  align-items: center;
  padding: 1.25rem 1.4rem;
  background: var(--clr-surface);
  border: 1px solid var(--clr-border);
  border-radius: 12px;
  margin-bottom: 1rem;
}
.dashboard-hero-mascot { display: flex; align-items: center; justify-content: center; }
.dashboard-hero-voice {
  display: flex; flex-direction: column; gap: 0.35rem;
  min-width: 0;
}
.dashboard-hero-voice-line {
  font-size: 1.05rem;
  font-weight: 600;
  color: var(--clr-text);
  line-height: 1.4;
}
.dashboard-hero-voice-line code {
  font-family: 'SF Mono', 'Fira Code', ui-monospace, monospace;
  font-size: 0.95rem;
  background: var(--clr-surface-muted);
  padding: 1px 6px;
  border-radius: 4px;
  color: var(--clr-accent);
}
.dashboard-hero-voice-sub {
  font-size: 0.82rem;
  color: var(--clr-text-muted);
  line-height: 1.45;
}
.dashboard-hero-score {
  display: flex; flex-direction: column; align-items: flex-end;
  gap: 0.35rem;
  min-width: 120px;
}
.dashboard-hero-score-value {
  font-size: 1.85rem;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  color: var(--clr-text);
  line-height: 1;
}
.dashboard-hero-score-label {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--clr-text-faint);
  font-weight: 600;
}
.dashboard-hero-score .dash-spark { margin-top: 0.15rem; }

.stat-strip {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0.65rem;
  margin-bottom: 1.25rem;
}
.stat-card {
  background: var(--clr-surface);
  border: 1px solid var(--clr-border);
  border-left: 3px solid var(--clr-border);
  border-radius: 10px;
  padding: 0.85rem 1rem;
  display: flex; flex-direction: column; gap: 0.25rem;
}
.stat-card-label {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--clr-text-faint);
  font-weight: 600;
}
.stat-card-value {
  font-size: 1.5rem;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  color: var(--clr-text);
  line-height: 1;
}
.stat-card-sub {
  font-size: 0.75rem;
  color: var(--clr-text-muted);
}
.stat-card-pass { border-left-color: var(--clr-pass); }
.stat-card-pass .stat-card-value { color: var(--clr-pass); }
.stat-card-warn { border-left-color: var(--clr-warn); }
.stat-card-warn .stat-card-value { color: var(--clr-warn); }
.stat-card-fail { border-left-color: var(--clr-fail); }
.stat-card-fail .stat-card-value { color: var(--clr-fail); }

@media (max-width: 720px) {
  .stat-strip { grid-template-columns: repeat(2, 1fr); }
  .dashboard-hero { grid-template-columns: 1fr; text-align: left; }
  .dashboard-hero-mascot { justify-content: flex-start; }
  .dashboard-hero-score { align-items: flex-start; }
}

/* ============================================================
   Drawer + add-domain wizard (PR 3)
   Hidden until JS toggles [data-open]. Server still renders the
   per-domain HTML page at /dashboard/domain/:domain so deep links
   keep working when JS is off.
   ============================================================ */
.dashboard-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.5);
  z-index: 100;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.18s ease-out;
}
.dashboard-overlay[data-open="1"] {
  opacity: 1;
  pointer-events: auto;
}

.domain-drawer {
  position: fixed; top: 0; right: 0; bottom: 0;
  width: min(560px, 92vw);
  background: var(--clr-surface);
  border-left: 1px solid var(--clr-border);
  box-shadow: -8px 0 32px var(--clr-shadow);
  z-index: 101;
  transform: translateX(100%);
  transition: transform 0.24s cubic-bezier(0.2, 0.8, 0.2, 1);
  display: flex; flex-direction: column;
  overflow: hidden;
}
.domain-drawer[data-open="1"] { transform: translateX(0); }
.domain-drawer-header {
  display: flex; align-items: center; gap: 1rem;
  padding: 1rem 1.25rem;
  border-bottom: 1px solid var(--clr-border);
  flex-shrink: 0;
}
.domain-drawer-title {
  flex: 1; min-width: 0;
  font-size: 1.05rem;
  font-weight: 700;
  color: var(--clr-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.domain-drawer-close {
  background: var(--clr-surface-muted);
  border: 1px solid var(--clr-border);
  border-radius: 6px;
  padding: 0.35rem 0.75rem;
  font-size: 0.85rem;
  color: var(--clr-text);
  cursor: pointer;
}
.domain-drawer-close:hover { border-color: var(--clr-border-hover); }
.domain-drawer-body {
  flex: 1; min-height: 0;
  overflow-y: auto;
  padding: 1.25rem;
}
.domain-drawer-meta {
  display: flex; flex-wrap: wrap; gap: 1.25rem;
  font-size: 0.8rem;
  color: var(--clr-text-muted);
  margin-bottom: 1rem;
}
.domain-drawer-meta strong { color: var(--clr-text); font-weight: 600; }
.domain-drawer-actions {
  display: flex; gap: 0.5rem; flex-wrap: wrap;
  padding-top: 1rem;
  border-top: 1px solid var(--clr-border);
  margin-top: 1rem;
}
.domain-drawer-actions form { margin: 0; }
.domain-drawer-loading,
.domain-drawer-error {
  text-align: center;
  color: var(--clr-text-muted);
  font-size: 0.9rem;
  padding: 2rem 0;
}
.domain-drawer-error { color: var(--clr-fail); }

/* Wizard modal */
.add-wizard {
  position: fixed; top: 50%; left: 50%;
  transform: translate(-50%, -50%) scale(0.96);
  width: min(480px, 92vw);
  max-height: 90vh;
  background: var(--clr-surface);
  border: 1px solid var(--clr-border);
  border-radius: 12px;
  box-shadow: 0 16px 48px var(--clr-shadow);
  z-index: 101;
  opacity: 0;
  pointer-events: none;
  transition: transform 0.18s cubic-bezier(0.2, 0.8, 0.2, 1), opacity 0.18s ease-out;
  display: flex; flex-direction: column;
  overflow: hidden;
}
.add-wizard[data-open="1"] {
  transform: translate(-50%, -50%) scale(1);
  opacity: 1;
  pointer-events: auto;
}
.add-wizard-header {
  display: flex; align-items: center; gap: 0.75rem;
  padding: 1rem 1.25rem;
  border-bottom: 1px solid var(--clr-border);
}
.add-wizard-title {
  flex: 1;
  font-size: 1rem;
  font-weight: 700;
  color: var(--clr-text);
}
.add-wizard-step-pill {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--clr-text-faint);
  font-weight: 600;
}
.add-wizard-body { padding: 1.25rem; }
.add-wizard-step { display: none; }
.add-wizard-step[data-active="1"] { display: block; }
.add-wizard-step label {
  display: block;
  font-size: 0.8rem;
  color: var(--clr-text-muted);
  margin-bottom: 0.4rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.add-wizard-step input[type="text"],
.add-wizard-step select {
  width: 100%;
  padding: 0.6rem 0.75rem;
  background: var(--clr-bg);
  border: 1px solid var(--clr-border);
  border-radius: 6px;
  color: var(--clr-text);
  font-size: 0.95rem;
  font-family: inherit;
}
.add-wizard-step input[type="text"]:focus,
.add-wizard-step select:focus {
  outline: 2px solid var(--clr-accent);
  outline-offset: 2px;
}
.add-wizard-step p {
  margin: 0;
  color: var(--clr-text);
  font-size: 0.92rem;
  line-height: 1.5;
}
.add-wizard-step p strong { color: var(--clr-accent); }
.add-wizard-error {
  margin-top: 0.75rem;
  font-size: 0.82rem;
  color: var(--clr-fail);
}
.add-wizard-footer {
  display: flex; justify-content: space-between;
  gap: 0.75rem;
  padding: 1rem 1.25rem;
  border-top: 1px solid var(--clr-border);
}
.add-wizard-footer button {
  padding: 0.55rem 1rem;
  border-radius: 6px;
  font-size: 0.88rem;
  font-weight: 600;
  cursor: pointer;
  font-family: inherit;
}
.add-wizard-footer .wizard-secondary {
  background: transparent;
  border: 1px solid var(--clr-border);
  color: var(--clr-text);
}
.add-wizard-footer .wizard-secondary:hover { border-color: var(--clr-border-hover); }
.add-wizard-footer .wizard-primary {
  background: var(--clr-accent);
  border: 1px solid var(--clr-accent);
  color: var(--clr-on-accent);
}
.add-wizard-footer .wizard-primary:hover { background: var(--clr-accent-hover); }
.add-wizard-footer .wizard-primary:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

/* Re-scanning row pulse — drives the post-add row state. */
@keyframes domain-row-pulse {
  0%, 100% { background-color: var(--clr-accent-muted); }
  50%      { background-color: rgba(249, 115, 22, 0.18); }
}
.domain-table tr.is-rescanning td {
  animation: domain-row-pulse 1.6s ease-in-out infinite;
}
@media (prefers-reduced-motion: reduce) {
  .domain-table tr.is-rescanning td {
    animation: none;
    background: var(--clr-accent-muted);
  }
}

/* Add-domain trigger button on the dashboard */
.dashboard-add-btn {
  display: inline-flex; align-items: center;
  padding: 0.5rem 0.95rem;
  background: var(--clr-accent);
  color: var(--clr-on-accent);
  border: 1px solid var(--clr-accent);
  border-radius: 6px;
  font-size: 0.85rem;
  font-weight: 600;
  text-decoration: none;
  cursor: pointer;
  font-family: inherit;
}
.dashboard-add-btn:hover { background: var(--clr-accent-hover); text-decoration: none; }

/* ---- Drawer detail (PR follow-up: protocols, diff, recs, footer) ---- */
.domain-drawer-body { padding-bottom: 5rem; }
.drawer-section-title {
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--clr-text-faint);
  font-family: 'SF Mono', 'Fira Code', ui-monospace, monospace;
  margin: 1.5rem 0 0.6rem;
}
.drawer-section-title:first-child { margin-top: 0; }

/* Header restyle: grade pill + name + cadence sub */
.domain-drawer-title {
  display: flex; align-items: center; gap: 0.85rem;
  flex: 1; min-width: 0;
  white-space: normal;
  overflow: visible;
}
.drawer-header-stack {
  display: flex; flex-direction: column; gap: 2px;
  min-width: 0;
}
.drawer-header-name {
  font-size: 1.05rem;
  font-weight: 700;
  color: var(--clr-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.drawer-header-sub {
  font-size: 0.72rem;
  color: var(--clr-text-faint);
  text-transform: uppercase;
  letter-spacing: 1.2px;
  font-family: 'SF Mono', 'Fira Code', ui-monospace, monospace;
}

/* Grade pill (drawer header). The detail page's grade-badge is rounded;
   this is the prototype's rounded-square variant scaled to fit the header. */
.grade-pill {
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 38px; height: 32px;
  padding: 0 6px;
  border-radius: 7px;
  border: 1px solid;
  font-size: 0.95rem;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  flex-shrink: 0;
}
.grade-pill-s {
  color: #78350f;
  background: linear-gradient(135deg, #fde68a, #f59e0b, #facc15);
  border-color: #f59e0b;
}
.grade-pill-a {
  color: var(--clr-pass);
  background: var(--clr-pass-bg);
  border-color: var(--clr-pass-border);
}
.grade-pill-c {
  color: var(--clr-warn);
  background: var(--clr-warn-bg);
  border-color: var(--clr-warn-border);
}
.grade-pill-f {
  color: var(--clr-fail);
  background: var(--clr-fail-bg);
  border-color: var(--clr-fail-border);
}

/* Status dots inside the drawer */
.drawer-status-dot {
  display: inline-block;
  width: 9px; height: 9px;
  border-radius: 50%;
  flex-shrink: 0;
}
.drawer-status-pass { background: var(--clr-pass); box-shadow: 0 0 8px var(--clr-pass-glow); }
.drawer-status-warn { background: var(--clr-warn); box-shadow: 0 0 8px var(--clr-warn-glow); }
.drawer-status-fail { background: var(--clr-fail); box-shadow: 0 0 8px var(--clr-fail-glow); }
.drawer-status-info { background: var(--clr-info); box-shadow: 0 0 8px var(--clr-info-glow); }
.drawer-status-unknown { background: var(--clr-text-faint); }

/* Copy button shared by diff lines + protocol records */
.drawer-copy-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 9px;
  background: transparent;
  color: var(--clr-text-muted);
  border: 1px solid var(--clr-border);
  border-radius: 6px;
  font-size: 0.72rem;
  font-weight: 500;
  font-family: inherit;
  cursor: pointer;
  flex-shrink: 0;
  transition: background 0.12s, color 0.12s, border-color 0.12s;
}
.drawer-copy-btn:hover {
  border-color: var(--clr-border-hover);
  color: var(--clr-text);
}
.drawer-copy-btn-copied,
.drawer-copy-btn-copied:hover {
  background: var(--clr-pass-bg);
  color: var(--clr-pass);
  border-color: var(--clr-pass-border);
}
.drawer-copy-btn-suggested {
  border-color: var(--clr-pass-border);
  color: var(--clr-pass);
}

/* Diff card */
.drawer-diff-card {
  background: var(--clr-bg);
  border: 1px solid var(--clr-fail-border);
  border-left: 3px solid var(--clr-fail);
  border-radius: 10px;
  padding: 1rem 1.1rem;
  margin-bottom: 1.5rem;
}
.drawer-diff-label {
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  font-family: 'SF Mono', 'Fira Code', ui-monospace, monospace;
  color: var(--clr-fail);
  margin-bottom: 0.5rem;
}
.drawer-diff-msg {
  font-size: 0.9rem;
  color: var(--clr-text);
  margin-bottom: 0.7rem;
}
.drawer-diff-block {
  background: var(--clr-surface);
  border: 1px solid var(--clr-border);
  border-radius: 6px;
  font-family: 'SF Mono', 'Fira Code', ui-monospace, monospace;
  font-size: 0.74rem;
  line-height: 1.55;
  overflow: hidden;
  margin-bottom: 0.75rem;
}
.drawer-diff-row {
  display: flex; align-items: flex-start;
  gap: 10px;
  padding: 0.55rem 0.85rem;
}
.drawer-diff-row + .drawer-diff-row { border-top: 1px solid var(--clr-border); }
.drawer-diff-current { color: var(--clr-fail); }
.drawer-diff-previous {
  background: var(--clr-pass-bg);
  color: var(--clr-pass);
}
.drawer-diff-line-text {
  flex: 1; min-width: 0;
  word-break: break-all;
}
.drawer-diff-marker { opacity: 0.7; }
.drawer-diff-actions {
  display: flex; flex-wrap: wrap; align-items: center;
  gap: 0.6rem;
  margin-top: 0.25rem;
}
.drawer-diff-hint {
  font-size: 0.74rem;
  color: var(--clr-text-muted);
  flex: 1;
  min-width: 220px;
}

/* Protocol rows */
.drawer-protocol-list {
  display: flex; flex-direction: column;
  gap: 8px;
  margin-bottom: 0.5rem;
}
.drawer-protocol-card {
  background: var(--clr-bg);
  border: 1px solid var(--clr-border);
  border-radius: 8px;
  overflow: hidden;
}
.drawer-protocol-head {
  display: flex; align-items: center;
  width: 100%;
  gap: 12px;
  padding: 0.7rem 1rem;
  background: transparent;
  border: 0;
  color: var(--clr-text);
  font: inherit;
  text-align: left;
  cursor: pointer;
}
.drawer-protocol-head[disabled] { cursor: default; }
.drawer-protocol-head:not([disabled]):hover { background: var(--clr-surface-muted); }
.drawer-protocol-name {
  font-weight: 600;
  font-size: 0.88rem;
  min-width: 80px;
}
.drawer-protocol-summary {
  flex: 1; min-width: 0;
  color: var(--clr-text-muted);
  font-size: 0.8rem;
  font-family: 'SF Mono', 'Fira Code', ui-monospace, monospace;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.drawer-protocol-chevron {
  color: var(--clr-text-faint);
  font-size: 0.75rem;
  transition: transform 0.15s;
  display: inline-flex;
}
.drawer-protocol-chevron.is-open { transform: rotate(90deg); }
.drawer-protocol-detail {
  display: flex; align-items: flex-start;
  gap: 12px;
  padding: 0.75rem 1rem;
  border-top: 1px solid var(--clr-border);
  background: var(--clr-surface-muted);
}
.drawer-protocol-detail[hidden] { display: none; }
.drawer-protocol-record {
  flex: 1; min-width: 0;
  font-family: 'SF Mono', 'Fira Code', ui-monospace, monospace;
  font-size: 0.74rem;
  color: var(--clr-text);
  line-height: 1.5;
  word-break: break-all;
}

/* Recommendations */
.drawer-rec-list { display: flex; flex-direction: column; }
.drawer-rec-row {
  display: flex; gap: 12px;
  padding: 0.85rem 0;
  border-bottom: 1px solid var(--clr-border);
}
.drawer-rec-row:last-child { border-bottom: 0; }
.drawer-rec-priority {
  width: 30px; height: 24px;
  border-radius: 6px;
  display: inline-flex; align-items: center; justify-content: center;
  font-size: 0.68rem;
  font-weight: 700;
  font-family: 'SF Mono', 'Fira Code', ui-monospace, monospace;
  flex-shrink: 0;
  border: 1px solid var(--clr-border);
}
.drawer-rec-p1 {
  background: var(--clr-fail-bg);
  color: var(--clr-fail);
  border-color: var(--clr-fail-border);
}
.drawer-rec-p2 {
  background: var(--clr-warn-bg);
  color: var(--clr-warn);
  border-color: var(--clr-warn-border);
}
.drawer-rec-p3 {
  background: var(--clr-surface-muted);
  color: var(--clr-text-muted);
}
.drawer-rec-body { flex: 1; min-width: 0; }
.drawer-rec-title {
  font-size: 0.88rem;
  font-weight: 500;
  color: var(--clr-text);
}
.drawer-rec-impact {
  font-size: 0.78rem;
  color: var(--clr-text-muted);
  margin-top: 4px;
  line-height: 1.45;
}

/* History rows (replaces the wide-spread table) */
.drawer-history-list { display: flex; flex-direction: column; }
.drawer-history-row {
  display: flex; align-items: center;
  gap: 12px;
  padding: 0.55rem 0;
  border-bottom: 1px solid var(--clr-border);
  font-size: 0.85rem;
}
.drawer-history-row:last-child { border-bottom: 0; }
.drawer-history-grade {
  font-weight: 600;
  color: var(--clr-text);
  min-width: 36px;
}
.drawer-history-time {
  margin-left: auto;
  color: var(--clr-text-faint);
  font-family: 'SF Mono', 'Fira Code', ui-monospace, monospace;
  font-size: 0.74rem;
}
.drawer-history-empty {
  color: var(--clr-text-muted);
  font-size: 0.85rem;
}

/* Sticky footer */
.drawer-footer {
  position: sticky;
  bottom: 0;
  display: flex; gap: 0.6rem; align-items: center;
  padding: 0.85rem 1.25rem;
  border-top: 1px solid var(--clr-border);
  background: var(--clr-surface);
  flex-shrink: 0;
}
.drawer-footer-form { margin: 0; }
.drawer-cta-primary,
.drawer-cta-secondary {
  display: inline-flex; align-items: center;
  padding: 0.5rem 0.95rem;
  border-radius: 6px;
  font-size: 0.85rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  text-decoration: none;
  border: 1px solid transparent;
}
.drawer-cta-primary {
  background: var(--clr-accent);
  color: var(--clr-on-accent);
  border-color: var(--clr-accent);
}
.drawer-cta-primary:hover { background: var(--clr-accent-hover); text-decoration: none; }
.drawer-cta-secondary {
  background: transparent;
  color: var(--clr-text);
  border-color: var(--clr-border);
}
.drawer-cta-secondary:hover {
  border-color: var(--clr-border-hover);
  text-decoration: none;
}
.drawer-cta-fixed {
  color: var(--clr-pass);
  border-color: var(--clr-pass-border);
}

@media (max-width: 720px) {
  .domain-drawer { width: 100vw; }
}
`;

function dashboardPage(title: string, body: string, email: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)}</title>
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<script>(function(){var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)})()</script>
<style>${CSS}</style>
<style>${DASHBOARD_CSS}</style>
</head>
<body>
<nav class="dashboard-nav">
  <a href="/" class="nav-logo">${generateCreature("sm")} dmarc.mx</a>
  <div class="nav-links">
    <a href="/dashboard">Domains</a>
    <a href="/dashboard/bulk">Bulk Scan</a>
    <a href="/dashboard/settings">Settings</a>
  </div>
  <div class="nav-user">
    <span>${esc(email)}</span>
    <a href="/auth/logout">Logout</a>
    ${themeToggle()}
  </div>
</nav>
<div class="dashboard-body">
${body}
</div>
<script>${JS}</script>
</body>
</html>`;
}

export interface DashboardDomain {
  domain: string;
  grade: string;
  frequency: string;
  lastScanned: string | null;
  isFree: boolean;
  unacknowledgedAlerts?: number;
}

export interface DashboardAlert {
  id: number;
  domain: string;
  alertType: string;
  previousValue: string | null;
  newValue: string | null;
  createdAt: number;
}

export interface ScanHistoryEntry {
  date: string;
  grade: string;
}

function describeAlert(alert: DashboardAlert): string {
  const prev = alert.previousValue ?? "";
  const next = alert.newValue ?? "";
  if (alert.alertType === "grade_drop") {
    return `Grade dropped from ${prev || "—"} to ${next || "—"}`;
  }
  if (alert.alertType === "protocol_regression") {
    // Detector writes values shaped as "${proto}:${status}" — strip protocol
    // names to keep the message scannable, fall back to raw if shape changes.
    const prevColon = prev.indexOf(":");
    const nextColon = next.indexOf(":");
    const proto =
      prevColon > 0
        ? prev.slice(0, prevColon)
        : nextColon > 0
          ? next.slice(0, nextColon)
          : "";
    const prevStatus = prevColon > 0 ? prev.slice(prevColon + 1) : prev;
    const nextStatus = nextColon > 0 ? next.slice(nextColon + 1) : next;
    const protoLabel = proto
      ? proto.toUpperCase().replace(/_/g, "-")
      : "Protocol";
    return `${protoLabel} regressed: ${prevStatus || "—"} → ${nextStatus || "—"}`;
  }
  return `${alert.alertType}: ${prev} → ${next}`;
}

function relativeTime(unixSeconds: number, now: number): string {
  const deltaSec = Math.max(0, now - unixSeconds);
  if (deltaSec < 60) return "just now";
  if (deltaSec < 3600) return `${Math.floor(deltaSec / 60)}m ago`;
  if (deltaSec < 86400) return `${Math.floor(deltaSec / 3600)}h ago`;
  return `${Math.floor(deltaSec / 86400)}d ago`;
}

export function renderAlertsSection(
  alerts: DashboardAlert[],
  now: number = Math.floor(Date.now() / 1000),
): string {
  if (alerts.length === 0) return "";
  const items = alerts
    .map((a) => {
      const domainHref = `/dashboard/domain/${encodeURIComponent(a.domain)}`;
      const ackHref = `/dashboard/alerts/${a.id}/acknowledge`;
      return `<li>
  <span class="alert-domain"><a href="${domainHref}">${esc(a.domain)}</a></span>
  <span class="alert-message">${esc(describeAlert(a))}</span>
  <span class="alert-time">${esc(relativeTime(a.createdAt, now))}</span>
  <form method="post" action="${ackHref}">
    <button type="submit" class="btn-dismiss" aria-label="Dismiss alert for ${esc(a.domain)}">Dismiss</button>
  </form>
</li>`;
    })
    .join("");
  return `<section class="alerts-needs-attention" aria-label="Domain regressions needing attention">
  <h2>Needs attention</h2>
  <ul>${items}</ul>
</section>`;
}

export type DashboardSortColumn =
  | "domain"
  | "grade"
  | "last_scanned"
  | "created";
export type DashboardSortDirection = "asc" | "desc";

export interface DashboardControls {
  search: string;
  grade: string | null;
  frequency: "weekly" | "monthly" | null;
  sort: DashboardSortColumn;
  direction: DashboardSortDirection;
  page: number;
  pageSize: number;
  totalPages: number;
  total: number;
}

const GRADE_FILTER_OPTIONS = [
  "A+",
  "A",
  "A-",
  "B+",
  "B",
  "B-",
  "C+",
  "C",
  "C-",
  "D+",
  "D",
  "D-",
  "F",
  "ungraded",
];

// Build a URL-encoded query string for /dashboard from the current control
// state plus a set of overrides. Centralizes the "preserve every other knob"
// rule so sort headers and pagination links don't drop filters.
function buildDashboardHref(
  controls: DashboardControls,
  overrides: Partial<{
    sort: DashboardSortColumn;
    direction: DashboardSortDirection;
    page: number;
  }>,
): string {
  const params = new URLSearchParams();
  if (controls.search) params.set("q", controls.search);
  if (controls.grade) params.set("grade", controls.grade);
  if (controls.frequency) params.set("frequency", controls.frequency);
  const sort = overrides.sort ?? controls.sort;
  const direction = overrides.direction ?? controls.direction;
  if (sort !== "domain") params.set("sort", sort);
  if (direction !== "asc") params.set("dir", direction);
  const page = overrides.page ?? controls.page;
  if (page > 1) params.set("page", String(page));
  if (controls.pageSize !== 25) {
    params.set("pageSize", String(controls.pageSize));
  }
  const qs = params.toString();
  return qs ? `/dashboard?${qs}` : "/dashboard";
}

function renderSortableHeader(
  controls: DashboardControls,
  column: DashboardSortColumn,
  label: string,
): string {
  const isActive = controls.sort === column;
  // Toggle direction when re-clicking the active column; otherwise default to
  // ascending so users see best→worst for grade and oldest→newest for dates
  // unless they explicitly flip it.
  const nextDirection: DashboardSortDirection = isActive
    ? controls.direction === "asc"
      ? "desc"
      : "asc"
    : "asc";
  const arrow = isActive ? (controls.direction === "asc" ? "▲" : "▼") : "";
  const href = buildDashboardHref(controls, {
    sort: column,
    direction: nextDirection,
    page: 1,
  });
  return `<th><a class="sort-link${isActive ? " active" : ""}" href="${esc(href)}">${esc(label)}<span class="sort-arrow">${arrow}</span></a></th>`;
}

function renderDomainToolbar(controls: DashboardControls): string {
  const gradeOpts = GRADE_FILTER_OPTIONS.map((g) => {
    const sel = controls.grade === g ? " selected" : "";
    const label = g === "ungraded" ? "Not yet scanned" : g;
    return `<option value="${esc(g)}"${sel}>${esc(label)}</option>`;
  }).join("");
  const freqOpts = ["weekly", "monthly"]
    .map(
      (f) =>
        `<option value="${esc(f)}"${controls.frequency === f ? " selected" : ""}>${esc(f.charAt(0).toUpperCase() + f.slice(1))}</option>`,
    )
    .join("");
  return `<form class="domain-toolbar" method="get" action="/dashboard" role="search">
  <input
    type="search"
    class="toolbar-search"
    name="q"
    value="${esc(controls.search)}"
    placeholder="Search domains…"
    aria-label="Search domains"
    maxlength="60"
    autocapitalize="none"
    autocorrect="off"
    spellcheck="false"
  >
  <select name="grade" aria-label="Filter by grade">
    <option value="">All grades</option>
    ${gradeOpts}
  </select>
  <select name="frequency" aria-label="Filter by scan frequency">
    <option value="">All frequencies</option>
    ${freqOpts}
  </select>
  ${controls.sort !== "domain" ? `<input type="hidden" name="sort" value="${esc(controls.sort)}">` : ""}
  ${controls.direction !== "asc" ? `<input type="hidden" name="dir" value="${esc(controls.direction)}">` : ""}
  ${controls.pageSize !== 25 ? `<input type="hidden" name="pageSize" value="${controls.pageSize}">` : ""}
  <div class="toolbar-actions">
    <button type="submit" class="btn">Apply</button>
    <a href="/dashboard" class="btn btn-secondary">Reset</a>
  </div>
</form>`;
}

function renderPagination(controls: DashboardControls): string {
  if (controls.total === 0) return "";
  const start = (controls.page - 1) * controls.pageSize + 1;
  const end = Math.min(controls.page * controls.pageSize, controls.total);
  const prev = controls.page > 1;
  const next = controls.page < controls.totalPages;

  // Window of page numbers around the current page so the link list stays
  // readable when a user has many domains.
  const window: number[] = [];
  const span = 2;
  const lo = Math.max(1, controls.page - span);
  const hi = Math.min(controls.totalPages, controls.page + span);
  for (let p = lo; p <= hi; p += 1) window.push(p);

  const pageLinks = window
    .map((p) =>
      p === controls.page
        ? `<span class="page-current" aria-current="page">${p}</span>`
        : `<a href="${esc(buildDashboardHref(controls, { page: p }))}">${p}</a>`,
    )
    .join("");

  const prevLink = prev
    ? `<a href="${esc(buildDashboardHref(controls, { page: controls.page - 1 }))}" rel="prev">‹ Prev</a>`
    : `<span class="page-disabled">‹ Prev</span>`;
  const nextLink = next
    ? `<a href="${esc(buildDashboardHref(controls, { page: controls.page + 1 }))}" rel="next">Next ›</a>`
    : `<span class="page-disabled">Next ›</span>`;

  return `<nav class="domain-pagination" aria-label="Domain list pagination">
  <span>Showing ${start}–${end} of ${controls.total}</span>
  <span class="pagination-links">
    ${prevLink}
    ${pageLinks}
    ${nextLink}
  </span>
</nav>`;
}

// Renders just the toolbar + table + pagination, wrapped in a stable
// `#domain-panel` element so the live-search client script can swap it in
// place via /dashboard/domains. Used both inline by renderDashboardPage and
// directly by the fragment route — keep the wrapper markup identical between
// the two so the swap is a clean replace.
export function renderDomainPanel({
  domains,
  controls,
  usage,
}: {
  domains: DashboardDomain[];
  controls: DashboardControls | null;
  usage?: WatchlistUsage;
}): string {
  const isFiltered =
    controls !== null &&
    (controls.search !== "" ||
      controls.grade !== null ||
      controls.frequency !== null);

  let tableBody: string;

  if (domains.length === 0) {
    // Filtered-empty differs from "no domains at all" — keep the upgrade /
    // add-domain CTA out of the way when the user is just narrowing a list.
    tableBody = isFiltered
      ? `<div class="empty-state">
  <p>No domains match these filters.</p>
  <a href="/dashboard" class="btn btn-secondary">Clear filters</a>
</div>`
      : `<div class="empty-state">
  <p>No domains yet. Add your first domain to start monitoring.</p>
  <a href="/dashboard/domain/add" class="btn">Add Domain</a>
</div>`;
  } else {
    const rows = domains
      .map((d) => {
        const alertCount = d.unacknowledgedAlerts ?? 0;
        const alertBadge =
          alertCount > 0
            ? `<span class="badge-alert">${alertCount} alert${alertCount === 1 ? "" : "s"}</span>`
            : "";
        return `<tr data-domain="${esc(d.domain)}">
  <td>
    <a href="/dashboard/domain/${encodeURIComponent(d.domain)}" data-drawer-link>${esc(d.domain)}</a>
    ${d.isFree ? '<span class="badge-free">Free</span>' : ""}
    ${alertBadge}
  </td>
  <td><span class="inline-grade ${gradeClass(d.grade)}">${esc(d.grade)}</span></td>
  <td>${esc(d.frequency)}</td>
  <td>${d.lastScanned ? esc(d.lastScanned) : '<span style="color:var(--clr-text-muted)">Never</span>'}</td>
</tr>`;
      })
      .join("");

    const headerRow = controls
      ? `<tr>
      ${renderSortableHeader(controls, "domain", "Domain")}
      ${renderSortableHeader(controls, "grade", "Grade")}
      <th>Frequency</th>
      ${renderSortableHeader(controls, "last_scanned", "Last Scan")}
    </tr>`
      : `<tr>
      <th>Domain</th>
      <th>Grade</th>
      <th>Frequency</th>
      <th>Last Scan</th>
    </tr>`;

    tableBody = `<table class="domain-table">
  <thead>${headerRow}</thead>
  <tbody>${rows}</tbody>
</table>`;
  }

  // Pro accounts get the full toolbar + pagination. Free accounts cap out at
  // a tiny list, so the controls only add noise.
  const toolbar = controls ? renderDomainToolbar(controls) : "";
  const pagination = controls ? renderPagination(controls) : "";

  const usageHint = usage ? renderUsageHint(usage) : "";

  // data-pro="1" is the signal the client script uses to enable live
  // search/swap. Free users render the same wrapper so a future plan upgrade
  // doesn't need a markup migration, but the script bails out early.
  return `<div id="domain-panel" data-pro="${controls ? "1" : "0"}">
${usageHint}
${toolbar}
${tableBody}
${pagination}
</div>`;
}

// Numeric weight for ranking grades from worst (F=0) to best (S=12). Mirrors
// the table in db/scans.ts; kept private here so the view layer doesn't need
// to import a db module just to compute hero copy.
const HERO_GRADE_RANK: Record<string, number> = {
  S: 12,
  "A+": 11,
  A: 10,
  "A-": 9,
  "B+": 8,
  B: 7,
  "B-": 6,
  "C+": 5,
  C: 4,
  "C-": 3,
  "D+": 2,
  D: 1,
  "D-": 1,
  F: 0,
};

function gradeRank(grade: string): number {
  return HERO_GRADE_RANK[grade] ?? -1;
}

// Picks the lowest-graded entry, ignoring ungraded ("—" / "ungraded") rows.
// Returns null when no domain has been scored yet — callers fall back to a
// neutral copy/mood instead of mis-labeling a fresh, never-scanned entry.
function worstDomain(domains: DashboardDomain[]): DashboardDomain | null {
  let worst: DashboardDomain | null = null;
  let worstScore = Number.POSITIVE_INFINITY;
  for (const d of domains) {
    const score = gradeRank(d.grade);
    if (score < 0) continue; // skip ungraded
    if (score < worstScore) {
      worst = d;
      worstScore = score;
    }
  }
  return worst;
}

interface PortfolioStats {
  total: number;
  healthy: number;
  drifting: number;
  failing: number;
  ungraded: number;
}

function portfolioStats(domains: DashboardDomain[]): PortfolioStats {
  let healthy = 0;
  let drifting = 0;
  let failing = 0;
  let ungraded = 0;
  for (const d of domains) {
    const letter = d.grade.charAt(0).toUpperCase();
    if (letter === "S" || letter === "A" || letter === "B") healthy += 1;
    else if (letter === "C" || letter === "D") drifting += 1;
    else if (letter === "F") failing += 1;
    else ungraded += 1;
  }
  return { total: domains.length, healthy, drifting, failing, ungraded };
}

// Composes the DMarcus voice line for the hero in the "terse" register the
// CLAUDE.md mascot guide and the Dashboard handoff both call out as the
// shipping voice. Returns plain HTML; ` … ` segments around domain names get
// rendered as <code> via the markdown-ish hero-line lookup in render.
function heroVoiceLine(
  stats: PortfolioStats,
  worst: DashboardDomain | null,
): {
  line: string;
  sub: string;
} {
  if (stats.total === 0) {
    return {
      line: "Add a domain and I'll keep watch.",
      sub: "Free plan starts with one domain. Upgrade for more.",
    };
  }
  if (stats.failing >= 3) {
    return {
      line: `${stats.failing} domains are failing. Triage <code>${esc(worst?.domain ?? "")}</code> first.`,
      sub: "DMARC, SPF, or DKIM regressions usually trace to a recent DNS edit.",
    };
  }
  if (stats.failing > 0 && worst) {
    return {
      line: `<code>${esc(worst.domain)}</code> is failing. The rest of the watchlist is steady.`,
      sub: "Open it to see the diff and grab the fix.",
    };
  }
  if (stats.drifting > 0) {
    const word = stats.drifting === 1 ? "domain" : "domains";
    return {
      line: `${stats.drifting} ${word} drifted. ${worst ? `Click <code>${esc(worst.domain)}</code> first.` : ""}`,
      sub: "Drift usually means a record was edited but not promoted.",
    };
  }
  // No failures, no drift — but if nothing has been graded yet we shouldn't
  // claim everything's green. The first scan happens within seconds of
  // signup; this copy bridges that gap.
  if (stats.healthy === 0) {
    const word = stats.ungraded === 1 ? "domain" : "domains";
    const count = stats.ungraded === 1 ? "" : `${stats.ungraded} `;
    return {
      line: `Scanning your ${count}${word} now…`,
      sub: "First grades land in a few seconds. I'll refresh when they do.",
    };
  }
  return {
    line: "Everything's green. Nice.",
    sub: "I'll re-check on schedule and email you the moment anything moves.",
  };
}

function renderFreeTierBanner(): string {
  return `<div class="dashboard-banner dashboard-banner-free" role="region" aria-label="Plan upgrade">
  <span class="dashboard-banner-text">You're on the <strong>free plan</strong> — daily scans, alerts, and per-domain detail are Pro features.</span>
  <a href="/pricing" class="dashboard-banner-cta">Upgrade to Pro — $19/mo</a>
</div>`;
}

function renderFirstRunBanner(domain: string): string {
  return `<div class="dashboard-banner dashboard-banner-firstrun" role="region" aria-label="Welcome">
  <span class="dashboard-banner-text">Welcome — we auto-added <strong>${esc(domain)}</strong> from your email. <a href="/dashboard/domain/add">Add more</a> any time.</span>
</div>`;
}

function renderOnFireBanner(failing: number): string {
  return `<div class="dashboard-banner dashboard-banner-fire" role="region" aria-label="Multiple failures">
  <span class="dashboard-banner-text"><strong>${failing} domains failing.</strong> Walk down the list — most regressions share a single root cause.</span>
</div>`;
}

function renderDashboardHero(
  domains: DashboardDomain[],
  portfolioTrend: number[],
): string {
  const stats = portfolioStats(domains);
  const worst = worstDomain(domains);
  // Mood comes from the worst *graded* domain. With nothing scored yet there
  // is no signal to react to, so DMarcus defaults to neutral rather than
  // panicking at a freshly-added entry that just hasn't been scanned.
  const mood = worst ? gradeToMood(worst.grade) : "content";
  // Celebrate only when at least one domain has actually been graded as
  // healthy. An entirely ungraded portfolio is "we don't know yet", not
  // "we won".
  const partyHat =
    stats.healthy > 0 && stats.failing === 0 && stats.drifting === 0;
  const { line, sub } = heroVoiceLine(stats, worst);

  // Score on a 0–100 scale derived from the latest portfolio average (0–12),
  // for legibility in the hero's right column. Falls back to a sensible
  // default for empty portfolios so the markup never has an undefined slot.
  const latest = portfolioTrend.length
    ? portfolioTrend[portfolioTrend.length - 1]
    : null;
  const scoreText =
    latest === null ? "—" : Math.round((latest / 12) * 100).toString();

  const trendMarkup =
    portfolioTrend.length >= 2
      ? sparkline(portfolioTrend, "var(--clr-accent)", {
          width: 120,
          height: 28,
          fill: true,
          ariaLabel: `Portfolio score trend, ${portfolioTrend.length} data points`,
        })
      : "";

  return `<section class="dashboard-hero" aria-label="Portfolio summary">
  <div class="dashboard-hero-mascot">${generateCreature("lg", mood, partyHat)}</div>
  <div class="dashboard-hero-voice">
    <div class="dashboard-hero-voice-line">${line}</div>
    <div class="dashboard-hero-voice-sub">${esc(sub)}</div>
  </div>
  <div class="dashboard-hero-score">
    <span class="dashboard-hero-score-value">${esc(scoreText)}</span>
    <span class="dashboard-hero-score-label">Portfolio score</span>
    ${trendMarkup}
  </div>
</section>`;
}

function renderDomainDrawerShell(): string {
  // Markup is hidden until the dashboard-drawer.js controller toggles
  // [data-open]. The HTML route /dashboard/domain/:domain stays the source
  // of truth for shareable deep links — the drawer hydrates from the JSON
  // sibling, but a user with JS off (or who shares a link) lands on the
  // same data via the legacy route.
  return `<div class="dashboard-overlay" data-overlay-for="domain-drawer" hidden></div>
<aside id="domain-drawer" class="domain-drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title" tabindex="-1" hidden>
  <div class="domain-drawer-header">
    <span id="drawer-title" class="domain-drawer-title">Loading…</span>
    <button type="button" class="domain-drawer-close" data-drawer-close aria-label="Close domain detail">Close</button>
  </div>
  <div class="domain-drawer-body" data-drawer-body>
    <div class="domain-drawer-loading">Loading…</div>
  </div>
</aside>`;
}

function renderAddDomainWizardShell(): string {
  return `<div class="dashboard-overlay" data-overlay-for="add-wizard" hidden></div>
<div id="add-wizard" class="add-wizard" role="dialog" aria-modal="true" aria-labelledby="wizard-title" tabindex="-1" hidden>
  <form data-wizard-form action="/dashboard/domain/add" method="post" novalidate>
    <div class="add-wizard-header">
      <span id="wizard-title" class="add-wizard-title">Add a domain</span>
      <span class="add-wizard-step-pill" data-wizard-pill>Step 1 of 3</span>
      <button type="button" class="domain-drawer-close" data-wizard-close aria-label="Close add-domain wizard">Close</button>
    </div>
    <div class="add-wizard-body">
      <div class="add-wizard-step" data-active="1" data-step="1">
        <label for="wizard-domain">Domain</label>
        <input type="text" id="wizard-domain" name="domain" placeholder="example.com" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" required aria-describedby="wizard-domain-error">
        <div id="wizard-domain-error" class="add-wizard-error" data-wizard-error role="alert" aria-live="polite" hidden></div>
      </div>
      <div class="add-wizard-step" data-step="2">
        <label for="wizard-frequency">Scan frequency</label>
        <select id="wizard-frequency" name="frequency">
          <option value="daily">Daily (Pro)</option>
          <option value="weekly" selected>Weekly</option>
          <option value="monthly">Monthly</option>
        </select>
      </div>
      <div class="add-wizard-step" data-step="3">
        <p>About to add <strong data-wizard-confirm-domain>—</strong> on a <strong data-wizard-confirm-frequency>—</strong> cadence.</p>
        <p style="margin-top:0.75rem;color:var(--clr-text-muted);font-size:0.85rem;">First scan kicks off immediately. You'll see a grade in a few seconds.</p>
      </div>
    </div>
    <div class="add-wizard-footer">
      <button type="button" class="wizard-secondary" data-wizard-back hidden>Back</button>
      <span style="flex:1"></span>
      <button type="button" class="wizard-primary" data-wizard-next>Next</button>
      <button type="submit" class="wizard-primary" data-wizard-submit hidden>Add domain</button>
    </div>
  </form>
</div>`;
}

function renderDashboardStatStrip(domains: DashboardDomain[]): string {
  const stats = portfolioStats(domains);
  const totalCard = statCard(
    "Domains",
    stats.total,
    stats.ungraded > 0
      ? `${stats.ungraded} not yet scanned`
      : "in your watchlist",
  );
  const healthyCard = statCard(
    "Healthy",
    stats.healthy,
    "graded A or B",
    stats.healthy > 0 ? "pass" : undefined,
  );
  const driftingCard = statCard(
    "Drifting",
    stats.drifting,
    "graded C or D",
    stats.drifting > 0 ? "warn" : undefined,
  );
  const failingCard = statCard(
    "Failing",
    stats.failing,
    "graded F",
    stats.failing > 0 ? "fail" : undefined,
  );
  return `<section class="stat-strip" aria-label="Portfolio status">
  ${totalCard}
  ${healthyCard}
  ${driftingCard}
  ${failingCard}
</section>`;
}

export function renderDashboardPage({
  email,
  alerts = [],
  domains,
  controls = null,
  usage,
  plan = "pro",
  portfolioTrend = [],
  isFirstRun = false,
}: {
  email: string;
  alerts?: DashboardAlert[];
  domains: DashboardDomain[];
  // Set only for Pro accounts; gates the search/sort/pagination UI.
  plan?: "free" | "pro";
  controls?: DashboardControls | null;
  // Cap usage shown in the panel header. Optional so older callers (and
  // the fragment route under live search) can omit it.
  usage?: WatchlistUsage;
  // 30-day rolling portfolio score (0–12 per day, oldest first). Empty array
  // for users with no scan history yet — hero suppresses the sparkline.
  portfolioTrend?: number[];
  // True when the user just signed up and the only domain is the auto-
  // provisioned one from their email suffix. Drives the welcome banner.
  isFirstRun?: boolean;
}): string {
  const stats = portfolioStats(domains);
  const banners: string[] = [];
  if (plan === "free") banners.push(renderFreeTierBanner());
  if (isFirstRun && domains.length === 1) {
    banners.push(renderFirstRunBanner(domains[0].domain));
  }
  if (stats.failing >= 3) banners.push(renderOnFireBanner(stats.failing));

  const hero =
    domains.length > 0
      ? renderDashboardHero(domains, portfolioTrend)
      : renderDashboardHero([], []);
  const statStrip = domains.length > 0 ? renderDashboardStatStrip(domains) : "";

  return dashboardPage(
    "Domains — dmarc.mx",
    `${banners.join("\n")}
${hero}
${statStrip}
${renderAlertsSection(alerts)}
<div class="dashboard-domains-header" style="display:flex;align-items:center;gap:1rem;margin-bottom:0.75rem;">
  <h2 class="dashboard-title" style="margin:0;flex:1;">Your Domains</h2>
  <button type="button" class="dashboard-add-btn" data-wizard-open>Add domain</button>
</div>
${renderDomainPanel({ domains, controls, usage })}
${renderDomainDrawerShell()}
${renderAddDomainWizardShell()}`,
    email,
  );
}

// === Local-only fixture preview ============================================
// Backs the /_dev/dashboard?fixture=<name> route in src/index.ts. Lets a
// developer eyeball every dashboard scenario without going through WorkOS
// auth or having a populated D1. The fixture data is a TypeScript port of
// docs/dmarcheck.zip handoff-bundle/proto-states.jsx — same shapes, same
// scenario keys. Production code never reaches this; the dev route 404s
// unless the request is from localhost.

export type DashboardFixtureName =
  | "current"
  | "fire"
  | "allGreen"
  | "firstRun"
  | "free"
  | "zero";

export const DASHBOARD_FIXTURE_NAMES: readonly DashboardFixtureName[] = [
  "current",
  "fire",
  "allGreen",
  "firstRun",
  "free",
  "zero",
] as const;

interface DashboardFixture {
  email: string;
  plan: "free" | "pro";
  domains: DashboardDomain[];
  portfolioTrend: number[];
  alerts: DashboardAlert[];
  isFirstRun: boolean;
}

const FIXTURE_NOW = 1714060800; // Fixed timestamp so alerts render deterministically.

const dom = (
  domain: string,
  grade: string,
  lastScanned: string,
  alerts = 0,
): DashboardDomain => ({
  domain,
  grade,
  frequency: "daily",
  lastScanned,
  isFree: false,
  unacknowledgedAlerts: alerts,
});

const DASHBOARD_FIXTURES: Record<DashboardFixtureName, DashboardFixture> = {
  current: {
    email: "you@example.com",
    plan: "pro",
    isFirstRun: false,
    portfolioTrend: [
      9, 9, 9, 8, 9, 9, 8, 9, 8, 7, 8, 9, 9, 8, 8, 9, 8, 7, 8, 8, 7, 7, 8, 7, 8,
      7, 6, 7, 7, 7,
    ],
    domains: [
      dom("acme.com", "A", "2h ago"),
      dom("acme-mail.io", "F", "2h ago", 2),
      dom("acme-pay.com", "B", "5h ago"),
      dom("newsletter.acme.com", "C", "5h ago", 1),
      dom("support.acme.com", "A", "5h ago"),
    ],
    alerts: [
      {
        id: 1,
        domain: "acme-mail.io",
        alertType: "grade_drop",
        previousValue: "B",
        newValue: "F",
        createdAt: FIXTURE_NOW - 2 * 3600,
      },
    ],
  },
  fire: {
    email: "you@example.com",
    plan: "pro",
    isFirstRun: false,
    portfolioTrend: [10, 10, 10, 9, 9, 8, 7, 6, 5, 4, 3, 2, 2, 2],
    domains: [
      dom("acme-mail.io", "F", "2h ago", 2),
      dom("billing.acme.com", "F", "1h ago", 3),
      dom("api.acme.com", "F", "30m ago", 1),
      dom("acme.com", "B", "5h ago"),
    ],
    alerts: [
      {
        id: 11,
        domain: "acme-mail.io",
        alertType: "grade_drop",
        previousValue: "B",
        newValue: "F",
        createdAt: FIXTURE_NOW - 2 * 3600,
      },
      {
        id: 12,
        domain: "billing.acme.com",
        alertType: "protocol_regression",
        previousValue: "dmarc:pass",
        newValue: "dmarc:fail",
        createdAt: FIXTURE_NOW - 3600,
      },
    ],
  },
  allGreen: {
    email: "you@example.com",
    plan: "pro",
    isFirstRun: false,
    portfolioTrend: Array.from({ length: 30 }, () => 11),
    domains: [
      dom("acme.com", "A", "2h ago"),
      dom("acme-pay.com", "A", "2h ago"),
      dom("billing.acme.com", "S", "2h ago"),
      dom("support.acme.com", "A", "2h ago"),
    ],
    alerts: [],
  },
  firstRun: {
    email: "newuser@example.com",
    plan: "free",
    isFirstRun: true,
    portfolioTrend: [],
    domains: [dom("example.com", "—", "Never")],
    alerts: [],
  },
  free: {
    email: "you@example.com",
    plan: "free",
    isFirstRun: false,
    portfolioTrend: [9, 9, 8, 9, 9, 8, 9],
    domains: [dom("example.com", "B", "1d ago")],
    alerts: [],
  },
  zero: {
    email: "newuser@example.com",
    plan: "free",
    isFirstRun: false,
    portfolioTrend: [],
    domains: [],
    alerts: [],
  },
};

export function renderDashboardFixture(name: DashboardFixtureName): string {
  const fx = DASHBOARD_FIXTURES[name];
  return renderDashboardPage({
    email: fx.email,
    plan: fx.plan,
    alerts: fx.alerts,
    portfolioTrend: fx.portfolioTrend,
    isFirstRun: fx.isFirstRun,
    domains: fx.domains,
    controls: null,
    usage: {
      plan: fx.plan,
      current: fx.domains.length,
      cap: fx.plan === "pro" ? 25 : 1,
    },
  });
}

export function renderDashboardFixtureIndex(): string {
  const links = DASHBOARD_FIXTURE_NAMES.map(
    (n) => `<li><a href="/_dev/dashboard?fixture=${esc(n)}">${esc(n)}</a></li>`,
  ).join("");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Dashboard fixtures</title>
<style>body{font:14px system-ui;padding:2rem;}a{color:#f97316;}</style></head>
<body><h1>Dashboard fixture preview</h1><p>Local development only. Pick a scenario:</p>
<ul>${links}</ul></body></html>`;
}

export function renderDomainDetailPage({
  email,
  domain,
  grade,
  lastScanned,
  isFree,
  scanFrequency,
  scanHistory,
}: {
  email: string;
  domain: string;
  grade: string;
  lastScanned: string | null;
  isFree: boolean;
  scanFrequency: string;
  scanHistory: ScanHistoryEntry[];
}): string {
  const historyItems = scanHistory
    .slice(0, 12)
    .map(
      (entry) => `<li>
  <span class="history-date">${esc(entry.date)}</span>
  <span class="inline-grade ${gradeClass(entry.grade)}">${esc(entry.grade)}</span>
</li>`,
    )
    .join("");

  const historySection =
    scanHistory.length > 0
      ? `<ul class="history-list">${historyItems}</ul>`
      : `<p style="color:var(--clr-text-muted);font-size:0.875rem;padding:0.75rem 0">No scan history yet.</p>`;

  const body = `<div class="domain-detail-header">
  <span class="grade-badge ${gradeClass(grade)}">${esc(grade)}</span>
  <span class="domain-detail-name">${esc(domain)}</span>
  ${isFree ? '<span class="badge-free">Free</span>' : ""}
</div>
<div class="domain-detail-meta">
  <span><strong>Scan Frequency:</strong> ${esc(scanFrequency)}</span>
  <span><strong>Last Scanned:</strong> ${lastScanned ? esc(lastScanned) : "Never"}</span>
</div>
<div class="action-row" style="margin-bottom:1.5rem">
  <form method="POST" action="/dashboard/domain/${encodeURIComponent(domain)}/scan" style="display:inline">
    <button type="submit" class="btn">Scan Now</button>
  </form>
  <a href="/check?domain=${encodeURIComponent(domain)}" class="btn btn-secondary">View Full Report</a>
  <form method="POST" action="/dashboard/domain/${encodeURIComponent(domain)}/delete" style="display:inline" onsubmit="return confirm('Stop monitoring ${esc(domain)}?');">
    <button type="submit" class="btn btn-danger" aria-label="Delete domain ${esc(domain)}">Delete</button>
  </form>
</div>
<div class="section-card">
  <h2>Grade History</h2>
  ${historySection}
  <div style="margin-top:0.75rem">
    <a href="/dashboard/domain/${encodeURIComponent(domain)}/history" style="color:var(--clr-accent);font-size:0.875rem;text-decoration:none">See full history &rarr;</a>
  </div>
</div>`;

  return dashboardPage(`${domain} — dmarc.mx`, body, email);
}

export type HistoryProtocolStatus = "pass" | "warn" | "fail" | "info" | null;

export interface HistoryScanEntry {
  date: string;
  scannedAt: number;
  grade: string;
  protocols: {
    dmarc: HistoryProtocolStatus;
    spf: HistoryProtocolStatus;
    dkim: HistoryProtocolStatus;
    bimi: HistoryProtocolStatus;
    mta_sts: HistoryProtocolStatus;
  };
}

// Higher = better. Matches src/alerts/detector.ts GRADE_RANK. Duplicated here
// because the detector file is policy; the view is presentation — keeping
// them decoupled avoids pulling a dep chain through the render path.
const GRADE_RANK_FOR_SPARKLINE: Record<string, number> = {
  F: 0,
  "D-": 1,
  D: 2,
  "D+": 3,
  "C-": 4,
  C: 5,
  "C+": 6,
  "B-": 7,
  B: 8,
  "B+": 9,
  "A-": 10,
  A: 11,
  "A+": 12,
  S: 13,
};

function renderSparkline(entries: HistoryScanEntry[]): string {
  if (entries.length === 0) {
    return `<p style="color:var(--clr-text-muted);font-size:0.875rem;padding:0.75rem 0">No scans yet to chart.</p>`;
  }
  const width = 600;
  const height = 80;
  const pad = 8;
  // Chart oldest → newest left-to-right, so reverse the newest-first input.
  const ordered = [...entries].reverse();
  const n = ordered.length;
  const maxRank = 13;
  const points = ordered.map((entry, i) => {
    const rank = GRADE_RANK_FOR_SPARKLINE[entry.grade] ?? 0;
    const x = n === 1 ? width / 2 : pad + (i * (width - pad * 2)) / (n - 1);
    const y = pad + (1 - rank / maxRank) * (height - pad * 2);
    return { x, y };
  });
  const path = points
    .map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(1)},${p.y.toFixed(1)}`)
    .join(" ");
  const dots = points
    .map(
      (p) =>
        `<circle class="sparkline-dot" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="2.5" />`,
    )
    .join("");
  const midY = pad + (height - pad * 2) / 2;
  return `<svg class="sparkline" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="Grade trend sparkline">
  <line class="sparkline-grid" x1="${pad}" y1="${midY}" x2="${width - pad}" y2="${midY}" />
  <path class="sparkline-line" d="${path}" />
  ${dots}
</svg>`;
}

function statusLabel(status: HistoryProtocolStatus): string {
  if (status === null) return "—";
  return status;
}

function renderDriftCell(
  status: HistoryProtocolStatus,
  previous: HistoryProtocolStatus,
): string {
  const changed = previous !== null && status !== previous;
  const cls = `drift-cell${changed ? " drift-changed" : ""}`;
  const dotCls = status ? `drift-dot status-${status}` : "drift-dot";
  const title = changed ? ` title="changed from ${previous}"` : "";
  return `<span class="${cls}"${title}><span class="${dotCls}"></span>${esc(statusLabel(status))}</span>`;
}

function renderDriftTable(entries: HistoryScanEntry[]): string {
  if (entries.length === 0) {
    return `<p style="color:var(--clr-text-muted);font-size:0.875rem;padding:0.75rem 0">No scans yet.</p>`;
  }
  // Rows are newest-first. To highlight "changed vs the prior (older) scan",
  // we compare each row to the NEXT row in the list (which is chronologically
  // older). The oldest row has no "previous" — its cells never highlight.
  const rows = entries
    .map((entry, i) => {
      const prev: HistoryScanEntry["protocols"] | null =
        i + 1 < entries.length ? entries[i + 1].protocols : null;
      const protos = entry.protocols;
      return `<tr>
  <td class="drift-date">${esc(entry.date)}</td>
  <td><span class="inline-grade ${gradeClass(entry.grade)}">${esc(entry.grade)}</span></td>
  <td>${renderDriftCell(protos.dmarc, prev?.dmarc ?? null)}</td>
  <td>${renderDriftCell(protos.spf, prev?.spf ?? null)}</td>
  <td>${renderDriftCell(protos.dkim, prev?.dkim ?? null)}</td>
  <td>${renderDriftCell(protos.bimi, prev?.bimi ?? null)}</td>
  <td>${renderDriftCell(protos.mta_sts, prev?.mta_sts ?? null)}</td>
</tr>`;
    })
    .join("");
  return `<table class="drift-table">
  <thead>
    <tr>
      <th>Scanned</th>
      <th>Grade</th>
      <th>DMARC</th>
      <th>SPF</th>
      <th>DKIM</th>
      <th>BIMI</th>
      <th>MTA-STS</th>
    </tr>
  </thead>
  <tbody>${rows}</tbody>
</table>`;
}

export function renderDomainHistoryPage({
  email,
  domain,
  plan,
  history,
}: {
  email: string;
  domain: string;
  plan: "free" | "pro";
  history: HistoryScanEntry[];
}): string {
  const sparkline = renderSparkline(history);
  const drift = renderDriftTable(history);

  const upgradePrompt =
    plan === "free"
      ? `<div class="upgrade-prompt">
  <h2>Upgrade to see the full history</h2>
  <p>Pro unlocks 30 scans of grade-trend and protocol-drift detail per domain, plus nightly monitoring and higher API rate limits.</p>
  <a href="/dashboard/billing/subscribe" class="btn">Upgrade to Pro</a>
</div>`
      : "";

  const body = `<h1 class="dashboard-title">History — ${esc(domain)}</h1>
<div class="section-card">
  <h2>Grade trend</h2>
  ${sparkline}
</div>
<div class="section-card">
  <h2>Protocol drift</h2>
  ${drift}
</div>
${upgradePrompt}
<div style="margin-top:1rem">
  <a href="/dashboard/domain/${encodeURIComponent(domain)}" style="color:var(--clr-accent);font-size:0.875rem;text-decoration:none">&larr; Back to ${esc(domain)}</a>
</div>`;

  return dashboardPage(`History — ${domain} — dmarc.mx`, body, email);
}

export interface WatchlistUsage {
  plan: "free" | "pro";
  current: number;
  cap: number;
}

export function renderAddDomainPage({
  email,
  error,
  usage,
}: {
  email: string;
  error: string | null;
  usage: WatchlistUsage;
}): string {
  const errorBlock = error
    ? `<div class="settings-section" style="border-color:var(--clr-danger, #b91c1c);color:var(--clr-danger, #b91c1c)">${esc(error)}</div>`
    : "";

  const usageBlock = renderUsageHint(usage);
  const atCap = usage.current >= usage.cap;
  const submitDisabled = atCap ? " disabled" : "";

  const body = `<h1 class="dashboard-title">Add Domain</h1>
${errorBlock}
${usageBlock}
<form method="POST" action="/dashboard/domain/add" class="settings-section">
  <label for="domain-input" style="display:block;font-size:0.875rem;color:var(--clr-text-muted);margin-bottom:0.4rem">Domain to monitor</label>
  <input
    id="domain-input"
    class="settings-input"
    type="text"
    name="domain"
    placeholder="example.com"
    autofocus
    required
    autocapitalize="none"
    autocorrect="off"
    spellcheck="false"
    aria-describedby="domain-help"
  >
  <p id="domain-help" style="font-size:0.8125rem;color:var(--clr-text-muted);margin:0.5rem 0 1rem">
    We'll run a full DMARC/SPF/DKIM/BIMI/MTA-STS scan and notify you if the grade drops.
  </p>
  <div class="action-row">
    <button type="submit" class="btn"${submitDisabled}>Add Domain</button>
    <a href="/dashboard" class="btn btn-secondary">Cancel</a>
  </div>
</form>`;

  return dashboardPage("Add Domain — dmarc.mx", body, email);
}

// Shared "X of N domains used" hint shown above the add-domain form and
// in the main dashboard's domain panel toolbar. Free plans get an upgrade
// CTA, Pro plans show a contact pointer when at cap.
export function renderUsageHint(usage: WatchlistUsage): string {
  const atCap = usage.current >= usage.cap;
  const planLabel = usage.plan === "pro" ? "Pro" : "Free";
  const cta =
    usage.plan === "free"
      ? `<a href="/dashboard/billing/subscribe" style="color:var(--clr-accent);text-decoration:none">Upgrade →</a>`
      : atCap
        ? `<a href="mailto:support@dmarc.mx" style="color:var(--clr-accent);text-decoration:none">Contact support</a>`
        : "";
  const tone = atCap
    ? "color:var(--clr-danger, #b91c1c);font-weight:600"
    : "color:var(--clr-text-muted)";
  return `<p class="watchlist-usage" style="font-size:0.875rem;margin:0 0 1rem;${tone}">
  <span>${esc(String(usage.current))} of ${esc(String(usage.cap))} ${planLabel} domains used.</span>
  ${cta}
</p>`;
}

export interface BulkResultRow {
  domain: string;
  status: "scanned" | "queued" | "error" | "invalid";
  grade?: string;
  error?: string;
}

export interface BulkRenderResults {
  accepted: number;
  rejected: number;
  results: BulkResultRow[];
}

export function renderBulkScanPage({
  email,
  plan,
  submitted,
  results,
  error,
  totalCap,
  inBandCap,
}: {
  email: string;
  plan: "free" | "pro";
  submitted: number | null;
  results: BulkRenderResults | null;
  error: string | null;
  totalCap: number;
  inBandCap: number;
}): string {
  if (plan !== "pro") {
    const body = `<h1 class="dashboard-title">Bulk Scan</h1>
<div class="upgrade-prompt">
  <h2>Pro feature</h2>
  <p>Bulk scan accepts up to ${totalCap} domains per request and runs the first ${inBandCap} immediately. Available on the Pro plan.</p>
  <a href="/dashboard/billing/subscribe" class="btn">Upgrade to Pro</a>
</div>
${error ? `<div class="bulk-error">${esc(error)}</div>` : ""}`;
    return dashboardPage("Bulk Scan — dmarc.mx", body, email);
  }

  const errorBlock = error ? `<div class="bulk-error">${esc(error)}</div>` : "";

  const resultsBlock = results
    ? `<div class="section-card">
  <h2>Results</h2>
  <p class="bulk-summary">
    ${submitted ?? results.results.length} submitted —
    <strong>${results.accepted}</strong> accepted,
    <strong>${results.rejected}</strong> rejected.
    First ${inBandCap} scanned in-band; the rest queued for the next nightly cron pass.
  </p>
  ${
    results.results.length === 0
      ? `<p class="bulk-summary">No domains parsed from the submission.</p>`
      : `<table class="bulk-results-table">
    <thead>
      <tr>
        <th>Domain</th>
        <th>Status</th>
        <th>Grade / Error</th>
      </tr>
    </thead>
    <tbody>${results.results.map(renderBulkRow).join("")}</tbody>
  </table>`
  }
</div>`
    : "";

  const body = `<h1 class="dashboard-title">Bulk Scan</h1>
<p id="bulk-help" class="bulk-summary">
  Paste up to <strong>${totalCap}</strong> domains (one per line, or comma-separated). The first
  <strong>${inBandCap}</strong> will be scanned immediately; the rest queue for the next cron pass.
</p>
${errorBlock}
<form method="POST" action="/dashboard/bulk" class="settings-section">
  <label for="bulk-input" style="display:block;font-size:0.875rem;color:var(--clr-text-muted);margin-bottom:0.4rem">Domains</label>
  <textarea
    id="bulk-input"
    class="bulk-textarea"
    name="domains"
    placeholder="example.com&#10;another.org&#10;corp.example"
    autocapitalize="none"
    autocorrect="off"
    spellcheck="false"
    required
    aria-describedby="bulk-help"
  ></textarea>
  <div class="action-row">
    <button type="submit" class="btn">Scan</button>
    <a href="/dashboard" class="btn btn-secondary">Cancel</a>
  </div>
</form>
${resultsBlock}`;

  return dashboardPage("Bulk Scan — dmarc.mx", body, email);
}

function renderBulkRow(row: BulkResultRow): string {
  const detail =
    row.status === "scanned" && row.grade
      ? `<span class="inline-grade ${gradeClass(row.grade)}">${esc(row.grade)}</span>`
      : row.error
        ? esc(row.error)
        : row.status === "queued"
          ? '<span style="color:var(--clr-text-muted)">Queued for cron</span>'
          : "";
  return `<tr>
  <td><a href="/dashboard/domain/${encodeURIComponent(row.domain)}">${esc(row.domain)}</a></td>
  <td><span class="bulk-status ${row.status}">${row.status}</span></td>
  <td>${detail}</td>
</tr>`;
}

export interface RecentWebhookDelivery {
  eventType: string;
  ok: boolean;
  statusCode: number | null;
  error: string | null;
  attemptedAt: number;
}

export interface WebhookTestFlash {
  ok: boolean;
  statusCode: number | null;
  error: string | null;
}

export function renderSettingsPage({
  email,
  webhookUrl,
  webhookFormat = "raw",
  plan,
  billingEnabled,
  emailAlertsEnabled,
  showRetirementBanner,
  recentDeliveries = [],
  testFlash = null,
}: {
  email: string;
  webhookUrl: string | null;
  webhookFormat?: WebhookFormat;
  plan: "free" | "pro";
  billingEnabled: boolean;
  emailAlertsEnabled: boolean;
  showRetirementBanner: boolean;
  recentDeliveries?: RecentWebhookDelivery[];
  testFlash?: WebhookTestFlash | null;
}): string {
  const retirementBanner = showRetirementBanner
    ? `<div class="settings-section" style="border-color:var(--clr-accent);background:var(--clr-accent-muted, rgba(249,115,22,0.08))">
  <h2 style="color:var(--clr-accent)">Your API key was retired</h2>
  <p>We rebuilt API keys to store only a hash, so any key you had before has been invalidated. Generate a new one to keep using the dmarc.mx API.</p>
  <a href="/dashboard/settings/api-keys" class="btn">Manage API Keys</a>
</div>`
    : "";

  const planLabel = plan === "pro" ? "Pro" : "Free";
  const billingSection = !billingEnabled
    ? `<p>Billing is not configured on this deployment.</p>`
    : plan === "pro"
      ? `<p>You're on the <strong>${planLabel}</strong> plan.</p>
<a href="/dashboard/billing/portal" class="btn btn-secondary">Manage Billing</a>`
      : `<p>You're on the <strong>${planLabel}</strong> plan.</p>
<a href="/dashboard/billing/subscribe" class="btn">Upgrade to Pro</a>`;

  const body = `<h1 class="dashboard-title">Settings</h1>
${retirementBanner}
<div class="settings-section">
  <h2>Account</h2>
  <p>Signed in as <strong>${esc(email)}</strong></p>
</div>

<div class="settings-section">
  <h2>API Keys</h2>
  <p>Generate a bearer token to call the dmarc.mx API. Keys are hashed at rest; the raw value is shown only once at creation.</p>
  <a href="/dashboard/settings/api-keys" class="btn btn-secondary">Manage API Keys</a>
</div>

<div class="settings-section">
  <h2>Webhook</h2>
  <p style="font-size:0.875rem;color:var(--clr-text-muted);margin-bottom:0.75rem">
    Receive a POST when a scan completes. Pick a format: the raw JSON
    envelope is signed with a <code>Dmarcheck-Signature</code> header
    (HMAC-SHA256 over <code>&lt;timestamp&gt;.&lt;body&gt;</code>), or
    target a Slack / Google Chat incoming webhook for chat delivery.
  </p>
  <form method="POST" action="/dashboard/settings/webhook">
    <label for="webhook-url" style="display:block;font-size:0.875rem;color:var(--clr-text-muted);margin-bottom:0.4rem">Webhook URL</label>
    <input
      id="webhook-url"
      class="settings-input"
      type="url"
      name="webhookUrl"
      placeholder="https://your-server.example/webhook"
      value="${webhookUrl ? esc(webhookUrl) : ""}"
      autocapitalize="none"
      autocorrect="off"
      spellcheck="false"
    >
    <label for="webhook-format" style="display:block;font-size:0.875rem;color:var(--clr-text-muted);margin-bottom:0.4rem;margin-top:0.75rem">Format</label>
    <select id="webhook-format" class="settings-input" name="format">
      <option value="raw"${webhookFormat === "raw" ? " selected" : ""}>Raw (signed JSON envelope)</option>
      <option value="slack"${webhookFormat === "slack" ? " selected" : ""}>Slack incoming webhook</option>
      <option value="google_chat"${webhookFormat === "google_chat" ? " selected" : ""}>Google Chat incoming webhook</option>
    </select>
    <p style="font-size:0.8125rem;color:var(--clr-text-muted);margin:0.4rem 0 0.75rem">
      Raw posts the signed envelope for your own receiver. Slack and Google Chat send a chat message and omit the signature header (those platforms don't verify it).
    </p>
    <button type="submit" class="btn">Save Webhook</button>
  </form>
  ${
    webhookUrl
      ? `<form method="POST" action="/dashboard/settings/webhook/test" style="margin-top:0.5rem">
    <button type="submit" class="btn btn-secondary">Send test event</button>
  </form>`
      : ""
  }
  ${renderWebhookTestFlash(testFlash)}
  ${renderWebhookDeliveries(recentDeliveries)}
</div>

<div class="settings-section">
  <h2>Email Alerts</h2>
  <p style="font-size:0.875rem;color:var(--clr-text-muted);margin-bottom:0.75rem">
    We email you when a monitored domain's grade drops or a protocol regresses.
  </p>
  <form method="POST" action="/dashboard/settings/email-alerts">
    <label style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.75rem">
      <input type="checkbox" name="enabled" ${emailAlertsEnabled ? "checked" : ""}>
      <span>Send me grade-drop alerts by email</span>
    </label>
    <button type="submit" class="btn btn-secondary">Save Preference</button>
  </form>
</div>

<div class="settings-section">
  <h2>Billing</h2>
  ${billingSection}
</div>`;

  return dashboardPage("Settings — dmarc.mx", body, email);
}

function renderWebhookTestFlash(flash: WebhookTestFlash | null): string {
  if (!flash) return "";
  const headline = flash.ok
    ? `Test event delivered (HTTP ${flash.statusCode ?? "?"})`
    : flash.statusCode !== null
      ? `Test event failed: HTTP ${flash.statusCode}`
      : `Test event failed: ${flash.error ?? "network error"}`;
  const tone = flash.ok
    ? "var(--clr-success, #16a34a)"
    : "var(--clr-danger, #dc2626)";
  return `<p style="margin-top:0.75rem;color:${tone};font-size:0.875rem">${esc(headline)}</p>`;
}

function renderWebhookDeliveries(rows: RecentWebhookDelivery[]): string {
  if (rows.length === 0) return "";
  const items = rows
    .map((row) => {
      const when = new Date(row.attemptedAt * 1000).toLocaleString();
      const result = row.ok
        ? `HTTP ${row.statusCode ?? "?"} ✓`
        : row.statusCode !== null
          ? `HTTP ${row.statusCode} ✗`
          : `${esc(row.error ?? "error")} ✗`;
      return `<tr>
  <td style="padding:0.25rem 0.5rem">${esc(when)}</td>
  <td style="padding:0.25rem 0.5rem"><code>${esc(row.eventType)}</code></td>
  <td style="padding:0.25rem 0.5rem">${result}</td>
</tr>`;
    })
    .join("");
  return `<details style="margin-top:1rem">
  <summary style="cursor:pointer;font-size:0.875rem;color:var(--clr-text-muted)">Recent deliveries (${rows.length})</summary>
  <table style="margin-top:0.5rem;font-size:0.8125rem;border-collapse:collapse;width:100%">
    <thead><tr style="text-align:left;color:var(--clr-text-muted)">
      <th style="padding:0.25rem 0.5rem">When</th>
      <th style="padding:0.25rem 0.5rem">Event</th>
      <th style="padding:0.25rem 0.5rem">Result</th>
    </tr></thead>
    <tbody>${items}</tbody>
  </table>
</details>`;
}

export interface ApiKeyListEntry {
  id: string;
  name: string | null;
  prefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  revoked: boolean;
}

function formatEpochSeconds(ts: number | null | undefined): string | null {
  if (ts === null || ts === undefined) return null;
  return new Date(ts * 1000).toLocaleDateString();
}

export function toApiKeyListEntry(row: {
  id: string;
  name: string | null;
  prefix: string;
  created_at: number;
  last_used_at: number | null;
  revoked_at: number | null;
}): ApiKeyListEntry {
  return {
    id: row.id,
    name: row.name,
    prefix: row.prefix,
    createdAt: formatEpochSeconds(row.created_at) ?? "—",
    lastUsedAt: formatEpochSeconds(row.last_used_at),
    revoked: row.revoked_at !== null,
  };
}

export function renderApiKeysPage({
  email,
  keys,
  justCreated,
  showRetirementBanner,
}: {
  email: string;
  keys: ApiKeyListEntry[];
  justCreated: string | null;
  showRetirementBanner: boolean;
}): string {
  const retirementBanner = showRetirementBanner
    ? `<div class="settings-section" style="border-color:var(--clr-accent);background:var(--clr-accent-muted, rgba(249,115,22,0.08))">
  <h2 style="color:var(--clr-accent)">Your old API key was retired</h2>
  <p>We now store only a hash of each key, so anything you generated before has been invalidated. Generate a replacement below.</p>
</div>`
    : "";

  // The raw key is shown exactly once — reload and it's gone. Copy button
  // reuses the `.copy-btn[data-copy]` handler in src/views/scripts.ts.
  const justCreatedBanner = justCreated
    ? `<div class="settings-section" style="border-color:var(--clr-accent);background:var(--clr-accent-muted, rgba(249,115,22,0.08))">
  <h2 style="color:var(--clr-accent)">Save this key now</h2>
  <p>This is the only time the full key will be shown. Copy it somewhere safe before navigating away.</p>
  <div class="api-key-display" style="display:flex;gap:0.5rem;align-items:center">
    <span style="flex:1;overflow-x:auto">${esc(justCreated)}</span>
    <button type="button" class="copy-btn" data-copy="${esc(justCreated)}" aria-label="Copy API key">Copy</button>
  </div>
</div>`
    : "";

  let table: string;
  if (keys.length === 0) {
    table = `<p style="color:var(--clr-text-muted);font-size:0.875rem">No API keys yet.</p>`;
  } else {
    const rows = keys
      .map((k) => {
        const name = k.name ? esc(k.name) : "<em>(unnamed)</em>";
        const status = k.revoked
          ? '<span style="color:var(--clr-fail)">Revoked</span>'
          : '<span style="color:var(--clr-pass)">Active</span>';
        const lastUsed = k.lastUsedAt
          ? esc(k.lastUsedAt)
          : '<span style="color:var(--clr-text-muted)">Never</span>';
        const labelName = k.name ? esc(k.name) : "unnamed";
        const actions = k.revoked
          ? ""
          : `<form method="POST" action="/dashboard/settings/api-keys/revoke" style="display:inline" onsubmit="return confirm('Revoke this key? Requests using it will start failing.');">
              <input type="hidden" name="id" value="${esc(k.id)}">
              <button type="submit" class="btn btn-secondary" style="padding:0.25rem 0.6rem;font-size:0.8125rem" aria-label="Revoke API key ${labelName}">Revoke</button>
            </form>`;
        return `<tr>
  <td>${name}</td>
  <td><code>${esc(k.prefix)}…</code></td>
  <td>${esc(k.createdAt)}</td>
  <td>${lastUsed}</td>
  <td>${status}</td>
  <td>${actions}</td>
</tr>`;
      })
      .join("");

    table = `<table class="domain-table">
  <thead>
    <tr>
      <th>Name</th>
      <th>Prefix</th>
      <th>Created</th>
      <th>Last Used</th>
      <th>Status</th>
      <th></th>
    </tr>
  </thead>
  <tbody>${rows}</tbody>
</table>`;
  }

  const body = `<h1 class="dashboard-title">API Keys</h1>
${retirementBanner}
${justCreatedBanner}
<div class="settings-section">
  <h2>Generate a new key</h2>
  <p id="api-keys-help">Bearer tokens authenticate <code>/api/check</code> requests. Free and Pro plans share key generation; Pro users get higher per-key rate limits.</p>
  <form method="POST" action="/dashboard/settings/api-keys/generate">
    <label for="api-key-name" style="display:block;font-size:0.875rem;color:var(--clr-text-muted);margin-bottom:0.4rem">Label (optional)</label>
    <input id="api-key-name" class="settings-input" type="text" name="name" placeholder="ci-pipeline" maxlength="60" autocapitalize="none" autocorrect="off" spellcheck="false" aria-describedby="api-keys-help">
    <div class="action-row">
      <button type="submit" class="btn">Generate API Key</button>
      <a href="/dashboard/settings" class="btn btn-secondary">Back to Settings</a>
    </div>
  </form>
</div>

<div class="settings-section">
  <h2>Your keys</h2>
  ${table}
</div>`;

  return dashboardPage("API Keys — dmarc.mx", body, email);
}
