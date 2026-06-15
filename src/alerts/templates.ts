// Grade-drop email templates. Kept simple — no external CSS, no remote
// fonts, inline styles only so render consistency doesn't depend on the
// recipient's client. DMarcus (worried mood) keeps the brand visible.

import { esc } from "../shared/escape.js";
import type { AlertType } from "./detector.js";

export interface GradeDropEmailInput {
  domain: string;
  alertType: AlertType;
  previousValue: string;
  newValue: string;
  dashboardUrl: string;
  unsubscribeUrl: string;
}

// Account-deletion confirmation (issue #550). Sent best-effort after a user
// erases their account so the address owner is notified — a safety signal if
// the deletion was triggered by a hijacked session. No dashboard link (the
// account is gone); points at support for questions.
export interface AccountDeletedEmailInput {
  email: string;
}

export function renderAccountDeletedSubject(): string {
  return "dmarc.mx: your account has been deleted";
}

export function renderAccountDeletedText(
  _input: AccountDeletedEmailInput,
): string {
  return [
    "Your dmarc.mx account has been deleted.",
    "",
    "Everything I held — your watchlist, scan history, API keys, and login",
    "identity — has been permanently erased. Any active subscription was",
    "cancelled. This cannot be undone.",
    "",
    "If you did NOT request this, contact support@dmarc.mx right away.",
    "",
    "—",
    "DMarcus, dmarc.mx",
  ].join("\n");
}

export function renderAccountDeletedHtml(
  input: AccountDeletedEmailInput,
): string {
  return `<!doctype html>
<html>
<head><meta charset="utf-8"><title>dmarc.mx account deleted</title></head>
<body style="margin:0;padding:0;background:#0a0a0f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#e4e4e7">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#0a0a0f">
    <tr><td align="center" style="padding:32px 16px">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;width:100%">
        <tr><td style="padding:24px;background:#18181b;border-radius:12px">
          <h1 style="margin:0 0 16px;font-size:20px;line-height:1.3;color:#fafafa">Your account has been deleted</h1>
          <p style="margin:0 0 16px;color:#a1a1aa;font-size:14px;line-height:1.5">
            The dmarc.mx account for <strong>${esc(input.email)}</strong> has been
            permanently erased — watchlist, scan history, API keys, and login
            identity. Any active subscription was cancelled. This cannot be undone.
          </p>
          <p style="margin:0;color:#a1a1aa;font-size:14px;line-height:1.5">
            If you did <strong>not</strong> request this, email
            <a href="mailto:support@dmarc.mx" style="color:#f97316">support@dmarc.mx</a> right away.
          </p>
        </td></tr>
        <tr><td style="padding:24px 8px;color:#71717a;font-size:12px;line-height:1.5">
          DMarcus, dmarc.mx
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

export function renderGradeDropSubject(input: GradeDropEmailInput): string {
  if (input.alertType === "grade_drop") {
    return `dmarc.mx: ${input.domain} dropped from ${input.previousValue} to ${input.newValue}`;
  }
  return `dmarc.mx: ${input.domain} protocol regression (${input.previousValue} → ${input.newValue})`;
}

export function renderGradeDropText(input: GradeDropEmailInput): string {
  const headline =
    input.alertType === "grade_drop"
      ? `${input.domain} dropped from ${input.previousValue} to ${input.newValue}.`
      : `${input.domain} regressed: ${input.previousValue} → ${input.newValue}.`;

  return [
    headline,
    "",
    "Open the dashboard to see the full protocol breakdown and fix recommendations:",
    input.dashboardUrl,
    "",
    "—",
    "You are receiving this because you have grade-drop alerts enabled.",
    `Unsubscribe: ${input.unsubscribeUrl}`,
  ].join("\n");
}

// Inline-CSS HTML. The DMarcus "worried" SVG here is a compact variant of
// the one in src/views/components.ts — a full SVG + CSS animation pipeline
// would not survive most email clients, so we ship a static image.
function dmarcusWorriedSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" width="72" height="72" role="img" aria-label="DMarcus looking worried">
    <text x="60" y="82" font-family="monospace" font-size="72" fill="#f97316" text-anchor="middle">@</text>
    <circle cx="44" cy="44" r="9" fill="#fff"/>
    <circle cx="76" cy="44" r="9" fill="#fff"/>
    <circle cx="41" cy="46" r="4" fill="#0a0a0f"/>
    <circle cx="73" cy="46" r="4" fill="#0a0a0f"/>
    <rect x="38" y="96" width="7" height="14" rx="3" fill="#ea580c"/>
    <rect x="56" y="96" width="7" height="10" rx="3" fill="#ea580c"/>
    <rect x="74" y="96" width="7" height="14" rx="3" fill="#ea580c"/>
  </svg>`;
}

export function renderGradeDropHtml(input: GradeDropEmailInput): string {
  const headline =
    input.alertType === "grade_drop"
      ? `${esc(input.domain)} dropped from <strong>${esc(input.previousValue)}</strong> to <strong>${esc(input.newValue)}</strong>`
      : `${esc(input.domain)} regressed: <strong>${esc(input.previousValue)}</strong> → <strong>${esc(input.newValue)}</strong>`;

  return `<!doctype html>
<html>
<head><meta charset="utf-8"><title>dmarc.mx alert</title></head>
<body style="margin:0;padding:0;background:#0a0a0f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#e4e4e7">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#0a0a0f">
    <tr><td align="center" style="padding:32px 16px">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;width:100%">
        <tr><td align="center" style="padding-bottom:16px">${dmarcusWorriedSvg()}</td></tr>
        <tr><td style="padding:24px;background:#18181b;border-radius:12px">
          <h1 style="margin:0 0 16px;font-size:20px;line-height:1.3;color:#fafafa">${headline}</h1>
          <p style="margin:0 0 24px;color:#a1a1aa;font-size:14px;line-height:1.5">
            The nightly scan detected a change in your domain's email-security posture.
            Click through to see which protocol regressed and how to fix it.
          </p>
          <p style="margin:0 0 16px">
            <a href="${esc(input.dashboardUrl)}" style="display:inline-block;padding:12px 20px;background:#f97316;color:#0a0a0f;text-decoration:none;border-radius:8px;font-weight:600">Open dashboard</a>
          </p>
        </td></tr>
        <tr><td style="padding:24px 8px;color:#71717a;font-size:12px;line-height:1.5">
          You are receiving this because you have grade-drop alerts enabled.
          <a href="${esc(input.unsubscribeUrl)}" style="color:#71717a;text-decoration:underline">Unsubscribe</a>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}
