import * as Sentry from "@sentry/cloudflare";
import {
  type AccountDeletedEmailInput,
  type GradeDropEmailInput,
  renderAccountDeletedHtml,
  renderAccountDeletedSubject,
  renderAccountDeletedText,
  renderGradeDropHtml,
  renderGradeDropSubject,
  renderGradeDropText,
} from "./templates.js";

export interface SendOutcome {
  sent: boolean;
  reason?: "no_binding" | "send_error";
  messageId?: string;
}

// Thin wrapper around the Cloudflare `send_email` binding. The binding is
// optional (self-host safety); callers must handle the `no_binding` outcome.
// Errors from the binding (E_SENDER_NOT_VERIFIED, E_RATE_LIMIT_EXCEEDED,
// network) are captured to Sentry and surfaced as `send_error` rather than
// rethrown, so one bad delivery cannot abort the dispatcher loop.
export async function sendGradeDropEmail(
  email: SendEmail | undefined,
  toAddress: string,
  fromAddress: string,
  input: GradeDropEmailInput,
): Promise<SendOutcome> {
  if (!email) {
    return { sent: false, reason: "no_binding" };
  }

  try {
    const response = await email.send({
      to: toAddress,
      from: fromAddress,
      subject: renderGradeDropSubject(input),
      html: renderGradeDropHtml(input),
      text: renderGradeDropText(input),
    });
    return { sent: true, messageId: response?.messageId };
  } catch (err) {
    Sentry.captureException(err);
    return { sent: false, reason: "send_error" };
  }
}

// Account-deletion confirmation (issue #550). Same binding + failure-handling
// contract as sendGradeDropEmail: optional binding (self-host safety), errors
// captured to Sentry and surfaced as `send_error` rather than thrown — the
// deletion already succeeded, so a failed confirmation email must never abort
// or roll anything back.
export async function sendAccountDeletedEmail(
  email: SendEmail | undefined,
  toAddress: string,
  fromAddress: string,
  input: AccountDeletedEmailInput,
): Promise<SendOutcome> {
  if (!email) {
    return { sent: false, reason: "no_binding" };
  }

  try {
    const response = await email.send({
      to: toAddress,
      from: fromAddress,
      subject: renderAccountDeletedSubject(),
      html: renderAccountDeletedHtml(input),
      text: renderAccountDeletedText(input),
    });
    return { sent: true, messageId: response?.messageId };
  } catch (err) {
    Sentry.captureException(err);
    return { sent: false, reason: "send_error" };
  }
}
