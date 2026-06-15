import * as Sentry from "@sentry/cloudflare";
import { sendAccountDeletedEmail } from "../alerts/email.js";
import { deleteWorkosUser } from "../auth/workos.js";
import { isBillingEnabled } from "../billing/feature-flag.js";
import { cancelSubscription } from "../billing/stripe.js";
import { getSubscriptionByUserId, statusToPlan } from "../db/subscriptions.js";
import { deleteUser } from "../db/users.js";
import type { Env } from "../env.js";

// Confirmation emails are sent from the same verified sender as alerts. A
// distinct "support@" identity would need its own Cloudflare Email Sending
// verification, so we reuse the address we know is verified.
const SENDER_ADDRESS = "alerts@dmarc.mx";

export interface AccountDeletionResult {
  // A Stripe subscription was found active and successfully cancelled.
  stripeCancelled: boolean;
  // The WorkOS identity was deleted.
  workosDeleted: boolean;
  // WorkOS deletion was attempted but failed — flagged for a retry sweep; the
  // local erasure was NOT rolled back.
  workosFailed: boolean;
  // WorkOS deletion was skipped because no WORKOS_API_KEY is configured.
  workosSkipped: boolean;
  // A confirmation email was sent.
  emailSent: boolean;
}

// Performs immediate, permanent erasure of a user's account (issue #550). The
// target id is the caller's responsibility to derive from the verified session
// (session.sub) — this function never reads request input.
//
// Strict operation order (THREAT_MODEL T1/T4 + financial safety):
//   1. Cancel an active Stripe subscription. THROWS on failure → the caller
//      aborts and NOTHING local is deleted (never orphan an active sub).
//   2. Hard-delete the local D1 row (cascades to all owned tables).
//   3. Delete the WorkOS identity. On failure: log + flag for retry, but do
//      NOT roll back the local delete (local erasure is the core promise).
//   4. Send a best-effort confirmation email (failure never aborts).
//
// Every external step degrades gracefully when its binding/secret is absent so
// a self-host deploy without Stripe/WorkOS/email still erases local data.
export async function deleteAccount(
  env: Env,
  user: { id: string; email: string },
): Promise<AccountDeletionResult> {
  // 1. Stripe — cancel an active subscription first, abort on failure.
  let stripeCancelled = false;
  if (isBillingEnabled(env)) {
    const subscription = await getSubscriptionByUserId(env.DB, user.id);
    if (subscription && statusToPlan(subscription.status) === "pro") {
      // No try/catch: a failure here must propagate so the caller aborts
      // BEFORE any local data is removed.
      await cancelSubscription(env, subscription.stripe_subscription_id);
      stripeCancelled = true;
    }
  }

  // 2. Local D1 — single cascading hard delete.
  await deleteUser(env.DB, user.id);

  // 3. WorkOS — delete the identity; never roll back the local delete.
  let workosDeleted = false;
  let workosFailed = false;
  let workosSkipped = false;
  if (env.WORKOS_API_KEY) {
    try {
      await deleteWorkosUser(env.WORKOS_API_KEY, user.id);
      workosDeleted = true;
    } catch (err) {
      workosFailed = true;
      Sentry.captureException(err);
      // Breadcrumb the orphaned identity so a retry sweep / on-call can find
      // it; the user can't log in (no local row to provision against), so this
      // is non-functional, just incomplete erasure of the WorkOS record.
      console.error(
        `WorkOS identity deletion failed for user ${user.id}; flagged for retry`,
      );
    }
  } else {
    workosSkipped = true;
  }

  // 4. Confirmation email — best-effort.
  const outcome = await sendAccountDeletedEmail(
    env.EMAIL,
    user.email,
    SENDER_ADDRESS,
    { email: user.email },
  );

  return {
    stripeCancelled,
    workosDeleted,
    workosFailed,
    workosSkipped,
    emailSent: outcome.sent,
  };
}
