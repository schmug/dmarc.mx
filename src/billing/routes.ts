import { Hono } from "hono";
import { requireAuth } from "../auth/middleware.js";
import type { SessionPayload } from "../auth/session.js";
import {
  getSubscriptionByUserId,
  isStripeEventRecorded,
  recordStripeEventOnce,
  upsertSubscription,
} from "../db/subscriptions.js";
import {
  getUserById,
  getUserByStripeCustomerId,
  setStripeCustomerId,
} from "../db/users.js";
import type { Env } from "../env.js";
import { isBillingEnabled } from "./feature-flag.js";
import {
  constructWebhookEvent,
  createCheckoutSession,
  createPortalSession,
  createStripeCustomer,
  StripeSignatureError,
  type StripeSubscriptionEvent,
} from "./stripe.js";

// Authed billing routes — mounted under /dashboard/billing by src/index.ts.
// All handlers assume requireAuth has already attached a SessionPayload and
// that isBillingEnabled(env) is true at mount time.
export const dashboardBillingRoutes = new Hono();

dashboardBillingRoutes.use("*", requireAuth);

// GET /dashboard/billing/subscribe — starts the upgrade flow. Creates a Stripe
// Customer on first click (lazy so free users never touch Stripe), then a
// Checkout Session, then 303-redirects to Stripe's hosted checkout page.
dashboardBillingRoutes.get("/subscribe", async (c) => {
  const env = c.env as Env;
  if (!isBillingEnabled(env)) {
    return c.text("Billing not configured", 404);
  }
  const session = c.get("user" as never) as SessionPayload;
  const db = env.DB;
  const user = await getUserById(db, session.sub);
  if (!user) {
    return c.redirect("/auth/logout");
  }

  let customerId = user.stripe_customer_id;
  if (!customerId) {
    customerId = await createStripeCustomer(env, {
      userId: user.id,
      email: user.email,
    });
    await setStripeCustomerId(db, user.id, customerId);
  }

  const origin = new URL(c.req.url).origin;
  const checkout = await createCheckoutSession(env, {
    customerId,
    userId: user.id,
    successUrl: `${origin}/dashboard/settings?upgraded=1`,
    cancelUrl: `${origin}/dashboard/settings?upgrade_cancelled=1`,
  });
  return c.redirect(checkout.url, 303);
});

// GET /dashboard/billing/portal — Stripe Customer Portal for managing
// subscription, payment method, invoices, cancellation.
dashboardBillingRoutes.get("/portal", async (c) => {
  const env = c.env as Env;
  if (!isBillingEnabled(env)) {
    return c.text("Billing not configured", 404);
  }
  const session = c.get("user" as never) as SessionPayload;
  const db = env.DB;
  const user = await getUserById(db, session.sub);
  if (!user?.stripe_customer_id) {
    return c.redirect("/dashboard/settings");
  }

  const origin = new URL(c.req.url).origin;
  const portal = await createPortalSession(env, {
    customerId: user.stripe_customer_id,
    returnUrl: `${origin}/dashboard/settings`,
  });
  return c.redirect(portal.url, 303);
});

// Public webhook route. Mounted at /webhooks/stripe by src/index.ts. Not
// authed (obviously) — signature verification is the auth. No CORS.
export const stripeWebhookRoutes = new Hono();

stripeWebhookRoutes.post("/stripe", async (c) => {
  const env = c.env as Env;
  if (!isBillingEnabled(env)) {
    return c.text("Billing not configured", 404);
  }

  // MUST read raw body before anything else parses it — the signature is
  // over the exact byte sequence Stripe sent.
  const rawBody = await c.req.text();
  const sigHeader = c.req.header("stripe-signature") ?? null;

  let event: StripeSubscriptionEvent;
  try {
    event = await constructWebhookEvent(
      rawBody,
      sigHeader,
      env.STRIPE_WEBHOOK_SECRET,
    );
  } catch (err) {
    if (err instanceof StripeSignatureError) {
      return c.text("Invalid signature", 400);
    }
    throw err;
  }

  // Idempotency guard — Stripe retries delivery for up to 3 days on 5xx or
  // network error. Apply side effects BEFORE recording the event id so a
  // transient upsert failure does not permanently skip processing on replay.
  const db = env.DB;

  const isSubscriptionEvent =
    event.type === "customer.subscription.created" ||
    event.type === "customer.subscription.updated" ||
    event.type === "customer.subscription.deleted";

  if (isSubscriptionEvent) {
    const sub = event.data.object;
    const user = await getUserByStripeCustomerId(db, sub.customer);
    if (!user) {
      // Probably a misrouted event from the shared donthype-me Stripe
      // account, or a customer created outside dmarcheck's flow. Log once
      // via Sentry (caller's onError) by rethrowing? No — safer to 200
      // so Stripe stops retrying, but surface via a minimal log.
      console.warn(
        `[stripe webhook] no dmarcheck user for customer ${sub.customer} (event ${event.id})`,
      );
      return c.json({ received: true, ignored: "unknown_customer" });
    }

    const priceId = sub.items?.data?.[0]?.price?.id ?? "";
    const eventRecorded = await isStripeEventRecorded(db, event.id);
    const localSub = await getSubscriptionByUserId(db, user.id);
    // Upsert on first delivery, and on replay only when repairing a row that
    // was never written (event id recorded before upsert in older builds).
    if (!eventRecorded || !localSub) {
      await upsertSubscription(db, {
        user_id: user.id,
        stripe_subscription_id: sub.id,
        stripe_price_id: priceId,
        status: sub.status,
        current_period_end: sub.current_period_end ?? null,
        cancel_at_period_end: sub.cancel_at_period_end === true,
      });
    }
  }

  const fresh = await recordStripeEventOnce(db, event.id);
  if (!fresh) {
    return c.json({ received: true, replay: true });
  }
  // All other event types are accepted but not acted on. Returning 2xx stops
  // Stripe from retrying them; we'd rather silently ignore unknown types
  // than error the delivery pipeline.

  return c.json({ received: true });
});
