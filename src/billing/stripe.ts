import { constantTimeEqualHex, hmacSha256Hex } from "../shared/hmac.js";
import type { BillingEnv } from "./feature-flag.js";

// Minimal Stripe client built on the Workers Fetch API. We avoid the official
// `stripe` npm package to keep the Worker bundle small; we only need a tiny
// slice of the API surface (Checkout, Portal, webhook verification) and all
// of it is straightforward REST + HMAC.

export interface StripeSubscriptionEvent {
  id: string;
  type:
    | "customer.subscription.created"
    | "customer.subscription.updated"
    | "customer.subscription.deleted"
    | (string & {});
  data: {
    object: {
      id: string;
      customer: string;
      status: string;
      cancel_at_period_end?: boolean;
      current_period_end?: number;
      items?: {
        data: Array<{ price: { id: string } }>;
      };
    };
  };
}

// Stripe-Signature header format: `t=<ts>,v1=<sig>[,v1=<sig>...]`.
// Signed payload is `${ts}.${body}`, HMAC-SHA256 with the endpoint secret.
// We accept within a 5-minute skew window (Stripe's default) to protect
// against replay while tolerating clock drift.
const SIG_TOLERANCE_SECONDS = 5 * 60;

export class StripeSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StripeSignatureError";
  }
}

// Verifies the Stripe-Signature header and returns the parsed event. Throws
// StripeSignatureError on any validation failure — callers should map that to
// a 400 response without leaking which check failed.
export async function constructWebhookEvent(
  rawBody: string,
  signatureHeader: string | null,
  secret: string,
  now: number = Math.floor(Date.now() / 1000),
): Promise<StripeSubscriptionEvent> {
  if (!signatureHeader) {
    throw new StripeSignatureError("missing signature header");
  }

  const parts = parseSignatureHeader(signatureHeader);
  if (parts.timestamp === null || parts.signatures.length === 0) {
    throw new StripeSignatureError("malformed signature header");
  }

  if (Math.abs(now - parts.timestamp) > SIG_TOLERANCE_SECONDS) {
    throw new StripeSignatureError("timestamp outside tolerance");
  }

  const expected = await hmacSha256Hex(secret, `${parts.timestamp}.${rawBody}`);
  const matched = parts.signatures.some((sig) =>
    constantTimeEqualHex(sig, expected),
  );
  if (!matched) {
    throw new StripeSignatureError("signature mismatch");
  }

  try {
    return JSON.parse(rawBody) as StripeSubscriptionEvent;
  } catch {
    throw new StripeSignatureError("body is not valid JSON");
  }
}

interface ParsedSignature {
  timestamp: number | null;
  signatures: string[];
}

function parseSignatureHeader(header: string): ParsedSignature {
  const out: ParsedSignature = { timestamp: null, signatures: [] };
  for (const part of header.split(",")) {
    const [key, value] = part.split("=", 2);
    if (!key || value === undefined) continue;
    if (key === "t") {
      const ts = Number.parseInt(value, 10);
      if (Number.isFinite(ts)) out.timestamp = ts;
    } else if (key === "v1") {
      out.signatures.push(value);
    }
  }
  return out;
}

// Thin helper for Checkout / Portal / Customer / subscription calls. Defaults
// to POST (Stripe's form-encoded create/update convention); pass `method:
// "DELETE"` for resource deletion (e.g. immediate subscription cancellation),
// in which case no body is sent.
export async function stripeRequest<T>(
  env: BillingEnv,
  path: string,
  form: Record<string, string>,
  method: "POST" | "DELETE" = "POST",
): Promise<T> {
  const body =
    method === "DELETE" ? undefined : new URLSearchParams(form).toString();
  const res = await fetch(`https://api.stripe.com/v1${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });
  const json = (await res.json()) as T | { error: { message: string } };
  if (!res.ok) {
    const err = (json as { error?: { message?: string } }).error;
    throw new Error(`Stripe API ${res.status}: ${err?.message ?? "unknown"}`);
  }
  return json as T;
}

interface StripeCustomer {
  id: string;
}

// Creates a Stripe Customer for a dmarcheck user. We do this lazily on the
// first upgrade click rather than at signup so free users never hit Stripe.
// Email is set so it appears in the Stripe dashboard; metadata.user_id lets
// the webhook handler resolve a Stripe event back to our user row.
export async function createStripeCustomer(
  env: BillingEnv,
  input: { userId: string; email: string },
): Promise<string> {
  const customer = await stripeRequest<StripeCustomer>(env, "/customers", {
    email: input.email,
    "metadata[user_id]": input.userId,
  });
  return customer.id;
}

interface StripeCheckoutSession {
  id: string;
  url: string;
}

// Creates a Checkout Session in `subscription` mode for the Pro plan. The
// returned `url` is the hosted Checkout page we redirect the user to.
export async function createCheckoutSession(
  env: BillingEnv,
  input: {
    customerId: string;
    successUrl: string;
    cancelUrl: string;
    userId: string;
  },
): Promise<StripeCheckoutSession> {
  return stripeRequest<StripeCheckoutSession>(env, "/checkout/sessions", {
    mode: "subscription",
    customer: input.customerId,
    "line_items[0][price]": env.STRIPE_PRICE_ID_PRO,
    "line_items[0][quantity]": "1",
    // Renders the "Add promotion code" link on the hosted Checkout page so
    // operator-issued coupons (e.g. founder/free-Pro grants) can be redeemed
    // without us minting one-off price IDs.
    allow_promotion_codes: "true",
    success_url: input.successUrl,
    cancel_url: input.cancelUrl,
    // Stripe copies this onto the created subscription; lets the webhook
    // handler cross-check the user_id matches the customer lookup.
    "subscription_data[metadata][user_id]": input.userId,
  });
}

interface StripeSubscription {
  id: string;
  status: string;
}

// Cancels a subscription immediately (not at period end). Used by account
// deletion (issue #550): we must stop billing a card for a service the user is
// erasing. `DELETE /v1/subscriptions/{id}` is Stripe's immediate-cancel verb.
// Throws on any non-2xx except 404 — a missing subscription is already gone,
// so deletion can proceed (mirrors deleteWorkosUser's idempotent 404 handling).
// Other failures still propagate so the caller can ABORT rather than orphan an
// active subscription.
export async function cancelSubscription(
  env: BillingEnv,
  subscriptionId: string,
): Promise<StripeSubscription> {
  const path = `/subscriptions/${encodeURIComponent(subscriptionId)}`;
  const res = await fetch(`https://api.stripe.com/v1${path}`, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
  });
  if (res.status === 404) {
    return { id: subscriptionId, status: "canceled" };
  }
  const json = (await res.json()) as
    | StripeSubscription
    | { error: { message: string } };
  if (!res.ok) {
    const err = (json as { error?: { message?: string } }).error;
    throw new Error(`Stripe API ${res.status}: ${err?.message ?? "unknown"}`);
  }
  return json as StripeSubscription;
}

interface StripePortalSession {
  id: string;
  url: string;
}

// Creates a Customer Portal session. Users manage cancel / payment method /
// invoice history here — dmarcheck doesn't need to build any of that.
export async function createPortalSession(
  env: BillingEnv,
  input: { customerId: string; returnUrl: string },
): Promise<StripePortalSession> {
  return stripeRequest<StripePortalSession>(env, "/billing_portal/sessions", {
    customer: input.customerId,
    return_url: input.returnUrl,
  });
}
