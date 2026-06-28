import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createSessionToken } from "../src/auth/session.js";
import {
  dashboardBillingRoutes,
  stripeWebhookRoutes,
} from "../src/billing/routes.js";

const SECRET = "test-session-secret";
const STRIPE_SECRETS = {
  STRIPE_SECRET_KEY: "sk_test_billing_routes",
  STRIPE_WEBHOOK_SECRET: "whsec_test_billing_routes",
  STRIPE_PRICE_ID_PRO: "price_test_pro",
};

// Minimal mock D1 targeted at the SQL executed by the billing webhook and
// dashboard routes. Tracks in-memory state so replay semantics can be
// asserted.
interface MockState {
  users: Map<
    string,
    {
      id: string;
      email: string;
      email_domain: string;
      stripe_customer_id: string | null;
      email_alerts_enabled: number;
      api_key_retirement_acknowledged_at: number | null;
      created_at: number;
    }
  >;
  subscriptions: Map<string, Record<string, unknown>>;
  events: Set<string>;
}

function makeDb(state: MockState): D1Database {
  const prepare = (sql: string) => ({
    bind: (...params: unknown[]) => ({
      run: async () => {
        if (/^INSERT OR IGNORE INTO stripe_events/i.test(sql)) {
          const [eventId] = params as [string];
          if (state.events.has(eventId)) {
            return { success: true, meta: { changes: 0 } };
          }
          state.events.add(eventId);
          return { success: true, meta: { changes: 1 } };
        }
        if (/^INSERT INTO subscriptions/i.test(sql)) {
          const [
            user_id,
            stripe_subscription_id,
            stripe_price_id,
            status,
            current_period_end,
            cancel_at_period_end,
          ] = params as [string, string, string, string, number | null, number];
          state.subscriptions.set(user_id, {
            user_id,
            stripe_subscription_id,
            stripe_price_id,
            status,
            current_period_end,
            cancel_at_period_end,
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (/^UPDATE users SET stripe_customer_id/i.test(sql)) {
          const [cid, uid] = params as [string, string];
          const u = state.users.get(uid);
          if (u) state.users.set(uid, { ...u, stripe_customer_id: cid });
          return { success: true, meta: { changes: 1 } };
        }
        return { success: true, meta: { changes: 0 } };
      },
      first: async <T>(): Promise<T | null> => {
        if (/FROM users WHERE id = \?/i.test(sql)) {
          return (state.users.get(params[0] as string) ?? null) as T | null;
        }
        if (/FROM users WHERE stripe_customer_id = \?/i.test(sql)) {
          for (const u of state.users.values()) {
            if (u.stripe_customer_id === params[0]) return u as T;
          }
          return null;
        }
        if (/FROM subscriptions WHERE user_id = \?/i.test(sql)) {
          return (state.subscriptions.get(params[0] as string) ??
            null) as T | null;
        }
        if (/FROM stripe_events WHERE event_id = \?/i.test(sql)) {
          return state.events.has(params[0] as string)
            ? ({ exists: 1 } as T)
            : null;
        }
        return null;
      },
    }),
  });
  return { prepare } as unknown as D1Database;
}

function makeState(): MockState {
  return {
    users: new Map(),
    subscriptions: new Map(),
    events: new Set(),
  };
}

async function signStripePayload(
  secret: string,
  timestamp: number,
  body: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${timestamp}.${body}`),
  );
  const hex = [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `t=${timestamp},v1=${hex}`;
}

function subscriptionEventBody(input: {
  eventId: string;
  eventType: string;
  customerId: string;
  subscriptionId: string;
  status: string;
  priceId?: string;
  currentPeriodEnd?: number;
  cancelAtPeriodEnd?: boolean;
}): string {
  return JSON.stringify({
    id: input.eventId,
    type: input.eventType,
    data: {
      object: {
        id: input.subscriptionId,
        customer: input.customerId,
        status: input.status,
        cancel_at_period_end: input.cancelAtPeriodEnd ?? false,
        current_period_end: input.currentPeriodEnd ?? 1_700_000_000,
        items: {
          data: [{ price: { id: input.priceId ?? "price_test_pro" } }],
        },
      },
    },
  });
}

describe("stripeWebhookRoutes POST /webhooks/stripe", () => {
  it("returns 404 when billing is not configured", async () => {
    const app = new Hono();
    app.route("/webhooks", stripeWebhookRoutes);
    const state = makeState();
    const res = await app.request(
      "/webhooks/stripe",
      { method: "POST", body: "{}" },
      { DB: makeDb(state) },
    );
    expect(res.status).toBe(404);
  });

  it("rejects an invalid signature with 400", async () => {
    const app = new Hono();
    app.route("/webhooks", stripeWebhookRoutes);
    const state = makeState();
    const res = await app.request(
      "/webhooks/stripe",
      {
        method: "POST",
        body: "{}",
        headers: { "stripe-signature": "t=123,v1=deadbeef" },
      },
      { DB: makeDb(state), ...STRIPE_SECRETS },
    );
    expect(res.status).toBe(400);
  });

  it("upserts a subscription on customer.subscription.created", async () => {
    const state = makeState();
    state.users.set("u1", {
      id: "u1",
      email: "pro@example.com",
      email_domain: "example.com",
      stripe_customer_id: "cus_pro",
      email_alerts_enabled: 1,
      api_key_retirement_acknowledged_at: 0,
      created_at: 0,
    });
    const app = new Hono();
    app.route("/webhooks", stripeWebhookRoutes);

    const body = subscriptionEventBody({
      eventId: "evt_1",
      eventType: "customer.subscription.created",
      customerId: "cus_pro",
      subscriptionId: "sub_1",
      status: "active",
    });
    const ts = Math.floor(Date.now() / 1000);
    const sig = await signStripePayload(
      STRIPE_SECRETS.STRIPE_WEBHOOK_SECRET,
      ts,
      body,
    );
    const res = await app.request(
      "/webhooks/stripe",
      {
        method: "POST",
        body,
        headers: { "stripe-signature": sig },
      },
      { DB: makeDb(state), ...STRIPE_SECRETS },
    );
    expect(res.status).toBe(200);
    expect(state.subscriptions.get("u1")).toMatchObject({
      stripe_subscription_id: "sub_1",
      status: "active",
      stripe_price_id: "price_test_pro",
    });
  });

  it("flips status to canceled on customer.subscription.deleted", async () => {
    const state = makeState();
    state.users.set("u1", {
      id: "u1",
      email: "pro@example.com",
      email_domain: "example.com",
      stripe_customer_id: "cus_pro",
      email_alerts_enabled: 1,
      api_key_retirement_acknowledged_at: 0,
      created_at: 0,
    });
    state.subscriptions.set("u1", {
      user_id: "u1",
      stripe_subscription_id: "sub_1",
      stripe_price_id: "price_test_pro",
      status: "active",
      current_period_end: 1_700_000_000,
      cancel_at_period_end: 0,
    });
    const app = new Hono();
    app.route("/webhooks", stripeWebhookRoutes);

    const body = subscriptionEventBody({
      eventId: "evt_2",
      eventType: "customer.subscription.deleted",
      customerId: "cus_pro",
      subscriptionId: "sub_1",
      status: "canceled",
    });
    const ts = Math.floor(Date.now() / 1000);
    const sig = await signStripePayload(
      STRIPE_SECRETS.STRIPE_WEBHOOK_SECRET,
      ts,
      body,
    );
    const res = await app.request(
      "/webhooks/stripe",
      { method: "POST", body, headers: { "stripe-signature": sig } },
      { DB: makeDb(state), ...STRIPE_SECRETS },
    );
    expect(res.status).toBe(200);
    expect(state.subscriptions.get("u1")).toMatchObject({ status: "canceled" });
  });

  it("repairs a missing subscription row on replay when the event was recorded before upsert", async () => {
    const state = makeState();
    state.users.set("u1", {
      id: "u1",
      email: "pro@example.com",
      email_domain: "example.com",
      stripe_customer_id: "cus_pro",
      email_alerts_enabled: 1,
      api_key_retirement_acknowledged_at: 0,
      created_at: 0,
    });
    // Simulate the old bug: event id recorded but upsert never ran.
    state.events.add("evt_orphan");
    const app = new Hono();
    app.route("/webhooks", stripeWebhookRoutes);

    const body = subscriptionEventBody({
      eventId: "evt_orphan",
      eventType: "customer.subscription.created",
      customerId: "cus_pro",
      subscriptionId: "sub_1",
      status: "active",
    });
    const ts = Math.floor(Date.now() / 1000);
    const sig = await signStripePayload(
      STRIPE_SECRETS.STRIPE_WEBHOOK_SECRET,
      ts,
      body,
    );

    const res = await app.request(
      "/webhooks/stripe",
      { method: "POST", body, headers: { "stripe-signature": sig } },
      { DB: makeDb(state), ...STRIPE_SECRETS },
    );

    expect(res.status).toBe(200);
    const payload = (await res.json()) as { replay?: boolean };
    expect(payload.replay).toBe(true);
    expect(state.subscriptions.get("u1")).toMatchObject({
      stripe_subscription_id: "sub_1",
      status: "active",
    });
  });

  it("replays the same event id without re-processing", async () => {
    const state = makeState();
    state.users.set("u1", {
      id: "u1",
      email: "pro@example.com",
      email_domain: "example.com",
      stripe_customer_id: "cus_pro",
      email_alerts_enabled: 1,
      api_key_retirement_acknowledged_at: 0,
      created_at: 0,
    });
    const app = new Hono();
    app.route("/webhooks", stripeWebhookRoutes);

    const body = subscriptionEventBody({
      eventId: "evt_replay",
      eventType: "customer.subscription.created",
      customerId: "cus_pro",
      subscriptionId: "sub_1",
      status: "active",
    });
    const ts = Math.floor(Date.now() / 1000);
    const sig = await signStripePayload(
      STRIPE_SECRETS.STRIPE_WEBHOOK_SECRET,
      ts,
      body,
    );

    const first = await app.request(
      "/webhooks/stripe",
      { method: "POST", body, headers: { "stripe-signature": sig } },
      { DB: makeDb(state), ...STRIPE_SECRETS },
    );
    expect(first.status).toBe(200);

    // Simulate Stripe retry — mutate subscription in DB to prove replay
    // didn't overwrite it.
    state.subscriptions.set("u1", {
      ...(state.subscriptions.get("u1") ?? {}),
      status: "manually_mutated_between_deliveries",
    });

    const second = await app.request(
      "/webhooks/stripe",
      { method: "POST", body, headers: { "stripe-signature": sig } },
      { DB: makeDb(state), ...STRIPE_SECRETS },
    );
    expect(second.status).toBe(200);
    const payload = (await second.json()) as { replay?: boolean };
    expect(payload.replay).toBe(true);
    expect(state.subscriptions.get("u1")?.status).toBe(
      "manually_mutated_between_deliveries",
    );
  });

  it("ignores events for customers not owned by any dmarcheck user", async () => {
    const state = makeState();
    const app = new Hono();
    app.route("/webhooks", stripeWebhookRoutes);
    const body = subscriptionEventBody({
      eventId: "evt_unknown",
      eventType: "customer.subscription.created",
      customerId: "cus_donthypeme_not_ours",
      subscriptionId: "sub_1",
      status: "active",
    });
    const ts = Math.floor(Date.now() / 1000);
    const sig = await signStripePayload(
      STRIPE_SECRETS.STRIPE_WEBHOOK_SECRET,
      ts,
      body,
    );
    const res = await app.request(
      "/webhooks/stripe",
      { method: "POST", body, headers: { "stripe-signature": sig } },
      { DB: makeDb(state), ...STRIPE_SECRETS },
    );
    expect(res.status).toBe(200);
    expect(state.subscriptions.size).toBe(0);
  });

  it("ignores unsupported event types without error", async () => {
    const state = makeState();
    const app = new Hono();
    app.route("/webhooks", stripeWebhookRoutes);
    const body = JSON.stringify({
      id: "evt_ping",
      type: "ping",
      data: { object: { id: "x", customer: "y", status: "z" } },
    });
    const ts = Math.floor(Date.now() / 1000);
    const sig = await signStripePayload(
      STRIPE_SECRETS.STRIPE_WEBHOOK_SECRET,
      ts,
      body,
    );
    const res = await app.request(
      "/webhooks/stripe",
      { method: "POST", body, headers: { "stripe-signature": sig } },
      { DB: makeDb(state), ...STRIPE_SECRETS },
    );
    expect(res.status).toBe(200);
    expect(state.subscriptions.size).toBe(0);
  });
});

describe("dashboardBillingRoutes GET /subscribe", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith("/customers")) {
        return new Response(JSON.stringify({ id: "cus_new" }), {
          status: 200,
        });
      }
      if (url.endsWith("/checkout/sessions")) {
        return new Response(
          JSON.stringify({
            id: "cs_123",
            url: "https://checkout.stripe.com/pay/cs_123",
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/billing_portal/sessions")) {
        return new Response(
          JSON.stringify({
            id: "bps_123",
            url: "https://billing.stripe.com/p/session/bps_123",
          }),
          { status: 200 },
        );
      }
      return new Response("{}", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  async function sessionCookie(sub: string, email: string): Promise<string> {
    const token = await createSessionToken({ sub, email }, SECRET);
    return `session=${token}`;
  }

  it("returns 404 when billing is not configured", async () => {
    const app = new Hono();
    app.route("/dashboard/billing", dashboardBillingRoutes);
    const state = makeState();
    const cookie = await sessionCookie("u1", "x@y.com");
    const res = await app.request(
      "/dashboard/billing/subscribe",
      { headers: { Cookie: cookie } },
      { DB: makeDb(state), SESSION_SECRET: SECRET },
    );
    expect(res.status).toBe(404);
  });

  it("creates a Stripe customer lazily then redirects to Checkout", async () => {
    const app = new Hono();
    app.route("/dashboard/billing", dashboardBillingRoutes);
    const state = makeState();
    state.users.set("u1", {
      id: "u1",
      email: "upgrade@example.com",
      email_domain: "example.com",
      stripe_customer_id: null,
      email_alerts_enabled: 1,
      api_key_retirement_acknowledged_at: 0,
      created_at: 0,
    });
    const cookie = await sessionCookie("u1", "upgrade@example.com");

    const res = await app.request(
      "/dashboard/billing/subscribe",
      { headers: { Cookie: cookie } },
      { DB: makeDb(state), SESSION_SECRET: SECRET, ...STRIPE_SECRETS },
    );

    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe(
      "https://checkout.stripe.com/pay/cs_123",
    );
    expect(state.users.get("u1")?.stripe_customer_id).toBe("cus_new");
    // First call creates the customer, second creates the Checkout Session.
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("reuses an existing Stripe customer on re-upgrade", async () => {
    const app = new Hono();
    app.route("/dashboard/billing", dashboardBillingRoutes);
    const state = makeState();
    state.users.set("u1", {
      id: "u1",
      email: "upgrade@example.com",
      email_domain: "example.com",
      stripe_customer_id: "cus_existing",
      email_alerts_enabled: 1,
      api_key_retirement_acknowledged_at: 0,
      created_at: 0,
    });
    const cookie = await sessionCookie("u1", "upgrade@example.com");

    const res = await app.request(
      "/dashboard/billing/subscribe",
      { headers: { Cookie: cookie } },
      { DB: makeDb(state), SESSION_SECRET: SECRET, ...STRIPE_SECRETS },
    );

    expect(res.status).toBe(303);
    // Only the Checkout Session call — no customer creation.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("/checkout/sessions");
  });
});

describe("dashboardBillingRoutes GET /portal", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              id: "bps_123",
              url: "https://billing.stripe.com/p/session/bps_123",
            }),
            { status: 200 },
          ),
      ),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("redirects to settings when the user has no Stripe customer", async () => {
    const app = new Hono();
    app.route("/dashboard/billing", dashboardBillingRoutes);
    const state = makeState();
    state.users.set("u1", {
      id: "u1",
      email: "free@example.com",
      email_domain: "example.com",
      stripe_customer_id: null,
      email_alerts_enabled: 1,
      api_key_retirement_acknowledged_at: 0,
      created_at: 0,
    });
    const token = await createSessionToken(
      { sub: "u1", email: "free@example.com" },
      SECRET,
    );
    const res = await app.request(
      "/dashboard/billing/portal",
      { headers: { Cookie: `session=${token}` } },
      { DB: makeDb(state), SESSION_SECRET: SECRET, ...STRIPE_SECRETS },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/dashboard/settings");
  });

  it("redirects to the Stripe portal URL when the user has a customer", async () => {
    const app = new Hono();
    app.route("/dashboard/billing", dashboardBillingRoutes);
    const state = makeState();
    state.users.set("u1", {
      id: "u1",
      email: "pro@example.com",
      email_domain: "example.com",
      stripe_customer_id: "cus_pro",
      email_alerts_enabled: 1,
      api_key_retirement_acknowledged_at: 0,
      created_at: 0,
    });
    const token = await createSessionToken(
      { sub: "u1", email: "pro@example.com" },
      SECRET,
    );
    const res = await app.request(
      "/dashboard/billing/portal",
      { headers: { Cookie: `session=${token}` } },
      { DB: makeDb(state), SESSION_SECRET: SECRET, ...STRIPE_SECRETS },
    );
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe(
      "https://billing.stripe.com/p/session/bps_123",
    );
  });
});
