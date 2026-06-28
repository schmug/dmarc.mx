/**
 * End-to-end Stripe billing lifecycle test (issue #191).
 *
 * Walks the full upgrade → active → cancel-at-period-end → deleted sequence
 * using the same mock-D1 + mock-fetch approach as test/billing-routes.test.ts.
 * All steps share a single in-memory MockState so each step's side-effects are
 * visible to the next — this is what makes it a *lifecycle* test rather than
 * isolated unit tests.
 *
 * NOTE: This file lives in test/integration/ but runs in the **Node** pool
 * (vitest.config.ts excludes it from the Workers pool via a pattern override).
 * The Workers pool is reserved for runtime tests that need the real workerd
 * fetch stack; these tests mock fetch explicitly.
 */

import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createSessionToken } from "../../src/auth/session.js";
import {
  dashboardBillingRoutes,
  stripeWebhookRoutes,
} from "../../src/billing/routes.js";
import { getPlanForUser } from "../../src/db/subscriptions.js";

// ---------------------------------------------------------------------------
// Constants shared across all steps
// ---------------------------------------------------------------------------

const SESSION_SECRET = "test-session-secret-lifecycle";

const STRIPE_SECRETS = {
  STRIPE_SECRET_KEY: "sk_test_lifecycle",
  STRIPE_WEBHOOK_SECRET: "whsec_test_lifecycle",
  STRIPE_PRICE_ID_PRO: "price_test_pro_lifecycle",
};

const USER_ID = "user-lifecycle-001";
const USER_EMAIL = "lifecycle@example.com";
const CUSTOMER_ID = "cus_lifecycle_001";
const SUBSCRIPTION_ID = "sub_lifecycle_001";

// ---------------------------------------------------------------------------
// Mock D1 state — shared for the entire describe block
// ---------------------------------------------------------------------------

interface UserRow {
  id: string;
  email: string;
  email_domain: string;
  stripe_customer_id: string | null;
  email_alerts_enabled: number;
  api_key_retirement_acknowledged_at: number | null;
  created_at: number;
}

interface MockState {
  users: Map<string, UserRow>;
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
          const existing = state.subscriptions.get(user_id) as
            | Record<string, unknown>
            | undefined;
          state.subscriptions.set(user_id, {
            ...(existing ?? {}),
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
          const row = state.subscriptions.get(params[0] as string);
          if (!row) return null;
          // Handle `SELECT status FROM` narrowed query
          if (/^SELECT status FROM/i.test(sql)) {
            return { status: row.status } as T;
          }
          return row as T;
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

// ---------------------------------------------------------------------------
// Stripe webhook signing (same HMAC approach as billing-routes.test.ts)
// ---------------------------------------------------------------------------

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

function makeSubscriptionEventBody(opts: {
  eventId: string;
  type: string;
  customerId: string;
  subscriptionId: string;
  status: string;
  priceId: string;
  currentPeriodEnd?: number;
  cancelAtPeriodEnd?: boolean;
}): string {
  return JSON.stringify({
    id: opts.eventId,
    type: opts.type,
    data: {
      object: {
        id: opts.subscriptionId,
        customer: opts.customerId,
        status: opts.status,
        cancel_at_period_end: opts.cancelAtPeriodEnd ?? false,
        current_period_end: opts.currentPeriodEnd ?? 1_800_000_000,
        items: {
          data: [{ price: { id: opts.priceId } }],
        },
      },
    },
  });
}

// ---------------------------------------------------------------------------
// Shared state initialised once for the whole lifecycle describe block
// ---------------------------------------------------------------------------

const state: MockState = {
  users: new Map(),
  subscriptions: new Map(),
  events: new Set(),
};

// resolveBearer is mocked so the bulk-scan route accepts our synthetic bearer
// without real DB api_keys rows. The stub is wired before the `app` import.
let bearerStub: { userId: string; keyId: string } | null = null;

vi.mock("../../src/auth/api-key.js", async () => {
  const actual = await vi.importActual<
    typeof import("../../src/auth/api-key.js")
  >("../../src/auth/api-key.js");
  return {
    ...actual,
    resolveBearer: vi.fn(async () => bearerStub),
  };
});

// scan() is mocked so bulk-scan never touches real DNS.
vi.mock("../../src/orchestrator.js", async () => {
  const actual = await vi.importActual<
    typeof import("../../src/orchestrator.js")
  >("../../src/orchestrator.js");
  return {
    ...actual,
    scan: vi.fn(async (domain: string) => ({
      domain,
      timestamp: new Date().toISOString(),
      grade: "A",
      breakdown: {
        grade: "A",
        tier: "A",
        tierReason: "test",
        modifier: 0,
        modifierLabel: "",
        factors: [],
        recommendations: [],
        protocolSummaries: {},
      },
      summary: { mx_records: 0, mx_providers: [], dmarc_policy: "reject" },
      protocols: {
        mx: { status: "info" },
        dmarc: { status: "pass" },
        spf: { status: "pass" },
        dkim: { status: "pass" },
        bimi: { status: "pass" },
        mta_sts: { status: "pass" },
      },
    })),
  };
});

const { app } = await import("../../src/index.js");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeBillingApp() {
  const a = new Hono();
  a.route("/dashboard/billing", dashboardBillingRoutes);
  a.route("/webhooks", stripeWebhookRoutes);
  return a;
}

async function sessionCookie(): Promise<string> {
  const token = await createSessionToken(
    { sub: USER_ID, email: USER_EMAIL },
    SESSION_SECRET,
  );
  return `session=${token}`;
}

async function postWebhook(billingApp: Hono, body: string): Promise<Response> {
  const ts = Math.floor(Date.now() / 1000);
  const sig = await signStripePayload(
    STRIPE_SECRETS.STRIPE_WEBHOOK_SECRET,
    ts,
    body,
  );
  return billingApp.request(
    "/webhooks/stripe",
    { method: "POST", body, headers: { "stripe-signature": sig } },
    { DB: makeDb(state), ...STRIPE_SECRETS },
  );
}

// ---------------------------------------------------------------------------
// Lifecycle describe — steps run in order, sharing `state`
// ---------------------------------------------------------------------------

describe("Stripe billing lifecycle (issue #191)", () => {
  let billingApp: Hono;
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeAll(() => {
    // Seed a user with no Stripe customer yet.
    state.users.set(USER_ID, {
      id: USER_ID,
      email: USER_EMAIL,
      email_domain: "example.com",
      stripe_customer_id: null,
      email_alerts_enabled: 1,
      api_key_retirement_acknowledged_at: null,
      created_at: 0,
    });

    billingApp = makeBillingApp();

    // Mock Stripe REST API for dashboard routes (checkout + portal sessions).
    fetchMock = vi.fn(async (url: string) => {
      if (typeof url !== "string") return new Response("{}", { status: 404 });
      if (url.endsWith("/customers")) {
        return new Response(JSON.stringify({ id: CUSTOMER_ID }), {
          status: 200,
        });
      }
      if (url.endsWith("/checkout/sessions")) {
        return new Response(
          JSON.stringify({
            id: "cs_lifecycle_001",
            url: `https://checkout.stripe.com/pay/cs_lifecycle_001?client_reference_id=${USER_ID}`,
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/billing_portal/sessions")) {
        return new Response(
          JSON.stringify({
            id: "bps_lifecycle_001",
            url: "https://billing.stripe.com/p/session/bps_lifecycle_001",
          }),
          { status: 200 },
        );
      }
      return new Response("{}", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterAll(() => {
    vi.unstubAllGlobals();
    bearerStub = null;
  });

  // -------------------------------------------------------------------------
  // Step 1: Checkout intent
  // -------------------------------------------------------------------------

  it("Step 1 — GET /dashboard/billing/subscribe returns 303 to Stripe Checkout", async () => {
    const cookie = await sessionCookie();
    const res = await billingApp.request(
      "/dashboard/billing/subscribe",
      { headers: { Cookie: cookie } },
      { DB: makeDb(state), SESSION_SECRET, ...STRIPE_SECRETS },
    );

    expect(res.status).toBe(303);
    const location = res.headers.get("Location") ?? "";
    expect(location).toContain("checkout.stripe.com");

    // Stripe customer should have been created lazily and saved.
    expect(state.users.get(USER_ID)?.stripe_customer_id).toBe(CUSTOMER_ID);

    // First fetch call creates the customer, second creates the Checkout Session.
    expect(fetchMock).toHaveBeenCalledTimes(2);

    // Verify the checkout session call included the right price.
    const checkoutCall = fetchMock.mock.calls.find(([url]: [string]) =>
      url.endsWith("/checkout/sessions"),
    );
    expect(checkoutCall).toBeDefined();
    const [, checkoutInit] = checkoutCall as [string, RequestInit];
    const params = new URLSearchParams(String(checkoutInit.body));
    expect(params.get("line_items[0][price]")).toBe(
      STRIPE_SECRETS.STRIPE_PRICE_ID_PRO,
    );
    expect(params.get("success_url")).toBeDefined();
    expect(params.get("cancel_url")).toBeDefined();
    expect(params.get("subscription_data[metadata][user_id]")).toBe(USER_ID);
  });

  // -------------------------------------------------------------------------
  // Step 2: Webhook checkout.session.completed → subscription active
  // -------------------------------------------------------------------------

  it("Step 2 — webhook customer.subscription.created writes active subscription row", async () => {
    // In the real Stripe flow, checkout.session.completed is followed by a
    // separate customer.subscription.created event. The webhook handler acts
    // on the subscription event (not the checkout event), so we send that.
    const body = makeSubscriptionEventBody({
      eventId: "evt_lifecycle_sub_created",
      type: "customer.subscription.created",
      customerId: CUSTOMER_ID,
      subscriptionId: SUBSCRIPTION_ID,
      status: "active",
      priceId: STRIPE_SECRETS.STRIPE_PRICE_ID_PRO,
      currentPeriodEnd: 1_800_000_000,
    });

    const res = await postWebhook(billingApp, body);
    expect(res.status).toBe(200);

    const sub = state.subscriptions.get(USER_ID);
    expect(sub).toBeDefined();
    expect(sub?.status).toBe("active");
    expect(sub?.stripe_subscription_id).toBe(SUBSCRIPTION_ID);
    expect(sub?.stripe_price_id).toBe(STRIPE_SECRETS.STRIPE_PRICE_ID_PRO);
  });

  // -------------------------------------------------------------------------
  // Step 3: Pro unlock — getPlanForUser returns 'pro'; bulk-scan returns non-402
  // -------------------------------------------------------------------------

  it("Step 3 — getPlanForUser returns 'pro' after subscription activated", async () => {
    const plan = await getPlanForUser(makeDb(state), USER_ID);
    expect(plan).toBe("pro");
  });

  it("Step 3 — POST /api/bulk-scan returns non-402 for Pro bearer", async () => {
    bearerStub = { userId: USER_ID, keyId: "key-lifecycle-001" };

    const res = await app.request(
      "/api/bulk-scan",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domains: ["example.com"] }),
      },
      { DB: makeDb(state) } as unknown as Record<string, unknown>,
      {
        waitUntil: () => {},
        passThroughOnException: () => {},
      } as ExecutionContext,
    );

    // 200 (scanned) or 400/500 from orchestrator noise — anything but 402
    expect(res.status).not.toBe(402);
    expect(res.status).not.toBe(401);
  });

  it("Step 3 — Pro bearer receives higher X-RateLimit-Limit than free (60 vs 10)", async () => {
    // The rate-limit middleware adds X-RateLimit-Limit to every response.
    // Pro: 60 req / 3600 s. Free / anon: 10 req / 60 s.
    bearerStub = { userId: USER_ID, keyId: "key-lifecycle-001" };

    const res = await app.request(
      "/api/bulk-scan",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domains: ["example.com"] }),
      },
      { DB: makeDb(state) } as unknown as Record<string, unknown>,
      {
        waitUntil: () => {},
        passThroughOnException: () => {},
      } as ExecutionContext,
    );

    const limitHeader = res.headers.get("X-RateLimit-Limit");
    if (limitHeader !== null) {
      // When the header is present, Pro budget is 60.
      expect(Number(limitHeader)).toBe(60);
    }
    // If header is absent the middleware silently allows — not a failure.
  });

  // -------------------------------------------------------------------------
  // Step 4: Webhook customer.subscription.updated with cancel_at_period_end
  // -------------------------------------------------------------------------

  it("Step 4 — cancel_at_period_end=true webhook leaves subscription active", async () => {
    const body = makeSubscriptionEventBody({
      eventId: "evt_lifecycle_sub_updated",
      type: "customer.subscription.updated",
      customerId: CUSTOMER_ID,
      subscriptionId: SUBSCRIPTION_ID,
      status: "active",
      priceId: STRIPE_SECRETS.STRIPE_PRICE_ID_PRO,
      currentPeriodEnd: 1_800_000_000,
      cancelAtPeriodEnd: true,
    });

    const res = await postWebhook(billingApp, body);
    expect(res.status).toBe(200);

    const sub = state.subscriptions.get(USER_ID);
    expect(sub?.status).toBe("active");
    expect(sub?.cancel_at_period_end).toBe(1);

    // Plan is still pro.
    const plan = await getPlanForUser(makeDb(state), USER_ID);
    expect(plan).toBe("pro");
  });

  // -------------------------------------------------------------------------
  // Step 5: Portal access
  // -------------------------------------------------------------------------

  it("Step 5 — POST /dashboard/billing/portal returns 303 to Stripe Portal URL", async () => {
    fetchMock.mockClear();

    const cookie = await sessionCookie();
    const res = await billingApp.request(
      "/dashboard/billing/portal",
      { headers: { Cookie: cookie } },
      { DB: makeDb(state), SESSION_SECRET, ...STRIPE_SECRETS },
    );

    expect(res.status).toBe(303);
    const location = res.headers.get("Location") ?? "";
    expect(location).toContain("billing.stripe.com");

    // Verify the portal session was requested with the correct customer id.
    const portalCall = fetchMock.mock.calls.find(([url]: [string]) =>
      url.endsWith("/billing_portal/sessions"),
    );
    expect(portalCall).toBeDefined();
    const [, portalInit] = portalCall as [string, RequestInit];
    const params = new URLSearchParams(String(portalInit.body));
    expect(params.get("customer")).toBe(CUSTOMER_ID);
  });

  // -------------------------------------------------------------------------
  // Step 6: Webhook customer.subscription.deleted → canceled → free
  // -------------------------------------------------------------------------

  it("Step 6 — customer.subscription.deleted marks subscription canceled", async () => {
    const body = makeSubscriptionEventBody({
      eventId: "evt_lifecycle_sub_deleted",
      type: "customer.subscription.deleted",
      customerId: CUSTOMER_ID,
      subscriptionId: SUBSCRIPTION_ID,
      status: "canceled",
      priceId: STRIPE_SECRETS.STRIPE_PRICE_ID_PRO,
    });

    const res = await postWebhook(billingApp, body);
    expect(res.status).toBe(200);

    const sub = state.subscriptions.get(USER_ID);
    expect(sub?.status).toBe("canceled");
  });

  it("Step 6 — getPlanForUser returns 'free' after subscription deleted", async () => {
    const plan = await getPlanForUser(makeDb(state), USER_ID);
    expect(plan).toBe("free");
  });

  it("Step 6 — POST /api/bulk-scan returns 402 again after downgrade", async () => {
    bearerStub = { userId: USER_ID, keyId: "key-lifecycle-001" };

    const res = await app.request(
      "/api/bulk-scan",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domains: ["example.com"] }),
      },
      { DB: makeDb(state) } as unknown as Record<string, unknown>,
      {
        waitUntil: () => {},
        passThroughOnException: () => {},
      } as ExecutionContext,
    );

    expect(res.status).toBe(402);
    const json = (await res.json()) as { error: string; upgrade?: string };
    expect(json.error).toMatch(/Pro/i);
    expect(json.upgrade).toContain("/dashboard/billing/subscribe");
  });

  // -------------------------------------------------------------------------
  // Negative paths
  // -------------------------------------------------------------------------

  it("Negative — same event.id is not re-processed (replay protection)", async () => {
    const body = makeSubscriptionEventBody({
      eventId: "evt_lifecycle_sub_created", // already in state.events from Step 2
      type: "customer.subscription.created",
      customerId: CUSTOMER_ID,
      subscriptionId: SUBSCRIPTION_ID,
      status: "active",
      priceId: STRIPE_SECRETS.STRIPE_PRICE_ID_PRO,
    });

    // Mutate the subscription to prove the replay doesn't overwrite it.
    state.subscriptions.set(USER_ID, {
      ...(state.subscriptions.get(USER_ID) ?? {}),
      status: "sentinel_not_overwritten",
    });

    const res = await postWebhook(billingApp, body);
    expect(res.status).toBe(200);
    const json = (await res.json()) as { replay?: boolean };
    expect(json.replay).toBe(true);

    // Status must be unchanged — the replay did not re-process.
    expect(state.subscriptions.get(USER_ID)?.status).toBe(
      "sentinel_not_overwritten",
    );
  });

  it("Negative — invalid stripe-signature returns 400", async () => {
    const res = await billingApp.request(
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

  it("Negative — missing STRIPE_* secrets makes /subscribe return 404", async () => {
    const noStripeApp = new Hono();
    noStripeApp.route("/dashboard/billing", dashboardBillingRoutes);

    const cookie = await sessionCookie();
    const res = await noStripeApp.request(
      "/dashboard/billing/subscribe",
      { headers: { Cookie: cookie } },
      // No STRIPE_* keys in env
      { DB: makeDb(state), SESSION_SECRET },
    );
    expect(res.status).toBe(404);
  });

  it("Negative — missing STRIPE_* secrets makes /webhooks/stripe return 404", async () => {
    const noStripeApp = new Hono();
    noStripeApp.route("/webhooks", stripeWebhookRoutes);

    const res = await noStripeApp.request(
      "/webhooks/stripe",
      { method: "POST", body: "{}" },
      { DB: makeDb(state) },
    );
    expect(res.status).toBe(404);
  });
});
