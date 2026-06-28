import { afterEach, describe, expect, it, vi } from "vitest";
import { deleteAccount } from "../src/account/deletion.js";
import type { Env } from "../src/env.js";

vi.mock("@sentry/cloudflare", () => ({
  captureException: vi.fn(),
}));

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// A write-recording D1 mock that also models the cascade DELETE so we can both
// (a) assert ordering / that the local delete did or did not fire, and
// (b) assert zero rows remain for the user across every owned table.
// ---------------------------------------------------------------------------
interface CascadeState {
  users: Array<{ id: string; email: string; stripe_customer_id?: string }>;
  domains: Array<{ id: number; user_id: string }>;
  scanHistory: Array<{ domain_id: number }>;
  alerts: Array<{ domain_id: number }>;
  apiKeys: Array<{ user_id: string }>;
  webhooks: Array<{ id: number; user_id: string }>;
  deliveries: Array<{ webhook_id: number }>;
  subscriptions: Array<{
    user_id: string;
    stripe_subscription_id: string;
    status: string;
  }>;
}

function emptyState(): CascadeState {
  return {
    users: [],
    domains: [],
    scanHistory: [],
    alerts: [],
    apiKeys: [],
    webhooks: [],
    deliveries: [],
    subscriptions: [],
  };
}

function makeDB(state: CascadeState, order: string[]) {
  const prepare = (sql: string) => ({
    bind: (...b: unknown[]) => ({
      first: async <T>() => {
        if (/SELECT \* FROM subscriptions WHERE user_id = \?/i.test(sql)) {
          return (state.subscriptions.find((s) => s.user_id === b[0]) ??
            null) as T | null;
        }
        if (/SELECT \* FROM users WHERE id = \?/i.test(sql)) {
          return (state.users.find((u) => u.id === b[0]) ?? null) as T | null;
        }
        return null as T | null;
      },
      run: async () => {
        if (/^DELETE FROM users WHERE id = \?/i.test(sql)) {
          order.push("delete-users");
          const id = b[0] as string;
          state.users = state.users.filter((u) => u.id !== id);
          const domainIds = state.domains
            .filter((d) => d.user_id === id)
            .map((d) => d.id);
          state.domains = state.domains.filter((d) => d.user_id !== id);
          state.scanHistory = state.scanHistory.filter(
            (s) => !domainIds.includes(s.domain_id),
          );
          state.alerts = state.alerts.filter(
            (a) => !domainIds.includes(a.domain_id),
          );
          state.apiKeys = state.apiKeys.filter((k) => k.user_id !== id);
          const webhookIds = state.webhooks
            .filter((w) => w.user_id === id)
            .map((w) => w.id);
          state.webhooks = state.webhooks.filter((w) => w.user_id !== id);
          state.deliveries = state.deliveries.filter(
            (dlv) => !webhookIds.includes(dlv.webhook_id),
          );
          state.subscriptions = state.subscriptions.filter(
            (s) => s.user_id !== id,
          );
        }
        return { success: true, meta: { changes: 1 } };
      },
    }),
  });
  return { prepare } as unknown as D1Database;
}

const BILLING_ENV = {
  STRIPE_SECRET_KEY: "sk_test_x",
  STRIPE_WEBHOOK_SECRET: "whsec_x",
  STRIPE_PRICE_ID_PRO: "price_pro_test",
};

function makeEnv(
  state: CascadeState,
  order: string[],
  overrides: Partial<Env> = {},
): Env {
  return {
    DB: makeDB(state, order),
    WORKOS_CLIENT_ID: "",
    WORKOS_CLIENT_SECRET: "",
    WORKOS_REDIRECT_URI: "",
    SESSION_SECRET: "test-secret",
    ...overrides,
  } as Env;
}

// Routes Stripe + WorkOS REST calls and records the order they fire in.
function stubFetch(
  order: string[],
  opts: {
    stripeStatus?: number;
    workosStatus?: number;
    stripeList?: Array<{ id: string; status: string }>;
  } = {},
) {
  const fetchMock = vi.fn(async (url: string) => {
    // Match on the parsed host + path (not a substring) so the router can't be
    // fooled by an arbitrary host that merely contains the API hostname.
    const { hostname, pathname, search } = new URL(url);
    if (
      hostname === "api.stripe.com" &&
      pathname === "/v1/subscriptions" &&
      search.includes("customer=")
    ) {
      order.push("stripe-list");
      return new Response(JSON.stringify({ data: opts.stripeList ?? [] }), {
        status: 200,
      });
    }
    if (
      hostname === "api.stripe.com" &&
      pathname.startsWith("/v1/subscriptions/")
    ) {
      order.push("stripe-cancel");
      return new Response(JSON.stringify({ id: "sub_1", status: "canceled" }), {
        status: opts.stripeStatus ?? 200,
      });
    }
    if (
      hostname === "api.workos.com" &&
      pathname.startsWith("/user_management/users/")
    ) {
      order.push("workos-delete");
      return new Response(null, { status: opts.workosStatus ?? 200 });
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const USER = { id: "user_1", email: "alice@example.com" };

describe("account/deletion.deleteAccount", () => {
  it("cancels an active Stripe subscription BEFORE deleting locally", async () => {
    const state = emptyState();
    state.users.push({ ...USER });
    state.subscriptions.push({
      user_id: "user_1",
      stripe_subscription_id: "sub_1",
      status: "active",
    });
    const order: string[] = [];
    const fetchMock = stubFetch(order);
    const env = makeEnv(state, order, BILLING_ENV);

    const result = await deleteAccount(env, USER);

    expect(result.stripeCancelled).toBe(true);
    expect(fetchMock).toHaveBeenCalled();
    // Stripe cancel must precede the local DELETE.
    expect(order.indexOf("stripe-cancel")).toBeLessThan(
      order.indexOf("delete-users"),
    );
    expect(state.users).toHaveLength(0);
  });

  it("ABORTS (no local delete) when the Stripe cancel fails", async () => {
    const state = emptyState();
    state.users.push({ ...USER });
    state.subscriptions.push({
      user_id: "user_1",
      stripe_subscription_id: "sub_1",
      status: "active",
    });
    const order: string[] = [];
    stubFetch(order, { stripeStatus: 500 });
    const env = makeEnv(state, order, BILLING_ENV);

    await expect(deleteAccount(env, USER)).rejects.toThrow();

    // The user row must survive — we never orphan an active subscription.
    expect(order).not.toContain("delete-users");
    expect(state.users).toHaveLength(1);
  });

  it("cancels via Stripe customer lookup when the local subscription row is missing", async () => {
    const state = emptyState();
    state.users.push({ ...USER, stripe_customer_id: "cus_orphan" });
    const order: string[] = [];
    const fetchMock = stubFetch(order, {
      stripeList: [{ id: "sub_live", status: "active" }],
    });
    const env = makeEnv(state, order, BILLING_ENV);

    const result = await deleteAccount(env, USER);

    expect(result.stripeCancelled).toBe(true);
    expect(order).toContain("stripe-list");
    expect(order).toContain("stripe-cancel");
    expect(order.indexOf("stripe-list")).toBeLessThan(
      order.indexOf("stripe-cancel"),
    );
    expect(order.indexOf("stripe-cancel")).toBeLessThan(
      order.indexOf("delete-users"),
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(state.users).toHaveLength(0);
  });

  it("proceeds when Stripe cancel returns 404 (stale local sub id)", async () => {
    const state = emptyState();
    state.users.push({ ...USER });
    state.subscriptions.push({
      user_id: "user_1",
      stripe_subscription_id: "sub_gone",
      status: "active",
    });
    const order: string[] = [];
    stubFetch(order, { stripeStatus: 404 });
    const env = makeEnv(state, order, BILLING_ENV);

    const result = await deleteAccount(env, USER);

    expect(result.stripeCancelled).toBe(true);
    expect(order).toContain("stripe-cancel");
    expect(order.indexOf("stripe-cancel")).toBeLessThan(
      order.indexOf("delete-users"),
    );
    expect(state.users).toHaveLength(0);
  });

  it("skips Stripe when there is no active subscription", async () => {
    const state = emptyState();
    state.users.push({ ...USER });
    state.subscriptions.push({
      user_id: "user_1",
      stripe_subscription_id: "sub_1",
      status: "canceled",
    });
    const order: string[] = [];
    stubFetch(order);
    const env = makeEnv(state, order, BILLING_ENV);

    const result = await deleteAccount(env, USER);

    expect(result.stripeCancelled).toBe(false);
    expect(order).not.toContain("stripe-cancel");
    expect(state.users).toHaveLength(0);
  });

  it("skips Stripe entirely when billing is not configured (self-host)", async () => {
    const state = emptyState();
    state.users.push({ ...USER });
    state.subscriptions.push({
      user_id: "user_1",
      stripe_subscription_id: "sub_1",
      status: "active",
    });
    const order: string[] = [];
    stubFetch(order);
    const env = makeEnv(state, order); // no Stripe keys

    const result = await deleteAccount(env, USER);

    expect(result.stripeCancelled).toBe(false);
    expect(order).not.toContain("stripe-cancel");
    expect(state.users).toHaveLength(0);
  });

  it("deletes the WorkOS identity using the user id when the key is present", async () => {
    const state = emptyState();
    state.users.push({ ...USER });
    const order: string[] = [];
    const fetchMock = stubFetch(order);
    const env = makeEnv(state, order, { WORKOS_API_KEY: "sk_workos" });

    const result = await deleteAccount(env, USER);

    expect(result.workosDeleted).toBe(true);
    const workosCall = fetchMock.mock.calls.find(
      (c) => new URL(String(c[0])).hostname === "api.workos.com",
    );
    expect(workosCall?.[0]).toBe(
      "https://api.workos.com/user_management/users/user_1",
    );
  });

  it("does NOT roll back the local delete when WorkOS deletion fails", async () => {
    const state = emptyState();
    state.users.push({ ...USER });
    const order: string[] = [];
    stubFetch(order, { workosStatus: 500 });
    const env = makeEnv(state, order, { WORKOS_API_KEY: "sk_workos" });

    const result = await deleteAccount(env, USER);

    // Local erasure stands; WorkOS is flagged for retry, not rolled back.
    expect(state.users).toHaveLength(0);
    expect(result.workosFailed).toBe(true);
    expect(result.workosDeleted).toBe(false);
    // The local DELETE happened before the WorkOS attempt.
    expect(order.indexOf("delete-users")).toBeLessThan(
      order.indexOf("workos-delete"),
    );
  });

  it("skips WorkOS gracefully when WORKOS_API_KEY is absent", async () => {
    const state = emptyState();
    state.users.push({ ...USER });
    const order: string[] = [];
    stubFetch(order);
    const env = makeEnv(state, order); // no WORKOS_API_KEY

    const result = await deleteAccount(env, USER);

    expect(result.workosSkipped).toBe(true);
    expect(order).not.toContain("workos-delete");
    expect(state.users).toHaveLength(0);
  });

  it("sends a confirmation email best-effort when the binding is present", async () => {
    const state = emptyState();
    state.users.push({ ...USER });
    const order: string[] = [];
    stubFetch(order);
    const send = vi.fn().mockResolvedValue({ messageId: "m1" });
    const env = makeEnv(state, order, {
      EMAIL: { send } as unknown as SendEmail,
    });

    const result = await deleteAccount(env, USER);

    expect(result.emailSent).toBe(true);
    expect(send).toHaveBeenCalledTimes(1);
    expect((send.mock.calls[0][0] as { to: string }).to).toBe(
      "alice@example.com",
    );
  });

  it("completes deletion even when the email binding is absent", async () => {
    const state = emptyState();
    state.users.push({ ...USER });
    const order: string[] = [];
    stubFetch(order);
    const env = makeEnv(state, order); // no EMAIL

    const result = await deleteAccount(env, USER);

    expect(result.emailSent).toBe(false);
    expect(state.users).toHaveLength(0);
  });

  it("erases every owned row across all cascaded tables (zero rows remain)", async () => {
    const state = emptyState();
    state.users.push({ ...USER });
    state.domains.push({ id: 1, user_id: "user_1" });
    state.scanHistory.push({ domain_id: 1 });
    state.alerts.push({ domain_id: 1 });
    state.apiKeys.push({ user_id: "user_1" });
    state.webhooks.push({ id: 7, user_id: "user_1" });
    state.deliveries.push({ webhook_id: 7 });
    state.subscriptions.push({
      user_id: "user_1",
      stripe_subscription_id: "sub_1",
      status: "canceled",
    });
    // A second user's data must be untouched.
    state.users.push({ id: "user_2", email: "bob@example.com" });
    state.domains.push({ id: 2, user_id: "user_2" });

    const order: string[] = [];
    stubFetch(order);
    const env = makeEnv(state, order);

    await deleteAccount(env, USER);

    expect(state.users.filter((u) => u.id === "user_1")).toHaveLength(0);
    expect(state.domains.filter((d) => d.user_id === "user_1")).toHaveLength(0);
    expect(state.scanHistory).toHaveLength(0);
    expect(state.alerts).toHaveLength(0);
    expect(state.apiKeys).toHaveLength(0);
    expect(state.webhooks.filter((w) => w.user_id === "user_1")).toHaveLength(
      0,
    );
    expect(state.deliveries).toHaveLength(0);
    expect(
      state.subscriptions.filter((s) => s.user_id === "user_1"),
    ).toHaveLength(0);
    // Other tenant intact.
    expect(state.users.filter((u) => u.id === "user_2")).toHaveLength(1);
    expect(state.domains.filter((d) => d.user_id === "user_2")).toHaveLength(1);
  });
});
