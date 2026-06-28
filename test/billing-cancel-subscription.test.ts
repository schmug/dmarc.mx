import { afterEach, describe, expect, it, vi } from "vitest";
import { cancelSubscription } from "../src/billing/stripe.js";

const ENV = {
  STRIPE_SECRET_KEY: "sk_test_x",
  STRIPE_WEBHOOK_SECRET: "whsec_x",
  STRIPE_PRICE_ID_PRO: "price_pro_test",
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("billing/stripe.cancelSubscription", () => {
  it("cancels a subscription immediately via DELETE /v1/subscriptions/{id}", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "sub_123", status: "canceled" }), {
        status: 200,
      }),
    );

    const result = await cancelSubscription(ENV, "sub_123");

    expect(result.status).toBe("canceled");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.stripe.com/v1/subscriptions/sub_123");
    expect(init.method).toBe("DELETE");
    expect((init.headers as Record<string, string>).Authorization).toBe(
      "Bearer sk_test_x",
    );
  });

  it("treats 404 as idempotent canceled (sub already gone in Stripe)", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({ error: { message: "No such subscription" } }),
        {
          status: 404,
        },
      ),
    );

    const result = await cancelSubscription(ENV, "sub_missing");

    expect(result).toEqual({ id: "sub_missing", status: "canceled" });
  });

  it("throws on non-404 Stripe errors (so the caller can abort)", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: { message: "Internal error" } }), {
        status: 500,
      }),
    );

    await expect(cancelSubscription(ENV, "sub_1")).rejects.toThrow(
      /Stripe API 500/,
    );
  });
});

describe("billing/stripe.cancelActiveSubscriptionsForCustomer", () => {
  it("lists billable subscriptions for the customer and cancels each", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url) => {
        const { pathname } = new URL(String(url));
        if (pathname === "/v1/subscriptions") {
          return new Response(
            JSON.stringify({
              data: [
                { id: "sub_a", status: "active" },
                { id: "sub_b", status: "canceled" },
              ],
            }),
            { status: 200 },
          );
        }
        if (pathname === "/v1/subscriptions/sub_a") {
          return new Response(
            JSON.stringify({ id: "sub_a", status: "canceled" }),
            { status: 200 },
          );
        }
        throw new Error(`unexpected fetch: ${url}`);
      });

    const { cancelActiveSubscriptionsForCustomer } = await import(
      "../src/billing/stripe.js"
    );
    const cancelled = await cancelActiveSubscriptionsForCustomer(
      ENV,
      "cus_123",
    );

    expect(cancelled).toBe(true);
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("returns false when the customer has no billable subscriptions", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({ data: [{ id: "sub_x", status: "canceled" }] }),
        { status: 200 },
      ),
    );

    const { cancelActiveSubscriptionsForCustomer } = await import(
      "../src/billing/stripe.js"
    );
    const cancelled = await cancelActiveSubscriptionsForCustomer(
      ENV,
      "cus_123",
    );

    expect(cancelled).toBe(false);
  });
});
