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

  it("treats 404 as already-canceled (idempotent for account deletion)", async () => {
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

  it("throws on other Stripe errors so the caller can abort deletion", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: { message: "Server error" } }), {
        status: 500,
      }),
    );

    await expect(cancelSubscription(ENV, "sub_123")).rejects.toThrow(
      /Stripe API 500/,
    );
  });
});
