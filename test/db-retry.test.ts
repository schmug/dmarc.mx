import { describe, expect, it, vi } from "vitest";
import { createSessionToken } from "../src/auth/session.js";
import {
  D1_READ_ATTEMPTS,
  d1Read,
  isTransientD1Error,
} from "../src/db/retry.js";
import { getPlanForUser, upsertSubscription } from "../src/db/subscriptions.js";
import { app } from "../src/index.js";

// The exact pair D1 threw on GET /dashboard (Sentry e4a8361d…): the outer
// error carries the D1_ERROR prefix, the `cause` carries the bare message.
function d1InternalError(): Error {
  const inner = new Error(
    "internal error; reference = f8f5ikbfo3lj5die9eble9r8",
  );
  const outer = new Error(
    "D1_ERROR: internal error; reference = f8f5ikbfo3lj5die9eble9r8",
  );
  (outer as { cause?: unknown }).cause = inner;
  return outer;
}

describe("db/retry.isTransientD1Error", () => {
  it("recognizes D1's internal-error blip", () => {
    expect(isTransientD1Error(d1InternalError())).toBe(true);
  });

  it("recognizes a transient marker that only appears on the cause", () => {
    const err = new Error("D1_ERROR");
    (err as { cause?: unknown }).cause = new Error("Network connection lost.");
    expect(isTransientD1Error(err)).toBe(true);
  });

  it("recognizes a storage reset", () => {
    expect(
      isTransientD1Error(new Error("storage caused object to be reset")),
    ).toBe(true);
  });

  it("does not classify a SQL bug as transient", () => {
    expect(
      isTransientD1Error(new Error("D1_ERROR: no such column: bogus")),
    ).toBe(false);
    expect(
      isTransientD1Error(new Error("D1_ERROR: UNIQUE constraint failed")),
    ).toBe(false);
  });

  it("does not classify non-Error throws as transient", () => {
    expect(isTransientD1Error("internal error")).toBe(false);
    expect(isTransientD1Error(null)).toBe(false);
  });

  it("terminates on a self-referential cause chain", () => {
    const err = new Error("boom") as Error & { cause?: unknown };
    err.cause = err;
    expect(isTransientD1Error(err)).toBe(false);
  });
});

describe("db/retry.d1Read", () => {
  it("returns the first successful result without retrying", async () => {
    const run = vi.fn().mockResolvedValue("ok");
    await expect(d1Read(run, { baseDelayMs: 0 })).resolves.toBe("ok");
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("retries a transient failure and returns the retried result", async () => {
    const run = vi
      .fn()
      .mockRejectedValueOnce(d1InternalError())
      .mockResolvedValue("ok");
    await expect(d1Read(run, { baseDelayMs: 0 })).resolves.toBe("ok");
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("rethrows a non-transient error on the first attempt", async () => {
    const run = vi.fn().mockRejectedValue(new Error("no such table: domains"));
    await expect(d1Read(run, { baseDelayMs: 0 })).rejects.toThrow(
      "no such table",
    );
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("gives up after the attempt budget and rethrows the last error", async () => {
    const run = vi.fn().mockRejectedValue(d1InternalError());
    await expect(d1Read(run, { baseDelayMs: 0 })).rejects.toThrow("D1_ERROR");
    expect(run).toHaveBeenCalledTimes(D1_READ_ATTEMPTS);
  });

  it("honors a caller-supplied attempt budget", async () => {
    const run = vi.fn().mockRejectedValue(d1InternalError());
    await expect(
      d1Read(run, { attempts: 2, baseDelayMs: 0 }),
    ).rejects.toThrow();
    expect(run).toHaveBeenCalledTimes(2);
  });
});

// A D1 stand-in whose statements fail the first `failures` executions with the
// blip, then serve `row`. Counts every execution so the tests can assert how
// many attempts a read or a write actually made.
function flakyDb(opts: { failures: number; row?: unknown }) {
  const calls = { first: 0, run: 0 };
  let remaining = opts.failures;
  const execute = <T>(kind: "first" | "run", value: T): Promise<T> => {
    calls[kind]++;
    if (remaining > 0) {
      remaining--;
      return Promise.reject(d1InternalError());
    }
    return Promise.resolve(value);
  };
  const db = {
    prepare: () => ({
      bind: () => ({
        first: () => execute("first", opts.row ?? null),
        run: () => execute("run", { success: true, meta: { changes: 1 } }),
      }),
    }),
  } as unknown as D1Database;
  return { db, calls };
}

describe("db reads under a transient D1 failure", () => {
  it("getPlanForUser rides out the blip that 500'd the dashboard", async () => {
    const { db, calls } = flakyDb({ failures: 1, row: { status: "active" } });
    await expect(getPlanForUser(db, "user_1")).resolves.toBe("pro");
    expect(calls.first).toBe(2);
  });

  it("getPlanForUser still surfaces a blip that outlasts the retries", async () => {
    const { db, calls } = flakyDb({ failures: 99 });
    await expect(getPlanForUser(db, "user_1")).rejects.toThrow("D1_ERROR");
    expect(calls.first).toBe(D1_READ_ATTEMPTS);
  });

  // Writes are deliberately excluded: D1 has no idempotency token, so a `.run()`
  // that failed after the row landed is indistinguishable from one that never
  // landed. Retrying would risk double-applying the statement.
  it("does not retry writes", async () => {
    const { db, calls } = flakyDb({ failures: 1 });
    await expect(
      upsertSubscription(db, {
        user_id: "user_1",
        stripe_subscription_id: "sub_1",
        stripe_price_id: "price_1",
        status: "active",
        current_period_end: null,
        cancel_at_period_end: false,
      }),
    ).rejects.toThrow("D1_ERROR");
    expect(calls.run).toBe(1);
  });
});

describe("app.onError on an exhausted D1 blip", () => {
  const SECRET = "test-session-secret";

  async function requestDashboard() {
    const { db } = flakyDb({ failures: 99 });
    const token = await createSessionToken(
      { sub: "user_1", email: "alice@example.com" },
      SECRET,
    );
    return app.request(
      "/dashboard",
      { headers: { Cookie: `session=${token}` } },
      { SESSION_SECRET: SECRET, DB: db },
      {
        waitUntil: () => {},
        passThroughOnException: () => {},
      } as ExecutionContext,
    );
  }

  it("answers 503 + Retry-After instead of a 500", async () => {
    const res = await requestDashboard();
    expect(res.status).toBe(503);
    expect(res.headers.get("Retry-After")).toBe("5");
  });

  it("keeps the raw D1 reference id out of the page", async () => {
    const res = await requestDashboard();
    const body = await res.text();
    expect(body).not.toContain("D1_ERROR");
    expect(body).not.toContain("f8f5ikbfo3lj5die9eble9r8");
    expect(body).toContain("briefly unavailable");
  });
});
