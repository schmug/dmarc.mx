import { afterEach, describe, expect, it, vi } from "vitest";
import { deleteAccount } from "../src/account/deletion.js";
import {
  enqueueWorkosRetry,
  sweepWorkosRetries,
} from "../src/account/workos-retry.js";
import type { Env } from "../src/env.js";

vi.mock("@sentry/cloudflare", () => ({
  captureException: vi.fn(),
}));

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Minimal D1 mock that drives the workos_identity_retry table in memory.
// ---------------------------------------------------------------------------
interface RetryRow {
  workos_user_id: string;
  attempt_count: number;
  next_attempt_at: number;
  enqueued_at: number;
}

function makeRetryDB(
  initialRows: RetryRow[] = [],
  activeUserIds: string[] = [],
) {
  const store: RetryRow[] = [...initialRows];
  const users = new Set(activeUserIds);

  const db = {
    prepare(sql: string) {
      return {
        bind(...args: unknown[]) {
          return {
            async run() {
              if (/INSERT OR IGNORE INTO workos_identity_retry/i.test(sql)) {
                const userId = args[0] as string;
                if (!store.find((r) => r.workos_user_id === userId)) {
                  store.push({
                    workos_user_id: userId,
                    attempt_count: args.length >= 2 ? (args[1] as number) : 0,
                    next_attempt_at: args.length >= 3 ? (args[2] as number) : 0,
                    enqueued_at: args.length >= 4 ? (args[3] as number) : 1000,
                  });
                }
              } else if (/DELETE FROM workos_identity_retry/i.test(sql)) {
                const userId = args[0] as string;
                if (/NOT EXISTS/i.test(sql) && users.has(userId)) {
                  return {
                    success: true,
                    meta: {
                      changes: 0,
                      duration: 0,
                      last_row_id: 0,
                      rows_read: 0,
                      rows_written: 0,
                      size_after: 0,
                      changed_db: false,
                    },
                  };
                }
                const idx = store.findIndex((r) => r.workos_user_id === userId);
                const changed = idx >= 0 ? 1 : 0;
                if (idx >= 0) store.splice(idx, 1);
                return {
                  success: true,
                  meta: {
                    changes: changed,
                    duration: 0,
                    last_row_id: 0,
                    rows_read: 0,
                    rows_written: 0,
                    size_after: 0,
                    changed_db: changed > 0,
                  },
                };
              } else if (/UPDATE workos_identity_retry/i.test(sql)) {
                const [newCount, newAt, userId] = args;
                const row = store.find(
                  (r) => r.workos_user_id === (userId as string),
                );
                if (row) {
                  row.attempt_count = newCount as number;
                  row.next_attempt_at = newAt as number;
                }
              }
              return {
                success: true,
                meta: {
                  changes: 1,
                  duration: 0,
                  last_row_id: 0,
                  rows_read: 0,
                  rows_written: 0,
                  size_after: 0,
                  changed_db: true,
                },
              };
            },
            async all<T>() {
              if (/SELECT .* FROM workos_identity_retry/i.test(sql)) {
                const threshold = args[0] as number;
                return {
                  results: store.filter(
                    (r) => r.next_attempt_at <= threshold,
                  ) as unknown as T[],
                  success: true,
                  meta: {
                    duration: 0,
                    last_row_id: 0,
                    rows_read: 0,
                    rows_written: 0,
                    size_after: 0,
                    changed_db: false,
                  },
                };
              }
              return {
                results: [] as T[],
                success: true,
                meta: {
                  duration: 0,
                  last_row_id: 0,
                  rows_read: 0,
                  rows_written: 0,
                  size_after: 0,
                  changed_db: false,
                },
              };
            },
            async first<T>() {
              if (/SELECT 1 AS exists FROM users WHERE id = \?/i.test(sql)) {
                const userId = args[0] as string;
                return (users.has(userId) ? { exists: 1 } : null) as T | null;
              }
              return null as T | null;
            },
          };
        },
      };
    },
  } as unknown as D1Database;

  return { store, db, users };
}

// ---------------------------------------------------------------------------
// Acceptance criterion (a): WorkOS-delete failure enqueues the user id
// ---------------------------------------------------------------------------
describe("deleteAccount → enqueueWorkosRetry on WorkOS failure", () => {
  it("writes the WorkOS user id into the retry table when WorkOS delete fails", async () => {
    const { store, db } = makeRetryDB();

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 500 }),
    );

    const env: Env = {
      DB: db,
      WORKOS_CLIENT_ID: "",
      WORKOS_CLIENT_SECRET: "",
      WORKOS_REDIRECT_URI: "",
      SESSION_SECRET: "s",
      WORKOS_API_KEY: "sk_workos",
    } as Env;

    const result = await deleteAccount(env, {
      id: "user_workos_01",
      email: "alice@example.com",
    });

    expect(result.workosFailed).toBe(true);
    expect(store).toHaveLength(1);
    expect(store[0].workos_user_id).toBe("user_workos_01");
  });

  it("does NOT enqueue when WorkOS delete succeeds", async () => {
    const { store, db } = makeRetryDB();

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 200 }),
    );

    const env: Env = {
      DB: db,
      WORKOS_CLIENT_ID: "",
      WORKOS_CLIENT_SECRET: "",
      WORKOS_REDIRECT_URI: "",
      SESSION_SECRET: "s",
      WORKOS_API_KEY: "sk_workos",
    } as Env;

    const result = await deleteAccount(env, {
      id: "user_workos_01",
      email: "alice@example.com",
    });

    expect(result.workosDeleted).toBe(true);
    expect(store).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// enqueueWorkosRetry unit tests
// ---------------------------------------------------------------------------
describe("enqueueWorkosRetry", () => {
  it("inserts the user id into the retry table", async () => {
    const { store, db } = makeRetryDB();

    await enqueueWorkosRetry(db, "user_abc");

    expect(store).toHaveLength(1);
    expect(store[0].workos_user_id).toBe("user_abc");
  });

  it("is idempotent — a second call for the same id does not duplicate", async () => {
    const { store, db } = makeRetryDB();

    await enqueueWorkosRetry(db, "user_abc");
    await enqueueWorkosRetry(db, "user_abc");

    expect(store).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Acceptance criterion (b): sweep retries and clears on success
// ---------------------------------------------------------------------------
describe("sweepWorkosRetries", () => {
  it("calls deleteWorkosUser and removes the row on success", async () => {
    const now = 2000;
    const { store, db } = makeRetryDB([
      {
        workos_user_id: "user_retry_01",
        attempt_count: 0,
        next_attempt_at: now - 1,
        enqueued_at: 1000,
      },
    ]);

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 200 }),
    );

    const result = await sweepWorkosRetries(db, "sk_workos", now);

    expect(result.retried).toBe(1);
    expect(result.cleared).toBe(1);
    expect(result.errors).toBe(0);
    expect(result.givenUp).toBe(0);
    expect(store).toHaveLength(0);
  });

  it("treats a 404 as already-deleted and clears the row", async () => {
    const now = 2000;
    const { store, db } = makeRetryDB([
      {
        workos_user_id: "user_gone",
        attempt_count: 2,
        next_attempt_at: now - 1,
        enqueued_at: 1000,
      },
    ]);

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 404 }),
    );

    const result = await sweepWorkosRetries(db, "sk_workos", now);

    expect(result.cleared).toBe(1);
    expect(store).toHaveLength(0);
  });

  it("increments attempt_count and sets next_attempt_at on failure", async () => {
    const now = 2000;
    const { store, db } = makeRetryDB([
      {
        workos_user_id: "user_fail",
        attempt_count: 1,
        next_attempt_at: now - 1,
        enqueued_at: 1000,
      },
    ]);

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("error", { status: 500 }),
    );

    const result = await sweepWorkosRetries(db, "sk_workos", now);

    expect(result.errors).toBe(1);
    expect(result.cleared).toBe(0);
    expect(store).toHaveLength(1);
    expect(store[0].attempt_count).toBe(2);
    // Backoff at attempt_count=1 is min(86400, 3600 * 2^1) = 7200s
    expect(store[0].next_attempt_at).toBe(now + 7200);
  });

  it("gives up and removes the row after MAX_ATTEMPTS", async () => {
    const now = 2000;
    const { store, db } = makeRetryDB([
      {
        workos_user_id: "user_exhaust",
        attempt_count: 9,
        next_attempt_at: now - 1,
        enqueued_at: 1000,
      },
    ]);

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("error", { status: 503 }),
    );

    const result = await sweepWorkosRetries(db, "sk_workos", now);

    expect(result.givenUp).toBe(1);
    expect(result.errors).toBe(0);
    expect(store).toHaveLength(0);
  });

  it("skips WorkOS delete when the user re-registered locally", async () => {
    const now = 2000;
    const { store, db } = makeRetryDB(
      [
        {
          workos_user_id: "user_reregistered",
          attempt_count: 0,
          next_attempt_at: now - 1,
          enqueued_at: 1000,
        },
      ],
      ["user_reregistered"],
    );

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const result = await sweepWorkosRetries(db, "sk_workos", now);

    expect(result.retried).toBe(0);
    expect(result.cleared).toBe(1);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(store).toHaveLength(0);
  });

  it("re-checks local user immediately before WorkOS delete (signup race)", async () => {
    const now = 2000;
    let userSelectCount = 0;
    const store: RetryRow[] = [
      {
        workos_user_id: "user_signup_race",
        attempt_count: 0,
        next_attempt_at: now - 1,
        enqueued_at: 1000,
      },
    ];
    const users = new Set<string>();
    const db = {
      prepare(sql: string) {
        return {
          bind(...args: unknown[]) {
            return {
              async run() {
                if (/DELETE FROM workos_identity_retry/i.test(sql)) {
                  const userId = args[0] as string;
                  if (/NOT EXISTS/i.test(sql) && users.has(userId)) {
                    return { success: true, meta: { changes: 0 } };
                  }
                  const idx = store.findIndex(
                    (r) => r.workos_user_id === userId,
                  );
                  const changed = idx >= 0 ? 1 : 0;
                  if (idx >= 0) store.splice(idx, 1);
                  return { success: true, meta: { changes: changed } };
                }
                return { success: true, meta: { changes: 1 } };
              },
              async all<T>() {
                if (/SELECT .* FROM workos_identity_retry/i.test(sql)) {
                  const threshold = args[0] as number;
                  return {
                    results: store.filter(
                      (r) => r.next_attempt_at <= threshold,
                    ) as unknown as T[],
                  };
                }
                return { results: [] as T[] };
              },
              async first<T>() {
                if (/SELECT 1 AS exists FROM users WHERE id = \?/i.test(sql)) {
                  userSelectCount += 1;
                  // Guard: no user. Pre-delete check: signup completed.
                  return (
                    userSelectCount >= 2 ? { exists: 1 } : null
                  ) as T | null;
                }
                return null as T | null;
              },
            };
          },
        };
      },
    } as unknown as D1Database;

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const result = await sweepWorkosRetries(db, "sk_workos", now);

    expect(result.retried).toBe(0);
    expect(result.cleared).toBe(1);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(store).toHaveLength(0);
    expect(userSelectCount).toBeGreaterThanOrEqual(2);
  });

  it("alerts when signup completes during the WorkOS delete HTTP call", async () => {
    const now = 2000;
    const store: RetryRow[] = [
      {
        workos_user_id: "user_http_race",
        attempt_count: 0,
        next_attempt_at: now - 1,
        enqueued_at: 1000,
      },
    ];
    const users = new Set<string>();
    const db = {
      prepare(sql: string) {
        return {
          bind(...args: unknown[]) {
            return {
              async run() {
                if (/DELETE FROM workos_identity_retry/i.test(sql)) {
                  const userId = args[0] as string;
                  if (/NOT EXISTS/i.test(sql) && users.has(userId)) {
                    return { success: true, meta: { changes: 0 } };
                  }
                  const idx = store.findIndex(
                    (r) => r.workos_user_id === userId,
                  );
                  const changed = idx >= 0 ? 1 : 0;
                  if (idx >= 0) store.splice(idx, 1);
                  return { success: true, meta: { changes: changed } };
                }
                return { success: true, meta: { changes: 1 } };
              },
              async all<T>() {
                if (/SELECT .* FROM workos_identity_retry/i.test(sql)) {
                  const threshold = args[0] as number;
                  return {
                    results: store.filter(
                      (r) => r.next_attempt_at <= threshold,
                    ) as unknown as T[],
                  };
                }
                return { results: [] as T[] };
              },
              async first<T>() {
                if (/SELECT 1 AS exists FROM users WHERE id = \?/i.test(sql)) {
                  return (
                    users.has(args[0] as string) ? { exists: 1 } : null
                  ) as T | null;
                }
                return null as T | null;
              },
            };
          },
        };
      },
    } as unknown as D1Database;

    const Sentry = await import("@sentry/cloudflare");
    const captureSpy = vi.spyOn(Sentry, "captureException");

    vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      users.add("user_http_race");
      return new Response(null, { status: 200 });
    });

    const result = await sweepWorkosRetries(db, "sk_workos", now);

    expect(result.retried).toBe(1);
    expect(result.cleared).toBe(1);
    expect(captureSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.stringContaining("re-registration during sweep"),
      }),
    );
  });

  it("skips rows whose next_attempt_at is in the future", async () => {
    const now = 2000;
    const { store, db } = makeRetryDB([
      {
        workos_user_id: "user_future",
        attempt_count: 0,
        next_attempt_at: now + 3600,
        enqueued_at: 1000,
      },
    ]);

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const result = await sweepWorkosRetries(db, "sk_workos", now);

    expect(result.retried).toBe(0);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(store).toHaveLength(1);
  });

  // -------------------------------------------------------------------------
  // Acceptance criterion (c): no-op when WORKOS_API_KEY is absent
  // -------------------------------------------------------------------------
  it("is a no-op and makes no DB calls when apiKey is absent", async () => {
    const { store, db } = makeRetryDB([
      {
        workos_user_id: "user_skipped",
        attempt_count: 0,
        next_attempt_at: 0,
        enqueued_at: 1000,
      },
    ]);

    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const result = await sweepWorkosRetries(db, undefined);

    expect(result).toEqual({ retried: 0, cleared: 0, givenUp: 0, errors: 0 });
    expect(fetchSpy).not.toHaveBeenCalled();
    // Store untouched — no DB queries ran
    expect(store).toHaveLength(1);
  });
});
