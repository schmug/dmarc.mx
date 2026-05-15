// Tests for Google Chat webhook rate-limit throttling (issue #242).
//
// Google Chat incoming webhooks cap at ~1 msg/second per space. Without
// throttling, fireBulkScanWebhooks batches 10 concurrent POSTs and causes an
// 87.5% 429 failure rate during cron rescans.
//
// Strategy: mock dispatchWebhook entirely so tests only exercise the
// scheduling logic in fireBulkScanWebhooks. Fake timers make the 1100ms
// inter-send delays free in CI.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { BulkResultEntry } from "../src/api/bulk-scan.js";

// ---------------------------------------------------------------------------
// Module-level mocks — declared before any dynamic import so Vitest can hoist
// them before module evaluation.
// ---------------------------------------------------------------------------

const getWebhookForUserMock = vi.fn();
vi.mock("../src/db/webhooks.js", () => ({
  getWebhookForUser: getWebhookForUserMock,
}));

// Mock dispatchWebhook so scheduling tests don't touch HTTP machinery.
const dispatchWebhookMock = vi.fn();
vi.mock("../src/webhooks/dispatcher.js", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

// Import after mocks are declared.
const { fireBulkScanWebhooks } = await import("../src/webhooks/triggers.js");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const GOOGLE_CHAT_URL =
  "https://chat.googleapis.com/v1/spaces/X/messages?key=k&token=t";

function makeGoogleChatWebhook() {
  return {
    id: 1,
    user_id: "u1",
    url: GOOGLE_CHAT_URL,
    secret: null,
    format: "google_chat" as const,
    created_at: 0,
  };
}

function makeResults(n: number): BulkResultEntry[] {
  return Array.from({ length: n }, (_, i) => ({
    domain: `domain${i}.com`,
    status: "scanned" as const,
    grade: "A",
  }));
}

const fakeDb = {} as D1Database;

function okDispatch() {
  return Promise.resolve({
    ok: true,
    status: 200,
    error: null,
    attempted_at: 0,
    event_id: "evt_x",
  });
}

// ---------------------------------------------------------------------------
// Google Chat — serial throttled dispatch
// ---------------------------------------------------------------------------

describe("fireBulkScanWebhooks — Google Chat serial dispatch", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    getWebhookForUserMock.mockResolvedValue(makeGoogleChatWebhook());
    dispatchWebhookMock.mockImplementation(okDispatch);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    getWebhookForUserMock.mockReset();
    dispatchWebhookMock.mockReset();
  });

  it("dispatches all N entries for a google_chat webhook", async () => {
    const N = 10;
    const promise = fireBulkScanWebhooks(fakeDb, "u1", makeResults(N), "cron");
    // Advance time past all inter-send delays: (N-1) × 1100ms.
    await vi.advanceTimersByTimeAsync(15_000);
    await promise;

    expect(dispatchWebhookMock).toHaveBeenCalledTimes(N);
  });

  it("inserts a delay of at least 1100ms between consecutive sends", async () => {
    const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout");

    const N = 4;
    const promise = fireBulkScanWebhooks(fakeDb, "u1", makeResults(N), "cron");
    await vi.advanceTimersByTimeAsync(10_000);
    await promise;

    expect(dispatchWebhookMock).toHaveBeenCalledTimes(N);

    // Exactly N-1 inter-send timeouts, each ≥ 1100ms.
    const delays = setTimeoutSpy.mock.calls
      .map(([, ms]) => ms as number)
      .filter((ms) => ms >= 1000);

    expect(delays.length).toBe(N - 1);
    for (const ms of delays) {
      expect(ms).toBeGreaterThanOrEqual(1100);
    }
  });

  it("does not dispatch non-scanned entries", async () => {
    const results: BulkResultEntry[] = [
      { domain: "ok.com", status: "scanned", grade: "A" },
      { domain: "q.com", status: "queued" },
      { domain: "bad.com", status: "invalid", error: "Not valid" },
    ];
    const promise = fireBulkScanWebhooks(fakeDb, "u1", results, "cron");
    await vi.advanceTimersByTimeAsync(5_000);
    await promise;

    expect(dispatchWebhookMock).toHaveBeenCalledTimes(1);
    expect(dispatchWebhookMock.mock.calls[0][2].data.domain).toBe("ok.com");
  });
});

// ---------------------------------------------------------------------------
// Raw format — parallel batch dispatch (no throttle)
// ---------------------------------------------------------------------------

describe("fireBulkScanWebhooks — raw format uses parallel dispatch", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    getWebhookForUserMock.mockReset();
    dispatchWebhookMock.mockReset();
  });

  beforeEach(() => {
    getWebhookForUserMock.mockResolvedValue({
      id: 2,
      user_id: "u1",
      url: "https://hooks.example.com/recv",
      secret: "shhh",
      format: "raw" as const,
      created_at: 0,
    });
  });

  it("dispatches raw webhooks concurrently (maxActive > 1 within a batch)", async () => {
    let active = 0;
    let maxActive = 0;
    dispatchWebhookMock.mockImplementation(async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      for (let i = 0; i < 5; i++) await Promise.resolve();
      active--;
      return {
        ok: true,
        status: 200,
        error: null,
        attempted_at: 0,
        event_id: "e",
      };
    });

    const N = 8;
    await fireBulkScanWebhooks(fakeDb, "u1", makeResults(N), "cron");

    expect(dispatchWebhookMock).toHaveBeenCalledTimes(N);
    expect(maxActive).toBeGreaterThan(1);
  });

  it("does not insert any rate-limit delays for raw format", async () => {
    vi.useFakeTimers();
    const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout");
    dispatchWebhookMock.mockImplementation(okDispatch);

    await fireBulkScanWebhooks(fakeDb, "u1", makeResults(5), "cron");

    vi.useRealTimers();

    const throttleDelays = setTimeoutSpy.mock.calls
      .map(([, ms]) => ms as number)
      .filter((ms) => ms >= 1000);
    expect(throttleDelays.length).toBe(0);
  });
});
