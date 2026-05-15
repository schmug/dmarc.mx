import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { BulkResultEntry } from "../src/api/bulk-scan.js";

const dispatchWebhookMock = vi.fn();
vi.mock("../src/webhooks/dispatcher.js", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

// fireBulkScanWebhooks now calls getWebhookForUser to decide the dispatch
// strategy (serial for rate-limited formats, parallel otherwise). Return null
// here so the existing concurrency tests exercise the parallel path, which
// matches the pre-throttle behaviour these tests were written to assert.
const getWebhookForUserMock = vi.fn().mockResolvedValue(null);
vi.mock("../src/db/webhooks.js", () => ({
  getWebhookForUser: getWebhookForUserMock,
}));

// Imported after the mocks so the trigger module sees both mocked modules.
const { fireBulkScanWebhooks, fireScanCompletedWebhook } = await import(
  "../src/webhooks/triggers.js"
);

beforeEach(() => {
  dispatchWebhookMock.mockReset();
  getWebhookForUserMock.mockReset();
  // Default: no webhook configured → parallel path (null format → no throttle).
  getWebhookForUserMock.mockResolvedValue(null);
});

afterEach(() => {
  vi.restoreAllMocks();
});

const fakeDb = {} as D1Database;

describe("webhooks/triggers.fireScanCompletedWebhook", () => {
  it("forwards a scan.completed event with the canonical report URL", async () => {
    dispatchWebhookMock.mockResolvedValue({
      ok: true,
      status: 200,
      error: null,
      attempted_at: 0,
      event_id: "evt_x",
    });

    await fireScanCompletedWebhook(fakeDb, "u1", {
      domain: "example.com",
      grade: "A",
      scanId: 42,
      trigger: "cron",
    });

    expect(dispatchWebhookMock).toHaveBeenCalledTimes(1);
    const [, userId, event] = dispatchWebhookMock.mock.calls[0];
    expect(userId).toBe("u1");
    expect(event).toMatchObject({
      type: "scan.completed",
      data: {
        domain: "example.com",
        grade: "A",
        scan_id: 42,
        trigger: "cron",
        report_url: "https://dmarc.mx/check?domain=example.com",
      },
    });
  });

  it("swallows dispatcher errors so the caller's waitUntil cannot crash", async () => {
    dispatchWebhookMock.mockRejectedValue(new Error("network down"));
    await expect(
      fireScanCompletedWebhook(fakeDb, "u1", {
        domain: "example.com",
        grade: "B",
        scanId: 1,
        trigger: "dashboard",
      }),
    ).resolves.toBeUndefined();
  });
});

describe("webhooks/triggers.fireBulkScanWebhooks", () => {
  it("fires only on entries with status 'scanned'", async () => {
    dispatchWebhookMock.mockResolvedValue(null);
    const results: BulkResultEntry[] = [
      { domain: "ok.com", status: "scanned", grade: "A" },
      { domain: "queued.com", status: "queued" },
      { domain: "bad input", status: "invalid", error: "Not a valid domain" },
      { domain: "boom.com", status: "error", error: "Scan failed" },
    ];

    await fireBulkScanWebhooks(fakeDb, "u1", results, "dashboard");

    expect(dispatchWebhookMock).toHaveBeenCalledTimes(1);
    const event = dispatchWebhookMock.mock.calls[0][2];
    expect(event.data.domain).toBe("ok.com");
    expect(event.data.grade).toBe("A");
  });

  // The point of the fan-out test is to lock in the fix for issue #186: a
  // serial loop over 25+ webhooks blows the waitUntil budget and the runtime
  // aborts every pending fetch with the literal message
  // "The operation was aborted due to timeout" — even though the chat
  // platform already received and acked the message. Parallel fan-out keeps
  // total wall-clock under budget.
  it("dispatches webhooks concurrently rather than one-at-a-time", async () => {
    let active = 0;
    let maxActive = 0;
    dispatchWebhookMock.mockImplementation(async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      // Yield enough times that every queued dispatcher invocation can
      // observe the increment before any of them resolves.
      for (let i = 0; i < 5; i++) {
        await Promise.resolve();
      }
      active--;
      return {
        ok: true,
        status: 200,
        error: null,
        attempted_at: 0,
        event_id: "evt",
      };
    });

    const results: BulkResultEntry[] = Array.from({ length: 8 }, (_, i) => ({
      domain: `e${i}.com`,
      status: "scanned",
      grade: "A",
    }));

    await fireBulkScanWebhooks(fakeDb, "u1", results, "bulk_api");

    expect(dispatchWebhookMock).toHaveBeenCalledTimes(8);
    // 8 entries fit inside one batch (batch size is 10), so all 8 dispatches
    // should be in flight simultaneously. A weaker `> 1` would still pass
    // under accidental serialization (e.g. batch size = 2) and miss the
    // regression we want to lock in.
    expect(maxActive).toBe(8);
  });

  it("does not propagate rejections from a failing dispatch", async () => {
    dispatchWebhookMock.mockRejectedValue(new Error("network down"));
    const results: BulkResultEntry[] = [
      { domain: "a.com", status: "scanned", grade: "A" },
      { domain: "b.com", status: "scanned", grade: "B" },
    ];

    await expect(
      fireBulkScanWebhooks(fakeDb, "u1", results, "dashboard"),
    ).resolves.toBeUndefined();
    expect(dispatchWebhookMock).toHaveBeenCalledTimes(2);
  });
});
