import { afterEach, describe, expect, it, vi } from "vitest";
import { deleteWorkosUser } from "../src/auth/workos.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("auth/workos.deleteWorkosUser", () => {
  it("DELETEs the WorkOS user via the Management API with a bearer key", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 200 }));

    await deleteWorkosUser("sk_live_workos", "user_01H");

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.workos.com/user_management/users/user_01H");
    expect(init.method).toBe("DELETE");
    expect((init.headers as Record<string, string>).Authorization).toBe(
      "Bearer sk_live_workos",
    );
  });

  it("treats a 404 as already-deleted (no throw)", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 404 }),
    );
    await expect(
      deleteWorkosUser("sk_live_workos", "user_gone"),
    ).resolves.toBeUndefined();
  });

  it("throws on an unexpected error status so the caller can flag for retry", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("boom", { status: 500 }),
    );
    await expect(
      deleteWorkosUser("sk_live_workos", "user_01H"),
    ).rejects.toThrow(/WorkOS/);
  });
});
