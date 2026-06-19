import { describe, expect, it } from "vitest";
import { createReauthProof, validateReauthProof } from "../src/auth/reauth.js";

const SECRET = "test-session-secret";

describe("auth/reauth proof token", () => {
  it("validates a fresh proof for the matching subject", async () => {
    const token = await createReauthProof("user_1", SECRET);
    expect(await validateReauthProof(token, SECRET, "user_1")).toBe(true);
  });

  it("rejects a proof minted for a different subject (no cross-account reuse)", async () => {
    const token = await createReauthProof("user_1", SECRET);
    expect(await validateReauthProof(token, SECRET, "user_2")).toBe(false);
  });

  it("rejects an expired proof", async () => {
    const token = await createReauthProof("user_1", SECRET, -1);
    expect(await validateReauthProof(token, SECRET, "user_1")).toBe(false);
  });

  it("rejects a proof signed with a different secret", async () => {
    const token = await createReauthProof("user_1", SECRET);
    expect(await validateReauthProof(token, "other-secret", "user_1")).toBe(
      false,
    );
  });

  it("rejects a tampered payload", async () => {
    const token = await createReauthProof("user_1", SECRET);
    const [, sig] = token.split(".");
    // Re-sign nothing — swap in a different (validly-encoded) payload.
    const forgedPayload = btoa(
      JSON.stringify({
        sub: "user_2",
        purpose: "account-deletion",
        exp: 9_999_999_999,
      }),
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(
      await validateReauthProof(`${forgedPayload}.${sig}`, SECRET, "user_2"),
    ).toBe(false);
  });

  it("rejects a malformed token", async () => {
    expect(await validateReauthProof("garbage", SECRET, "user_1")).toBe(false);
    expect(await validateReauthProof("a.b.c", SECRET, "user_1")).toBe(false);
  });

  it("rejects a session JWT presented as a proof (purpose mismatch)", async () => {
    // A normal session token has no `purpose: "account-deletion"` claim, so it
    // must not be accepted as a step-up proof even though it's validly signed.
    const { createSessionToken } = await import("../src/auth/session.js");
    const sessionToken = await createSessionToken(
      { sub: "user_1", email: "a@b.com" },
      SECRET,
    );
    expect(await validateReauthProof(sessionToken, SECRET, "user_1")).toBe(
      false,
    );
  });
});
