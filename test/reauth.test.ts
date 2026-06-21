import { describe, expect, it } from "vitest";
import {
  createReauthProof,
  type NonceConsumer,
  validateReauthProof,
} from "../src/auth/reauth.js";

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

  it("rejects a replayed proof when a nonce store is present", async () => {
    const consumed = new Set<string>();
    const consumeNonce: NonceConsumer = (jti, _expSec) => {
      if (consumed.has(jti)) return false;
      consumed.add(jti);
      return true;
    };
    const token = await createReauthProof("user_1", SECRET);
    expect(
      await validateReauthProof(token, SECRET, "user_1", consumeNonce),
    ).toBe(true);
    expect(
      await validateReauthProof(token, SECRET, "user_1", consumeNonce),
    ).toBe(false);
  });

  it("allows deletion when the nonce store binding is absent (graceful fallback)", async () => {
    const token = await createReauthProof("user_1", SECRET);
    // No consumeNonce passed — self-host / test without DO binding.
    expect(await validateReauthProof(token, SECRET, "user_1")).toBe(true);
    // Second call also passes (no nonce store to reject the replay).
    expect(await validateReauthProof(token, SECRET, "user_1")).toBe(true);
  });

  it("allows deletion when the nonce store throws (transient DO error)", async () => {
    const failingStore: NonceConsumer = () => {
      throw new Error("DO unavailable");
    };
    const token = await createReauthProof("user_1", SECRET);
    expect(
      await validateReauthProof(token, SECRET, "user_1", failingStore),
    ).toBe(true);
  });
});
