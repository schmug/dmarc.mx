// Step-up re-authentication proof for the destructive account-deletion flow
// (issue #550). After the user is forced through a fresh WorkOS login
// (authorize with `prompt=login`), the callback mints one of these proofs and
// stores it in an HttpOnly/Secure/SameSite=Lax cookie. The deletion endpoint
// only proceeds when it can validate a proof bound to the *current session
// subject*, so a hijacked-but-stale session can't nuke an account without the
// attacker also re-authenticating as the victim at WorkOS.
//
// The proof is a compact HMAC-signed token (same primitive as session.ts /
// unsubscribe.ts, keyed on SESSION_SECRET) carrying { sub, purpose, exp }.
// It is:
//   - short-lived  — default 10-minute TTL (`exp`), enforced on validate;
//   - effectively single-use — the deletion handler clears the cookie on
//                    success so the legitimate flow consumes it exactly once;
//                    there is no server-side nonce store, so a replay of a
//                    leaked proof value is bounded only by the short TTL — but
//                    the cookie is HttpOnly/Secure/SameSite=Lax (so JS/cross-
//                    site can't read or resend it) and deletion is idempotent
//                    (a replay targets an already-erased user and no-ops);
//   - purpose-scoped — the `purpose` claim prevents a plain session JWT (which
//                    has no such claim, and a different token shape) from being
//                    presented as a deletion proof.

const ENCODER = new TextEncoder();
const PROOF_PURPOSE = "account-deletion";
const DEFAULT_PROOF_TTL_SECONDS = 10 * 60;

interface ReauthProofPayload {
  sub: string;
  purpose: string;
  exp: number;
}

function base64UrlEncode(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function getKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    ENCODER.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function createReauthProof(
  sub: string,
  secret: string,
  ttlSeconds: number = DEFAULT_PROOF_TTL_SECONDS,
): Promise<string> {
  const payload: ReauthProofPayload = {
    sub,
    purpose: PROOF_PURPOSE,
    exp: Math.floor(Date.now() / 1000) + ttlSeconds,
  };
  const payloadEncoded = base64UrlEncode(
    ENCODER.encode(JSON.stringify(payload)),
  );
  const key = await getKey(secret);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    ENCODER.encode(payloadEncoded),
  );
  return `${payloadEncoded}.${base64UrlEncode(signature)}`;
}

// Returns true only when the token is a structurally-valid, correctly-signed,
// unexpired deletion proof whose subject equals `expectedSub`. Any deviation
// (bad shape, bad signature, wrong purpose, expired, wrong subject) returns
// false — never throws.
export async function validateReauthProof(
  token: string,
  secret: string,
  expectedSub: string,
): Promise<boolean> {
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [payloadEncoded, signatureStr] = parts;
  try {
    const key = await getKey(secret);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlDecode(signatureStr),
      ENCODER.encode(payloadEncoded),
    );
    if (!valid) return false;

    const payload: ReauthProofPayload = JSON.parse(
      new TextDecoder().decode(base64UrlDecode(payloadEncoded)),
    );
    if (payload.purpose !== PROOF_PURPOSE) return false;
    if (payload.exp < Math.floor(Date.now() / 1000)) return false;
    if (payload.sub !== expectedSub) return false;
    return true;
  } catch {
    return false;
  }
}
