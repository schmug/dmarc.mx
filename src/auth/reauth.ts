// Step-up re-authentication proof for the destructive account-deletion flow
// (issue #550). After the user is forced through a fresh WorkOS login
// (authorize with `prompt=login`), the callback mints one of these proofs and
// stores it in an HttpOnly/Secure/SameSite=Lax cookie. The deletion endpoint
// only proceeds when it can validate a proof bound to the *current session
// subject*, so a hijacked-but-stale session can't nuke an account without the
// attacker also re-authenticating as the victim at WorkOS.
//
// The proof is a compact HMAC-signed token (same primitive as session.ts /
// unsubscribe.ts, keyed on SESSION_SECRET) carrying { sub, purpose, exp, jti }.
// It is:
//   - short-lived  — default 10-minute TTL (`exp`), enforced on validate;
//   - cryptographically single-use — each proof embeds a unique `jti` nonce;
//                    the deletion handler records it in the RATE_LIMITER Durable
//                    Object on first use so a replayed proof is rejected even
//                    within its TTL. The cookie is also cleared on success.
//                    When the DO binding is absent (self-host), the nonce check
//                    is skipped and the short TTL + idempotent deletion remain
//                    as the backstop;
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
  jti: string;
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
    jti: crypto.randomUUID(),
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

// Returns { jti, exp } when the token is a structurally-valid, correctly-signed,
// unexpired deletion proof with a jti nonce whose subject equals `expectedSub`.
// Any deviation (bad shape, bad signature, wrong purpose, expired, missing jti,
// wrong subject) returns false — never throws.
export async function validateReauthProof(
  token: string,
  secret: string,
  expectedSub: string,
): Promise<{ jti: string; exp: number } | false> {
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
    if (typeof payload.jti !== "string" || payload.jti.length === 0)
      return false;
    return { jti: payload.jti, exp: payload.exp };
  } catch {
    return false;
  }
}
