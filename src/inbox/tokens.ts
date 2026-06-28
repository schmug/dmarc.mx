// Token + address helpers for inbound test-email scanning (issue #417).
//
// A user requests a one-time address `<token>@inbox.dmarc.mx`, sends a real
// message to it, and the Email Worker reads the authentication verdict back.
// The token IS the capability that scopes one user's result from another's, so
// it must be unguessable, and it is the only thing the `email()` handler has to
// map an inbound message back to a request (via `message.to`).

// The dedicated Email Routing subdomain. Onboarding `inbox.dmarc.mx` to Email
// Routing and pointing its catch-all rule at this Worker ("Send to a Worker")
// is an OWNER/zone-admin dashboard step — it is NOT committable. Kept as a
// single constant so issuance, validation, and rendering all agree, and a
// self-host / rename is a one-line edit.
//
// The apex `dmarc.mx` is a separate product (PhishSOC) with its own mailboxes
// and a `*@dmarc.mx` catch-all. Subdomain mail is matched against the
// subdomain's own Email Routing config, so the apex catch-all does NOT reach
// `*@inbox.dmarc.mx` — there is no collision.
export const INBOX_DOMAIN = "inbox.dmarc.mx";

// 128-bit tokens, lowercase hex. 16 random bytes → 32 hex chars.
const TOKEN_BYTES = 16;

// Strict charset for a token. Anchored + fixed-length so a crafted `message.to`
// local part can never smuggle anything (path traversal, KV key prefixes, etc.)
// into a KV key.
export const TOKEN_PATTERN = /^[0-9a-f]{32}$/;

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Mint a fresh 128-bit capability token (lowercase hex). */
export function generateToken(): string {
  return toHex(crypto.getRandomValues(new Uint8Array(TOKEN_BYTES)));
}

/** True only for a well-formed 32-char lowercase-hex token. */
export function isValidToken(token: string): boolean {
  return TOKEN_PATTERN.test(token);
}

/** Build the full one-time address for a token. */
export function inboxAddress(token: string): string {
  return `${token}@${INBOX_DOMAIN}`;
}

/**
 * Extract + strict-charset-validate the token from an envelope-To.
 *
 * `message.to` is set by Cloudflare at ingest (trustworthy, unlike spoofable
 * header addresses), but we still validate strictly before the value is ever
 * used as a KV key. Returns null when the address is not on our subdomain or
 * the local part is not a well-formed token — the caller treats null as a
 * no-op (no KV write, no throw).
 */
export function tokenFromAddress(to: string | null | undefined): string | null {
  if (!to) return null;
  const trimmed = to.trim().toLowerCase();
  const at = trimmed.lastIndexOf("@");
  if (at <= 0) return null;
  const local = trimmed.slice(0, at);
  const domain = trimmed.slice(at + 1);
  if (domain !== INBOX_DOMAIN) return null;
  if (!isValidToken(local)) return null;
  return local;
}
