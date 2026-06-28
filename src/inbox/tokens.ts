// Token + address helpers for inbound test-email scanning (issue #417).
//
// A user requests a one-time address, sends a real message to it, and the
// Email Worker reads the authentication verdict back. The token IS the
// capability that scopes one user's result from another's, so it must be
// unguessable, and it is the only thing the `email()` handler has to map an
// inbound message back to a request (via `message.to`).
//
// Address shape: `inbox+<token>@dmarc.mx` (subaddressing / "plus addressing").
// `dmarc.mx` already has a single zone-wide catch-all owned by a separate
// product (PhishSOC), and Cloudflare allows only one catch-all per zone — so we
// can't isolate a subdomain by catch-all. Instead we use ONE static routing
// rule (`inbox@dmarc.mx` → this Worker) plus subaddressing: a "+tag" recipient
// falls back to its base rule, and a *specific* rule outranks the catch-all.
// So every `inbox+<token>@dmarc.mx` reaches this Worker while all other mail
// keeps flowing to PhishSOC's catch-all — one rule covers unlimited dynamic
// tokens (no per-token rules, no 200-rule limit). Cloudflare preserves the full
// `+<token>` in `message.to` for us to parse.

// The apex the address lives on. Onboarding the routing rule + enabling
// subaddressing is an OWNER/zone-admin dashboard step (NOT committable). Kept as
// constants so issuance, validation, and rendering all agree and a rename is a
// one-line edit.
export const INBOX_DOMAIN = "dmarc.mx";
// The base local part. The owner creates one rule `inbox@dmarc.mx` → Worker;
// subaddressing routes `inbox+<token>@dmarc.mx` to that same rule.
export const INBOX_LOCAL_PART = "inbox";
// The address the owner points at the Worker (shown in setup docs).
export const INBOX_BASE_ADDRESS = `${INBOX_LOCAL_PART}@${INBOX_DOMAIN}`;

// 128-bit tokens, lowercase hex. 16 random bytes → 32 hex chars.
const TOKEN_BYTES = 16;

// Strict charset for a token. Anchored + fixed-length so a crafted `message.to`
// can never smuggle anything (path traversal, KV key prefixes, etc.) into a KV
// key.
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

/** Build the full one-time subaddress for a token. */
export function inboxAddress(token: string): string {
  return `${INBOX_LOCAL_PART}+${token}@${INBOX_DOMAIN}`;
}

/**
 * Extract + strict-charset-validate the token from an envelope-To shaped like
 * `inbox+<token>@dmarc.mx`.
 *
 * `message.to` is set by Cloudflare at ingest (trustworthy, unlike spoofable
 * header addresses), but we still validate strictly before the value is ever
 * used as a KV key. Returns null when the address is not our base local part on
 * our domain, or the "+tag" is not a well-formed token — the caller treats null
 * as a no-op (no KV write, no throw).
 */
export function tokenFromAddress(to: string | null | undefined): string | null {
  if (!to) return null;
  const trimmed = to.trim().toLowerCase();
  const at = trimmed.lastIndexOf("@");
  if (at <= 0) return null;
  const local = trimmed.slice(0, at);
  const domain = trimmed.slice(at + 1);
  if (domain !== INBOX_DOMAIN) return null;
  const plus = local.indexOf("+");
  if (plus === -1) return null;
  if (local.slice(0, plus) !== INBOX_LOCAL_PART) return null;
  const token = local.slice(plus + 1);
  if (!isValidToken(token)) return null;
  return token;
}
