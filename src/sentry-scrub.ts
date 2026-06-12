import type { Event } from "@sentry/cloudflare";

// Header-name snippets treated as sensitive, mirroring @sentry/core's
// SENSITIVE_HEADER_SNIPPETS (which the SDK only applies to span attributes,
// not to event.request.headers) plus "signature" for stripe-signature.
// Snippet matching (not exact names) is deliberate: it covers authorization,
// cookie, stripe-signature, cf-access-jwt-assertion (the Access credential on
// preview deploys), and any future *-token / *-key header without a code change.
const SENSITIVE_HEADER_SNIPPETS = [
  "auth",
  "token",
  "secret",
  "session",
  "password",
  "passwd",
  "pwd",
  "key",
  "jwt",
  "bearer",
  "sso",
  "saml",
  "csrf",
  "xsrf",
  "credentials",
  "signature",
  "cookie",
];

// Scrubs credentials from an outgoing Sentry event. Must be registered as BOTH
// `beforeSend` and `beforeSendTransaction`: beforeSend only runs for error
// events, while the SDK's requestDataIntegration attaches request headers to
// transaction events too (~30% of requests via tracesSampler).
export function scrubSentryEvent<E extends Event>(event: E): E {
  if (event.request?.headers) {
    // Copy before writing — the headers object is shared scope metadata.
    const scrubbed: Record<string, string> = { ...event.request.headers };
    for (const key of Object.keys(scrubbed)) {
      const lowerKey = key.toLowerCase();
      if (SENSITIVE_HEADER_SNIPPETS.some((s) => lowerKey.includes(s))) {
        scrubbed[key] = "[Filtered]";
      }
    }
    event.request.headers = scrubbed;
  }
  if (event.request?.cookies) {
    event.request.cookies = { filtered: "[Filtered]" };
  }
  return event;
}
