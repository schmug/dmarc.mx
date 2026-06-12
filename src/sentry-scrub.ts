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

// OAuth callback params not matched by SENSITIVE_HEADER_SNIPPETS but sensitive
// when they appear in request URLs (code is single-use; state carries CSRF token).
const SENSITIVE_PARAM_EXACT = new Set(["code", "state"]);

function isSensitiveParam(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    SENSITIVE_PARAM_EXACT.has(lower) ||
    SENSITIVE_HEADER_SNIPPETS.some((s) => lower.includes(s))
  );
}

function scrubQueryString(qs: string): string {
  if (!qs) return qs;
  const params = new URLSearchParams(qs);
  let changed = false;
  for (const key of [...params.keys()]) {
    if (isSensitiveParam(key)) {
      params.set(key, "[Filtered]");
      changed = true;
    }
  }
  return changed ? params.toString() : qs;
}

function scrubUrlString(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return raw;
  }
  let changed = false;
  for (const key of [...parsed.searchParams.keys()]) {
    if (isSensitiveParam(key)) {
      parsed.searchParams.set(key, "[Filtered]");
      changed = true;
    }
  }
  return changed ? parsed.toString() : raw;
}

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
  if (event.request?.url) {
    event.request.url = scrubUrlString(event.request.url);
  }
  if (event.request?.query_string !== undefined) {
    const qs = event.request.query_string;
    if (typeof qs === "string") {
      event.request.query_string = scrubQueryString(qs);
    } else if (Array.isArray(qs)) {
      event.request.query_string = (qs as [string, string][]).map(
        ([k, v]): [string, string] => [
          k,
          isSensitiveParam(k) ? "[Filtered]" : v,
        ],
      );
    } else if (qs !== null && typeof qs === "object") {
      const result: Record<string, string> = {};
      for (const [k, v] of Object.entries(qs)) {
        result[k] = isSensitiveParam(k) ? "[Filtered]" : v;
      }
      event.request.query_string = result;
    }
  }
  return event;
}
