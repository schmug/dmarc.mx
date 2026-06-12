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

// Query params whose exact (lowercased) name is sensitive even though it
// contains no header snippet: the unsubscribe HMAC (?token= is snippet-covered,
// but listed for clarity) and the WorkOS callback's ?code= / ?state=.
const SENSITIVE_PARAM_NAMES = ["token", "code", "state"];

function isSensitiveParamName(name: string): boolean {
  const lowerName = name.toLowerCase();
  return (
    SENSITIVE_PARAM_NAMES.includes(lowerName) ||
    SENSITIVE_HEADER_SNIPPETS.some((s) => lowerName.includes(s))
  );
}

// Masks sensitive param values in a raw query string (no leading "?"),
// preserving param names and the original encoding of everything else.
function maskQueryString(query: string): string {
  if (!query) return query;
  return query
    .split("&")
    .map((pair) => {
      const eq = pair.indexOf("=");
      if (eq === -1) return pair;
      const name = pair.slice(0, eq);
      return isSensitiveParamName(name) ? `${name}=[Filtered]` : pair;
    })
    .join("&");
}

function maskUrl(url: string): string {
  try {
    // Parseability check only — a relative or malformed URL is returned
    // as-is rather than risking a throw inside a beforeSend* hook (which
    // would drop the event). String surgery below avoids URL re-encoding.
    new URL(url);
  } catch {
    return url;
  }
  const queryStart = url.indexOf("?");
  if (queryStart === -1) return url;
  const prefix = url.slice(0, queryStart + 1);
  return prefix + maskQueryString(url.slice(queryStart + 1));
}

// Scrubs credentials from an outgoing Sentry event. Must be registered as BOTH
// `beforeSend` and `beforeSendTransaction`: beforeSend only runs for error
// events, while the SDK's requestDataIntegration attaches request headers,
// the full request URL, and the query string to transaction events too
// (~30% of requests via tracesSampler).
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
  if (typeof event.request?.url === "string") {
    event.request.url = maskUrl(event.request.url);
  }
  if (typeof event.request?.query_string === "string") {
    event.request.query_string = maskQueryString(event.request.query_string);
  }
  return event;
}
