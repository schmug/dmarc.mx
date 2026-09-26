import { beforeEach, describe, expect, it } from "vitest";
import { app } from "../src/index.js";
import { _memoryStore, _resetCallCount } from "../src/rate-limit.js";

// GHSA-j7p5-95v7-29v9: Hono runs matched handlers in registration order, and
// `app.route("/", sub)` copies the sub-router's handlers into `app` at the
// point it is called. A sub-router mounted above the rate-limit `app.use()`
// block answers the request before the limiter runs (#751 / #761 did this to
// /mcp, /check/email and /api/check/email/stream). This table drives the real
// exported `app` past the free-tier ceiling on every path the limiter block
// meters, so moving any of these routes into a sub-router mounted above the
// block fails here.
//
// Every request is chosen to exit its handler early (missing domain, missing
// bearer, unparseable JSON, no KV) so the test never scans. The env is empty,
// so the limiter uses its in-memory fallback.

const FREE_LIMIT = 10;
const SCAN_BLOCKED = "Please wait a minute before scanning again.";
const JSON_BLOCKED = "Rate limit exceeded. Try again in";

interface LimitedRoute {
  pattern: string; // the path argument of the limiter's app.use()
  method: "GET" | "POST";
  url: string;
  body?: string;
  blockedType: string; // content-type of that route's 429 responder
  blockedBody: string; // text only the limiter's 429 responder emits
}

const LIMITED_ROUTES: LimitedRoute[] = [
  {
    pattern: "/check",
    method: "GET",
    url: "/check",
    blockedType: "text/html",
    blockedBody: SCAN_BLOCKED,
  },
  {
    pattern: "/check/score",
    method: "GET",
    url: "/check/score",
    blockedType: "text/html",
    blockedBody: SCAN_BLOCKED,
  },
  // With no INBOX_TOKENS binding the handler answers 503 before it reaches the
  // 5-live-token cap, so a 429 here can only come from the rate limiter.
  {
    pattern: "/check/email",
    method: "GET",
    url: "/check/email",
    blockedType: "text/html",
    blockedBody: "before requesting another test address",
  },
  {
    pattern: "/api/check",
    method: "GET",
    url: "/api/check",
    blockedType: "application/json",
    blockedBody: JSON_BLOCKED,
  },
  {
    pattern: "/api/bulk-scan",
    method: "POST",
    url: "/api/bulk-scan",
    body: "{}",
    blockedType: "application/json",
    blockedBody: JSON_BLOCKED,
  },
  {
    pattern: "/api/domain/*",
    method: "GET",
    url: "/api/domain/example.com/history",
    blockedType: "application/json",
    blockedBody: JSON_BLOCKED,
  },
  {
    pattern: "/api/check/stream",
    method: "GET",
    url: "/api/check/stream",
    blockedType: "application/json",
    blockedBody: JSON_BLOCKED,
  },
  {
    pattern: "/api/check/email/stream",
    method: "GET",
    url: "/api/check/email/stream",
    blockedType: "application/json",
    blockedBody: JSON_BLOCKED,
  },
  {
    pattern: "/badge",
    method: "GET",
    url: "/badge",
    blockedType: "image/svg+xml",
    blockedBody: "rate limited",
  },
  {
    pattern: "/mcp",
    method: "POST",
    url: "/mcp",
    body: "{",
    blockedType: "application/json",
    blockedBody: JSON_BLOCKED,
  },
];

beforeEach(() => {
  _memoryStore.clear();
  _resetCallCount();
});

describe("rate limiter covers every metered path on the exported app", () => {
  it.each(
    LIMITED_ROUTES,
  )("$method $url (limiter $pattern) answers 429 on request ceiling+1", async (route) => {
    const headers: Record<string, string> = {
      "CF-Connecting-IP": "198.51.100.23",
    };
    if (route.body !== undefined) headers["Content-Type"] = "application/json";

    const responses: Response[] = [];
    for (let i = 0; i <= FREE_LIMIT; i++) {
      responses.push(
        await app.request(
          route.url,
          { method: route.method, headers, body: route.body },
          {},
        ),
      );
    }
    const statuses = responses.map((r) => r.status);

    expect(
      statuses.slice(0, FREE_LIMIT),
      `statuses: ${statuses}`,
    ).not.toContain(429);
    expect(statuses[FREE_LIMIT], `statuses: ${statuses}`).toBe(429);

    const blocked = responses[FREE_LIMIT];
    expect(blocked.headers.get("X-RateLimit-Limit")).toBe(String(FREE_LIMIT));
    expect(blocked.headers.get("X-RateLimit-Remaining")).toBe("0");
    expect(blocked.headers.get("X-RateLimit-Window")).toBe("60s");
    expect(blocked.headers.get("Content-Type")).toContain(route.blockedType);
    expect(await blocked.text()).toContain(route.blockedBody);
  });
});
