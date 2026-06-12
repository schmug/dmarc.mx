import type { Event } from "@sentry/cloudflare";
import { describe, expect, it } from "vitest";
import { scrubSentryEvent } from "../src/sentry-scrub.js";

function makeEvent(headers: Record<string, string>): Event {
  return { request: { headers } };
}

describe("scrubSentryEvent", () => {
  it("filters the credential headers dmarcheck receives", () => {
    const event = scrubSentryEvent(
      makeEvent({
        authorization: "Bearer dmk_abc123",
        cookie: "session=secret",
        "stripe-signature": "t=1,v1=abc",
        "cf-access-jwt-assertion": "eyJhbGciOi...",
      }),
    );
    expect(event.request?.headers).toEqual({
      authorization: "[Filtered]",
      cookie: "[Filtered]",
      "stripe-signature": "[Filtered]",
      "cf-access-jwt-assertion": "[Filtered]",
    });
  });

  it("matches header names case-insensitively", () => {
    const event = scrubSentryEvent(
      makeEvent({
        Authorization: "Bearer dmk_abc123",
        "CF-Access-Jwt-Assertion": "eyJhbGciOi...",
      }),
    );
    expect(event.request?.headers).toEqual({
      Authorization: "[Filtered]",
      "CF-Access-Jwt-Assertion": "[Filtered]",
    });
  });

  it("filters by sensitive snippet, not just exact names", () => {
    const event = scrubSentryEvent(
      makeEvent({
        "x-api-key": "dmk_abc123",
        "x-auth-token": "tok",
        "x-csrf-token": "tok",
      }),
    );
    expect(event.request?.headers).toEqual({
      "x-api-key": "[Filtered]",
      "x-auth-token": "[Filtered]",
      "x-csrf-token": "[Filtered]",
    });
  });

  it("leaves non-sensitive headers untouched", () => {
    const headers = {
      host: "dmarc.mx",
      "content-type": "application/json",
      "user-agent": "curl/8.0",
      accept: "text/html",
    };
    const event = scrubSentryEvent(makeEvent({ ...headers }));
    expect(event.request?.headers).toEqual(headers);
  });

  it("does not mutate the original headers object (shared scope data)", () => {
    const headers = { authorization: "Bearer dmk_abc123" };
    scrubSentryEvent(makeEvent(headers));
    expect(headers.authorization).toBe("Bearer dmk_abc123");
  });

  it("blanks parsed cookies when present", () => {
    const event: Event = {
      request: { cookies: { session: "secret", theme: "dark" } },
    };
    expect(scrubSentryEvent(event).request?.cookies).toEqual({
      filtered: "[Filtered]",
    });
  });

  it("returns events without request data unchanged", () => {
    const event: Event = { message: "boom" };
    expect(scrubSentryEvent(event)).toBe(event);
  });
});

describe("scrubSentryEvent — URL and query_string scrubbing", () => {
  it("masks token param in request.url", () => {
    const event = scrubSentryEvent({
      request: {
        url: "https://dmarc.mx/alerts/unsubscribe?token=abc123&domain=example.com",
      },
    } as Event);
    expect(event.request?.url).toBe(
      "https://dmarc.mx/alerts/unsubscribe?token=%5BFiltered%5D&domain=example.com",
    );
  });

  it("masks code and state params in auth callback URL", () => {
    const event = scrubSentryEvent({
      request: {
        url: "https://dmarc.mx/auth/callback?code=AUTHCODE&state=STATETOKEN&foo=bar",
      },
    } as Event);
    expect(event.request?.url).toBe(
      "https://dmarc.mx/auth/callback?code=%5BFiltered%5D&state=%5BFiltered%5D&foo=bar",
    );
  });

  it("leaves non-sensitive URL params unchanged", () => {
    const url = "https://dmarc.mx/check?domain=example.com&format=json";
    const event = scrubSentryEvent({ request: { url } } as Event);
    expect(event.request?.url).toBe(url);
  });

  it("does not throw on a malformed or relative URL, returns it unchanged", () => {
    const badUrl = "/relative/path?token=abc";
    const event = scrubSentryEvent({ request: { url: badUrl } } as Event);
    expect(event.request?.url).toBe(badUrl);
  });

  it("masks sensitive params in string query_string", () => {
    const event = scrubSentryEvent({
      request: {
        url: "https://dmarc.mx/alerts/unsubscribe?token=abc123&domain=example.com",
        query_string: "token=abc123&domain=example.com",
      },
    } as Event);
    expect(event.request?.query_string).toBe(
      "token=%5BFiltered%5D&domain=example.com",
    );
  });

  it("leaves non-sensitive query_string params unchanged", () => {
    const qs = "domain=example.com&format=json";
    const event = scrubSentryEvent({ request: { query_string: qs } } as Event);
    expect(event.request?.query_string).toBe(qs);
  });

  it("handles empty string query_string without throwing", () => {
    const event = scrubSentryEvent({
      request: { query_string: "" },
    } as Event);
    expect(event.request?.query_string).toBe("");
  });

  it("masks params case-insensitively (Token, CODE, STATE)", () => {
    const event = scrubSentryEvent({
      request: {
        url: "https://dmarc.mx/auth/callback?CODE=xyz&State=abc&domain=ex.com",
        query_string: "CODE=xyz&State=abc&domain=ex.com",
      },
    } as Event);
    expect(event.request?.url).toContain("CODE=%5BFiltered%5D");
    expect(event.request?.url).toContain("State=%5BFiltered%5D");
    expect(event.request?.url).toContain("domain=ex.com");
    expect(event.request?.query_string).toContain("CODE=%5BFiltered%5D");
    expect(event.request?.query_string).toContain("State=%5BFiltered%5D");
    expect(event.request?.query_string).toContain("domain=ex.com");
  });
});
