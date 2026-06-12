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
