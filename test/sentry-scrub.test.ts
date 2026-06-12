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

  describe("sensitive query params", () => {
    it("masks the unsubscribe token value in request.url", () => {
      const event: Event = {
        request: { url: "https://dmarc.mx/email/unsubscribe?token=abc123" },
      };
      expect(scrubSentryEvent(event).request?.url).toBe(
        "https://dmarc.mx/email/unsubscribe?token=[Filtered]",
      );
    });

    it("masks code and state in both url and query_string", () => {
      const event: Event = {
        request: {
          url: "https://dmarc.mx/auth/callback?code=authcode123&state=st456",
          query_string: "code=authcode123&state=st456",
        },
      };
      const scrubbed = scrubSentryEvent(event);
      expect(scrubbed.request?.url).toBe(
        "https://dmarc.mx/auth/callback?code=[Filtered]&state=[Filtered]",
      );
      expect(scrubbed.request?.query_string).toBe(
        "code=[Filtered]&state=[Filtered]",
      );
    });

    it("matches param names case-insensitively", () => {
      const event: Event = {
        request: { query_string: "TOKEN=abc&Code=def&State=ghi" },
      };
      expect(scrubSentryEvent(event).request?.query_string).toBe(
        "TOKEN=[Filtered]&Code=[Filtered]&State=[Filtered]",
      );
    });

    it("masks params whose names contain a sensitive header snippet", () => {
      const event: Event = {
        request: {
          query_string: "api_key=dmk_abc&session_id=s1&signature=sig",
        },
      };
      expect(scrubSentryEvent(event).request?.query_string).toBe(
        "api_key=[Filtered]&session_id=[Filtered]&signature=[Filtered]",
      );
    });

    it("leaves non-sensitive params unchanged alongside masked ones", () => {
      const event: Event = {
        request: {
          url: "https://dmarc.mx/check?domain=example.com&format=json&selectors=s1.s2&token=tok",
          query_string:
            "domain=example.com&format=json&selectors=s1.s2&token=tok",
        },
      };
      const scrubbed = scrubSentryEvent(event);
      expect(scrubbed.request?.url).toBe(
        "https://dmarc.mx/check?domain=example.com&format=json&selectors=s1.s2&token=[Filtered]",
      );
      expect(scrubbed.request?.query_string).toBe(
        "domain=example.com&format=json&selectors=s1.s2&token=[Filtered]",
      );
    });

    it("returns a relative or malformed url unchanged without throwing", () => {
      const relative: Event = {
        request: { url: "/email/unsubscribe?token=abc" },
      };
      expect(scrubSentryEvent(relative).request?.url).toBe(
        "/email/unsubscribe?token=abc",
      );
      const malformed: Event = { request: { url: "http://[bad" } };
      expect(scrubSentryEvent(malformed).request?.url).toBe("http://[bad");
    });

    it("returns an empty query_string and a query-less url unchanged", () => {
      const event: Event = {
        request: { url: "https://dmarc.mx/check", query_string: "" },
      };
      const scrubbed = scrubSentryEvent(event);
      expect(scrubbed.request?.url).toBe("https://dmarc.mx/check");
      expect(scrubbed.request?.query_string).toBe("");
    });
  });
});
