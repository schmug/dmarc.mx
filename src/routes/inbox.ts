import * as Sentry from "@sentry/cloudflare";
import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import type { BearerIdentity } from "../auth/api-key.js";
import type { Env } from "../env.js";
import {
  putPending,
  reserveLiveToken,
  streamInboxResult,
} from "../inbox/store.js";
import { generateToken, isValidToken } from "../inbox/tokens.js";
import { getClientIp } from "../shared/client.js";
import { renderError } from "../views/html.js";
import { renderInboxScanPage, renderInboxVerdict } from "../views/inbox.js";

export const inboxRoutes = new Hono<{ Bindings: Env }>();

inboxRoutes.get("/check/email", async (c) => {
  const kv = c.env?.INBOX_TOKENS;
  if (!kv) {
    return c.html(
      renderError("Test-email scanning isn't configured on this deployment."),
      503,
    );
  }

  // Reuse the rate-limit identity for the live-token cap. The middleware above
  // has already resolved + stashed any bearer; fall back to the client IP.
  const bearer =
    (c.get("bearer" as never) as BearerIdentity | undefined) ?? null;
  const identity = bearer ? `user:${bearer.userId}` : `ip:${getClientIp(c)}`;

  const token = generateToken();
  let reserved = false;
  try {
    reserved = await reserveLiveToken(
      kv,
      identity,
      token,
      undefined,
      c.env?.RATE_LIMITER,
    );
    if (reserved) {
      await putPending(kv, token);
    }
  } catch (err) {
    Sentry.captureException(err);
    return c.html(
      renderError("Couldn't allocate a test address. Please try again."),
      500,
    );
  }

  if (!reserved) {
    return c.html(
      renderError(
        "You have too many active test addresses. Wait for them to expire (30 minutes) before requesting another.",
      ),
      429,
    );
  }

  return c.html(renderInboxScanPage(token));
});

// Stream the verdict for a test-email token (issue #417). Mirrors
// /api/check/stream: emits a "waiting" state, polls KV server-side, pushes the
// parsed verdict when the message lands, then closes. An unknown/expired token
// yields a clean "closed" event — never a 500.
inboxRoutes.get("/api/check/email/stream", async (c) => {
  const token = c.req.query("token");
  if (!token || !isValidToken(token)) {
    return c.json({ error: "Missing or invalid token parameter" }, 400);
  }
  const kv = c.env?.INBOX_TOKENS;
  return streamSSE(c, async (stream) => {
    if (!kv) {
      await stream.writeSSE({
        event: "closed",
        data: JSON.stringify({ status: "unavailable" }),
      });
      return;
    }
    await streamInboxResult(stream, kv, token, {
      renderCard: renderInboxVerdict,
      rateLimiterNamespace: c.env?.RATE_LIMITER,
    });
  });
});
