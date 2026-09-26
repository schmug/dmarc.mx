import * as Sentry from "@sentry/cloudflare";
import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import { streamSSE } from "hono/streaming";
import type { BearerIdentity } from "../auth/api-key.js";
import { validateSessionToken } from "../auth/session.js";
import { type Domain, getDomainsByUser } from "../db/domains.js";
import type { Env } from "../env.js";
import {
  putPending,
  reserveLiveToken,
  streamInboxResult,
  type VerdictRecord,
} from "../inbox/store.js";
import { generateToken, isValidToken } from "../inbox/tokens.js";
import { getClientIp } from "../shared/client.js";
import { renderError } from "../views/html.js";
import {
  type InboxSaveSelectorTarget,
  renderInboxScanPage,
  renderInboxVerdict,
} from "../views/inbox.js";

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

// Relaxed-ish domain alignment: exact match or a parent/child relationship.
// Mirrors the private helper of the same name in src/inbox/store.ts (kept
// local here rather than exported/shared, since #867's scope doesn't touch
// store.ts).
function domainsAlign(a: string, b: string): boolean {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  return x === y || x.endsWith(`.${y}`) || y.endsWith(`.${x}`);
}

// Resolves the "save selector to domain" button target (issue #867): only
// when the verdict's DKIM signature passed AND aligns (exact or parent/child)
// with one of the signed-in viewer's watched domains. Anonymous viewers pass
// an empty `userDomains`, so this always returns null for them.
function resolveSaveTarget(
  rec: VerdictRecord,
  token: string,
  userDomains: Domain[],
): InboxSaveSelectorTarget | null {
  if (rec.dkim !== "pass" || !rec.dkim_selector || !rec.dkim_domain) {
    return null;
  }
  const dkimDomain = rec.dkim_domain;
  const match = userDomains.find((d) => domainsAlign(dkimDomain, d.domain));
  return match ? { token, domainId: match.id, domain: match.domain } : null;
}

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

  // Resolve the viewer's identity once, up front — it can't change over the
  // life of one SSE connection. Anonymous visitors (no/invalid session) get
  // an empty domain list, so resolveSaveTarget always yields null for them.
  let userDomains: Domain[] = [];
  const sessionCookie = getCookie(c, "session");
  if (sessionCookie && c.env?.SESSION_SECRET && c.env?.DB) {
    const session = await validateSessionToken(
      sessionCookie,
      c.env.SESSION_SECRET,
    );
    if (session) {
      userDomains = await getDomainsByUser(c.env.DB, session.sub);
    }
  }

  return streamSSE(c, async (stream) => {
    if (!kv) {
      await stream.writeSSE({
        event: "closed",
        data: JSON.stringify({ status: "unavailable" }),
      });
      return;
    }
    await streamInboxResult(stream, kv, token, {
      renderCard: (rec) =>
        renderInboxVerdict(rec, resolveSaveTarget(rec, token, userDomains)),
      rateLimiterNamespace: c.env?.RATE_LIMITER,
    });
  });
});
