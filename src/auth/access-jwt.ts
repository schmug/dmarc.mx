import type { Context, Next } from "hono";
import { getCookie } from "hono/cookie";
import {
  createRemoteJWKSet,
  type JWTPayload,
  type JWTVerifyGetKey,
  jwtVerify,
} from "jose";

// Cloudflare Access JWT validator for preview-branch deploys served on
// `*.workers.dev`. The production custom domain (`dmarc.mx`) is intentionally
// not protected by Access — public scanning is the whole product. This
// middleware exists so the preview URLs (which Cloudflare Access guards via a
// Self-Hosted application) cannot be reached out-of-band even if Access ever
// failed to attach to a hostname (defense-in-depth, not the primary control).
//
// Verification is delegated to `jose` — pinning `algorithms: ["RS256"]`
// closes the alg-confusion / `alg: none` foot-guns that hand-rolled JWT
// verification typically misses.

const jwksResolvers = new Map<string, JWTVerifyGetKey>();

function getJwksResolver(teamDomain: string): JWTVerifyGetKey {
  let resolver = jwksResolvers.get(teamDomain);
  if (!resolver) {
    resolver = createRemoteJWKSet(
      new URL(`https://${teamDomain}/cdn-cgi/access/certs`),
    );
    jwksResolvers.set(teamDomain, resolver);
  }
  return resolver;
}

export type VerifyFailReason =
  | "malformed"
  | "expired"
  | "bad_signature"
  | "bad_aud"
  | "bad_iss"
  | "unsupported_alg"
  | "jwks_unavailable"
  | "verify_error";

export type AccessVerifyResult =
  | { ok: true; payload: JWTPayload }
  | { ok: false; reason: VerifyFailReason };

export interface AccessVerifyOptions {
  aud: string;
  teamDomain: string;
  // Inject a JWKS resolver (e.g. `createLocalJWKSet`) for tests so we can
  // verify against an in-process keypair instead of fetching.
  jwks?: JWTVerifyGetKey;
}

interface JoseLikeError {
  code?: string;
  claim?: string;
}

function classifyError(err: unknown): VerifyFailReason {
  if (typeof err !== "object" || err === null) return "verify_error";
  const code = (err as JoseLikeError).code;
  switch (code) {
    case "ERR_JWT_EXPIRED":
      return "expired";
    case "ERR_JWS_SIGNATURE_VERIFICATION_FAILED":
    case "ERR_JWKS_NO_MATCHING_KEY":
    case "ERR_JWKS_MULTIPLE_MATCHING_KEYS":
      return "bad_signature";
    case "ERR_JOSE_ALG_NOT_ALLOWED":
      return "unsupported_alg";
    case "ERR_JWS_INVALID":
    case "ERR_JWT_INVALID":
    case "ERR_JWK_INVALID":
    case "ERR_JWKS_INVALID":
      return "malformed";
    case "ERR_JWKS_TIMEOUT":
      return "jwks_unavailable";
    case "ERR_JWT_CLAIM_VALIDATION_FAILED": {
      const claim = (err as JoseLikeError).claim;
      if (claim === "aud") return "bad_aud";
      if (claim === "iss") return "bad_iss";
      return "verify_error";
    }
    default:
      return "verify_error";
  }
}

export async function verifyAccessJwt(
  token: string,
  opts: AccessVerifyOptions,
): Promise<AccessVerifyResult> {
  const jwks = opts.jwks ?? getJwksResolver(opts.teamDomain);
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: `https://${opts.teamDomain}`,
      audience: opts.aud,
      algorithms: ["RS256"],
    });
    return { ok: true, payload };
  } catch (err) {
    return { ok: false, reason: classifyError(err) };
  }
}

export type VerifyFn = (
  token: string,
  opts: AccessVerifyOptions,
) => Promise<AccessVerifyResult>;

export interface AccessMiddlewareOptions {
  isProtectedHost?: (host: string) => boolean;
  verify?: VerifyFn;
}

// Normalise before comparing: a port (`x.workers.dev:443`) or trailing dot
// (`x.workers.dev.`) must not slip past the suffix check.
export function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/:\d*$/, "").replace(/\.+$/, "");
}

const defaultIsProtectedHost = (host: string) =>
  normalizeHost(host).endsWith(".workers.dev");

interface AccessEnv {
  ACCESS_AUD?: string;
  ACCESS_TEAM_DOMAIN?: string;
}

// Hono middleware. Passes through when the request hostname is not in the
// "preview deploy" set. On preview hostnames, requires a valid Cloudflare
// Access JWT (header `Cf-Access-Jwt-Assertion` first, then `CF_Authorization`
// cookie). When the hostname is preview-shaped but the env vars are missing,
// returns 503 — fail-CLOSED is the right default here, since the cost of
// silently serving unauthenticated requests on a workers.dev URL is much
// worse than a misconfigured preview being unreachable.
export function accessJwtMiddleware(options: AccessMiddlewareOptions = {}) {
  const isProtected = options.isProtectedHost ?? defaultIsProtectedHost;
  const verify = options.verify ?? verifyAccessJwt;

  return async (c: Context, next: Next) => {
    const host = (c.req.header("host") ?? "").toLowerCase();
    if (!isProtected(host)) {
      await next();
      return;
    }

    const env = c.env as AccessEnv;
    const aud = env.ACCESS_AUD;
    const teamDomain = env.ACCESS_TEAM_DOMAIN;
    if (!aud || !teamDomain) {
      return c.text(
        "Preview auth misconfigured: ACCESS_AUD and ACCESS_TEAM_DOMAIN must be set.",
        503,
      );
    }

    const token =
      c.req.header("Cf-Access-Jwt-Assertion") ??
      getCookie(c, "CF_Authorization");
    if (!token) {
      return c.text("Unauthorized: missing Access JWT", 401);
    }

    const result = await verify(token, { aud, teamDomain });
    if (!result.ok) {
      return c.text(`Unauthorized: ${result.reason}`, 401);
    }

    await next();
  };
}
