import { Hono } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { createDomain } from "../db/domains.js";
import { createUser, getUserByEmail } from "../db/users.js";
import { createSessionToken, validateSessionToken } from "./session.js";

export const authRoutes = new Hono();

// ---- Re-auth proof helpers (exported for testing and dashboard routes) ----
// A proof is a short-lived HMAC-signed token minted immediately after a
// forced WorkOS re-login. The dashboard execute-delete handler validates it
// before performing the irreversible deletion. Server-side single-use nonce
// hardening is tracked in issue #553.

const REAUTH_PROOF_TTL_SECONDS = 10 * 60; // must complete deletion within 10 min
const REAUTH_STATE_SUFFIX = ":reauth_delete";
export const REAUTH_PROOF_COOKIE = "reauth_proof";

const _ENC = new TextEncoder();

function _b64url(data: Uint8Array | ArrayBuffer): string {
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function _unb64url(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const s = atob(padded);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

async function _reauthKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    _ENC.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export interface ReauthProofPayload {
  sub: string;
  purpose: string;
  iat: number;
  exp: number;
}

export async function createReauthProof(
  sub: string,
  purpose: string,
  secret: string,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: ReauthProofPayload = {
    sub,
    purpose,
    iat: now,
    exp: now + REAUTH_PROOF_TTL_SECONDS,
  };
  const enc = _b64url(_ENC.encode(JSON.stringify(payload)));
  const key = await _reauthKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, _ENC.encode(enc));
  return `${enc}.${_b64url(sig)}`;
}

export async function validateReauthProof(
  token: string,
  expectedSub: string,
  purpose: string,
  secret: string,
): Promise<ReauthProofPayload | null> {
  const dot = token.indexOf(".");
  if (dot < 1 || dot >= token.length - 1) return null;
  const enc = token.slice(0, dot);
  const sigStr = token.slice(dot + 1);
  let valid: boolean;
  try {
    const key = await _reauthKey(secret);
    valid = await crypto.subtle.verify(
      "HMAC",
      key,
      _unb64url(sigStr),
      _ENC.encode(enc),
    );
  } catch {
    return null;
  }
  if (!valid) return null;
  let payload: ReauthProofPayload;
  try {
    payload = JSON.parse(
      new TextDecoder().decode(_unb64url(enc)),
    ) as ReauthProofPayload;
  } catch {
    return null;
  }
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;
  if (payload.sub !== expectedSub) return null;
  if (payload.purpose !== purpose) return null;
  return payload;
}

// ---- Auth routes ----

authRoutes.get("/login", (c) => {
  const env = c.env as {
    WORKOS_CLIENT_ID: string;
    WORKOS_REDIRECT_URI: string;
  };
  const state = crypto.randomUUID();
  setCookie(c, "oauth_state", state, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: 10 * 60, // 10 minutes
  });
  const params = new URLSearchParams({
    client_id: env.WORKOS_CLIENT_ID,
    redirect_uri: env.WORKOS_REDIRECT_URI,
    response_type: "code",
    provider: "authkit",
    state,
  });
  return c.redirect(
    `https://api.workos.com/user_management/authorize?${params}`,
  );
});

// Step-up re-authentication for destructive actions. Forces a fresh WorkOS
// login via `prompt=login` and carries a delete intent in the OAuth state so
// the callback mints a short-lived proof instead of creating a new session.
authRoutes.get("/reauth", async (c) => {
  const env = c.env as {
    SESSION_SECRET: string;
    WORKOS_CLIENT_ID: string;
    WORKOS_REDIRECT_URI: string;
  };
  // Only allow re-auth for already-authenticated users.
  const sessionToken = getCookie(c, "session");
  const session = sessionToken
    ? await validateSessionToken(sessionToken, env.SESSION_SECRET)
    : null;
  if (!session) {
    return c.redirect("/auth/login");
  }
  const nonce = crypto.randomUUID();
  const state = `${nonce}${REAUTH_STATE_SUFFIX}`;
  setCookie(c, "oauth_state", state, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: 10 * 60,
  });
  const params = new URLSearchParams({
    client_id: env.WORKOS_CLIENT_ID,
    redirect_uri: env.WORKOS_REDIRECT_URI,
    response_type: "code",
    provider: "authkit",
    prompt: "login",
    state,
  });
  return c.redirect(
    `https://api.workos.com/user_management/authorize?${params}`,
  );
});

authRoutes.get("/callback", async (c) => {
  const code = c.req.query("code");
  if (!code) {
    return c.text("Missing authorization code", 400);
  }

  const queryState = c.req.query("state");
  const cookieState = getCookie(c, "oauth_state");

  if (!queryState || !cookieState || queryState !== cookieState) {
    return c.text("Invalid or missing state parameter", 400);
  }

  const isReauth = cookieState.endsWith(REAUTH_STATE_SUFFIX);

  // Clear the state cookie after successful validation
  deleteCookie(c, "oauth_state", { path: "/" });

  const env = c.env as {
    WORKOS_CLIENT_ID: string;
    WORKOS_CLIENT_SECRET: string;
    SESSION_SECRET: string;
    DB: D1Database;
  };

  // Exchange code for user info
  const tokenRes = await fetch(
    "https://api.workos.com/user_management/authenticate",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        client_id: env.WORKOS_CLIENT_ID,
        client_secret: env.WORKOS_CLIENT_SECRET,
        grant_type: "authorization_code",
      }),
    },
  );

  if (!tokenRes.ok) {
    return c.text("Authentication failed", 401);
  }

  const data = (await tokenRes.json()) as {
    user: { id: string; email: string };
  };
  const { id, email } = data.user;

  if (isReauth) {
    // Step-up re-auth for account deletion. The re-authing user must match
    // the existing session subject; a mismatched id would indicate a
    // different account was used for the re-login, which we refuse.
    const sessionToken = getCookie(c, "session");
    const existingSession = sessionToken
      ? await validateSessionToken(sessionToken, env.SESSION_SECRET)
      : null;
    if (!existingSession || existingSession.sub !== id) {
      return c.text("Re-authentication failed: user mismatch", 400);
    }
    const proof = await createReauthProof(
      id,
      "account_delete",
      env.SESSION_SECRET,
    );
    setCookie(c, REAUTH_PROOF_COOKIE, proof, {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      path: "/dashboard/account",
      maxAge: REAUTH_PROOF_TTL_SECONDS,
    });
    return c.redirect("/dashboard/account/delete/execute");
  }

  // Create or find user (handle race condition on duplicate signups)
  let user = await getUserByEmail(env.DB, email);
  if (!user) {
    try {
      await createUser(env.DB, { id, email });
      // Auto-provision free domain from email
      const emailDomain = email.split("@")[1];
      await createDomain(env.DB, {
        userId: id,
        domain: emailDomain,
        isFree: true,
      });
    } catch {
      // Unique constraint violation — user was created by a concurrent request
    }
    user = await getUserByEmail(env.DB, email);
    if (!user) {
      return c.text("Account creation failed", 500);
    }
  }

  // Create session
  const token = await createSessionToken(
    { sub: user.id, email: user.email },
    env.SESSION_SECRET,
  );

  setCookie(c, "session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: 7 * 24 * 60 * 60, // 7 days
  });

  return c.redirect("/dashboard");
});

authRoutes.get("/logout", (c) => {
  deleteCookie(c, "session", { path: "/" });
  return c.redirect("/");
});
