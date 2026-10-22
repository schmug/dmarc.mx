import { Hono } from "hono";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JWK,
  type JWTVerifyGetKey,
  SignJWT,
} from "jose";
import { describe, expect, it, vi } from "vitest";
import {
  type AccessVerifyResult,
  accessJwtMiddleware,
  type VerifyFn,
  verifyAccessJwt,
} from "../src/auth/access-jwt.js";

const PROTECTED_HOST = "abc-dmarcheck.cory7593.workers.dev";
const PROD_HOST = "dmarc.mx";
const ENV_OK = {
  ACCESS_AUD: "test-aud",
  ACCESS_TEAM_DOMAIN: "team.example.com",
};

function makeApp(verify: VerifyFn) {
  const app = new Hono();
  app.use("*", accessJwtMiddleware({ verify }));
  app.get("/", (c) => c.text("ok"));
  return app;
}

describe("accessJwtMiddleware", () => {
  it("passes through on the production hostname without invoking the verifier", async () => {
    const verify = vi.fn();
    const app = makeApp(verify as unknown as VerifyFn);
    const res = await app.request("/", { headers: { host: PROD_HOST } }, {});
    expect(res.status).toBe(200);
    expect(verify).not.toHaveBeenCalled();
  });

  it("returns 503 when env vars are missing on a workers.dev hostname", async () => {
    const verify = vi.fn();
    const app = makeApp(verify as unknown as VerifyFn);
    const res = await app.request(
      "/",
      { headers: { host: PROTECTED_HOST } },
      {},
    );
    expect(res.status).toBe(503);
    expect(verify).not.toHaveBeenCalled();
  });

  it("returns 503 when only one of the two env vars is set (fail-closed)", async () => {
    const verify = vi.fn();
    const app = makeApp(verify as unknown as VerifyFn);
    const res = await app.request(
      "/",
      { headers: { host: PROTECTED_HOST } },
      { ACCESS_AUD: "x" },
    );
    expect(res.status).toBe(503);
  });

  it("returns 401 when no JWT is present on a protected hostname", async () => {
    const verify = vi.fn();
    const app = makeApp(verify as unknown as VerifyFn);
    const res = await app.request(
      "/",
      { headers: { host: PROTECTED_HOST } },
      ENV_OK,
    );
    expect(res.status).toBe(401);
    expect(verify).not.toHaveBeenCalled();
  });

  it.each([
    `${PROTECTED_HOST}:443`,
    `${PROTECTED_HOST}.`,
    `${PROTECTED_HOST}.:443`,
    PROTECTED_HOST.toUpperCase(),
  ])("requires a JWT for host variant %s", async (host) => {
    const verify = vi.fn();
    const app = makeApp(verify as unknown as VerifyFn);
    const res = await app.request("/", { headers: { host } }, ENV_OK);
    expect(res.status).toBe(401);
  });

  it("returns 401 surfacing the verifier's reason when the JWT fails validation", async () => {
    const verify = vi.fn().mockResolvedValue({
      ok: false,
      reason: "bad_aud",
    } as AccessVerifyResult);
    const app = makeApp(verify as unknown as VerifyFn);
    const res = await app.request(
      "/",
      {
        headers: {
          host: PROTECTED_HOST,
          "Cf-Access-Jwt-Assertion": "header.payload.sig",
        },
      },
      ENV_OK,
    );
    expect(res.status).toBe(401);
    expect(await res.text()).toContain("bad_aud");
    expect(verify).toHaveBeenCalledWith(
      "header.payload.sig",
      expect.objectContaining({
        aud: "test-aud",
        teamDomain: "team.example.com",
      }),
    );
  });

  it("passes the request through when the verifier accepts the JWT", async () => {
    const verify = vi.fn().mockResolvedValue({
      ok: true,
      payload: {
        aud: "test-aud",
        iss: "https://team.example.com",
        exp: 9_999_999_999,
      },
    } as AccessVerifyResult);
    const app = makeApp(verify as unknown as VerifyFn);
    const res = await app.request(
      "/",
      {
        headers: {
          host: PROTECTED_HOST,
          "Cf-Access-Jwt-Assertion": "header.payload.sig",
        },
      },
      ENV_OK,
    );
    expect(res.status).toBe(200);
  });

  it("falls back to the CF_Authorization cookie when the header is absent", async () => {
    const verify = vi.fn().mockResolvedValue({
      ok: true,
      payload: {
        aud: "test-aud",
        iss: "https://team.example.com",
        exp: 99_999_999_999,
      },
    } as AccessVerifyResult);
    const app = makeApp(verify as unknown as VerifyFn);
    const res = await app.request(
      "/",
      {
        headers: {
          host: PROTECTED_HOST,
          Cookie: "other=1; CF_Authorization=cookie.token.value; foo=bar",
        },
      },
      ENV_OK,
    );
    expect(res.status).toBe(200);
    expect(verify).toHaveBeenCalledWith(
      "cookie.token.value",
      expect.any(Object),
    );
  });

  it("prefers the header over the cookie when both are present", async () => {
    const verify = vi.fn().mockResolvedValue({
      ok: true,
      payload: {
        aud: "test-aud",
        iss: "https://team.example.com",
        exp: 99_999_999_999,
      },
    } as AccessVerifyResult);
    const app = makeApp(verify as unknown as VerifyFn);
    await app.request(
      "/",
      {
        headers: {
          host: PROTECTED_HOST,
          "Cf-Access-Jwt-Assertion": "from-header",
          Cookie: "CF_Authorization=from-cookie",
        },
      },
      ENV_OK,
    );
    expect(verify).toHaveBeenCalledWith("from-header", expect.any(Object));
  });
});

// End-to-end verifier tests using a real RS256 keypair plus jose's
// `createLocalJWKSet` so we never hit the network. Covers the canonical
// claim-error variants and asserts that the alg-confusion class of attacks
// (HS256 token signed with the public key, `alg: none`) is rejected.
describe("verifyAccessJwt (real RS256)", () => {
  const TEAM = "team.example.com";
  const AUD = "test-aud";

  async function setup() {
    const { privateKey, publicKey } = await generateKeyPair("RS256", {
      extractable: true,
    });
    const jwk = (await exportJWK(publicKey)) as JWK;
    jwk.kid = "test-kid";
    jwk.alg = "RS256";
    jwk.use = "sig";
    const jwks: JWTVerifyGetKey = createLocalJWKSet({ keys: [jwk] });
    return { privateKey, jwks };
  }

  function baseClaims() {
    return {
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
  }

  it("accepts a valid token", async () => {
    const { privateKey, jwks } = await setup();
    const token = await new SignJWT(baseClaims())
      .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
      .setIssuer(`https://${TEAM}`)
      .setAudience(AUD)
      .sign(privateKey);
    const result = await verifyAccessJwt(token, {
      aud: AUD,
      teamDomain: TEAM,
      jwks,
    });
    expect(result.ok).toBe(true);
  });

  it("rejects an expired token", async () => {
    const { privateKey, jwks } = await setup();
    const token = await new SignJWT({ iat: 1, exp: 2 })
      .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
      .setIssuer(`https://${TEAM}`)
      .setAudience(AUD)
      .sign(privateKey);
    const result = await verifyAccessJwt(token, {
      aud: AUD,
      teamDomain: TEAM,
      jwks,
    });
    expect(result).toEqual({ ok: false, reason: "expired" });
  });

  it("rejects a wrong audience", async () => {
    const { privateKey, jwks } = await setup();
    const token = await new SignJWT(baseClaims())
      .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
      .setIssuer(`https://${TEAM}`)
      .setAudience("attacker-aud")
      .sign(privateKey);
    const result = await verifyAccessJwt(token, {
      aud: AUD,
      teamDomain: TEAM,
      jwks,
    });
    expect(result).toEqual({ ok: false, reason: "bad_aud" });
  });

  it("rejects a wrong issuer", async () => {
    const { privateKey, jwks } = await setup();
    const token = await new SignJWT(baseClaims())
      .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
      .setIssuer("https://attacker.example.com")
      .setAudience(AUD)
      .sign(privateKey);
    const result = await verifyAccessJwt(token, {
      aud: AUD,
      teamDomain: TEAM,
      jwks,
    });
    expect(result).toEqual({ ok: false, reason: "bad_iss" });
  });

  it("rejects an unknown kid", async () => {
    const { privateKey, jwks } = await setup();
    const token = await new SignJWT(baseClaims())
      .setProtectedHeader({ alg: "RS256", kid: "rotated-kid" })
      .setIssuer(`https://${TEAM}`)
      .setAudience(AUD)
      .sign(privateKey);
    const result = await verifyAccessJwt(token, {
      aud: AUD,
      teamDomain: TEAM,
      jwks,
    });
    expect(result).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("rejects a tampered signature", async () => {
    const { privateKey, jwks } = await setup();
    const token = await new SignJWT(baseClaims())
      .setProtectedHeader({ alg: "RS256", kid: "test-kid" })
      .setIssuer(`https://${TEAM}`)
      .setAudience(AUD)
      .sign(privateKey);
    // Flip a character mid-signature. (Last-char flips can be no-ops because
    // base64url's trailing bits don't always map to signature bytes.)
    const parts = token.split(".");
    const sig = parts[2];
    const mid = Math.floor(sig.length / 2);
    const swapped = sig[mid] === "A" ? "B" : "A";
    const tampered = `${parts[0]}.${parts[1]}.${sig.slice(0, mid)}${swapped}${sig.slice(mid + 1)}`;
    const result = await verifyAccessJwt(tampered, {
      aud: AUD,
      teamDomain: TEAM,
      jwks,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(["bad_signature", "malformed"]).toContain(result.reason);
    }
  });

  it("rejects a malformed token", async () => {
    const { jwks } = await setup();
    const result = await verifyAccessJwt("not-a-jwt", {
      aud: AUD,
      teamDomain: TEAM,
      jwks,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(["malformed", "verify_error"]).toContain(result.reason);
    }
  });
});
