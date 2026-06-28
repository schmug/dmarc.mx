import { describe, expect, it } from "vitest";
import {
  generateToken,
  INBOX_DOMAIN,
  inboxAddress,
  isValidToken,
  tokenFromAddress,
} from "../src/inbox/tokens.js";

describe("inbox tokens — generateToken", () => {
  it("produces a 32-char lowercase-hex (128-bit) token", () => {
    const t = generateToken();
    expect(t).toMatch(/^[0-9a-f]{32}$/);
  });

  it("produces unique tokens across many draws", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) seen.add(generateToken());
    expect(seen.size).toBe(1000);
  });

  it("always validates its own output", () => {
    for (let i = 0; i < 50; i++) {
      expect(isValidToken(generateToken())).toBe(true);
    }
  });
});

describe("inbox tokens — isValidToken", () => {
  it("rejects wrong length / charset", () => {
    expect(isValidToken("")).toBe(false);
    expect(isValidToken("abc")).toBe(false);
    expect(isValidToken("g".repeat(32))).toBe(false); // non-hex
    expect(isValidToken("A".repeat(32))).toBe(false); // uppercase
    expect(isValidToken("a".repeat(31))).toBe(false); // too short
    expect(isValidToken("a".repeat(33))).toBe(false); // too long
    expect(isValidToken("../../etc/passwd")).toBe(false);
  });

  it("accepts a well-formed token", () => {
    expect(isValidToken("0123456789abcdef0123456789abcdef")).toBe(true);
  });
});

describe("inbox tokens — inboxAddress", () => {
  it("builds <token>@inbox.dmarc.mx", () => {
    const t = "0123456789abcdef0123456789abcdef";
    expect(inboxAddress(t)).toBe(`${t}@${INBOX_DOMAIN}`);
    expect(INBOX_DOMAIN).toBe("inbox.dmarc.mx");
  });
});

describe("inbox tokens — tokenFromAddress", () => {
  const token = "0123456789abcdef0123456789abcdef";

  it("extracts the token from a well-formed address", () => {
    expect(tokenFromAddress(`${token}@inbox.dmarc.mx`)).toBe(token);
  });

  it("is case-insensitive on the domain + uppercased token", () => {
    expect(tokenFromAddress(`${token.toUpperCase()}@INBOX.DMARC.MX`)).toBe(
      token,
    );
  });

  it("trims surrounding whitespace", () => {
    expect(tokenFromAddress(`  ${token}@inbox.dmarc.mx  `)).toBe(token);
  });

  it("rejects the apex domain (PhishSOC coexistence)", () => {
    expect(tokenFromAddress(`${token}@dmarc.mx`)).toBeNull();
  });

  it("rejects a different subdomain", () => {
    expect(tokenFromAddress(`${token}@scan.dmarc.mx`)).toBeNull();
    expect(tokenFromAddress(`${token}@inbox.evil.com`)).toBeNull();
  });

  it("rejects a non-token local part", () => {
    expect(tokenFromAddress("scan@inbox.dmarc.mx")).toBeNull();
    expect(tokenFromAddress("../x@inbox.dmarc.mx")).toBeNull();
  });

  it("rejects null / empty / malformed input", () => {
    expect(tokenFromAddress(null)).toBeNull();
    expect(tokenFromAddress(undefined)).toBeNull();
    expect(tokenFromAddress("")).toBeNull();
    expect(tokenFromAddress("no-at-sign")).toBeNull();
    expect(tokenFromAddress("@inbox.dmarc.mx")).toBeNull();
  });
});
