import { queryTxt } from "../dns/client.js";
import { parseTags } from "../shared/parse-tags.js";
import type { DkimResult, DkimSelectorResult, Validation } from "./types.js";

const COMMON_SELECTORS = [
  "google",
  "selector1",
  "selector2",
  "default",
  "dkim",
  "s1",
  "s2",
  "k1",
  "k2",
  "k3",
  "mail",
  "email",
  "pm",
  "protonmail",
  "protonmail2",
  "protonmail3",
  "fm1",
  "fm2",
  "fm3",
  "mandrill",
  "mxvault",
  "smtp",
  "cm",
  "amazonses",
  "ses",
  "everlytickey1",
  "everlytickey2",
  "dkim1",
  "dkim2",
  "mailo",
  "postmark",
  "turbo-smtp",
  "cf2024-1",
  "cf2024-2",
  "cf2025-1",
  "cf2025-2",
];

const PROVIDER_SELECTORS: Record<string, string[]> = {
  "Google Workspace": ["google"],
  "Microsoft 365": ["selector1", "selector2"],
  "Proton Mail": ["protonmail", "protonmail2", "protonmail3"],
  "Zoho Mail": ["default"],
  Fastmail: ["fm1", "fm2", "fm3"],
  "Rackspace Email": ["mail"],
};

export async function analyzeDkim(
  domain: string,
  customSelectors: string[] = [],
  providerNames: string[] = [],
): Promise<DkimResult> {
  const unique = [...new Set([...COMMON_SELECTORS, ...customSelectors])];
  const prioritized = providerNames.flatMap(
    (name) => PROVIDER_SELECTORS[name] ?? [],
  );
  const prioritySet = new Set(prioritized);
  const allSelectors = [
    ...prioritized.filter((s) => unique.includes(s)),
    ...unique.filter((s) => !prioritySet.has(s)),
  ];

  const results = await Promise.allSettled(
    allSelectors.map((sel) => probeSelector(domain, sel)),
  );

  const selectors: Record<string, DkimSelectorResult> = {};
  for (let i = 0; i < allSelectors.length; i++) {
    const result = results[i];
    if (result.status === "fulfilled") {
      selectors[allSelectors[i]] = result.value;
    } else {
      selectors[allSelectors[i]] = { found: false };
    }
  }

  // ⚡ Bolt Optimization: Use for...in instead of Object.entries().filter().map()
  // Avoids allocating multiple intermediate arrays (found, weakKeys, revoked, testing)
  // which reduces GC pressure on this hot path.
  let foundCount = 0;
  const weakKeyNames: string[] = [];
  const ed25519Names: string[] = [];
  const revokedNames: string[] = [];
  const testingNames: string[] = [];
  const ed25519Names: string[] = [];

  for (const name in selectors) {
    const v = selectors[name];
    if (v.found) {
      foundCount++;
      if (v.key_type === "ed25519") {
        ed25519Names.push(name);
      } else if (v.key_bits && v.key_bits < 2048) {
        weakKeyNames.push(name);
      }
      if (v.revoked) revokedNames.push(name);
      if (v.testing) testingNames.push(name);
      // Ed25519 keys (RFC 8463) are fixed-size and have no RSA bit length, so
      // they bypass the weak-key check; recognize them explicitly as modern.
      if (!v.revoked && v.key_type === "ed25519") ed25519Names.push(name);
    }
  }

  const validations: Validation[] = [];

  if (foundCount > 0) {
    validations.push({
      status: "pass",
      message: `${foundCount} DKIM selector${foundCount > 1 ? "s" : ""} found`,
    });
  } else {
    validations.push({
      status: "fail",
      message:
        "No DKIM selectors found among common selectors — try specifying a custom selector",
    });
  }

  // Explicitly acknowledge Ed25519 keys as modern and strong
  if (ed25519Names.length > 0) {
    validations.push({
      status: "pass",
      message: `${ed25519Names.join(", ")} — Ed25519 key — modern curve, strong by construction`,
    });
  }

  // Check for weak keys
  if (weakKeyNames.length > 0) {
    validations.push({
      status: "warn",
      message: `${weakKeyNames.join(", ")} — RSA key under 2048 bits (weak)`,
    });
  }

  // Check for revoked keys
  if (revokedNames.length > 0) {
    validations.push({
      status: "warn",
      message: `${revokedNames.join(", ")} — key revoked (empty p= tag)`,
    });
  }

  // Check for testing mode
  if (testingNames.length > 0) {
    validations.push({
      status: "warn",
      message: `${testingNames.join(", ")} — in testing mode (t=y)`,
    });
  }

  // Recognize modern Ed25519 keys (RFC 8463)
  if (ed25519Names.length > 0) {
    validations.push({
      status: "pass",
      message: `${ed25519Names.join(", ")} — Ed25519 key (modern, compact signing algorithm per RFC 8463)`,
    });
  }

  const hasFailure = validations.some((v) => v.status === "fail");
  const hasWarn = validations.some((v) => v.status === "warn");
  const status = hasFailure ? "fail" : hasWarn ? "warn" : "pass";

  return { status, selectors, validations };
}

async function probeSelector(
  domain: string,
  selector: string,
): Promise<DkimSelectorResult> {
  const txt = await queryTxt(`${selector}._domainkey.${domain}`);
  if (!txt) return { found: false };

  const dkimRecord = txt.entries.find(
    (e) => e.includes("v=DKIM1") || e.includes("p="),
  );
  if (!dkimRecord) return { found: false };

  const tags = parseTags(dkimRecord, { lowercaseKeys: false });

  const keyType = tags.k || "rsa";
  const publicKey = tags.p || "";
  const revoked = publicKey === "";
  const testing = tags.t === "y";

  // Estimate key bits from DER-encoded public key byte length
  let keyBits: number | undefined;
  if (publicKey && keyType === "rsa") {
    const decoded = atob(publicKey.replace(/\s/g, ""));
    keyBits = estimateRsaKeyBits(decoded.length);
  }

  return {
    found: true,
    key_type: keyType,
    key_bits: keyBits,
    testing,
    revoked,
  };
}

/**
 * Map DER-encoded SubjectPublicKeyInfo byte length to standard RSA key size.
 * Known DER sizes: 1024-bit ≈ 162 bytes, 2048-bit ≈ 294 bytes, 4096-bit ≈ 550 bytes.
 * Uses ranges to account for slight variations in key parameters.
 */
function estimateRsaKeyBits(derLength: number): number {
  if (derLength <= 200) return 1024;
  if (derLength <= 400) return 2048;
  return 4096;
}
