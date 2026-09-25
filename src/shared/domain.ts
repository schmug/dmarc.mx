// Shared, side-effect-free domain normalization + validation used by both
// the public scan endpoints in src/index.ts and the dashboard CRUD routes
// in src/dashboard/routes.ts. Kept in src/shared/ to avoid a circular
// import (dashboard → index → dashboard) when both sides need the helper.

export function normalizeDomain(raw: string | undefined): string | null {
  if (!raw) return null;
  let domain = raw.trim().toLowerCase();
  // Strip protocol if pasted as URL
  domain = domain.replace(/^https?:\/\//, "");
  // Use URL constructor to normalize (handles ports, userinfo, Punycode/IDN)
  try {
    domain = new URL(`http://${domain}`).hostname;
  } catch {
    // Fall back to manual parsing for inputs the URL constructor rejects
    domain = domain.split("/")[0].split("?")[0];
  }
  // RFC 1035: domain names must not exceed 253 characters
  if (domain.length > 253) return null;
  // Strip trailing dot
  domain = domain.replace(/\.$/, "");
  // Restrict to ASCII hostname charset. IDNs are Punycode-encoded by `new URL`
  // (e.g. münchen.de → xn--mnchen-3ya.de), so this set covers valid IDNs too.
  // Rejects anything exotic (quotes, spaces, brackets) that could break out of
  // an HTML attribute or JS literal downstream.
  if (!/^[a-z0-9.-]+$/.test(domain)) return null;
  // Must have at least one dot
  if (!domain.includes(".")) return null;
  // RFC 1035 §2.3.4 / RFC 1123: each label is 1-63 chars and must not start
  // or end with a hyphen. The charset check above lets through `a..com`
  // (empty label from adjacent dots), an over-long label, and a
  // leading/trailing hyphen like `-bad.com`, none of which are valid DNS
  // labels.
  for (const label of domain.split(".")) {
    if (label.length < 1 || label.length > 63) return null;
    if (label.startsWith("-") || label.endsWith("-")) return null;
  }
  // Reject IPv4 literals. DMARC/SPF/DKIM/BIMI/MTA-STS records are published
  // in DNS at domain names, not IPs — there is no legitimate dmarcheck use
  // case for scanning `1.2.3.4`. This also closes a defense-in-depth gap
  // around the MTA-STS fetch in `src/analyzers/mta-sts.ts`, which interpolates
  // the validated domain into a URL (flagged CWE-918 by static analysis);
  // previously, metadata-service IPs like 169.254.169.254 were only shielded
  // by the `mta-sts.` prefix happening to route them back through public DNS.
  // WHATWG URL (used above) normalizes hex, integer, and short-form IPv4
  // inputs into canonical dotted-decimal, so a single anchored check covers
  // `0xc0a80101`, `3232235777`, `127.1`, and `1.2.3` as well as plain forms.
  // `999.999.999.999` throws from `new URL` and is caught by the fallback
  // branch above, then rejected here by regex shape.
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain)) return null;
  return domain;
}
