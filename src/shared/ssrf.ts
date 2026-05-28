// SSRF guard for user-supplied URLs that the Worker fetches server-side
// (currently: outbound webhook delivery). Distinct from `normalizeDomain` in
// domain.ts, which rejects ALL IP literals because scanning a bare IP is never
// a legitimate DMARC/SPF/etc. lookup. Here we must allow arbitrary PUBLIC hosts
// (a webhook receiver can be any public HTTPS endpoint) while blocking hosts
// that point at internal/reserved address space.
//
// This is a string/literal-level guard: it stops an attacker from directly
// naming an internal address (`https://169.254.169.254/`, `https://10.0.0.5/`,
// `https://localhost/`). It does NOT defend against DNS rebinding — a public
// hostname whose A record resolves to an internal IP — which needs a
// resolution-time check the Workers fetch API does not cleanly expose. Pair it
// with `redirect: "manual"` on the fetch so a 3xx can't pivot past this guard.

function isPrivateIPv4(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  const octets = parts.map((p) => Number(p));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255))
    return false;
  const [a, b] = octets;
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 10) return true; // 10.0.0.0/8 private
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local (+ metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmark
  if (a >= 224) return true; // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved + 255.* broadcast
  return false;
}

function isPrivateIPv6(host: string): boolean {
  // `new URL(...).hostname` yields the canonical compressed lowercase form.
  if (host === "::1") return true; // loopback
  if (host === "::") return true; // unspecified
  if (host.startsWith("fc") || host.startsWith("fd")) return true; // fc00::/7 ULA
  if (/^fe[89ab]/.test(host)) return true; // fe80::/10 link-local
  if (host.startsWith("::ffff:")) return true; // IPv4-mapped — no legit webhook use
  return false;
}

// True if a hostname (as produced by `new URL(url).hostname`) points at
// internal/reserved space or an internal-only name and must NOT be fetched.
export function isBlockedFetchHost(hostname: string): boolean {
  let host = hostname.trim().toLowerCase();
  if (host === "") return true;
  // `new URL(...).hostname` wraps IPv6 literals in brackets, e.g. "[::1]".
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host.endsWith(".local") || host.endsWith(".internal")) return true;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return isPrivateIPv4(host);
  if (host.includes(":")) return isPrivateIPv6(host);
  return false;
}

// True only for an https: URL whose host is safe to fetch server-side.
export function isAllowedWebhookUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  return !isBlockedFetchHost(parsed.hostname);
}
