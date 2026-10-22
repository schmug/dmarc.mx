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

// Expand an IPv6 literal (no brackets, no zone) to 8 numeric groups, or null
// if it does not parse. Accepts a dotted-quad tail (`::127.0.0.1`).
function parseIPv6(host: string): number[] | null {
  let h = host;
  const tail = h.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (tail) {
    const o = tail[1].split(".").map(Number);
    if (o.some((n) => n > 255)) return null;
    h = `${h.slice(0, -tail[1].length)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const halves = h.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] === "" ? [] : halves[0].split(":");
  const rest =
    halves.length === 2 && halves[1] !== "" ? halves[1].split(":") : [];
  const fill = 8 - head.length - rest.length;
  if (halves.length === 1 ? head.length !== 8 : fill < 1) return null;
  const groups = [
    ...head,
    ...Array(halves.length === 2 ? fill : 0).fill("0"),
    ...rest,
  ];
  if (groups.length !== 8) return null;
  const nums = groups.map((g) =>
    /^[0-9a-f]{1,4}$/.test(g) ? Number.parseInt(g, 16) : Number.NaN,
  );
  return nums.some(Number.isNaN) ? null : nums;
}

function isPrivateIPv6(host: string): boolean {
  // `new URL(...).hostname` yields the canonical compressed lowercase form.
  if (host === "::1") return true; // loopback
  if (host === "::") return true; // unspecified
  if (host.startsWith("fc") || host.startsWith("fd")) return true; // fc00::/7 ULA
  if (/^fe[89ab]/.test(host)) return true; // fe80::/10 link-local
  if (host.startsWith("::ffff:")) return true; // IPv4-mapped — no legit webhook use
  const g = parseIPv6(host);
  if (!g) return false;
  const embedded = `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
  // ::/96 IPv4-compatible (deprecated) — classify by the embedded IPv4.
  if (g.slice(0, 6).every((n) => n === 0)) return isPrivateIPv4(embedded);
  // 64:ff9b::/96 NAT64 — classify by the embedded IPv4.
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((n) => n === 0))
    return isPrivateIPv4(embedded);
  // ::ffff:0:0/96 IPv4-mapped in expanded spelling.
  if (g.slice(0, 5).every((n) => n === 0) && g[5] === 0xffff) return true;
  return false;
}

// True if a hostname (as produced by `new URL(url).hostname`) points at
// internal/reserved space or an internal-only name and must NOT be fetched.
export function isBlockedFetchHost(hostname: string): boolean {
  let host = hostname.trim().toLowerCase();
  // `new URL(...).hostname` wraps IPv6 literals in brackets, e.g. "[::1]".
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  // A trailing dot is the DNS root label: `localhost.` is `localhost`.
  host = host.replace(/\.+$/, "");
  if (host === "") return true;
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
