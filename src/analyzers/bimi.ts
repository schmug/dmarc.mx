import { DnsLookupError, queryTxt } from "../dns/client.js";
import type { ScanBudget } from "../dns/scan-budget.js";
import type { TxtRecord } from "../dns/types.js";
import { LEARN_ANCHORS, learnAnchorHref } from "../shared/learn-anchors.js";
import { parseTags } from "../shared/parse-tags.js";
import type { BimiResult, Validation } from "./types.js";

// Fetch posture for BIMI artifacts (logo and VMC/CMC cert):
//   - `redirect: "follow"` — BIMI has no RFC-level prohibition on redirects,
//     unlike MTA-STS (RFC 8461 §3.3). Real-world BIMI logo and cert hosts
//     commonly redirect CDN URLs. Contrast with mta-sts.ts which must use
//     "manual" to comply with RFC 8461 §3.3. See CLAUDE.md §Security.
//   - 30s timeout — keeps a stalled upstream from hanging the whole scan.
//   - Hard body size limits — prevents an attacker-controlled server from
//     streaming megabytes into Worker memory.
const LOGO_TIMEOUT_MS = 30_000;
const LOGO_MAX_BYTES = 1 * 1024 * 1024; // 1 MB
const CERT_TIMEOUT_MS = 30_000;
const CERT_MAX_BYTES = 100 * 1024; // 100 KB

// A Worker cannot fetch its own zone — the subrequest re-enters the edge and
// Cloudflare answers 522 even though the asset is served correctly to
// outside clients (#749). Skip the logo fetch entirely when the l= host is
// this service's own zone rather than reporting a false "unreachable" warn.
const SELF_HOSTS = new Set(["dmarc.mx", "www.dmarc.mx"]);

function isSelfHostedLogo(url: string): boolean {
  try {
    return SELF_HOSTS.has(new URL(url).hostname.toLowerCase());
  } catch {
    return false;
  }
}

export function prefetchBimiDns(
  domain: string,
  budget?: ScanBudget,
): Promise<TxtRecord | null> {
  return queryTxt(`default._bimi.${domain}`, budget).catch((err) => {
    if (err instanceof DnsLookupError) return null;
    throw err;
  });
}

/** Fetch the BIMI logo SVG and validate reachability + Content-Type. */
async function fetchLogo(
  url: string,
): Promise<{ ok: boolean; message: string }> {
  try {
    const resp = await fetch(url, {
      headers: { "User-Agent": "dmarcheck/1.0" },
      redirect: "follow",
      signal: AbortSignal.timeout(LOGO_TIMEOUT_MS),
    });

    if (!resp.ok) {
      return {
        ok: false,
        message: `Logo fetch failed: HTTP ${resp.status} from logo URL`,
      };
    }

    // Consume up to LOGO_MAX_BYTES to enforce the size cap.
    const reader = resp.body?.getReader();
    if (reader) {
      let bytesRead = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        bytesRead += value?.length ?? 0;
        if (bytesRead > LOGO_MAX_BYTES) {
          reader.cancel();
          return {
            ok: false,
            message: "Logo fetch failed: response exceeds 1 MB size limit",
          };
        }
      }
    }

    const contentType = resp.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().includes("svg")) {
      return {
        ok: false,
        message: `Logo Content-Type is not SVG (got: ${contentType.split(";")[0].trim() || "unknown"}) — BIMI requires image/svg+xml`,
      };
    }

    return { ok: true, message: "Logo fetched and confirmed SVG" };
  } catch {
    return {
      ok: false,
      message: "Logo fetch failed: network error or timeout reaching logo URL",
    };
  }
}

/**
 * Return the value after the first "Not After :" label in a cert body, or
 * null. Gives exactly what the former
 * `body.match(/Not\s+After\s*:\s*(.+?)(?:\r?\n|$)/i)?.[1]` captured, in
 * linear time. That regex backtracked quadratically on an attacker-served
 * body (up to CERT_MAX_BYTES): a long whitespace run after the colon followed
 * by a lone `\r` made it re-scan the rest of the line once per whitespace
 * character.
 * Kept from the regex, on purpose:
 *   - A value counts only if it is followed by `\n`, `\r\n` or end of body.
 *     A lone `\r`, U+2028 or U+2029 fails that occurrence, and the search
 *     moves on to the next label.
 *   - If the value fails, shorter splits of the whitespace after the colon
 *     are tried, longest first, so a whitespace-only value that ends at an
 *     embedded `\n` is accepted. It trims to "" and still ends the search.
 */
export function findNotAfterValue(body: string): string | null {
  // Group 1 is the whole whitespace run after the colon.
  const label = /Not\s+After\s*:(\s*)/gi;
  // The characters `.` does not match without the `s` flag.
  const lineBreak = /[\n\r\u2028\u2029]/g;
  // Cache of the last line-break search: [scanFrom, lineEnd) holds no line
  // break, so many labels on one line do not rescan it.
  let scanFrom = -1;
  let lineEnd = -1;
  for (let m = label.exec(body); m !== null; m = label.exec(body)) {
    const textStart = m.index + m[0].length;
    const afterColon = textStart - m[1].length;
    if (textStart < scanFrom || textStart > lineEnd) {
      lineBreak.lastIndex = textStart;
      scanFrom = textStart;
      lineEnd = lineBreak.exec(body)?.index ?? body.length;
    }
    // `end` is the first line break (or body end) at or after `start`.
    let end = lineEnd;
    for (let start = textStart; start >= afterColon; start--) {
      if (start === body.length) continue; // the value needs one character
      const ch = body[start];
      if (ch === "\n" || ch === "\r" || ch === "\u2028" || ch === "\u2029") {
        end = start;
        continue;
      }
      if (
        end === body.length ||
        body[end] === "\n" ||
        (body[end] === "\r" && body[end + 1] === "\n")
      ) {
        return body.slice(start, end);
      }
    }
    label.lastIndex = m.index + 1;
  }
  return null;
}

/**
 * Fetch the VMC/CMC PEM certificate and validate reachability, PEM format,
 * and expiry. Only raw fetch bytes are read — no cert content reaches HTML.
 */
async function fetchCert(
  url: string,
): Promise<{ ok: boolean; expired?: boolean; message: string }> {
  try {
    const resp = await fetch(url, {
      headers: { "User-Agent": "dmarcheck/1.0" },
      redirect: "follow",
      signal: AbortSignal.timeout(CERT_TIMEOUT_MS),
    });

    if (!resp.ok) {
      return {
        ok: false,
        message: `Certificate fetch failed: HTTP ${resp.status} from cert URL`,
      };
    }

    // Read up to CERT_MAX_BYTES.
    const reader = resp.body?.getReader();
    const chunks: Uint8Array[] = [];
    let bytesRead = 0;
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          bytesRead += value.length;
          if (bytesRead > CERT_MAX_BYTES) {
            reader.cancel();
            return {
              ok: false,
              message:
                "Certificate fetch failed: response exceeds 100 KB size limit",
            };
          }
          chunks.push(value);
        }
      }
    }

    // ⚡ Bolt Optimization: Pre-allocate the entire Uint8Array using bytesRead
    // instead of creating O(n^2) allocations with .reduce().
    const merged = new Uint8Array(bytesRead);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.length;
    }
    const body = new TextDecoder().decode(merged);

    if (!body.includes("-----BEGIN CERTIFICATE-----")) {
      // Could be DER-encoded — report fetch success but skip expiry check.
      // DER is binary and uncommon from HTTPS cert URLs, but we don't break.
      return {
        ok: true,
        message:
          "Certificate fetched (binary/DER format — expiry check skipped; prefer PEM at this URL)",
      };
    }

    // Parse the first "Not After" date from the PEM text.
    // Match patterns like: "Not After : Jan  1 00:00:00 2025 GMT"
    // which appear in PEM bundles that include human-readable cert info,
    // or in cert chains serialized with OpenSSL text output.
    const notAfterValue = findNotAfterValue(body);
    if (notAfterValue !== null) {
      const notAfterStr = notAfterValue.trim();
      const notAfter = new Date(notAfterStr);
      if (!Number.isNaN(notAfter.getTime())) {
        if (notAfter < new Date()) {
          return {
            ok: false,
            expired: true,
            message: `Certificate is expired`,
          };
        }
        return {
          ok: true,
          message:
            "Certificate fetched, validated PEM format, and is not expired",
        };
      }
    }

    // PEM found but no parseable Not After date — report success without expiry.
    return {
      ok: true,
      message: "Certificate fetched and is PEM format (expiry date not parsed)",
    };
  } catch {
    return {
      ok: false,
      message:
        "Certificate fetch failed: network error or timeout reaching cert URL",
    };
  }
}

export async function analyzeBimi(
  domain: string,
  dmarcPolicy: string | null,
  prefetchedDns?: TxtRecord | null,
  budget?: ScanBudget,
): Promise<BimiResult> {
  const txt =
    prefetchedDns !== undefined
      ? prefetchedDns
      : await queryTxt(`default._bimi.${domain}`, budget);

  if (!txt) {
    const validations: Validation[] = [
      { status: "warn", message: `No BIMI record at default._bimi.${domain}` },
    ];
    if (dmarcPolicy && ["quarantine", "reject"].includes(dmarcPolicy)) {
      validations.push({
        status: "pass",
        message: "DMARC policy meets BIMI requirement (quarantine or reject)",
      });
    } else {
      validations.push({
        status: "warn",
        message: "BIMI requires a DMARC policy of quarantine or reject",
      });
    }
    return { status: "warn", record: null, tags: null, validations };
  }

  const bimiRecord = txt.entries.find((e) =>
    /^v=BIMI1(;|\s|$)/.test(e.trimStart()),
  );
  if (!bimiRecord) {
    return {
      status: "warn",
      record: txt.raw,
      tags: null,
      validations: [
        {
          status: "warn",
          message:
            "TXT record exists but is not a valid BIMI record (possibly a wildcard DNS entry)",
        },
      ],
    };
  }

  const tags = parseTags(bimiRecord);
  const validations: Validation[] = [];

  validations.push({ status: "pass", message: "BIMI record found" });

  // v= check
  if (tags.v !== "BIMI1") {
    validations.push({ status: "fail", message: "Invalid BIMI version tag" });
  }

  // l= check (logo URL) — presence + HTTPS + fetch-and-validate
  if (tags.l) {
    if (tags.l.startsWith("https://")) {
      validations.push({
        status: "pass",
        message: "Logo URL (l=) is present and uses HTTPS",
      });
      if (isSelfHostedLogo(tags.l)) {
        validations.push({
          status: "pass",
          message: "Logo hosted by this service; fetch check skipped",
        });
      } else {
        // Fetch and validate the logo artifact.
        const logoResult = await fetchLogo(tags.l);
        validations.push({
          status: logoResult.ok ? "pass" : "warn",
          message: logoResult.message,
        });
      }
    } else {
      validations.push({
        status: "warn",
        message: "Logo URL (l=) should use HTTPS",
      });
    }
  } else {
    validations.push({
      status: "warn",
      message: "No logo URL (l=) specified",
    });
  }

  // a= check (authority / VMC/CMC) — presence + HTTPS + fetch-and-validate
  if (tags.a) {
    let isHttpsUrl = false;
    try {
      isHttpsUrl = new URL(tags.a).protocol === "https:";
    } catch {
      isHttpsUrl = false;
    }

    if (isHttpsUrl) {
      validations.push({
        status: "pass",
        message: "Authority evidence (a=) VMC/CMC certificate URL present",
      });
      // Fetch and validate the cert artifact.
      const certResult = await fetchCert(tags.a);
      validations.push({
        status: certResult.ok ? "pass" : certResult.expired ? "fail" : "warn",
        message: certResult.message,
        ...(certResult.ok
          ? {}
          : { learnAnchor: learnAnchorHref(LEARN_ANCHORS.bimiCertification) }),
      });
    } else {
      validations.push({
        status: "fail",
        message:
          "Authority evidence (a=) must be an https:// URL — certificate not fetched",
        learnAnchor: learnAnchorHref(LEARN_ANCHORS.bimiCertification),
      });
    }
  } else {
    validations.push({
      status: "warn",
      message:
        "No authority certificate (a=) — add a VMC or CMC to display your logo in Gmail and Apple Mail",
      learnAnchor: learnAnchorHref(LEARN_ANCHORS.bimiCertification),
    });
  }

  // DMARC cross-check
  if (dmarcPolicy && ["quarantine", "reject"].includes(dmarcPolicy)) {
    validations.push({
      status: "pass",
      message: "DMARC policy meets BIMI requirement",
    });
  } else {
    validations.push({
      status: "fail",
      message:
        "DMARC policy must be quarantine or reject for BIMI to be honored",
    });
  }

  const hasFailure = validations.some((v) => v.status === "fail");
  const hasWarn = validations.some((v) => v.status === "warn");
  const status = hasFailure ? "fail" : hasWarn ? "warn" : "pass";

  return { status, record: bimiRecord, tags, validations };
}
