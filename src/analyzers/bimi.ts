import { DnsLookupError, queryTxt } from "../dns/client.js";
import type { TxtRecord } from "../dns/types.js";
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

export function prefetchBimiDns(domain: string): Promise<TxtRecord | null> {
  return queryTxt(`default._bimi.${domain}`).catch((err) => {
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
    const notAfterMatch = body.match(/Not\s+After\s*:\s*(.+?)(?:\r?\n|$)/i);
    if (notAfterMatch) {
      const notAfterStr = notAfterMatch[1].trim();
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
): Promise<BimiResult> {
  const txt =
    prefetchedDns !== undefined
      ? prefetchedDns
      : await queryTxt(`default._bimi.${domain}`);

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
    e.trimStart().startsWith("v=BIMI1"),
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
      // Fetch and validate the logo artifact.
      const logoResult = await fetchLogo(tags.l);
      validations.push({
        status: logoResult.ok ? "pass" : "warn",
        message: logoResult.message,
      });
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

  // a= check (authority / VMC/CMC) — presence + fetch-and-validate
  if (tags.a) {
    validations.push({
      status: "pass",
      message: "Authority evidence (a=) VMC/CMC certificate URL present",
    });
    // Fetch and validate the cert artifact.
    const certResult = await fetchCert(tags.a);
    validations.push({
      status: certResult.ok ? "pass" : certResult.expired ? "fail" : "warn",
      message: certResult.message,
    });
  } else {
    validations.push({
      status: "warn",
      message:
        "No authority certificate (a=) — add a VMC or CMC to display your logo in Gmail and Apple Mail",
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
