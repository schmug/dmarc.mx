// KV store + header-parsing + SSE polling for inbound test-email scanning
// (issue #417, first vertical slice).
//
// Trust model: the inbound message is fully attacker-controlled. `message.to`
// is trustworthy (Cloudflare sets it), but every header value — including the
// envelope From and the DKIM-Signature tags — is spoofable. We therefore
// (a) charset-validate the token before it touches a KV key, (b) cap every
// stored string, and (c) escape everything at render time. We trust
// Cloudflare's upstream `Authentication-Results` for the verdict; cryptographic
// DKIM re-verification and MIME body parsing are deferred to a follow-up.

import { isValidToken, tokenFromAddress } from "./tokens.js";

// 30-minute lifetime for both the pending reservation and the stored verdict.
// KV's `expirationTtl` garbage-collects expired tokens, so an abandoned address
// self-heals with no sweep job.
export const TOKEN_TTL_SECONDS = 30 * 60;

// Per-identity ceiling on simultaneously-live token addresses. Each token is a
// routable inbox, so this bounds how many open addresses one caller can hold at
// once — a backstop on top of the issuance rate limiter (free 10/60s).
export const MAX_LIVE_TOKENS_PER_IDENTITY = 5;

// We never read `message.raw` (headers only), so memory is bounded regardless
// of message size. This is a defensive ceiling recorded for transparency; the
// platform hard max is 25 MiB.
export const MAX_MESSAGE_BYTES = 10 * 1024 * 1024;

// Caps on stored attacker-controlled strings. Real headers are tiny; these
// bound a pathological sender and keep KV values small.
const MAX_AUTH_RESULTS_LEN = 2000;
const MAX_FROM_LEN = 320; // RFC 5321 max reverse/forward-path length.
const MAX_SELECTOR_LEN = 128;

const TOKEN_PREFIX = "tok:";
const LIVE_PREFIX = "live:";

export interface PendingRecord {
  status: "pending";
  created_at: string;
}

export interface VerdictRecord {
  status: "received";
  spf: string | null;
  dkim: string | null;
  dmarc: string | null;
  alignment: string | null;
  from: string | null;
  dkim_selector: string | null;
  dkim_domain: string | null;
  auth_results: string | null;
  size_bytes: number;
  received_at: string;
}

export type InboxRecord = PendingRecord | VerdictRecord;

function tokenKey(token: string): string {
  return `${TOKEN_PREFIX}${token}`;
}

// ---------------------------------------------------------------------------
// Token record store
// ---------------------------------------------------------------------------

/** Read + validate a token record. Returns null for unknown/expired/corrupt. */
export async function getRecord(
  kv: KVNamespace,
  token: string,
): Promise<InboxRecord | null> {
  if (!isValidToken(token)) return null;
  const raw = await kv.get(tokenKey(token));
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as InboxRecord;
    if (parsed?.status === "pending" || parsed?.status === "received") {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

/** Write the "pending" reservation issued by GET /check/email. */
export async function putPending(
  kv: KVNamespace,
  token: string,
): Promise<void> {
  const rec: PendingRecord = {
    status: "pending",
    created_at: new Date().toISOString(),
  };
  await kv.put(tokenKey(token), JSON.stringify(rec), {
    expirationTtl: TOKEN_TTL_SECONDS,
  });
}

/** Overwrite a token record with the parsed verdict (email handler path). */
export async function putVerdict(
  kv: KVNamespace,
  token: string,
  verdict: VerdictRecord,
): Promise<void> {
  await kv.put(tokenKey(token), JSON.stringify(verdict), {
    expirationTtl: TOKEN_TTL_SECONDS,
  });
}

// ---------------------------------------------------------------------------
// Per-identity live-token cap
// ---------------------------------------------------------------------------

interface LiveEntry {
  token: string;
  exp: number;
}

// Hash the rate-limit identity (`ip:<x>` / `user:<id>`) so raw IPs never land
// in a KV key.
async function liveKey(identity: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(identity),
  );
  let hex = "";
  for (const b of new Uint8Array(digest))
    hex += b.toString(16).padStart(2, "0");
  return `${LIVE_PREFIX}${hex}`;
}

/**
 * Reserve a slot in the identity's live-token index, returning false when the
 * identity is already at `MAX_LIVE_TOKENS_PER_IDENTITY`. The index is pruned of
 * expired entries on every read.
 *
 * This is a non-atomic read-modify-write; the per-identity issuance rate
 * limiter (free 10/60s) bounds concurrency, so this is an accumulation backstop
 * (don't let one caller hoard hundreds of open addresses), not a real-time
 * guarantee.
 */
export async function reserveLiveToken(
  kv: KVNamespace,
  identity: string,
  token: string,
  nowMs: number = Date.now(),
): Promise<boolean> {
  const key = await liveKey(identity);
  let entries: LiveEntry[] = [];
  const raw = await kv.get(key);
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        entries = parsed.filter(
          (e): e is LiveEntry =>
            !!e && typeof e.token === "string" && typeof e.exp === "number",
        );
      }
    } catch {
      // Corrupt index → treat as empty rather than locking the identity out.
    }
  }
  const live = entries.filter((e) => e.exp > nowMs);
  if (live.length >= MAX_LIVE_TOKENS_PER_IDENTITY) return false;
  live.push({ token, exp: nowMs + TOKEN_TTL_SECONDS * 1000 });
  await kv.put(key, JSON.stringify(live), { expirationTtl: TOKEN_TTL_SECONDS });
  return true;
}

// ---------------------------------------------------------------------------
// Header → verdict parsing
// ---------------------------------------------------------------------------

function cap(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) : s;
}

// Pull an authentication method result (spf/dkim/dmarc) from an
// Authentication-Results header. We only extract the result keyword
// (pass/fail/none/softfail/neutral/temperror/permerror), which is a clean
// [a-z] token — safe by construction — so a crafted header value cannot smuggle
// markup through these fields.
function extractMethodResult(
  authResults: string,
  method: string,
): string | null {
  const m = authResults.match(new RegExp(`\\b${method}\\s*=\\s*([a-zA-Z]+)`));
  return m ? m[1].toLowerCase() : null;
}

// Pull a DKIM-Signature tag value (`s=` selector, `d=` domain). These are
// attacker-controlled (the header is spoofable), so we charset-validate and cap
// before storing; rendering still escapes.
function extractDkimTag(
  dkimSig: string,
  tag: string,
  charset: RegExp,
): string | null {
  const m = dkimSig.match(new RegExp(`(?:^|;)\\s*${tag}\\s*=\\s*([^;]+)`));
  if (!m) return null;
  const value = m[1].trim();
  if (!charset.test(value)) return null;
  return cap(value, MAX_SELECTOR_LEN);
}

// DMARC pass implies at least one aligned + passing mechanism. We don't re-run
// alignment for this slice; we surface what Cloudflare's verdict already tells
// us.
function deriveAlignment(dmarc: string | null): string | null {
  if (dmarc === "pass") return "pass";
  if (dmarc) return "fail";
  return null;
}

// Charset-validate + cap an attacker-controlled tag value (selector/domain)
// pulled from a header. Returns null if it doesn't match the allowed charset.
function cleanTag(value: string | null, charset: RegExp): string | null {
  if (!value) return null;
  const v = value.trim();
  if (!charset.test(v)) return null;
  return cap(v, MAX_SELECTOR_LEN);
}

// Split an Authentication-Results value into its `;`-separated method clauses.
// Cloudflare's parenthetical comments don't contain `;`, so a plain split is
// enough to isolate each `method=result ...` clause for the verdict we trust.
function authClauses(authResults: string): string[] {
  return authResults
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);
}

// Relaxed-ish domain alignment: exact match or a parent/child relationship.
// Good enough to pick which signature to *surface*; Cloudflare's `dmarc=`
// result is the authoritative alignment verdict.
function domainsAlign(a: string, b: string): boolean {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  return x === y || x.endsWith(`.${y}`) || y.endsWith(`.${x}`);
}

// A message carries multiple SPF/DKIM results (the relay's and the author
// domain's). The DMARC-relevant ones are the SPF check tied to `smtp.mailfrom`
// (the envelope identity) and the DKIM signature whose `header.d` aligns with
// `header.from`. We surface those rather than the first clause, so the verdict
// reflects the *user's own* domain, not the forwarding relay.

function selectSpf(authResults: string, receivedSpf: string): string | null {
  const spfClauses = authClauses(authResults).filter((c) => /^spf=/i.test(c));
  if (spfClauses.length > 0) {
    const chosen =
      spfClauses.find((c) => /smtp\.mailfrom=/i.test(c)) ?? spfClauses[0];
    const m = chosen.match(/^spf=([a-zA-Z]+)/i);
    if (m) return m[1].toLowerCase();
  }
  // No SPF in Authentication-Results — fall back to a Received-SPF header.
  return receivedSpf.match(/^\s*([a-zA-Z]+)/)?.[1]?.toLowerCase() ?? null;
}

interface DkimClause {
  result: string;
  domain: string | null;
  selector: string | null;
}

function parseDkimClauses(authResults: string): DkimClause[] {
  const out: DkimClause[] = [];
  for (const clause of authClauses(authResults)) {
    const m = clause.match(/^dkim=([a-zA-Z]+)/i);
    if (!m) continue;
    out.push({
      result: m[1].toLowerCase(),
      domain: clause.match(/header\.d=([^\s;]+)/i)?.[1] ?? null,
      selector: clause.match(/header\.s=([^\s;]+)/i)?.[1] ?? null,
    });
  }
  return out;
}

/**
 * Parse the authentication verdict out of an inbound message's headers.
 * Cloudflare stamps `Authentication-Results` at ingest; no MIME body parse is
 * needed for this slice.
 */
export function parseVerdict(
  headers: Headers,
  from: string,
  sizeBytes: number,
): VerdictRecord {
  const authResultsRaw = headers.get("Authentication-Results") ?? "";
  const dkimSig = headers.get("DKIM-Signature") ?? "";
  const receivedSpf = headers.get("Received-SPF") ?? "";

  const dmarc = extractMethodResult(authResultsRaw, "dmarc");
  const spf = selectSpf(authResultsRaw, receivedSpf);

  // Prefer the DKIM signature aligned with the DMARC From domain (the user's
  // own), then any signature, then the raw DKIM-Signature header as a fallback.
  const fromDomain =
    authResultsRaw.match(/header\.from=([^\s;]+)/i)?.[1]?.toLowerCase() ?? null;
  const dkimClauses = parseDkimClauses(authResultsRaw);
  const chosenDkim =
    (fromDomain
      ? dkimClauses.find((c) => c.domain && domainsAlign(c.domain, fromDomain))
      : undefined) ?? dkimClauses[0];

  const dkim =
    chosenDkim?.result ?? extractMethodResult(authResultsRaw, "dkim");
  const dkim_selector =
    cleanTag(chosenDkim?.selector ?? null, /^[A-Za-z0-9._-]+$/) ??
    extractDkimTag(dkimSig, "s", /^[A-Za-z0-9._-]+$/);
  const dkim_domain =
    cleanTag(chosenDkim?.domain ?? null, /^[A-Za-z0-9.-]+$/) ??
    extractDkimTag(dkimSig, "d", /^[A-Za-z0-9.-]+$/);

  return {
    status: "received",
    spf,
    dkim,
    dmarc,
    alignment: deriveAlignment(dmarc),
    from: from ? cap(from, MAX_FROM_LEN) : null,
    dkim_selector,
    dkim_domain,
    auth_results: authResultsRaw
      ? cap(authResultsRaw, MAX_AUTH_RESULTS_LEN)
      : null,
    size_bytes: Number.isFinite(sizeBytes)
      ? Math.min(Math.max(0, sizeBytes), MAX_MESSAGE_BYTES + 1)
      : 0,
    received_at: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Email Worker entry point
// ---------------------------------------------------------------------------

/**
 * Handle one inbound message routed by the `inbox@dmarc.mx` subaddressing rule.
 *
 * No-op (no write, no throw) when KV is unbound, the address is not our
 * `inbox+<token>@dmarc.mx` shape / malformed, or the token is unknown/expired.
 * For a known token we read the verdict from the headers and store it under the
 * same token.
 */
export async function handleInboundEmail(
  message: ForwardableEmailMessage,
  kv: KVNamespace | undefined,
): Promise<void> {
  if (!kv) return;
  const token = tokenFromAddress(message.to);
  if (!token) return; // not our subdomain / malformed local part
  const existing = await getRecord(kv, token);
  if (!existing) return; // unknown or expired token — capability check failed
  const verdict = parseVerdict(message.headers, message.from, message.rawSize);
  await putVerdict(kv, token, verdict);
}

// ---------------------------------------------------------------------------
// SSE result stream
// ---------------------------------------------------------------------------

/** Scalar fields pushed on the SSE `result` event, plus a pre-escaped card. */
export interface InboxResultPayload {
  status: "received";
  spf: string | null;
  dkim: string | null;
  dmarc: string | null;
  alignment: string | null;
  received_at: string;
  html: string;
}

export function buildResultPayload(
  rec: VerdictRecord,
  renderCard: (r: VerdictRecord) => string,
): InboxResultPayload {
  return {
    status: "received",
    spf: rec.spf,
    dkim: rec.dkim,
    dmarc: rec.dmarc,
    alignment: rec.alignment,
    received_at: rec.received_at,
    html: renderCard(rec),
  };
}

interface SseWriter {
  writeSSE(message: { event: string; data: string }): Promise<void> | void;
}

interface StreamOptions {
  renderCard: (r: VerdictRecord) => string;
  pollIntervalMs?: number;
  maxWaitMs?: number;
  sleep?: (ms: number) => Promise<void>;
  nowMs?: () => number;
}

/**
 * Stream the verdict for a token over SSE:
 *   - unknown/expired token        → one `closed` {status:"expired"} event
 *   - verdict already stored        → one `result` event
 *   - still pending                 → a `waiting` event, then poll KV until the
 *                                     verdict lands (`result`), the record
 *                                     expires (`closed` expired) or the wait
 *                                     budget elapses (`closed` timeout)
 *
 * Every terminal state is a clean close — never a throw — so the route never
 * 500s on an unknown token.
 */
export async function streamInboxResult(
  stream: SseWriter,
  kv: KVNamespace,
  token: string,
  opts: StreamOptions,
): Promise<void> {
  const pollIntervalMs = opts.pollIntervalMs ?? 2000;
  const maxWaitMs = opts.maxWaitMs ?? TOKEN_TTL_SECONDS * 1000;
  const sleep =
    opts.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const nowMs = opts.nowMs ?? (() => Date.now());

  const emit = (event: string, data: unknown) =>
    stream.writeSSE({ event, data: JSON.stringify(data) });

  const initial = await getRecord(kv, token);
  if (!initial) {
    await emit("closed", { status: "expired" });
    return;
  }
  if (initial.status === "received") {
    await emit("result", buildResultPayload(initial, opts.renderCard));
    return;
  }

  await emit("waiting", { status: "pending" });

  const deadline = nowMs() + maxWaitMs;
  while (nowMs() < deadline) {
    await sleep(pollIntervalMs);
    const rec = await getRecord(kv, token);
    if (!rec) {
      await emit("closed", { status: "expired" });
      return;
    }
    if (rec.status === "received") {
      await emit("result", buildResultPayload(rec, opts.renderCard));
      return;
    }
  }
  await emit("closed", { status: "timeout" });
}
