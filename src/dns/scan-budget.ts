import { DnsLookupError } from "./errors.js";

// GHSA-f828-8wf8-vqp2 — orchestrator-level DoS umbrella.
//
// Per-analyzer guards (SPF's 10-lookup cap, DKIM's selector cap, DMARC's
// rua/ruf cap) each bound ONE analyzer in isolation. They do not bound the
// SUM across analyzers, nor the overall wall-clock. A single request that
// combines a large input surface (many DKIM selectors + a rua/ruf-stuffed
// _dmarc record on an attacker-controlled domain) could otherwise drive a
// large outbound-DNS burst on one rate-limit token.
//
// `ScanBudget` is the shared backstop: one instance per scan() / scanStreaming()
// threaded through every analyzer into the DNS client, so the TOTAL number of
// outbound queries is capped regardless of input, and no new query is issued
// once the overall scan deadline has fired.

export interface ScanLimits {
  /** Max outbound DNS queries (TXT + MX + DoH) drawn from one shared pool. */
  readonly maxDnsQueries: number;
  /** Max overall wall-clock for the whole scan, in milliseconds. */
  readonly deadlineMs: number;
}

// Defaults sized for a real multi-analyzer scan of a legitimate domain. DKIM
// alone probes ~37 common selectors; SPF can walk up to 10 includes; DANE
// queries once per MX host. ~150 leaves comfortable headroom for an honest
// scan while still capping attacker amplification two orders of magnitude
// below the worst case. The 12s deadline sits inside the ~10-15s target and
// well above the per-query 3s DNS timeout, so legitimate slow-but-answering
// resolvers still complete.
export const DEFAULT_SCAN_LIMITS: ScanLimits = {
  maxDnsQueries: 150,
  deadlineMs: 12_000,
};

// Both budget errors extend DnsLookupError so analyzers that already catch
// DnsLookupError (dmarc, spf, mx, dnssec, dane, tls-rpt) surface them as a
// "could not verify" warning rather than a false "not configured", and the
// orchestrator's per-analyzer settle() turns any uncaught throw into a
// synthetic fail result. Either way the breach degrades gracefully.

/** Thrown by {@link ScanBudget.consume} when the shared query pool is empty. */
export class ScanBudgetError extends DnsLookupError {
  constructor() {
    super("BUDGET_EXCEEDED", "Per-scan DNS query budget exhausted");
    this.name = "ScanBudgetError";
  }
}

/** Thrown by {@link ScanBudget.consume} once the overall scan deadline fires. */
export class ScanDeadlineError extends DnsLookupError {
  constructor() {
    super("SCAN_DEADLINE", "Scan deadline exceeded");
    this.name = "ScanDeadlineError";
  }
}

/**
 * A per-scan, shared pool of DNS-query permits plus a deadline signal. One
 * instance is created per scan and threaded through every analyzer into the
 * DNS client. Each outbound query reserves one permit via {@link consume};
 * once the pool is exhausted or the deadline has fired, consume() throws
 * WITHOUT issuing anything, so total work cannot scale with attacker input.
 *
 * Instances are per-scan (never module-global) because a Workers isolate
 * serves many concurrent requests — a shared counter would leak one scan's
 * usage into another.
 */
export class ScanBudget {
  private used = 0;

  constructor(
    private readonly maxQueries: number,
    private readonly signal?: AbortSignal,
  ) {}

  /** Number of permits consumed so far. */
  get queriesUsed(): number {
    return this.used;
  }

  /** True once the pool is empty. */
  get exhausted(): boolean {
    return this.used >= this.maxQueries;
  }

  /**
   * Reserve one query permit. Throws {@link ScanDeadlineError} if the deadline
   * has fired or {@link ScanBudgetError} if the pool is empty — in both cases
   * before any outbound query is made.
   */
  consume(): void {
    if (this.signal?.aborted) throw new ScanDeadlineError();
    if (this.used >= this.maxQueries) throw new ScanBudgetError();
    this.used++;
  }
}
