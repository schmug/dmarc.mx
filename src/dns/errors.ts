// DNS lookup error, split into its own module so it can be imported without
// pulling in (or being shadowed by a test mock of) the DNS client. queryTxt /
// queryMx / queryDoh throw this for resolver errors (SERVFAIL/timeout) so
// callers can distinguish "lookup failed" from "record absent" (which is null).
// scan-budget.ts subclasses it; importing from here keeps that subclassing
// working even in tests that vi.mock("./client.js").
export class DnsLookupError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "DnsLookupError";
  }
}
