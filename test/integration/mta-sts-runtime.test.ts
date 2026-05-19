import { describe, expect, it } from "vitest";
import { analyzeMtaSts } from "../../src/analyzers/mta-sts.js";

// This file runs inside the Cloudflare Workers runtime via
// `@cloudflare/vitest-pool-workers`. Unlike the Node-pool tests in
// `test/mta-sts.test.ts` (which mock DNS and `globalThis.fetch`), these
// tests exercise the real `workerd` fetch implementation end-to-end against
// the project's own production DNS and HTTPS endpoints.
//
// Why this exists:
// The MTA-STS `redirect: "error"` regression (PRs #58 and #92, fixed in
// commit 2b47fe7 and again in PR #104) throws a TypeError in the Workers
// fetch runtime but works fine in Node's global fetch. Mocked unit tests
// never saw it. A proper runtime test can't just check "analyzeMtaSts did
// not throw" either, because `fetchPolicy` has a try/catch that swallows
// the error and returns `null` — the caller would see a "policy not
// accessible" result, which is also a legitimate real-world outcome. So
// the only way to catch the regression class is to require *success*:
// fetch must return a parseable policy. This means the test needs a real
// target with a real MTA-STS record.
//
// Target: dmarc.mx (this project's own production domain). Self-scanning
// also acts as a canary on dmarcheck's production DMARC/SPF/MTA-STS
// configuration — if the MTA-STS record ever stops responding, CI tells
// you before users notice.
describe("analyzeMtaSts (runs inside real workerd runtime)", () => {
  it.skipIf(!process.env.CI)(
    "successfully fetches and parses the dmarc.mx MTA-STS policy (regression guard for #58/#92)",
    async () => {
      const result = await analyzeMtaSts("dmarc.mx");

      // Key assertion — the fetch must have completed successfully inside
      // the Workers runtime. If a future change reintroduces
      // `redirect: "error"`, workerd throws at the fetch call, fetchPolicy's
      // try/catch swallows it, `policy` becomes `null`, and this fails.
      expect(result.policy).not.toBeNull();
      expect(result.policy?.version).toBe("STSv1");
      expect(result.dns_record).not.toBeNull();

      // The analyzer should not have produced a failure-level validation
      // about the policy being unreachable. (Warnings about mode/max_age
      // are fine; they're mode-dependent.)
      const unreachable = result.validations.find(
        (v) =>
          v.status === "fail" &&
          v.message.includes("Policy file not accessible"),
      );
      expect(unreachable).toBeUndefined();
    },
    15_000,
  );
});
