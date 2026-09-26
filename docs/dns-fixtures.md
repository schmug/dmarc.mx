# DNS fixtures: reproducing a scan offline

A scan is only as debuggable as it is repeatable. Live DNS changes under you, so
"I cannot reproduce it" is the normal outcome of a grade complaint filed hours
after the fact. A fixture freezes one domain's DNS at one moment, so the same
scan produces the same grade every time and a fix can be proven rather than
asserted. See #655.

## Record

```
npm run record -- example.com                 # plus optional DKIM selectors:
npm run record -- example.com selector1,s2
```

This runs one real scan, captures every query the scan actually made — including
names derived at runtime such as SPF `include:` chains and DKIM selectors — and
writes `test/fixtures/dns/example.com.json`. Keys are sorted and field order is
fixed, so re-recording unchanged DNS produces a byte-identical file: a diff only
appears when the domain's DNS really changed.

A scan that throws is still recorded. Captured error answers are how a
resolver-failure bug gets reproduced at all.

Record from somewhere with working outbound DNS. In a sandboxed environment
without it, recording succeeds but captures a file full of `ECONNREFUSED`
answers, which replays faithfully and tells you nothing about the domain. If
every answer in a fresh recording carries a `lookup_error`, that is the
environment, not the domain.

## Replay

```ts
import { loadFixture, fixturePath } from "../scripts/fixtures.js";
import { scanFromFixture } from "../src/orchestrator.js";

const result = await scanFromFixture(loadFixture(fixturePath("example.com")));
expect(result.grade).toBe("B");
```

With a fixture installed, the four query functions in `src/dns/client.ts` answer
from it and the scan reaches the network zero times. A name the fixture does not
cover throws `FixtureMissError` instead of falling back to the wire — an
incomplete fixture fails loudly rather than quietly going live, which is the only
reason the offline guarantee can be trusted.

`scanFromFixture` takes a parsed fixture, not a path: `src/orchestrator.ts` is
bundled into the Worker, where `node:fs` does not exist. Node-side file I/O lives
in `scripts/fixtures.ts`.

## Secrets

The Spamhaus DQS key is part of the DNSBL query name by Spamhaus design. Fixture
keys for DNSBL lookups are recorded without it (`DNSBL <reversed-ip> <zone>`), so
a committed fixture never carries the key. Check any new fixture for it anyway
before committing.

## Where the seam is

The eight analyzers import the query functions directly from
`src/dns/client.js`, so there is no per-scan client object to inject. Both record
and replay therefore hook in one place, `throughFixture()` in
`src/dns/client.ts`, via `src/dns/replay.ts`. Neither hook is installed in
production, where the path is a single `null` check before the live query.
