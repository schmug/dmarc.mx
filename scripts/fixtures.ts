// Node-side fixture I/O for the DNS replay harness (#655).
// Kept out of src/ because the Worker bundle has no node:fs.

import { readFileSync, writeFileSync } from "node:fs";
import type { DnsFixture } from "../src/dns/replay.js";

export function fixturePath(domain: string): string {
  return new URL(
    `../test/fixtures/dns/${domain.toLowerCase()}.json`,
    import.meta.url,
  ).pathname;
}

export function loadFixture(path: string): DnsFixture {
  return JSON.parse(readFileSync(path, "utf8")) as DnsFixture;
}

// Sorted keys and a fixed field order, so re-recording unchanged DNS produces a
// byte-identical file and a real change is the only thing a diff can show.
export function serializeFixture(fixture: DnsFixture): string {
  const answers: DnsFixture["answers"] = {};
  for (const key of Object.keys(fixture.answers).sort()) {
    answers[key] = fixture.answers[key];
  }
  return `${JSON.stringify(
    { domain: fixture.domain, recordedAt: fixture.recordedAt, answers },
    null,
    2,
  )}\n`;
}

export function saveFixture(path: string, fixture: DnsFixture): void {
  writeFileSync(path, serializeFixture(fixture));
}
