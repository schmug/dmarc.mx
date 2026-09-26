// Fixture-backed DNS replay (#655).
//
// The eight analyzers import the query functions from ./client.js as module
// functions, so there is no per-scan client to inject. The seam therefore lives
// here: setFixtureSource() installs a fixture, and client.ts consults it before
// any outbound query. With a fixture installed, a scan reaches the network zero
// times — a miss throws FixtureMissError rather than falling back to the wire,
// which is what makes that claim testable instead of aspirational.

import type { DohResponse } from "./client.js";
import type { MxRecord, TxtRecord } from "./types.js";

/** A recorded answer: the resolved value, or an error code to replay. */
export type FixtureAnswer<T> =
  | { value: T | null }
  | { error: { code: string; message: string } };

export interface DnsFixture {
  /** Domain the fixture was recorded for. */
  domain: string;
  /** ISO timestamp of the recording, for staleness triage only. */
  recordedAt: string;
  /** Keyed by `TXT <name>`, `MX <name>`, `DOH <type> <name>`, `DNSBL <zone>`. */
  answers: Record<string, FixtureAnswer<unknown>>;
}

export class FixtureMissError extends Error {
  constructor(key: string, domain: string) {
    super(
      `DNS fixture for ${domain} has no answer for "${key}". ` +
        `Re-record it with: npm run record -- ${domain}`,
    );
    this.name = "FixtureMissError";
  }
}

let active: DnsFixture | null = null;
let lookups = 0;
let recorder: ((key: string, answer: FixtureAnswer<unknown>) => void) | null =
  null;

/**
 * Install a capture hook. scripts/record-fixture.ts uses it to build a fixture
 * from one live scan; it is a no-op in production because nothing else calls it.
 */
export function setRecorder(
  fn: ((key: string, answer: FixtureAnswer<unknown>) => void) | null,
): void {
  recorder = fn;
}

export function capture(key: string, answer: FixtureAnswer<unknown>): void {
  recorder?.(key, answer);
}

export function setFixtureSource(fixture: DnsFixture | null): void {
  active = fixture;
  lookups = 0;
}

export function activeFixture(): DnsFixture | null {
  return active;
}

/** Number of fixture lookups since the fixture was installed. */
export function fixtureLookupCount(): number {
  return lookups;
}

export function txtKey(name: string): string {
  return `TXT ${name.toLowerCase()}`;
}

export function mxKey(name: string): string {
  return `MX ${name.toLowerCase()}`;
}

export function dohKey(name: string, type: string): string {
  return `DOH ${type.toUpperCase()} ${name.toLowerCase()}`;
}

/** The DQS key is a secret and never part of a fixture key. */
export function dnsblKey(reversedIp: string, zone: string): string {
  return `DNSBL ${reversedIp} ${zone.toLowerCase()}`;
}

/**
 * Resolve `key` from the active fixture. Returns undefined when no fixture is
 * installed, so callers fall through to the real network.
 */
export function replay<T>(key: string): FixtureAnswer<T> | undefined {
  if (!active) return undefined;
  lookups += 1;
  const answer = active.answers[key];
  if (!answer) throw new FixtureMissError(key, active.domain);
  return answer as FixtureAnswer<T>;
}

// Narrow helpers exist so client.ts stays free of casts.
export type TxtAnswer = FixtureAnswer<TxtRecord>;
export type MxAnswer = FixtureAnswer<MxRecord[]>;
export type DohAnswer = FixtureAnswer<DohResponse>;
export type DnsblAnswer = FixtureAnswer<string[]>;
