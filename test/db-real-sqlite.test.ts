import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import {
  isStripeEventRecorded,
  recordStripeEventOnce,
} from "../src/db/subscriptions.js";

// The D1 mocks elsewhere match SQL by regex and never parse it, so a query
// SQLite rejects (e.g. `AS exists`, a reserved word) can pass every test and
// still fail in production. These run the real statements on real SQLite.
function realD1(): D1Database {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec(readFileSync("src/db/schema.sql", "utf8"));
  const prepare = (sql: string) => {
    const stmt = sqlite.prepare(sql);
    return {
      bind: (...params: (string | number | null)[]) => ({
        first: async () => stmt.get(...params) ?? null,
        all: async () => ({ results: stmt.all(...params) }),
        run: async () => ({ meta: { changes: stmt.run(...params).changes } }),
      }),
    };
  };
  return { prepare } as unknown as D1Database;
}

describe("stripe_events queries on real SQLite", () => {
  it("records an event once and reports it as recorded", async () => {
    const db = realD1();
    expect(await isStripeEventRecorded(db, "evt_1")).toBe(false);
    expect(await recordStripeEventOnce(db, "evt_1")).toBe(true);
    expect(await recordStripeEventOnce(db, "evt_1")).toBe(false);
    expect(await isStripeEventRecorded(db, "evt_1")).toBe(true);
  });
});
