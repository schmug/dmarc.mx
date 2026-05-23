import { beforeEach, describe, expect, it } from "vitest";
import {
  type AlertRow,
  acknowledgeAlert,
  countUnacknowledgedByDomain,
  listUnacknowledgedForUser,
  listUnsentAlerts,
  markAlertNotified,
  recordAlert,
  recordAlerts,
} from "../src/db/alerts.js";

let alertStore: Map<number, AlertRow>;
let domainStore: Map<number, { id: number; user_id: string; domain: string }>;
let nextId: number;

function makeD1Mock(): D1Database {
  const prepare = (sql: string) => ({
    bind: (...params: unknown[]) => ({
      run: async () => {
        if (/^INSERT INTO alerts/i.test(sql)) {
          const [domainId, type, prevVal, newVal, createdAt] = params as [
            number,
            string,
            string,
            string,
            number,
          ];
          const id = nextId++;
          alertStore.set(id, {
            id,
            domain_id: domainId,
            alert_type: type,
            previous_value: prevVal,
            new_value: newVal,
            notified_via: null,
            acknowledged_at: null,
            created_at: createdAt,
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (/^UPDATE alerts SET notified_via/i.test(sql)) {
          const [channel, id] = params as [string, number];
          const row = alertStore.get(id);
          if (row) alertStore.set(id, { ...row, notified_via: channel });
          return { success: true, meta: { changes: row ? 1 : 0 } };
        }
        if (/^\s*UPDATE alerts\s+SET acknowledged_at/i.test(sql)) {
          const [now, alertId, userId] = params as [number, number, string];
          const row = alertStore.get(alertId);
          if (!row || row.acknowledged_at !== null) {
            return { success: true, meta: { changes: 0 } };
          }
          const ownerDomain = domainStore.get(row.domain_id);
          if (!ownerDomain || ownerDomain.user_id !== userId) {
            return { success: true, meta: { changes: 0 } };
          }
          alertStore.set(alertId, { ...row, acknowledged_at: now });
          return { success: true, meta: { changes: 1 } };
        }
        return { success: true, meta: { changes: 0 } };
      },
      all: async <T>(): Promise<{ results: T[] }> => {
        // listUnacknowledgedForUser: filters on user_id + acknowledged_at
        if (
          /acknowledged_at IS NULL[\s\S]*ORDER BY a\.created_at DESC/i.test(sql)
        ) {
          const [userId, limit] = params as [string, number];
          const rows = [...alertStore.values()]
            .filter((a) => {
              const d = domainStore.get(a.domain_id);
              return (
                a.acknowledged_at === null &&
                d !== undefined &&
                d.user_id === userId
              );
            })
            .sort((a, b) => b.created_at - a.created_at)
            .slice(0, limit)
            .map((a) => ({
              ...a,
              domain: domainStore.get(a.domain_id)?.domain ?? "",
            }));
          return { results: rows as T[] };
        }
        // countUnacknowledgedByDomain: GROUP BY a.domain_id
        if (/GROUP BY a\.domain_id/i.test(sql)) {
          const [userId] = params as [string];
          const counts = new Map<number, number>();
          for (const a of alertStore.values()) {
            if (a.acknowledged_at !== null) continue;
            const d = domainStore.get(a.domain_id);
            if (!d || d.user_id !== userId) continue;
            counts.set(a.domain_id, (counts.get(a.domain_id) ?? 0) + 1);
          }
          const rows = [...counts.entries()].map(([domain_id, count]) => ({
            domain_id,
            count,
          }));
          return { results: rows as T[] };
        }
        // listUnsentAlerts (legacy): filters on notified_via
        if (
          /notified_via IS NULL[\s\S]*ORDER BY a\.created_at ASC/i.test(sql)
        ) {
          const [limit] = params as [number];
          const rows = [...alertStore.values()]
            .filter((a) => a.notified_via === null)
            .sort((a, b) => a.created_at - b.created_at)
            .slice(0, limit)
            .map((a) => {
              const d = domainStore.get(a.domain_id);
              return {
                ...a,
                user_id: d?.user_id ?? "",
                domain: d?.domain ?? "",
              };
            });
          return { results: rows as T[] };
        }
        return { results: [] };
      },
    }),
  });
  return {
    prepare,
    batch: async (
      stmts: Array<{ run: () => Promise<{ success: boolean }> }>,
    ) => {
      for (const stmt of stmts) await stmt.run();
      return [];
    },
  } as unknown as D1Database;
}

describe("db/alerts", () => {
  let db: D1Database;

  beforeEach(() => {
    alertStore = new Map();
    domainStore = new Map([
      [7, { id: 7, user_id: "user_1", domain: "example.com" }],
      [9, { id: 9, user_id: "user_2", domain: "other.com" }],
    ]);
    nextId = 1;
    db = makeD1Mock();
  });

  describe("recordAlerts", () => {
    it("inserts multiple alerts in a single batch", async () => {
      await recordAlerts(db, [
        {
          domainId: 7,
          type: "grade_drop",
          previousValue: "A",
          newValue: "C",
          createdAt: 1_700_000_000,
        },
        {
          domainId: 9,
          type: "protocol_regression",
          previousValue: "dmarc:pass",
          newValue: "dmarc:fail",
          createdAt: 1_700_000_001,
        },
      ]);

      expect(alertStore.size).toBe(2);

      const rows = [...alertStore.values()];
      expect(rows[0].domain_id).toBe(7);
      expect(rows[0].alert_type).toBe("grade_drop");
      expect(rows[0].created_at).toBe(1_700_000_000);

      expect(rows[1].domain_id).toBe(9);
      expect(rows[1].alert_type).toBe("protocol_regression");
      expect(rows[1].created_at).toBe(1_700_000_001);
    });

    it("does nothing when given an empty array", async () => {
      await recordAlerts(db, []);
      expect(alertStore.size).toBe(0);
    });
  });

  describe("recordAlert", () => {
    it("inserts a grade_drop alert with the given values", async () => {
      await recordAlert(db, {
        domainId: 7,
        type: "grade_drop",
        previousValue: "A",
        newValue: "C",
        createdAt: 1_700_000_000,
      });

      expect(alertStore.size).toBe(1);
      const row = [...alertStore.values()][0];
      expect(row.domain_id).toBe(7);
      expect(row.alert_type).toBe("grade_drop");
      expect(row.previous_value).toBe("A");
      expect(row.new_value).toBe("C");
      expect(row.notified_via).toBeNull();
      expect(row.acknowledged_at).toBeNull();
      expect(row.created_at).toBe(1_700_000_000);
    });

    it("defaults createdAt to current unix time", async () => {
      const before = Math.floor(Date.now() / 1000);
      await recordAlert(db, {
        domainId: 7,
        type: "protocol_regression",
        previousValue: "dmarc:pass",
        newValue: "dmarc:fail",
      });
      const after = Math.floor(Date.now() / 1000);
      const row = [...alertStore.values()][0];
      expect(row.created_at).toBeGreaterThanOrEqual(before);
      expect(row.created_at).toBeLessThanOrEqual(after);
    });
  });

  describe("listUnsentAlerts", () => {
    it("returns only alerts with notified_via IS NULL, oldest first", async () => {
      await recordAlert(db, {
        domainId: 7,
        type: "grade_drop",
        previousValue: "A",
        newValue: "B",
        createdAt: 100,
      });
      await recordAlert(db, {
        domainId: 9,
        type: "grade_drop",
        previousValue: "B",
        newValue: "C",
        createdAt: 50,
      });
      await recordAlert(db, {
        domainId: 7,
        type: "grade_drop",
        previousValue: "C",
        newValue: "D",
        createdAt: 200,
      });

      await markAlertNotified(db, 1, "email");

      const unsent = await listUnsentAlerts(db);
      expect(unsent.map((a) => a.id)).toEqual([2, 3]);
      expect(unsent[0].user_id).toBe("user_2");
      expect(unsent[0].domain).toBe("other.com");
    });

    it("respects the limit", async () => {
      for (let i = 0; i < 5; i++) {
        await recordAlert(db, {
          domainId: 7,
          type: "grade_drop",
          previousValue: "A",
          newValue: "B",
          createdAt: 100 + i,
        });
      }
      const unsent = await listUnsentAlerts(db, 2);
      expect(unsent).toHaveLength(2);
    });
  });

  describe("markAlertNotified", () => {
    it("sets notified_via on the target row only", async () => {
      await recordAlert(db, {
        domainId: 7,
        type: "grade_drop",
        previousValue: "A",
        newValue: "B",
        createdAt: 100,
      });
      await recordAlert(db, {
        domainId: 7,
        type: "grade_drop",
        previousValue: "B",
        newValue: "C",
        createdAt: 101,
      });

      await markAlertNotified(db, 1, "email");

      expect(alertStore.get(1)?.notified_via).toBe("email");
      expect(alertStore.get(2)?.notified_via).toBeNull();
    });
  });

  describe("listUnacknowledgedForUser", () => {
    it("returns only the requesting user's unacknowledged alerts, newest first", async () => {
      await recordAlert(db, {
        domainId: 7, // user_1
        type: "grade_drop",
        previousValue: "A",
        newValue: "B",
        createdAt: 100,
      });
      await recordAlert(db, {
        domainId: 7,
        type: "grade_drop",
        previousValue: "B",
        newValue: "C",
        createdAt: 200,
      });
      await recordAlert(db, {
        domainId: 9, // user_2 — must NOT appear for user_1
        type: "grade_drop",
        previousValue: "A",
        newValue: "F",
        createdAt: 300,
      });

      const rows = await listUnacknowledgedForUser(db, "user_1");
      expect(rows.map((r) => r.id)).toEqual([2, 1]); // DESC by created_at
      expect(rows.every((r) => r.domain === "example.com")).toBe(true);
    });

    it("excludes already-acknowledged alerts", async () => {
      await recordAlert(db, {
        domainId: 7,
        type: "grade_drop",
        previousValue: "A",
        newValue: "B",
        createdAt: 100,
      });
      await acknowledgeAlert(db, "user_1", 1, 999);

      const rows = await listUnacknowledgedForUser(db, "user_1");
      expect(rows).toEqual([]);
    });

    it("respects the limit", async () => {
      for (let i = 0; i < 5; i++) {
        await recordAlert(db, {
          domainId: 7,
          type: "grade_drop",
          previousValue: "A",
          newValue: "B",
          createdAt: 100 + i,
        });
      }
      const rows = await listUnacknowledgedForUser(db, "user_1", 2);
      expect(rows).toHaveLength(2);
    });
  });

  describe("acknowledgeAlert", () => {
    beforeEach(async () => {
      await recordAlert(db, {
        domainId: 7, // user_1
        type: "grade_drop",
        previousValue: "A",
        newValue: "C",
        createdAt: 100,
      });
    });

    it("returns true and sets acknowledged_at on first call", async () => {
      const ok = await acknowledgeAlert(db, "user_1", 1, 555);
      expect(ok).toBe(true);
      expect(alertStore.get(1)?.acknowledged_at).toBe(555);
    });

    it("is idempotent: second call returns false without overwriting timestamp", async () => {
      await acknowledgeAlert(db, "user_1", 1, 555);
      const second = await acknowledgeAlert(db, "user_1", 1, 999);
      expect(second).toBe(false);
      expect(alertStore.get(1)?.acknowledged_at).toBe(555);
    });

    it("returns false for another user's alert id (IDOR)", async () => {
      const ok = await acknowledgeAlert(db, "user_2", 1, 555);
      expect(ok).toBe(false);
      expect(alertStore.get(1)?.acknowledged_at).toBeNull();
    });

    it("returns false for a nonexistent alert id", async () => {
      const ok = await acknowledgeAlert(db, "user_1", 999, 555);
      expect(ok).toBe(false);
    });
  });

  describe("countUnacknowledgedByDomain", () => {
    it("groups unacknowledged alerts by domain id and excludes other users", async () => {
      await recordAlert(db, {
        domainId: 7,
        type: "grade_drop",
        previousValue: "A",
        newValue: "B",
        createdAt: 100,
      });
      await recordAlert(db, {
        domainId: 7,
        type: "grade_drop",
        previousValue: "B",
        newValue: "C",
        createdAt: 200,
      });
      await recordAlert(db, {
        domainId: 9, // user_2's domain — must not appear
        type: "grade_drop",
        previousValue: "A",
        newValue: "F",
        createdAt: 300,
      });

      const counts = await countUnacknowledgedByDomain(db, "user_1");
      expect(counts.get(7)).toBe(2);
      expect(counts.has(9)).toBe(false);
    });

    it("excludes acknowledged alerts from the count", async () => {
      await recordAlert(db, {
        domainId: 7,
        type: "grade_drop",
        previousValue: "A",
        newValue: "B",
        createdAt: 100,
      });
      await recordAlert(db, {
        domainId: 7,
        type: "grade_drop",
        previousValue: "B",
        newValue: "C",
        createdAt: 200,
      });
      await acknowledgeAlert(db, "user_1", 1, 999);

      const counts = await countUnacknowledgedByDomain(db, "user_1");
      expect(counts.get(7)).toBe(1);
    });
  });
});
