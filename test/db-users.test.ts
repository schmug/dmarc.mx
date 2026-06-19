import { beforeEach, describe, expect, it } from "vitest";
import {
  acknowledgeApiKeyRetirement,
  createUser,
  deleteUser,
  getUserByEmail,
  getUserById,
  type User,
} from "../src/db/users.js";

let store: Map<string, User>;

function makeD1Mock(): D1Database {
  const prepare = (sql: string) => {
    return {
      bind: (...params: unknown[]) => {
        return {
          run: async () => {
            if (/^INSERT INTO users/i.test(sql)) {
              const [id, email, email_domain, ackAt] = params as [
                string,
                string,
                string,
                number,
              ];
              store.set(id, {
                id,
                email,
                email_domain,
                stripe_customer_id: null,
                email_alerts_enabled: 1,
                api_key_retirement_acknowledged_at: ackAt,
                created_at: Math.floor(Date.now() / 1000),
              });
            } else if (
              /^UPDATE users SET api_key_retirement_acknowledged_at/i.test(sql)
            ) {
              const [ackAt, userId] = params as [number, string];
              const user = store.get(userId);
              if (user) {
                store.set(userId, {
                  ...user,
                  api_key_retirement_acknowledged_at: ackAt,
                });
              }
            } else if (/^DELETE FROM users WHERE id = \?/i.test(sql)) {
              const [userId] = params as [string];
              store.delete(userId);
            }
            return { success: true };
          },
          first: async <T>(): Promise<T | null> => {
            if (/WHERE id = \?/i.test(sql)) {
              const [id] = params as [string];
              return (store.get(id) as T | undefined) ?? null;
            }
            if (/WHERE email = \?/i.test(sql)) {
              const [email] = params as [string];
              for (const user of store.values()) {
                if (user.email === email) return user as T;
              }
              return null;
            }
            return null;
          },
        };
      },
    };
  };

  return { prepare } as unknown as D1Database;
}

describe("db/users", () => {
  let db: D1Database;

  beforeEach(() => {
    store = new Map();
    db = makeD1Mock();
  });

  describe("createUser + getUserById", () => {
    it("creates a user and retrieves it by id", async () => {
      await createUser(db, { id: "user-1", email: "alice@example.com" });
      const user = await getUserById(db, "user-1");

      expect(user).not.toBeNull();
      expect(user?.id).toBe("user-1");
      expect(user?.email).toBe("alice@example.com");
    });

    it("extracts email_domain from the email address", async () => {
      await createUser(db, { id: "user-2", email: "bob@dmarc.mx" });
      const user = await getUserById(db, "user-2");

      expect(user?.email_domain).toBe("dmarc.mx");
    });

    it("pre-acks API-key retirement for new users so the banner doesn't show for them", async () => {
      const before = Math.floor(Date.now() / 1000);
      await createUser(db, { id: "user-3", email: "carol@test.org" });
      const user = await getUserById(db, "user-3");

      expect(user?.stripe_customer_id).toBeNull();
      expect(user?.api_key_retirement_acknowledged_at).not.toBeNull();
      expect(user?.api_key_retirement_acknowledged_at).toBeGreaterThanOrEqual(
        before,
      );
    });
  });

  describe("getUserByEmail", () => {
    it("retrieves an existing user by email", async () => {
      await createUser(db, { id: "user-4", email: "dave@example.com" });
      const user = await getUserByEmail(db, "dave@example.com");

      expect(user).not.toBeNull();
      expect(user?.id).toBe("user-4");
    });

    it("returns null for an unknown email", async () => {
      const user = await getUserByEmail(db, "nobody@example.com");
      expect(user).toBeNull();
    });
  });

  describe("getUserById", () => {
    it("returns null for a non-existent id", async () => {
      const user = await getUserById(db, "does-not-exist");
      expect(user).toBeNull();
    });
  });

  describe("deleteUser", () => {
    it("hard-deletes the user row by id (no soft-delete)", async () => {
      await createUser(db, { id: "user-del", email: "del@example.com" });
      expect(await getUserById(db, "user-del")).not.toBeNull();

      await deleteUser(db, "user-del");

      expect(await getUserById(db, "user-del")).toBeNull();
    });

    it("only deletes the targeted id, leaving other users intact", async () => {
      await createUser(db, { id: "victim", email: "victim@example.com" });
      await createUser(db, { id: "target", email: "target@example.com" });

      await deleteUser(db, "target");

      expect(await getUserById(db, "target")).toBeNull();
      expect(await getUserById(db, "victim")).not.toBeNull();
    });
  });

  describe("acknowledgeApiKeyRetirement", () => {
    it("stamps api_key_retirement_acknowledged_at with a unix-second timestamp", async () => {
      await createUser(db, { id: "user-5", email: "eve@example.com" });
      // Force the ack to null (simulating a pre-migration legacy user)
      const user = store.get("user-5");
      if (user) {
        store.set("user-5", {
          ...user,
          api_key_retirement_acknowledged_at: null,
        });
      }

      const before = Math.floor(Date.now() / 1000);
      await acknowledgeApiKeyRetirement(db, "user-5");
      const after = await getUserById(db, "user-5");

      expect(after?.api_key_retirement_acknowledged_at).not.toBeNull();
      expect(after?.api_key_retirement_acknowledged_at).toBeGreaterThanOrEqual(
        before,
      );
    });
  });
});
