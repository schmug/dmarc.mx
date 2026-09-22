import { d1Read } from "./retry.js";

export interface ApiKeyRow {
  id: string;
  user_id: string;
  name: string | null;
  prefix: string;
  hash: string;
  created_at: number;
  last_used_at: number | null;
  revoked_at: number | null;
}

export interface CreateApiKeyInput {
  id: string;
  userId: string;
  name: string | null;
  prefix: string;
  hash: string;
}

export async function createApiKey(
  db: D1Database,
  input: CreateApiKeyInput,
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO api_keys (id, user_id, name, prefix, hash) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(input.id, input.userId, input.name, input.prefix, input.hash)
    .run();
}

export async function listApiKeysByUser(
  db: D1Database,
  userId: string,
): Promise<ApiKeyRow[]> {
  const result = await d1Read(() =>
    db
      .prepare(
        "SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
      )
      .bind(userId)
      .all<ApiKeyRow>(),
  );
  return result.results;
}

// Looks up a key by its hash. Returns null when the key does not exist OR has
// been revoked — callers treat both the same (unauthorized).
export async function findActiveApiKeyByHash(
  db: D1Database,
  hash: string,
): Promise<Pick<ApiKeyRow, "id" | "user_id"> | null> {
  return d1Read(() =>
    db
      .prepare(
        "SELECT id, user_id FROM api_keys WHERE hash = ? AND revoked_at IS NULL",
      )
      .bind(hash)
      .first<Pick<ApiKeyRow, "id" | "user_id">>(),
  );
}

// Ownership check is enforced by the WHERE clause keying on both id and
// user_id, so a user cannot revoke another user's key by guessing its id.
export async function revokeApiKey(
  db: D1Database,
  keyId: string,
  userId: string,
): Promise<void> {
  await db
    .prepare(
      "UPDATE api_keys SET revoked_at = unixepoch() WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
    )
    .bind(keyId, userId)
    .run();
}

export async function touchApiKeyLastUsed(
  db: D1Database,
  keyId: string,
): Promise<void> {
  await db
    .prepare("UPDATE api_keys SET last_used_at = unixepoch() WHERE id = ?")
    .bind(keyId)
    .run();
}
