// WorkOS User Management API client. dmarcheck is a WorkOS AuthKit relying
// party; the user id we store (session.sub === users.id) IS the WorkOS user
// id, so identity erasure is a single Management API call (issue #550).
//
// Requires the `WORKOS_API_KEY` secret (distinct from the public client id /
// client secret used in the OAuth login flow). Optional: self-host deploys
// without the key skip WorkOS deletion entirely (see account deletion).

const WORKOS_BASE_URL = "https://api.workos.com";

// Deletes the WorkOS identity record for `userId`. Resolves on success and on
// 404 (the identity is already gone — deletion is idempotent). Throws on any
// other non-2xx so the caller can log + flag the user for a retry sweep WITHOUT
// rolling back the already-completed local D1 erasure (our local-erasure
// promise is what we directly control).
export async function deleteWorkosUser(
  apiKey: string,
  userId: string,
): Promise<void> {
  const res = await fetch(
    `${WORKOS_BASE_URL}/user_management/users/${encodeURIComponent(userId)}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${apiKey}` },
    },
  );
  if (res.ok || res.status === 404) return;
  throw new Error(`WorkOS user deletion failed: ${res.status}`);
}
