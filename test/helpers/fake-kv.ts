/**
 * Minimal in-memory KVNamespace stand-in for the Node test pool (which has no
 * real KV binding). Implements only the surface the inbox store uses:
 * `get` / `put`. `expirationTtl` is recorded but not enforced — tests that need
 * expiry semantics drive them explicitly (e.g. by deleting a key).
 */
export class FakeKV {
  store = new Map<string, string>();
  puts: Array<{ key: string; value: string; ttl?: number }> = [];

  async get(key: string): Promise<string | null> {
    return this.store.has(key) ? (this.store.get(key) as string) : null;
  }

  async put(
    key: string,
    value: string,
    opts?: { expirationTtl?: number },
  ): Promise<void> {
    this.store.set(key, value);
    this.puts.push({ key, value, ttl: opts?.expirationTtl });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  /** Cast helper so call sites read cleanly. */
  asKv(): KVNamespace {
    return this as unknown as KVNamespace;
  }
}
