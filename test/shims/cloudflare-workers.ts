// Node-pool shim for the `cloudflare:workers` virtual module, which only
// exists inside the workerd runtime. The Node test pool imports `src/index.ts`
// (and therefore `RateLimiterDO`, which `extends DurableObject`), but those
// tests never instantiate the Durable Object — they exercise the in-memory
// limiter via `checkRateLimit` with no binding. This stub base class lets the
// class definition load under Node.
//
// The Workers pool does NOT apply this alias (see vitest.config.ts), so the
// real `cloudflare:workers` base class is used where the DO actually runs.
// `src/` typechecking also uses the real `@cloudflare/workers-types`
// declaration — this file is excluded from tsc (test/ is out of scope).
export class DurableObject<Env = unknown> {
  protected ctx: DurableObjectState;
  protected env: Env;
  constructor(ctx: DurableObjectState, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}
