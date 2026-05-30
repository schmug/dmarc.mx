## 2024-05-27 - Initializing Bolt Journal
**Learning:** Initial journal setup.
**Action:** Always maintain performance learning journal.
## 2026-05-27 - Array pushing vs running sum in map
**Learning:** In Cloudflare Workers and Hono environments, maintaining a running sum and count directly in a Map is much more memory efficient than pushing thousands of values into an array and using .reduce(), drastically lowering GC pressure on hot paths.
**Action:** Always prefer maintaining running metrics (sum/count/min/max) in Maps or objects over array accumulation when bucketing metrics.
## 2024-05-30 - Array mapping vs for loops on hot paths
**Learning:** In Cloudflare Workers and Hono environments, using `.map()` on large arrays inside `db.batch()` creates an intermediate array of bound prepared statements and allocates an anonymous function per iteration. This significantly increases garbage collection (GC) pressure on hot paths, like the `cron` rescan routines that run batch insertions via `recordAlerts`.
**Action:** Prefer using a simple `for` loop to build the array of statements `[]` and `push` them, avoiding the `.map()` method's overhead on hot paths.
## 2024-05-30 - Object.values().filter().length vs for...in
**Learning:** In Cloudflare Workers and Hono environments, using `Object.values(obj).filter(...).length` to count matching object entries on hot paths (like `dkimFound` in the `orchestrator`, `scoring`, `html`, and `components`) creates intermediate array allocations. This increases garbage collection (GC) pressure unnecessarily.
**Action:** Always prefer using a simple `for...in` loop with an accumulator counter to iterate over object properties when you just need to count matches or filter specific values, drastically lowering GC pressure.
