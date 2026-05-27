## 2024-05-27 - Initializing Bolt Journal
**Learning:** Initial journal setup.
**Action:** Always maintain performance learning journal.
## 2026-05-27 - Array pushing vs running sum in map
**Learning:** In Cloudflare Workers and Hono environments, maintaining a running sum and count directly in a Map is much more memory efficient than pushing thousands of values into an array and using .reduce(), drastically lowering GC pressure on hot paths.
**Action:** Always prefer maintaining running metrics (sum/count/min/max) in Maps or objects over array accumulation when bucketing metrics.
