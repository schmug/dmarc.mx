import type { RateLimiterDO } from "./rate-limit-do.js";

export interface Env {
  DB: D1Database;
  // Atomic per-identity rate-limit counter (GHSA-v7qc-7qh8-h69g). Optional so
  // self-host deploys without the binding fall back to the in-memory limiter
  // (see checkRateLimit in src/rate-limit.ts); the hosted dmarc.mx worker has
  // it wired in wrangler.toml.
  RATE_LIMITER?: DurableObjectNamespace<RateLimiterDO>;
  WORKOS_CLIENT_ID: string;
  WORKOS_CLIENT_SECRET: string;
  WORKOS_REDIRECT_URI: string;
  // WorkOS Management API key (Bearer), distinct from the OAuth client
  // secret. Used to delete the WorkOS identity record on account deletion
  // (issue #550). Optional: self-host deploys without it skip the WorkOS
  // delete step. Also doubles as the "is this the hosted prod worker"
  // sentinel that gates the /_dev/dashboard fixture route in src/index.ts.
  WORKOS_API_KEY?: string;
  SESSION_SECRET: string;
  SENTRY_DSN?: string;
  // Cloudflare Email Sending binding. Optional so self-host deploys without
  // a verified sender still boot; the dispatcher no-ops when absent.
  EMAIL?: SendEmail;
  // Stripe billing (Phase 3 M2). All three must be present for billing to
  // activate; isBillingEnabled() in src/billing/feature-flag.ts gates paid
  // code paths so self-hosters without Stripe keys still get a working
  // free-tier deploy.
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  STRIPE_PRICE_ID_PRO?: string;
  // Cloudflare Web Analytics token. Optional: when unset, the beacon script
  // is not injected. Set this on the hosted deploy (wrangler secret) to turn
  // on analytics. The token itself is non-secret (ends up in public HTML)
  // but lives here so self-host forks don't accidentally ship data to the
  // hosted tier's dashboard.
  CF_ANALYTICS_TOKEN?: string;
  // Self-host scoring rubric override (issue #25). A single JSON string of
  // ScoringConfig knobs (see src/shared/scoring-config.ts). Absent/invalid →
  // the shipped default rubric, so hosted dmarc.mx and config-less self-hosts
  // are unaffected. Parsed per request via parseScoringConfig().
  SCORING_CONFIG?: string;
  // Cloudflare Access enforcement on `*.workers.dev` preview-branch deploys.
  // Both must be set together — the middleware fail-CLOSEDs (503) on a
  // workers.dev hostname when either is missing. The production custom
  // domain (`dmarc.mx`) is not affected by these vars.
  ACCESS_AUD?: string;
  ACCESS_TEAM_DOMAIN?: string;
  // Spamhaus DQS key for DNSBL/IP-reputation checks (issue #587). Optional:
  // when absent, the DNSBL analyzer returns a clean "not configured" info
  // result and no outbound DNS queries are issued. Set via `wrangler secret
  // put DNSBL_DQS_KEY` — never add to [vars] (key must stay out of source).
  DNSBL_DQS_KEY?: string;
}
