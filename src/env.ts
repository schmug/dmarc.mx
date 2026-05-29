export interface Env {
  DB: D1Database;
  WORKOS_CLIENT_ID: string;
  WORKOS_CLIENT_SECRET: string;
  WORKOS_REDIRECT_URI: string;
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
}
