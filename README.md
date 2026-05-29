<p align="center">
  <img src="https://dmarc.mx/logo.svg" alt="DMarcus — the dmarcheck mascot" width="120" height="120">
</p>

<h1 align="center">dmarcheck</h1>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://dmarc.mx"><img src="https://img.shields.io/badge/Cloudflare%20Workers-Deployed-f38020?logo=cloudflare" alt="Deploy to Cloudflare Workers"></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-5.7-blue?logo=typescript" alt="TypeScript"></a>
  <a href="https://deepwiki.com/schmug/dmarcheck"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
</p>

DNS email security analyzer — checks DMARC, SPF, DKIM, BIMI, and MTA-STS records for any domain.

Meet **DMarcus**, the @ creature who guards your inbox.

**Live at [dmarc.mx](https://dmarc.mx)**

## Three ways to use dmarcheck

|  | Where | What you get |
|---|---|---|
| **Free scanner** | [dmarc.mx](https://dmarc.mx) | Unlimited on-demand scans, JSON API, 10 req/min per IP |
| **Pro — $19/mo** | [dmarc.mx/pricing](https://dmarc.mx/pricing) | Nightly monitoring (25 domains), email alerts on grade drops, saved history, bulk scan, 60 req/hour API key |
| **Self-host** | this repo | Clone, `wrangler deploy`, run your own. MIT-licensed. Pro features activate when you configure D1 / WorkOS / Stripe bindings — optional, see [below](#optional-paid-tier-env-vars). |

The hosted tier at `dmarc.mx` exists for people who'd rather pay than run it. Everything is MIT and there is no crippled-OSS / paid-premium split.

## Features

- **DMARC** — Policy parsing, validation, reporting URI checks
- **SPF** — Full recursive include chain resolution, 10-lookup limit tracking, misconfiguration detection
- **DKIM** — Auto-probes ~30 common selectors + custom selectors, key strength analysis
- **BIMI** — Logo and VMC validation, DMARC policy cross-check
- **MTA-STS** — DNS record + HTTPS policy file fetch and validation

### Dual Output

- **JSON API** for developers — `curl https://dmarc.mx/api/check?domain=dmarc.mx`
- **Interactive HTML report** for browsers — expandable protocol cards, SPF include tree, educational tooltips

### Grading

Letter grades from A+ to F. DMARC is the gatekeeper — no DMARC record or `p=none` is an automatic F.

| Grade | Criteria |
|-------|----------|
| **A+** | All five protocols fully configured and validated |
| **A** | DMARC reject, SPF valid with hardfail, DKIM found, + BIMI or MTA-STS |
| **B** | DMARC reject, SPF + DKIM present |
| **C** | DMARC quarantine, SPF + DKIM present |
| **D** | DMARC quarantine but missing SPF or DKIM |
| **F** | No DMARC record or `p=none` |

## What is email security?

New to DMARC, SPF, and DKIM? Cloudflare has a great primer: [What are DMARC, DKIM, and SPF?](https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/)

### Message header analyzers

Once your DNS records are configured, you can verify authentication results in actual email headers:

- [Google Admin Toolbox — Message Header Analyzer](https://toolbox.googleapps.com/apps/messageheader/)
- [Microsoft Remote Connectivity Analyzer — Message Header](https://mha.azurewebsites.net/)

## API

```bash
# JSON response
curl https://dmarc.mx/api/check?domain=dmarc.mx

# With custom DKIM selectors
curl "https://dmarc.mx/api/check?domain=dmarc.mx&selectors=myselector,other"

# Content negotiation on /check
curl -H "Accept: application/json" "https://dmarc.mx/check?domain=dmarc.mx"
```

Response includes a `summary` with elevated fields and full `protocols` detail:

```json
{
  "domain": "example.com",
  "grade": "A",
  "summary": {
    "dmarc_policy": "reject",
    "spf_result": "pass",
    "spf_lookups": "3/10",
    "dkim_selectors_found": 2,
    "bimi_enabled": true,
    "mta_sts_mode": "enforce"
  },
  "protocols": { ... }
}
```

## Self-Hosting

You can deploy your own instance of dmarcheck to Cloudflare Workers.

### Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- A [Cloudflare account](https://dash.cloudflare.com/sign-up) (free plan works)

### Setup

```bash
git clone https://github.com/schmug/dmarcheck.git
cd dmarcheck
npm install
```

### Local Development

```bash
npm run dev       # starts local dev server on http://localhost:8790
npm test          # runs unit tests
```

To point the DNS resolver at custom servers during local development (useful
for testing against `1.1.1.1`, `8.8.8.8`, or an internal resolver), set
`DNS_SERVERS` to a comma-separated list:

```bash
DNS_SERVERS=8.8.8.8,1.1.1.1 npm run dev
```

When unset, the system default resolver (or the Cloudflare Workers DNS
polyfill in production) is used.

### Deploy to Your Own Cloudflare Account

1. Authenticate with Cloudflare:
   ```bash
   npx wrangler login
   ```

2. Edit `wrangler.toml` to use your own custom domain (or remove the `routes` block to use the default `*.workers.dev` subdomain):
   ```toml
   routes = [
     { pattern = "yourdomain.com", custom_domain = true },
   ]
   ```

3. Deploy:
   ```bash
   npm run deploy
   ```

### Configuration

| Setting | Location | Default |
|---------|----------|---------|
| Dev server port | `wrangler.toml` → `[dev].port` | 8790 |
| Rate limit | `src/rate-limit.ts` → `LIMIT` | 10 req/IP/min |
| Rate limit window | `src/rate-limit.ts` → `WINDOW_SECONDS` | 60s |
| DKIM selectors | `src/analyzers/dkim.ts` → `COMMON_SELECTORS` | ~30 common selectors |
| Scoring rubric | `wrangler.toml` → `[vars].SCORING_CONFIG` (JSON) | shipped rubric — see [`src/shared/scoring-config.ts`](src/shared/scoring-config.ts) for the knobs |

### Database migrations

The dashboard, history, and alerts features use Cloudflare D1. Migrations live
in `src/db/migrations/` and apply automatically via
`.github/workflows/migrate.yml` after CI passes on `main`. The workflow
expects two GitHub repo secrets (Settings → Secrets and variables → Actions):

| Secret | Value |
|--------|-------|
| `CLOUDFLARE_D1_TOKEN` | API token scoped to **D1:Edit** only (separate from the Workers deploy token so a leak in one doesn't widen into the other) |
| `CLOUDFLARE_ACCOUNT_ID` | Your Cloudflare account ID |

If you skip the secrets, the workflow will fail and you can either delete
`.github/workflows/migrate.yml` from your fork or apply migrations manually
with `npx wrangler d1 migrations apply dmarcheck-db --remote`.

### Optional: paid-tier env vars

These unlock the same Pro features the hosted tier at `dmarc.mx` offers — see the [three ways to use dmarcheck](#three-ways-to-use-dmarcheck) table up top. They're all optional: the free scanner, dashboard, and API work without any of them. Set any as wrangler secrets (`wrangler secret put NAME`):

| Secret | Purpose |
|--------|---------|
| `STRIPE_SECRET_KEY` | Stripe API key for Checkout + Portal calls |
| `STRIPE_WEBHOOK_SECRET` | Signing secret for the `/webhooks/stripe` endpoint |
| `STRIPE_PRICE_ID_PRO` | Price ID for the Pro plan offered via Checkout |
| `CF_ANALYTICS_TOKEN` | Cloudflare Web Analytics beacon token (32-char lowercase hex). Injects a cookieless beacon on public HTML pages; skipped on `/dashboard/*`, `/auth/*`, `/webhooks/*`. Leave unset to disable. |

If any of the three Stripe secrets are missing, `isBillingEnabled` returns false and all
paid-tier routes return 404. This keeps a fresh `wrangler deploy` working
end-to-end for self-hosters who only want the free scanner. `CF_ANALYTICS_TOKEN`
is independent — set it only if you want to send analytics to your own
Cloudflare Web Analytics dashboard.

## Stack

- [Hono](https://hono.dev) — lightweight web framework for Cloudflare Workers
- TypeScript + `node:dns` via `nodejs_compat`
- Rate limited via Cloudflare Cache API (no extra bindings needed)
- Pro features (auth, billing, history, cron) use Cloudflare D1 + WorkOS + Stripe. The hosted tier at `dmarc.mx` runs on the same code and same stack — no private fork.

## License

MIT
