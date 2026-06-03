// /llms.txt per https://llmstxt.org — vendor-neutral pointer for LLM
// ingestion. Robots.txt is to crawlers what llms.txt is to LLM training/
// retrieval clients: a single, well-known file that names the canonical
// markdown URLs an LLM should pull instead of scraping rendered HTML.
//
// The structure (H1, blockquote, `## Section` with markdown-link bullets)
// is what the spec mandates and what existing parsers (e.g. the official
// llms.txt parser) expect. Each URL points at a content-negotiated
// markdown rendering that already exists in src/views/markdown.ts.

import { CANONICAL_ORIGIN } from "./catalog.js";

export function buildLlmsTxt(origin: string = CANONICAL_ORIGIN): string {
  return `# dmarcheck

> Free, open-source DNS email security analyzer. Grades a domain's DMARC, SPF, DKIM, BIMI, and MTA-STS posture into a single A+/F letter grade with explanations and remediation.

## Docs

- [Landing page](${origin}/?format=md): What dmarcheck does, how to scan a domain, rate limits.
- [Learn hub](${origin}/learn?format=md): Plain-English explainers for the email security DNS records dmarcheck covers — DMARC, SPF, DKIM, BIMI, MTA-STS, and more.
- [Scoring rubric](${origin}/scoring?format=md): How the letter grade is computed and which factors weigh most.
- [Pricing](${origin}/pricing?format=md): Free tier and Pro plan limits.

## API

- [API reference](${origin}/docs/api?format=md): Endpoints, query parameters, and response shapes.
- [OpenAPI 3.1 spec](${origin}/openapi.json): Machine-readable service description (\`application/openapi+json\`).
- [API catalog](${origin}/.well-known/api-catalog): RFC 9727 linkset (\`application/linkset+json\`).
- [Agent Skills index](${origin}/.well-known/agent-skills/index.json): Cloudflare Agent Skills Discovery v0.2.0 entries for the \`scan_domain\` skill.

## Pro

- [Privacy policy](${origin}/legal/privacy?format=md): What we store, what we don't, and how Cloudflare Web Analytics is configured.

## Source

- [GitHub repository](https://github.com/schmug/dmarcheck): MIT-licensed source, issue tracker, and self-host instructions.
`;
}

export const LLMS_TXT = buildLlmsTxt();
