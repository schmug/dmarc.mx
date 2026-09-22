import { Hono } from "hono";
import {
  getAgentSkillsIndexJson,
  SCAN_DOMAIN_SKILL_MD,
} from "../api/agent-skills.js";
import { AGENT_CARD_JSON, API_CATALOG_JSON } from "../api/catalog.js";
import { LLMS_TXT } from "../api/llms-txt.js";
import { OPENAPI_JSON } from "../api/openapi.js";
import type { Env } from "../env.js";
import { handleMcpRequest, MCP_SERVER_CARD } from "../mcp/handler.js";
import {
  markdownResponse,
  wantsMarkdown,
} from "../shared/content-negotiation.js";
import { parseScoringConfig } from "../shared/scoring-config.js";
import { renderApiDocs } from "../views/html.js";
import { renderApiDocsMarkdown } from "../views/markdown.js";

export const agentDiscoveryRoutes = new Hono<{ Bindings: Env }>();

// RFC 9727 API catalog — agents discover this via the Link header on HTML
// pages or by fetching a well-known URI directly.
agentDiscoveryRoutes.get("/.well-known/api-catalog", (c) => {
  return c.body(API_CATALOG_JSON, 200, {
    "Content-Type": "application/linkset+json",
    "Cache-Control": "public, max-age=3600",
  });
});

// Agent Skills discovery index — Cloudflare RFC v0.2.0.
// https://github.com/cloudflare/agent-skills-discovery-rfc
agentDiscoveryRoutes.get("/.well-known/agent-skills/index.json", async (c) => {
  const json = await getAgentSkillsIndexJson();
  return c.body(json, 200, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

agentDiscoveryRoutes.get(
  "/.well-known/agent-skills/scan-domain/SKILL.md",
  (c) => {
    return c.body(SCAN_DOMAIN_SKILL_MD, 200, {
      "Content-Type": "text/markdown; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
    });
  },
);

// DNS-AID agent metadata contract — draft-mozleywilliams-dnsop-dnsaid.
// Publishes the scan_domain capability at the HTTP layer; the matching DNS
// SVCB/TXT records under _agents.dmarc.mx are owner zone-admin work (#461).
agentDiscoveryRoutes.get("/.well-known/agent.json", (c) => {
  return c.body(AGENT_CARD_JSON, 200, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

// Remote MCP server — streamable-HTTP transport (POST only; stateless).
// Agents discover this endpoint via /.well-known/mcp/server-card.json and
// the agent-skills index.
agentDiscoveryRoutes.post("/mcp", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json(
      {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" },
      },
      400,
    );
  }
  return handleMcpRequest(body, {
    executionCtx: c.executionCtx,
    scoringConfig: parseScoringConfig(c.env?.SCORING_CONFIG),
    dnsblKey: c.env?.DNSBL_DQS_KEY,
  });
});

// SEP-1649 MCP server card — minimal shape, served before the RFC finalises.
agentDiscoveryRoutes.get("/.well-known/mcp/server-card.json", (c) => {
  return c.body(MCP_SERVER_CARD, 200, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

agentDiscoveryRoutes.get("/openapi.json", (c) => {
  return c.body(OPENAPI_JSON, 200, {
    "Content-Type": "application/openapi+json; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});

agentDiscoveryRoutes.get("/docs/api", (c) => {
  if (wantsMarkdown(c)) return markdownResponse(c, renderApiDocsMarkdown());
  return c.html(renderApiDocs());
});

// llmstxt.org — vendor-neutral pointer to the canonical markdown URLs LLM
// clients should pull instead of scraping rendered HTML. See src/api/llms-txt.ts.
agentDiscoveryRoutes.get("/llms.txt", (c) => {
  return c.body(LLMS_TXT, 200, {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
  });
});
