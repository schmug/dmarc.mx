// RFC 9727 API catalog — advertises the public scan API to automated agents.
// https://www.rfc-editor.org/rfc/rfc9727

export const CANONICAL_ORIGIN = "https://dmarc.mx";

export interface LinksetEntry {
  anchor: string;
  "service-desc": Array<{ href: string; type: string }>;
  "service-doc": Array<{ href: string; type: string }>;
  status: Array<{ href: string }>;
}

export interface ApiCatalog {
  linkset: LinksetEntry[];
}

export function buildApiCatalog(origin: string = CANONICAL_ORIGIN): ApiCatalog {
  const sharedRefs = {
    "service-desc": [
      { href: `${origin}/openapi.json`, type: "application/openapi+json" },
    ],
    "service-doc": [{ href: `${origin}/docs/api`, type: "text/html" }],
    status: [{ href: `${origin}/health` }],
  };
  return {
    linkset: [
      { anchor: `${origin}/api/check`, ...sharedRefs },
      { anchor: `${origin}/api/bulk-scan`, ...sharedRefs },
      // RFC 6570 URI template — RFC 9727 §3 permits templates in linkset
      // anchors for parameterized resources. Agents resolve `{name}` from
      // the OpenAPI path parameter.
      { anchor: `${origin}/api/domain/{name}/history`, ...sharedRefs },
      { anchor: `${origin}/mcp`, ...sharedRefs },
    ],
  };
}

// Built once per Worker instance — payload is ~300 bytes.
export const API_CATALOG_JSON = JSON.stringify(buildApiCatalog());

// DNS-AID agent metadata contract — draft-mozleywilliams-dnsop-dnsaid.
// https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/
//
// Served at /.well-known/agent.json, this is the DNS-layer equivalent of the
// HTTP discovery surfaces above: it publishes our `scan_domain` capability so
// agents that resolve the `_agents.dmarc.mx` DNS records can fetch a richer
// metadata document. The `aid_version` key marks this as a DNS-AID-native
// document (a Google A2A agent card shares the same well-known path but omits
// that key, letting consumers auto-detect the format).
//
// This is the HTTP-layer half only. The DNS SVCB/TXT zone records that point
// here (`_scan._mcp._agents.dmarc.mx`, `_index._agents.dmarc.mx`) are owner
// zone-admin work tracked separately (#461); we do NOT grade `_agents` records
// as an analyzed protocol.
export interface AgentCardAction {
  name: string;
  description: string;
  // `query` (read-only lookup) vs `transaction` (state-changing). Orchestrators
  // use this to decide caching/parallelisation; scan_domain is a pure query.
  intent: "query" | "transaction";
  // `read` vs `write` — governs retry-safety assumptions.
  semantics: "read" | "write";
}

export interface AgentCard {
  aid_version: string;
  identity: {
    name: string;
    version: string;
    description: string;
    url: string;
    documentation: string;
  };
  connection: {
    protocol: string;
    transport: string;
    endpoint: string;
  };
  auth: {
    type: string;
  };
  capabilities: {
    supports_streaming: boolean;
    actions: AgentCardAction[];
  };
}

export function buildAgentCard(origin: string = CANONICAL_ORIGIN): AgentCard {
  return {
    // Track the single IETF draft draft-mozleywilliams-dnsop-dnsaid; the wire
    // shape may shift, but the JSON surface is cheap to revise.
    aid_version: "1.0",
    identity: {
      name: "dmarcheck",
      version: "1.0.0",
      description:
        "DNS email-security scanner (DMARC, SPF, DKIM, BIMI, MTA-STS, MX, security.txt, TLS-RPT, DNSSEC, DANE).",
      url: origin,
      documentation: `${origin}/docs/api`,
    },
    connection: {
      protocol: "mcp",
      transport: "streamable-http",
      endpoint: `${origin}/mcp`,
    },
    // scan_domain is a public, rate-limited capability — no credential required.
    auth: { type: "none" },
    capabilities: {
      supports_streaming: true,
      actions: [
        {
          name: "scan_domain",
          description:
            "Analyse a domain's email-security DNS posture and return a graded result. Equivalent to GET /api/check.",
          intent: "query",
          semantics: "read",
        },
      ],
    },
  };
}

// Built once per Worker instance — payload is ~600 bytes.
export const AGENT_CARD_JSON = JSON.stringify(buildAgentCard());
