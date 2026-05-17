// MCP streamable-HTTP transport handler.
// Stateless — each POST /mcp is a complete JSON-RPC 2.0 exchange.
// Implements: initialize, notifications/initialized, tools/list, tools/call
// Protocol: https://modelcontextprotocol.io/specification (2025-03-26)

import { getCachedScan, setCachedScan } from "../cache.js";
import { scan } from "../orchestrator.js";
import { normalizeDomain } from "../shared/domain.js";

// DKIM selector charset per RFC 6376 §3.1 — mirrors VALID_SELECTOR in index.ts.
const VALID_SELECTOR = /^[A-Za-z0-9._-]+$/;

function parseSelectorsFromArray(raw: string[]): string[] {
  return raw.filter((s) => s.length > 0 && VALID_SELECTOR.test(s));
}

export const MCP_PROTOCOL_VERSION = "2025-03-26";

const SERVER_INFO = { name: "dmarcheck", version: "1.0.0" };

// SEP-1649 server card — minimal shape until the RFC finalises.
// https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2127
export const MCP_SERVER_CARD = JSON.stringify({
  name: "dmarcheck",
  version: "1.0.0",
  description:
    "DNS email-security scanner (DMARC, SPF, DKIM, BIMI, MTA-STS, MX). Rate-limited to 10 req/IP/60s.",
  url: "https://dmarc.mx/mcp",
  tools: [{ name: "scan_domain" }],
});

const SCAN_DOMAIN_TOOL = {
  name: "scan_domain",
  description:
    "Analyse a domain's email-security DNS posture (DMARC, SPF, DKIM, BIMI, MTA-STS, MX) and return a graded result. Equivalent to GET /api/check.",
  inputSchema: {
    type: "object",
    required: ["domain"],
    properties: {
      domain: {
        type: "string",
        description: "Domain to scan, e.g. 'dmarc.mx'",
        pattern: "^[a-z0-9.-]+$",
        maxLength: 253,
      },
      dkim_selectors: {
        type: "array",
        items: { type: "string", pattern: "^[A-Za-z0-9._-]+$" },
        description:
          "Extra DKIM selectors to probe beyond the built-in defaults.",
      },
    },
  },
};

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: unknown;
}

interface JsonRpcSuccess {
  jsonrpc: "2.0";
  id: string | number | null;
  result: unknown;
}

interface JsonRpcError {
  jsonrpc: "2.0";
  id: string | number | null;
  error: { code: number; message: string; data?: unknown };
}

function ok(
  id: string | number | null | undefined,
  result: unknown,
): JsonRpcSuccess {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

function rpcError(
  id: string | number | null | undefined,
  code: number,
  message: string,
  data?: unknown,
): JsonRpcError {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message, data } };
}

export interface McpEnv {
  executionCtx: ExecutionContext;
}

export async function handleMcpRequest(
  body: unknown,
  env: McpEnv,
): Promise<Response> {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return jsonRpcResponse(rpcError(null, -32600, "Invalid Request"));
  }

  const req = body as JsonRpcRequest;
  if (req.jsonrpc !== "2.0" || typeof req.method !== "string") {
    return jsonRpcResponse(rpcError(req.id ?? null, -32600, "Invalid Request"));
  }

  const { id, method, params } = req;

  switch (method) {
    case "initialize":
      return jsonRpcResponse(
        ok(id, {
          protocolVersion: MCP_PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: SERVER_INFO,
        }),
      );

    case "notifications/initialized":
      // Notification — no response per JSON-RPC 2.0 spec.
      return new Response(null, { status: 204 });

    case "tools/list":
      return jsonRpcResponse(ok(id, { tools: [SCAN_DOMAIN_TOOL] }));

    case "tools/call":
      return handleToolCall(id ?? null, params, env);

    default:
      return jsonRpcResponse(rpcError(id, -32601, "Method not found"));
  }
}

async function handleToolCall(
  id: string | number | null,
  params: unknown,
  env: McpEnv,
): Promise<Response> {
  if (typeof params !== "object" || params === null) {
    return jsonRpcResponse(rpcError(id, -32602, "Invalid params"));
  }

  const p = params as Record<string, unknown>;
  if (p.name !== "scan_domain") {
    return jsonRpcResponse(rpcError(id, -32602, `Unknown tool: ${p.name}`));
  }

  const args = p.arguments as Record<string, unknown> | undefined;
  const rawDomain = typeof args?.domain === "string" ? args.domain : undefined;
  const domain = normalizeDomain(rawDomain);
  if (!domain) {
    return jsonRpcResponse(
      ok(id, {
        content: [{ type: "text", text: "Invalid or missing domain." }],
        isError: true,
      }),
    );
  }

  const rawSelectors = args?.dkim_selectors;
  const selectors: string[] = Array.isArray(rawSelectors)
    ? parseSelectorsFromArray(
        rawSelectors.filter((s): s is string => typeof s === "string"),
      )
    : [];

  try {
    const cached = await getCachedScan(domain, selectors);
    const result = cached ?? (await scan(domain, selectors));
    if (!cached) {
      const pendingWrite = setCachedScan(domain, selectors, result);
      if (pendingWrite) {
        env.executionCtx.waitUntil(pendingWrite.catch(() => {}));
      }
    }
    return jsonRpcResponse(
      ok(id, {
        content: [{ type: "text", text: JSON.stringify(result) }],
        isError: false,
      }),
    );
  } catch (err) {
    return jsonRpcResponse(
      ok(id, {
        content: [
          {
            type: "text",
            text: err instanceof Error ? err.message : "Scan failed.",
          },
        ],
        isError: true,
      }),
    );
  }
}

function jsonRpcResponse(payload: JsonRpcSuccess | JsonRpcError): Response {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
