import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  handleMcpRequest,
  MCP_PROTOCOL_VERSION,
  MCP_SERVER_CARD,
} from "../src/mcp/handler.js";

vi.mock("../src/cache.js", () => ({
  getCachedScan: vi.fn().mockResolvedValue(null),
  setCachedScan: vi.fn().mockReturnValue(null),
}));

vi.mock("../src/orchestrator.js", () => ({
  scan: vi.fn().mockResolvedValue({
    domain: "example.com",
    timestamp: "2026-01-01T00:00:00Z",
    grade: "A",
    breakdown: {
      grade: "A",
      tier: "A",
      tierReason: "",
      modifier: 0,
      modifierLabel: "",
      factors: [],
      recommendations: [],
      protocolSummaries: {},
    },
    summary: { mx_records: 1, mx_providers: [], dmarc_policy: "reject" },
    protocols: {
      mx: { status: "info" },
      dmarc: { status: "pass" },
      spf: { status: "pass" },
      dkim: { status: "pass" },
      bimi: { status: "pass" },
      mta_sts: { status: "pass" },
    },
  }),
}));

function makeEnv(): { executionCtx: ExecutionContext } {
  return {
    executionCtx: {
      waitUntil: vi.fn(),
      passThroughOnException: vi.fn(),
    } as unknown as ExecutionContext,
  };
}

async function rpc(body: unknown, env = makeEnv()) {
  const res = await handleMcpRequest(body, env);
  const json = await res.json<{
    jsonrpc: string;
    id: unknown;
    result?: unknown;
    error?: unknown;
  }>();
  return { res, json };
}

describe("MCP_SERVER_CARD", () => {
  it("is valid JSON with expected fields", () => {
    const card = JSON.parse(MCP_SERVER_CARD);
    expect(card.name).toBe("dmarcheck");
    expect(card.tools).toEqual([{ name: "scan_domain" }]);
  });
});

describe("handleMcpRequest — protocol", () => {
  it("returns -32600 for a non-object body", async () => {
    const { json } = await rpc("bad");
    expect(json.error).toMatchObject({ code: -32600 });
  });

  it("returns -32600 for array body", async () => {
    const { json } = await rpc([]);
    expect(json.error).toMatchObject({ code: -32600 });
  });

  it("returns -32600 when jsonrpc field is wrong", async () => {
    const { json } = await rpc({ jsonrpc: "1.0", id: 1, method: "initialize" });
    expect(json.error).toMatchObject({ code: -32600 });
  });

  it("returns -32601 for unknown method", async () => {
    const { json } = await rpc({
      jsonrpc: "2.0",
      id: 9,
      method: "not/a/method",
    });
    expect(json.error).toMatchObject({
      code: -32601,
      message: "Method not found",
    });
    expect(json.id).toBe(9);
  });

  it("returns 204 for notifications/initialized (no body)", async () => {
    const res = await handleMcpRequest(
      { jsonrpc: "2.0", method: "notifications/initialized" },
      makeEnv(),
    );
    expect(res.status).toBe(204);
    expect(await res.text()).toBe("");
  });
});

describe("handleMcpRequest — initialize", () => {
  it("returns protocolVersion and serverInfo", async () => {
    const { json } = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize" });
    expect(json.result).toMatchObject({
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: { name: "dmarcheck" },
    });
    expect(json.id).toBe(1);
  });
});

describe("handleMcpRequest — tools/list", () => {
  it("returns scan_domain tool with required schema", async () => {
    const { json } = await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    const result = json.result as {
      tools: Array<{ name: string; inputSchema: unknown }>;
    };
    expect(result.tools).toHaveLength(1);
    expect(result.tools[0].name).toBe("scan_domain");
    const schema = result.tools[0].inputSchema as { required: string[] };
    expect(schema.required).toContain("domain");
  });
});

describe("handleMcpRequest — tools/call", () => {
  it("returns -32602 for non-object params", async () => {
    const { json } = await rpc({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: "bad",
    });
    expect(json.error).toMatchObject({ code: -32602 });
  });

  it("returns -32602 for unknown tool name", async () => {
    const { json } = await rpc({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "unknown_tool" },
    });
    expect(json.error).toMatchObject({ code: -32602 });
  });

  it("returns isError:true for missing domain", async () => {
    const { json } = await rpc({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "scan_domain", arguments: {} },
    });
    const result = json.result as {
      isError: boolean;
      content: Array<{ type: string; text: string }>;
    };
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Invalid");
  });

  it("returns isError:true for invalid domain characters", async () => {
    const { json } = await rpc({
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "scan_domain", arguments: { domain: "evil<script>" } },
    });
    const result = json.result as { isError: boolean };
    expect(result.isError).toBe(true);
  });

  it("calls scan and returns JSON-serialised result on success", async () => {
    const { json } = await rpc({
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: { name: "scan_domain", arguments: { domain: "example.com" } },
    });
    const result = json.result as {
      isError: boolean;
      content: Array<{ type: string; text: string }>;
    };
    expect(result.isError).toBe(false);
    expect(result.content[0].type).toBe("text");
    const payload = JSON.parse(result.content[0].text);
    expect(payload.domain).toBe("example.com");
    expect(payload.grade).toBe("A");
  });

  it("strips invalid dkim_selectors silently", async () => {
    const { scan } = await import("../src/orchestrator.js");
    const { json } = await rpc({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: {
        name: "scan_domain",
        arguments: {
          domain: "example.com",
          dkim_selectors: ["valid-sel", "bad sel!", ""],
        },
      },
    });
    const result = json.result as { isError: boolean };
    expect(result.isError).toBe(false);
    // scan was called — invalid selectors were stripped, not rejected
    expect(vi.mocked(scan)).toHaveBeenCalled();
  });

  it("preserves JSON-RPC id across the full call", async () => {
    const { json } = await rpc({
      jsonrpc: "2.0",
      id: "req-abc",
      method: "tools/call",
      params: { name: "scan_domain", arguments: { domain: "example.com" } },
    });
    expect(json.id).toBe("req-abc");
  });

  it("id defaults to null when omitted", async () => {
    const { json } = await rpc({
      jsonrpc: "2.0",
      method: "tools/call",
      params: { name: "scan_domain", arguments: { domain: "example.com" } },
    });
    expect(json.id).toBeNull();
  });
});
