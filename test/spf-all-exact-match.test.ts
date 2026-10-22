import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/dns/client.js", () => ({
  queryTxt: vi.fn(),
  queryMx: vi.fn(),
}));

import { analyzeSpf } from "../src/analyzers/spf.js";
import { queryTxt } from "../src/dns/client.js";

const mockQueryTxt = vi.mocked(queryTxt);

beforeEach(() => {
  vi.resetAllMocks();
});

async function spf(record: string) {
  mockQueryTxt.mockResolvedValueOnce({ entries: [record], raw: record });
  return analyzeSpf("example.com");
}

const messages = (r: Awaited<ReturnType<typeof spf>>) =>
  r.validations.map((v) => v.message).join("\n");

describe("SPF all mechanism exact match", () => {
  it("does not mistake a:mail.smallball for the all term, so +all is flagged", async () => {
    const r = await spf("v=spf1 a:mail.smallball +all");
    expect(r.validations.some((v) => v.status === "fail")).toBe(true);
    expect(messages(r)).toContain("+all");
    expect(messages(r)).not.toContain("after");
  });

  it("honest a:mail.hall -all keeps the -all qualifier and no unreachable-terms warning", async () => {
    const r = await spf("v=spf1 a:mail.hall -all");
    expect(messages(r)).toContain("-all (hardfail)");
    expect(messages(r)).not.toContain("unreachable");
  });

  it.each([
    ["-all", "pass", "-all (hardfail)"],
    ["~all", "warn", "~all (softfail)"],
    ["?all", "warn", "?all (neutral)"],
    ["+all", "fail", "+all"],
  ])("%s on its own", async (all, status, text) => {
    const r = await spf(`v=spf1 mx ${all}`);
    const v = r.validations.find((x) => x.message.includes(text));
    expect(v?.status).toBe(status);
    expect(messages(r)).not.toContain("unreachable");
  });
});
