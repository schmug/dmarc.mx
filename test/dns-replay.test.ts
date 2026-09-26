import dns from "node:dns";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { queryMx, queryTxt } from "../src/dns/client.js";
import {
  type DnsFixture,
  FixtureMissError,
  setFixtureSource,
  setRecorder,
} from "../src/dns/replay.js";

vi.mock("@sentry/cloudflare", () => ({ addBreadcrumb: vi.fn() }));

// Any live query during replay is a bug, so make the wire loudly unavailable.
const resolveTxt = vi
  .spyOn(dns.promises.Resolver.prototype, "resolveTxt")
  .mockRejectedValue(new Error("network used during replay"));
const resolveMx = vi
  .spyOn(dns.promises.Resolver.prototype, "resolveMx")
  .mockRejectedValue(new Error("network used during replay"));

const fixture: DnsFixture = {
  domain: "example.test",
  recordedAt: "2026-09-21T00:00:00.000Z",
  answers: {
    "TXT example.test": {
      value: { entries: ["v=spf1 -all"], raw: "v=spf1 -all" },
    },
    "TXT missing.example.test": { value: null },
    "MX example.test": {
      error: { code: "ESERVFAIL", message: "DNS query failed" },
    },
  },
};

describe("DNS fixture replay", () => {
  beforeEach(() => {
    resolveTxt.mockClear();
    resolveMx.mockClear();
    setFixtureSource(fixture);
  });

  it("answers recorded queries without touching the network", async () => {
    await expect(queryTxt("example.test")).resolves.toEqual({
      entries: ["v=spf1 -all"],
      raw: "v=spf1 -all",
    });
    expect(resolveTxt).not.toHaveBeenCalled();
  });

  it("replays a recorded absence as null and a recorded failure as an error", async () => {
    await expect(queryTxt("missing.example.test")).resolves.toBeNull();
    await expect(queryMx("example.test")).rejects.toMatchObject({
      code: "ESERVFAIL",
    });
    expect(resolveMx).not.toHaveBeenCalled();
  });

  it("throws on an uncovered name instead of silently going live", async () => {
    await expect(queryTxt("unrecorded.example.test")).rejects.toBeInstanceOf(
      FixtureMissError,
    );
    expect(resolveTxt).not.toHaveBeenCalled();
  });

  it("goes back to the network once the fixture is removed", async () => {
    setFixtureSource(null);
    await expect(queryTxt("example.test")).rejects.toThrow(
      "network used during replay",
    );
    expect(resolveTxt).toHaveBeenCalledWith("example.test");
  });

  it("captures live answers for the recorder", async () => {
    setFixtureSource(null);
    const captured: Record<string, unknown> = {};
    setRecorder((key, answer) => {
      captured[key] = answer;
    });
    resolveTxt.mockResolvedValueOnce([["v=spf1 include:a -all"]]);
    await queryTxt("record.example.test");
    setRecorder(null);
    expect(captured["TXT record.example.test"]).toEqual({
      value: {
        entries: ["v=spf1 include:a -all"],
        raw: "v=spf1 include:a -all",
      },
    });
  });
});
