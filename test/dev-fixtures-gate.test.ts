import { describe, expect, it } from "vitest";
import { app } from "../src/index.js";

describe("/_dev/dashboard fixture gate", () => {
  it("404s with no env", async () => {
    const res = await app.request("/_dev/dashboard", {}, {});
    expect(res.status).toBe(404);
  });

  it("404s when only WORKOS_API_KEY is absent/present without opt-in", async () => {
    for (const env of [{}, { WORKOS_API_KEY: "sk_test" }]) {
      const res = await app.request("/_dev/dashboard", {}, env);
      expect(res.status).toBe(404);
    }
  });

  it('404s when DEV_FIXTURES is anything but "1"', async () => {
    const res = await app.request(
      "/_dev/dashboard",
      {},
      { DEV_FIXTURES: "true" },
    );
    expect(res.status).toBe(404);
  });

  it('serves the fixture index when DEV_FIXTURES is "1"', async () => {
    const res = await app.request("/_dev/dashboard", {}, { DEV_FIXTURES: "1" });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("/_dev/dashboard?fixture=");
  });
});
