import { describe, expect, it } from "vitest";
import { isAllowedWebhookUrl, isBlockedFetchHost } from "../src/shared/ssrf.js";

describe("shared/ssrf.isBlockedFetchHost", () => {
  it("blocks loopback and internal-only hostnames", () => {
    for (const h of [
      "localhost",
      "app.localhost",
      "db.internal",
      "printer.local",
      "",
    ]) {
      expect(isBlockedFetchHost(h)).toBe(true);
    }
  });

  it("blocks private / reserved IPv4 literals", () => {
    for (const ip of [
      "127.0.0.1",
      "10.0.0.5",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "169.254.169.254", // cloud metadata
      "100.64.0.1", // CGNAT
      "0.0.0.0",
      "198.18.0.1", // benchmarking
      "224.0.0.1", // multicast
      "255.255.255.255",
    ]) {
      expect(isBlockedFetchHost(ip)).toBe(true);
    }
  });

  it("allows public IPv4 literals and normal hostnames", () => {
    for (const h of [
      "8.8.8.8",
      "1.1.1.1",
      "203.0.113.10",
      "hooks.slack.com",
      "chat.googleapis.com",
      "example.com",
    ]) {
      expect(isBlockedFetchHost(h)).toBe(false);
    }
  });

  it("blocks private / reserved IPv6 literals (bracketed and bare)", () => {
    for (const h of [
      "[::1]",
      "::1",
      "[fe80::1]",
      "[fc00::1]",
      "[fd12::1]",
      "::",
      "[::ffff:7f00:1]",
    ]) {
      expect(isBlockedFetchHost(h)).toBe(true);
    }
  });

  it("allows a public IPv6 literal", () => {
    expect(isBlockedFetchHost("[2606:4700:4700::1111]")).toBe(false);
  });
});

describe("shared/ssrf.isAllowedWebhookUrl", () => {
  it("requires https", () => {
    expect(isAllowedWebhookUrl("http://hooks.slack.com/x")).toBe(false);
    expect(isAllowedWebhookUrl("https://hooks.slack.com/x")).toBe(true);
  });

  it("rejects internal hosts even over https", () => {
    expect(isAllowedWebhookUrl("https://127.0.0.1:8787/admin")).toBe(false);
    expect(
      isAllowedWebhookUrl("https://169.254.169.254/latest/meta-data/"),
    ).toBe(false);
    expect(isAllowedWebhookUrl("https://localhost/hook")).toBe(false);
    expect(isAllowedWebhookUrl("https://[::1]/hook")).toBe(false);
  });

  it("rejects unparseable URLs", () => {
    expect(isAllowedWebhookUrl("not a url")).toBe(false);
    expect(isAllowedWebhookUrl("")).toBe(false);
  });

  it("allows a normal public https receiver", () => {
    expect(isAllowedWebhookUrl("https://hook.example/receive")).toBe(true);
  });
});
