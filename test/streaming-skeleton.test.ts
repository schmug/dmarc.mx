/**
 * Regression guard for the streaming scan report (#451).
 *
 * The streaming loading view (`renderStreamingLoading`) pre-renders one
 * skeleton card per protocol, each tagged `data-protocol="<id>"`. The client
 * SSE handler swaps each streamed protocol card into the matching skeleton
 * (see the inline script in `renderStreamingLoading`). If a protocol the
 * stream emits has no skeleton placeholder, its card is silently dropped —
 * exactly what happened to DNSSEC: the stream emitted a `dnssec` card, but the
 * skeleton list had no `data-protocol="dnssec"`, so it never rendered.
 *
 * This pins the invariant: the skeleton set must cover every ProtocolId the
 * orchestrator/stream can emit. `PROTOCOL_LABEL` is a
 * `Record<ProtocolId, string>`, so adding a protocol to the union forces a new
 * key here, which forces a matching skeleton — the next protocol can't drop.
 */
import { describe, expect, it } from "vitest";
import { PROTOCOL_LABEL } from "../src/orchestrator.js";
import { renderStreamingLoading } from "../src/views/html.js";

describe("renderStreamingLoading — skeleton coverage", () => {
  const html = renderStreamingLoading("example.com", "");

  for (const id of Object.keys(PROTOCOL_LABEL)) {
    it(`renders a skeleton placeholder for the ${id} protocol`, () => {
      expect(
        html.includes(`data-protocol="${id}"`),
        `streaming skeleton is missing data-protocol="${id}" — its streamed card would be silently dropped`,
      ).toBe(true);
    });
  }
});
