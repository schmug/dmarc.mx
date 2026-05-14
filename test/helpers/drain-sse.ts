/**
 * SSE stream drain helper for tests.
 *
 * Reads a `text/event-stream` Response body to completion and returns the
 * parsed events as an array.  Each element carries the raw `event` field
 * (from the `event:` line) and the raw `data` field (from the `data:` line).
 * Multi-line `data:` is joined with newlines, matching the EventSource spec.
 *
 * Only the `event` and `data` fields are extracted; `id:` and `retry:` lines
 * are ignored because the route doesn't emit them.
 */
export interface SseEvent {
  event: string;
  data: string;
}

/**
 * Drain a Server-Sent Events `Response` body to completion and return every
 * dispatched event.  The `response.body` ReadableStream is consumed once; do
 * not call `response.text()` or `response.json()` after calling this.
 *
 * @throws if `response.body` is null (non-streaming response)
 */
export async function drainSSE(response: Response): Promise<SseEvent[]> {
  if (!response.body) {
    throw new Error("Response has no body — cannot drain SSE stream");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const events: SseEvent[] = [];

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    // Split on double-newline event boundaries.  An SSE event block ends with
    // "\n\n".  We process all complete blocks from the accumulated buffer.
    const blocks = buffer.split(/\n\n/);
    // The last element may be an incomplete block — keep it in the buffer.
    buffer = blocks.pop() ?? "";

    for (const block of blocks) {
      const event = parseBlock(block);
      if (event) events.push(event);
    }
  }

  // Flush decoder
  buffer += decoder.decode(undefined, { stream: false });

  // Process any remaining complete blocks (stream ended without trailing \n\n)
  if (buffer.trim()) {
    const event = parseBlock(buffer);
    if (event) events.push(event);
  }

  return events;
}

function parseBlock(block: string): SseEvent | null {
  let eventName = "message"; // SSE default
  const dataLines: string[] = [];

  for (const line of block.split("\n")) {
    if (line.startsWith("event:")) {
      eventName = line.slice("event:".length).trim();
    } else if (line.startsWith("data:")) {
      dataLines.push(line.slice("data:".length).trim());
    }
    // comment lines (": ...") and unknown fields are ignored per spec
  }

  if (dataLines.length === 0) return null; // keep-alive or empty block

  return { event: eventName, data: dataLines.join("\n") };
}
