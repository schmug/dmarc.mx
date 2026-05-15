export interface SseEvent {
  event: string;
  data: string;
}

/**
 * Reads a Response body as text and parses all SSE events into an array.
 * Suitable for draining a complete in-memory SSE response in tests.
 */
export async function drainSSE(response: Response): Promise<SseEvent[]> {
  const text = await response.text();
  const events: SseEvent[] = [];

  for (const chunk of text.split("\n\n")) {
    if (!chunk.trim()) continue;
    let event = "message";
    let data = "";
    for (const line of chunk.split("\n")) {
      if (line.startsWith("event: ")) {
        event = line.slice(7).trim();
      } else if (line.startsWith("data: ")) {
        data = line.slice(6);
      }
    }
    if (data) {
      events.push({ event, data });
    }
  }

  return events;
}
