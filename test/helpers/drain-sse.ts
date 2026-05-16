/**
 * Drain a Server-Sent Events (SSE) response body into a structured array.
 *
 * SSE wire format (per HTML spec §9.2.5):
 *   event: name\n
 *   data: payload\n
 *   \n
 *
 * Each blank-line-terminated block is one event. Fields with the same name
 * accumulate (data lines join with "\n"). Only `event` and `data` fields are
 * captured; `id`, `retry`, and comments (": ...") are ignored.
 */
export async function drainSSE(
  response: Response,
): Promise<Array<{ event: string; data: string }>> {
  if (!response.body) {
    throw new Error("Response has no body");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const events: Array<{ event: string; data: string }> = [];

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (value) {
        buffer += decoder.decode(value, { stream: !done });
      }
      if (done) {
        // Flush any remaining text after the stream closes
        break;
      }
    }
  } finally {
    reader.releaseLock();
  }

  // Split the full buffer into SSE blocks delimited by blank lines
  // (\n\n or \r\n\r\n). Each block may contain multiple field lines.
  const blocks = buffer.split(/\n\n|\r\n\r\n/);

  for (const block of blocks) {
    const lines = block.split(/\n|\r\n/);
    let eventName = "message"; // default SSE event type
    const dataLines: string[] = [];

    for (const line of lines) {
      if (line.startsWith("event:")) {
        eventName = line.slice("event:".length).trim();
      } else if (line.startsWith("data:")) {
        dataLines.push(line.slice("data:".length).trim());
      }
      // Ignore id:, retry:, and comment lines (": ...")
    }

    // Only record blocks that carried at least a data field
    if (dataLines.length > 0) {
      events.push({ event: eventName, data: dataLines.join("\n") });
    }
  }

  return events;
}
