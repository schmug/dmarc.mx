/**
 * Reads a Server-Sent Events (SSE) response body stream to completion and
 * parses the individual SSE frames.
 *
 * SSE frame format:
 *   event: <name>\n
 *   data: <payload>\n
 *   \n
 *
 * Returns an array of parsed events in the order they were received.
 */
export interface SseFrame {
  event: string;
  data: string;
}

export async function drainSSE(response: Response): Promise<SseFrame[]> {
  if (!response.body) {
    throw new Error("Response body is null — cannot drain SSE stream");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const frames: SseFrame[] = [];

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      // SSE events are separated by a blank line (\n\n)
      // Process all complete events in the buffer
      let boundary = buffer.indexOf("\n\n");
      while (boundary !== -1) {
        const chunk = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        boundary = buffer.indexOf("\n\n");

        // Parse the SSE block into field/value pairs
        let eventName = "message";
        let dataLine = "";

        for (const line of chunk.split("\n")) {
          if (line.startsWith("event: ")) {
            eventName = line.slice("event: ".length);
          } else if (line.startsWith("data: ")) {
            dataLine = line.slice("data: ".length);
          }
        }

        if (dataLine !== "") {
          frames.push({ event: eventName, data: dataLine });
        }
      }
    }
  } finally {
    reader.releaseLock();
  }

  return frames;
}
