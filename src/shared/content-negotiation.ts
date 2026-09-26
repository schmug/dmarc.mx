import type { Context } from "hono";

export function markdownResponse(c: Context, body: string, status = 200) {
  return c.body(body, status as 200, {
    "Content-Type": "text/markdown; charset=utf-8",
  });
}

// Returns true when the client explicitly asked for markdown (via `?format=md`
// or an `Accept` header that lists `text/markdown` before `text/html`). HTML
// stays the default for browsers that send wildcards like `*/*`.
export function wantsMarkdown(c: Context): boolean {
  const format = c.req.query("format");
  if (format === "md" || format === "markdown") return true;
  const accept = c.req.header("Accept");
  if (!accept) return false;
  const types = accept.toLowerCase().split(",");
  const mdIndex = types.findIndex((t) => t.trim().startsWith("text/markdown"));
  if (mdIndex === -1) return false;
  const htmlIndex = types.findIndex((t) => t.trim().startsWith("text/html"));
  // Agents that send `Accept: text/markdown` (and nothing else, or markdown
  // first) get markdown. Browsers that prefer HTML keep getting HTML.
  return htmlIndex === -1 || mdIndex < htmlIndex;
}
