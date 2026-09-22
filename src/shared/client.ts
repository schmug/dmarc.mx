import type { Context } from "hono";

export function getClientIp(c: Context): string {
  const cfIp = c.req.header("CF-Connecting-IP");
  if (cfIp) return cfIp;

  return "unknown";
}
