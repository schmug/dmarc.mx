// Minimal TOML reader covering exactly what wrangler.toml files in this repo
// use: `[table]` headers, `[[array.of.table]]` headers, and `key = "value"` /
// `key = value` lines. Not a general TOML parser — do not extend it to be one.

export interface MiniToml {
  // Table path (dot-joined, e.g. "vars" or "durable_objects.bindings") ->
  // list of entries, each entry being that table's key/value pairs. A plain
  // `[table]` yields exactly one entry; a `[[table]]` array-of-tables yields
  // one entry per occurrence.
  tables: Map<string, Record<string, string>[]>;
}

function stripComment(line: string): string {
  let inString = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') inString = !inString;
    else if (c === "#" && !inString) return line.slice(0, i);
  }
  return line;
}

function unquote(raw: string): string {
  const v = raw.trim();
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    return v.slice(1, -1);
  }
  return v;
}

export function parseMiniToml(text: string): MiniToml {
  const tables = new Map<string, Record<string, string>[]>();
  let current: Record<string, string> | null = null;

  for (const rawLine of text.split("\n")) {
    const line = stripComment(rawLine).trim();
    if (line === "") continue;

    const arrayHeader = line.match(/^\[\[([^\]]+)\]\]$/);
    const tableHeader = !arrayHeader && line.match(/^\[([^\]]+)\]$/);

    if (arrayHeader) {
      const name = arrayHeader[1].trim();
      current = {};
      const list = tables.get(name) ?? [];
      list.push(current);
      tables.set(name, list);
      continue;
    }
    if (tableHeader) {
      const name = tableHeader[1].trim();
      current = {};
      tables.set(name, [current]);
      continue;
    }

    const eq = line.indexOf("=");
    if (eq === -1 || !current) continue;
    const key = line.slice(0, eq).trim();
    const value = unquote(line.slice(eq + 1));
    current[key] = value;
  }

  return { tables };
}
