export function parseTags(
  record: string,
  options?: { lowercaseKeys?: boolean },
): Record<string, string> {
  const lowercase = options?.lowercaseKeys ?? true;
  const tags: Record<string, string> = Object.create(null);
  let start = 0;
  const len = record.length;

  // Performance optimization:
  // Use a single-pass `indexOf` loop instead of `record.split(';')`
  // This avoids allocating intermediate arrays, reducing GC pressure.
  while (start < len) {
    let end = record.indexOf(";", start);
    if (end === -1) {
      end = len;
    }

    const part = record.slice(start, end).trim();
    start = end + 1;

    if (!part) continue;

    const eqIdx = part.indexOf("=");
    if (eqIdx === -1) continue;

    const key = part.slice(0, eqIdx).trim();
    tags[lowercase ? key.toLowerCase() : key] = part.slice(eqIdx + 1).trim();
  }

  return tags;
}
