import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parseMiniToml } from "./toml-mini.js";

export interface Exemption {
  binding: string;
  reason: string;
}

export interface Exemptions {
  prodOnly: Exemption[];
  stagingOnly: Exemption[];
}

// [sectionPath, key-to-collect, category name]
const BINDING_SECTIONS: Array<[string, string, string]> = [
  ["d1_databases", "binding", "d1_databases"],
  ["kv_namespaces", "binding", "kv_namespaces"],
  ["durable_objects.bindings", "name", "durable_objects.bindings"],
  ["send_email", "name", "send_email"],
  ["r2_buckets", "binding", "r2_buckets"],
  ["queues.producers", "binding", "queues.producers"],
  ["services", "binding", "services"],
  ["hyperdrive", "binding", "hyperdrive"],
  ["analytics_engine_datasets", "binding", "analytics_engine_datasets"],
  ["vectorize", "binding", "vectorize"],
];

export function collectBindings(text: string): Map<string, Set<string>> {
  const parsed = parseMiniToml(text);
  const byCategory = new Map<string, Set<string>>();

  for (const [sectionPath, key, category] of BINDING_SECTIONS) {
    const entries = parsed.tables.get(sectionPath) ?? [];
    const names = byCategory.get(category) ?? new Set<string>();
    for (const entry of entries) {
      const value = entry[key];
      if (value) names.add(value);
    }
    if (names.size > 0) byCategory.set(category, names);
  }

  const varsEntries = parsed.tables.get("vars") ?? [];
  const varNames = new Set<string>();
  for (const entry of varsEntries) {
    for (const k of Object.keys(entry)) varNames.add(k);
  }
  if (varNames.size > 0) byCategory.set("vars", varNames);

  return byCategory;
}

export interface Difference {
  category: string;
  binding: string;
  missingFrom: "staging" | "production";
}

export interface CompareResult {
  ok: boolean;
  bothCategories: Map<string, string[]>;
  prodOnly: Difference[];
  stagingOnly: Difference[];
  unexemptedProdOnly: Difference[];
  unexemptedStagingOnly: Difference[];
  staleExemptions: Exemption[];
  lines: string[];
}

/**
 * Reads the two configs and the exemptions out of `rootDir` and reports
 * whether they agree. Returns the process exit code. Takes the root as an
 * argument so it can be exercised against a fixture directory instead of
 * whichever tree it happens to be running in.
 */
export function runCheck(
  rootDir: string,
  log: (line: string) => void = console.log,
): number {
  const stagingPath = join(rootDir, "wrangler.staging.toml");
  if (!existsSync(stagingPath)) {
    log("wrangler.staging.toml not present, nothing to compare");
    return 0;
  }

  const exemptions: Exemptions = JSON.parse(
    readFileSync(
      join(rootDir, "scripts", "binding-parity", "exemptions.json"),
      "utf8",
    ),
  );

  const result = compareBindings(
    readFileSync(join(rootDir, "wrangler.toml"), "utf8"),
    readFileSync(stagingPath, "utf8"),
    exemptions,
  );
  for (const line of result.lines) log(line);
  return result.ok ? 0 : 1;
}

export function compareBindings(
  prodText: string,
  stagingText: string,
  exemptions: Exemptions,
): CompareResult {
  const prod = collectBindings(prodText);
  const staging = collectBindings(stagingText);

  const categories = new Set<string>([...prod.keys(), ...staging.keys()]);

  const bothCategories = new Map<string, string[]>();
  const prodOnly: Difference[] = [];
  const stagingOnly: Difference[] = [];

  for (const category of categories) {
    const prodNames = prod.get(category) ?? new Set<string>();
    const stagingNames = staging.get(category) ?? new Set<string>();
    const both: string[] = [];
    for (const name of prodNames) {
      if (stagingNames.has(name)) {
        both.push(name);
      } else {
        prodOnly.push({ category, binding: name, missingFrom: "staging" });
      }
    }
    for (const name of stagingNames) {
      if (!prodNames.has(name)) {
        stagingOnly.push({ category, binding: name, missingFrom: "production" });
      }
    }
    if (both.length > 0) bothCategories.set(category, both);
  }

  const prodOnlyExempted = new Set(exemptions.prodOnly.map((e) => e.binding));
  const stagingOnlyExempted = new Set(
    exemptions.stagingOnly.map((e) => e.binding),
  );

  const unexemptedProdOnly = prodOnly.filter(
    (d) => !prodOnlyExempted.has(d.binding),
  );
  const unexemptedStagingOnly = stagingOnly.filter(
    (d) => !stagingOnlyExempted.has(d.binding),
  );

  const actualProdOnlyNames = new Set(prodOnly.map((d) => d.binding));
  const actualStagingOnlyNames = new Set(stagingOnly.map((d) => d.binding));

  const staleExemptions: Exemption[] = [
    ...exemptions.prodOnly.filter((e) => !actualProdOnlyNames.has(e.binding)),
    ...exemptions.stagingOnly.filter(
      (e) => !actualStagingOnlyNames.has(e.binding),
    ),
  ];

  const lines: string[] = [];
  for (const [category, names] of bothCategories) {
    lines.push(`[${category}] in both: ${names.join(", ") || "(none)"}`);
  }
  for (const d of prodOnly) {
    const exempted = prodOnlyExempted.has(d.binding);
    lines.push(
      `[${d.category}] production-only: ${d.binding}${exempted ? " (exempted)" : ""}`,
    );
  }
  for (const d of stagingOnly) {
    const exempted = stagingOnlyExempted.has(d.binding);
    lines.push(
      `[${d.category}] staging-only: ${d.binding}${exempted ? " (exempted)" : ""}`,
    );
  }

  for (const d of unexemptedProdOnly) {
    lines.push(
      `ACTION: binding "${d.binding}" (${d.category}) is missing from wrangler.staging.toml — add it there or exempt it in exemptions.json with a reason.`,
    );
  }
  for (const d of unexemptedStagingOnly) {
    lines.push(
      `ACTION: binding "${d.binding}" (${d.category}) is missing from wrangler.toml — add it there or exempt it in exemptions.json with a reason.`,
    );
  }
  for (const e of staleExemptions) {
    lines.push(
      `STALE EXEMPTION: "${e.binding}" no longer differs between wrangler.toml and wrangler.staging.toml — remove it from exemptions.json.`,
    );
  }

  const ok =
    unexemptedProdOnly.length === 0 &&
    unexemptedStagingOnly.length === 0 &&
    staleExemptions.length === 0;

  lines.push(
    ok
      ? "SUMMARY: binding parity OK (all differences exempted or absent)."
      : `SUMMARY: binding parity FAILED (${unexemptedProdOnly.length} unexempted production-only, ${unexemptedStagingOnly.length} unexempted staging-only, ${staleExemptions.length} stale exemptions).`,
  );

  return {
    ok,
    bothCategories,
    prodOnly,
    stagingOnly,
    unexemptedProdOnly,
    unexemptedStagingOnly,
    staleExemptions,
    lines,
  };
}
