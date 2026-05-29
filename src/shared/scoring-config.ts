import type { ScoringConfig } from "./scoring.js";

// Boolean knobs are accepted only when the JSON value is a real boolean.
const BOOLEAN_KEYS = [
  "requireBimiForAPlus",
  "requireMtaStsForAPlus",
] as const satisfies readonly (keyof ScoringConfig)[];

// Numeric knobs are accepted only when finite and non-negative; anything else
// is dropped so the corresponding default applies.
const NUMBER_KEYS = [
  "spfEfficientLookupThreshold",
  "dkimKeyMinBits",
  "lowPctDowngradeThreshold",
  "dkimRotationSelectorCount",
] as const satisfies readonly (keyof ScoringConfig)[];

// Parses the SCORING_CONFIG wrangler var into a validated partial config.
// Returns {} (→ shipped defaults) when the var is absent, not valid JSON, not
// an object, or contains only unrecognised/invalid values. Per-key validation
// is permissive: unknown keys and bad values are dropped silently; only a
// hard JSON/shape failure emits a single console.warn. Self-hosters get a
// working free-tier deploy regardless of what they put in the var.
export function parseScoringConfig(
  raw: string | undefined,
): Partial<ScoringConfig> {
  if (!raw) return {};

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    console.warn("SCORING_CONFIG is not valid JSON; using the default rubric.");
    return {};
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    console.warn(
      "SCORING_CONFIG must be a JSON object; using the default rubric.",
    );
    return {};
  }

  const source = parsed as Record<string, unknown>;
  const out: Partial<ScoringConfig> = {};

  for (const key of BOOLEAN_KEYS) {
    const value = source[key];
    if (typeof value === "boolean") out[key] = value;
  }
  for (const key of NUMBER_KEYS) {
    const value = source[key];
    if (typeof value === "number" && Number.isFinite(value) && value >= 0) {
      out[key] = value;
    }
  }

  return out;
}
