/**
 * Single source of truth for validation→learn-page deep links (#524).
 *
 * Each entry pairs a learn-page path with the id of the section that explains
 * how to fix the finding. Analyzers set `Validation.learnAnchor` via
 * `learnAnchorHref()`, src/views/learn.ts renders the matching `id=`
 * attributes from the same constants, and test/learn-anchors.test.ts asserts
 * both sides — so the ids cannot silently drift.
 *
 * The ids are a stable kebab-case contract: external pages and saved reports
 * may link to them, so rename only with a redirect plan.
 */
export interface LearnAnchor {
  /** Learn-page path, e.g. "/learn/spf". */
  page: string;
  /** Element id on that page, stable kebab-case. */
  id: string;
}

export const LEARN_ANCHORS = {
  /** SPF "Exceeds 10-lookup limit" — flattening guidance. */
  spfLookupLimit: { page: "/learn/spf", id: "lookup-limit" },
  /** DKIM "RSA key under 2048 bits" — upgrade/rotation steps. */
  dkimKeyRotation: { page: "/learn/dkim", id: "key-rotation" },
  /** DKIM "No DKIM selectors found" — locating your provider's selector. */
  dkimFindSelector: { page: "/learn/dkim", id: "find-your-selector" },
  /** BIMI missing/invalid authority evidence (a=) — VMC/CMC guidance. */
  bimiCertification: { page: "/learn/bimi", id: "bimi-certification" },
  /** DMARC "p=none" — the none→quarantine→reject rollout path. */
  dmarcPolicyNone: { page: "/learn/dmarc", id: "p-none" },
} as const satisfies Record<string, LearnAnchor>;

export function learnAnchorHref(anchor: LearnAnchor): string {
  return `${anchor.page}#${anchor.id}`;
}
