import { DnsLookupError, queryTxt } from "../dns/client.js";
import type { ScanBudget } from "../dns/scan-budget.js";
import { LEARN_ANCHORS, learnAnchorHref } from "../shared/learn-anchors.js";
import type { SpfIncludeNode, SpfResult, Validation } from "./types.js";

const MAX_LOOKUPS = 10;

export async function analyzeSpf(
  domain: string,
  budget?: ScanBudget,
): Promise<SpfResult> {
  const ctx: ResolutionContext = {
    lookups: 0,
    visited: new Set(),
    hasCycle: false,
    voidLookups: 0,
    multipleRootRecords: false,
    duplicateRedirect: false,
    duplicateExp: false,
    malformedMacroTargets: [],
  };

  let tree: SpfIncludeNode | null;
  try {
    tree = await resolveSpfTree(domain, ctx, 0, budget);
  } catch (err) {
    if (err instanceof DnsLookupError) {
      return {
        status: "warn",
        record: null,
        lookups_used: 0,
        lookup_limit: MAX_LOOKUPS,
        include_tree: null,
        lookup_error: { code: err.code, message: err.message },
        validations: [
          {
            status: "warn",
            message: `SPF lookup failed (${err.code}) — result may be incomplete`,
          },
        ],
      };
    }
    throw err;
  }

  if (!tree?.record) {
    return {
      status: "fail",
      record: null,
      lookups_used: 0,
      lookup_limit: MAX_LOOKUPS,
      include_tree: null,
      validations: [{ status: "fail", message: "No SPF record found" }],
    };
  }

  const validations: Validation[] = [];
  validations.push({ status: "pass", message: "SPF record found" });

  // Lookup limit check
  if (ctx.lookups <= MAX_LOOKUPS) {
    validations.push({
      status: "pass",
      message: `Within 10-lookup limit (${ctx.lookups} used)`,
    });
  } else {
    validations.push({
      status: "fail",
      message: `Exceeds 10-lookup limit (${ctx.lookups} used) — SPF will permerror`,
      learnAnchor: learnAnchorHref(LEARN_ANCHORS.spfLookupLimit),
    });
  }

  // Circular include check
  if (ctx.hasCycle) {
    validations.push({
      status: "fail",
      message:
        "Circular include detected — SPF will permerror (RFC 7208 §4.6.4)",
    });
  }

  // Multiple SPF records check
  if (ctx.multipleRootRecords) {
    validations.push({
      status: "fail",
      message:
        "Multiple SPF records published — SPF will permerror (RFC 7208 §4.5)",
    });
  }

  // Repeated redirect=/exp= modifier (RFC 7208 §6: a modifier MUST NOT appear
  // more than once in a record)
  if (ctx.duplicateRedirect) {
    validations.push({
      status: "fail",
      message:
        "Duplicate redirect= modifier — SPF will permerror (RFC 7208 §6)",
    });
  }
  if (ctx.duplicateExp) {
    validations.push({
      status: "fail",
      message: "Duplicate exp= modifier — SPF will permerror (RFC 7208 §6)",
    });
  }

  // Malformed macro syntax in include:/exists:/redirect= targets (RFC 7208
  // §7.1) — checked anywhere in the tree, not just the root record.
  if (ctx.malformedMacroTargets.length > 0) {
    validations.push({
      status: "fail",
      message: `Malformed macro syntax — SPF will permerror (RFC 7208 §7.1): ${ctx.malformedMacroTargets.join(", ")}`,
    });
  }

  // Empty redirect=/exp= modifier target (RFC 7208 §6.1/§6.2 require a domain-spec)
  if (tree.mechanisms.some((m) => m.replace(/^[+\-~?]/, "") === "redirect=")) {
    validations.push({
      status: "fail",
      message: "Empty redirect= target — SPF will permerror (RFC 7208 §6.1)",
    });
  }
  if (tree.mechanisms.some((m) => m.replace(/^[+\-~?]/, "") === "exp=")) {
    validations.push({
      status: "fail",
      message: "Empty exp= target — SPF will permerror (RFC 7208 §6.2)",
    });
  }

  // Void-lookup limit check
  if (ctx.voidLookups > MAX_VOID_LOOKUPS) {
    validations.push({
      status: "fail",
      message: `Exceeds 2 void DNS lookups (${ctx.voidLookups}) — SPF will permerror (RFC 7208 §4.6.4)`,
    });
  }

  // all mechanism check
  const allIndex = tree.mechanisms.findIndex((m) => m.endsWith("all"));
  const allMech = allIndex === -1 ? undefined : tree.mechanisms[allIndex];
  if (allMech) {
    if (allMech === "-all") {
      validations.push({
        status: "pass",
        message: "Uses -all (hardfail) for strict enforcement",
      });
    } else if (allMech === "~all") {
      validations.push({
        status: "warn",
        message: "Uses ~all (softfail) — consider -all for strict enforcement",
      });
    } else if (allMech === "+all" || allMech === "all") {
      validations.push({
        status: "fail",
        message: "Uses +all — allows any sender, effectively no protection",
      });
    } else if (allMech === "?all") {
      validations.push({
        status: "warn",
        message: "Uses ?all (neutral) — provides no guidance to receivers",
      });
    }

    // RFC 7208 §5.1: terms after "all" are never evaluated
    const termsAfterAll = tree.mechanisms.slice(allIndex + 1);
    if (termsAfterAll.length > 0) {
      validations.push({
        status: "warn",
        message: `Terms after ${allMech} are unreachable and never evaluated (RFC 7208 §5.1): ${termsAfterAll.join(", ")}`,
      });
    }
  }

  // Deprecated ptr check. Strip the optional qualifier (+ - ~ ?) so
  // "+ptr"/"~ptr"/"-ptr:host" are recognized, not just the bare form.
  const hasPtr = tree.mechanisms.some((m) => {
    const bare = m.replace(/^[+\-~?]/, "");
    return bare === "ptr" || bare.startsWith("ptr:");
  });
  if (hasPtr) {
    validations.push({
      status: "warn",
      message: "Uses deprecated ptr mechanism (RFC 7208 recommends against it)",
    });
  } else {
    validations.push({
      status: "pass",
      message: "No deprecated ptr mechanism",
    });
  }

  // Unknown/malformed mechanism or modifier check (RFC 7208 §4.6.1)
  const unknownTerms = tree.mechanisms.filter((t) => !isKnownSpfTerm(t));
  if (unknownTerms.length > 0) {
    validations.push({
      status: "fail",
      message: `Unknown SPF ${unknownTerms.length === 1 ? "term" : "terms"} — receivers will permerror (RFC 7208 §4.6.1): ${unknownTerms.join(", ")}`,
    });
  }

  // Invalid ip4:/ip6: address or CIDR prefix length (RFC 7208 §5.6: ip4
  // prefix 0-32, ip6 prefix 0-128)
  const invalidIpTerms = tree.mechanisms.filter((m) => {
    const bare = m.replace(/^[+\-~?]/, "");
    if (bare.startsWith("ip4:")) return !isValidIp4Cidr(bare.slice(4));
    if (bare.startsWith("ip6:")) return !isValidIp6Cidr(bare.slice(4));
    return false;
  });
  if (invalidIpTerms.length > 0) {
    validations.push({
      status: "fail",
      message: `Invalid ip4/ip6 ${invalidIpTerms.length === 1 ? "address" : "addresses"} — receivers will permerror (RFC 7208 §5.6): ${invalidIpTerms.join(", ")}`,
    });
  }

  const hasFailure = validations.some((v) => v.status === "fail");
  const hasWarn = validations.some((v) => v.status === "warn");
  const status = hasFailure ? "fail" : hasWarn ? "warn" : "pass";

  return {
    status,
    record: tree.record,
    lookups_used: ctx.lookups,
    lookup_limit: MAX_LOOKUPS,
    include_tree: tree,
    validations,
  };
}

interface ResolutionContext {
  lookups: number;
  visited: Set<string>;
  hasCycle: boolean;
  // RFC 7208 §4.6.4: lookups that return NXDOMAIN/NODATA ("void lookups") are
  // capped at 2. We can only observe voids for include:/redirect= targets,
  // which actually issue a queryTxt. a/mx/exists are counted toward the
  // 10-lookup limit but never resolved here, so their voids are not yet
  // detected — tracked for future SPF work (see #435).
  voidLookups: number;
  // RFC 7208 §4.5: more than one v=spf1 record at the queried name is a
  // permerror. We only flag this for the published (root) domain.
  multipleRootRecords: boolean;
  // RFC 7208 §6: a record MUST NOT repeat the redirect= or exp= modifier.
  // Set if any record in the tree (root or included) repeats either.
  duplicateRedirect: boolean;
  duplicateExp: boolean;
  // RFC 7208 §7.1: include:/exists:/redirect= targets with malformed macro
  // syntax (anywhere in the tree, not just the root record). Collected as
  // the full mechanism text so the validation message can name each one.
  malformedMacroTargets: string[];
}

const MAX_VOID_LOOKUPS = 2;

async function resolveSpfTree(
  domain: string,
  ctx: ResolutionContext,
  depth: number,
  budget?: ScanBudget,
): Promise<SpfIncludeNode | null> {
  if (depth > 10) return null; // Prevent infinite recursion
  if (ctx.lookups > MAX_LOOKUPS) return null; // Prevent excessive DNS queries

  const normalizedDomain = domain.toLowerCase();
  if (ctx.visited.has(normalizedDomain)) {
    ctx.hasCycle = true;
    return null;
  }
  ctx.visited.add(normalizedDomain);

  const txt = await queryTxt(domain, budget);
  if (!txt) {
    // NXDOMAIN/NODATA. For include:/redirect= targets (depth > 0) this is a
    // void lookup under RFC 7208 §4.6.4; the root domain returning null just
    // means "no SPF record" and is handled by the caller.
    if (depth > 0) ctx.voidLookups++;
    return null;
  }

  const spfRecords = txt.entries.filter(
    (e) => e.trimStart().startsWith("v=spf1 ") || e.trim() === "v=spf1",
  );
  if (spfRecords.length === 0) return null;
  // RFC 7208 §4.5: more than one SPF record at the published domain is a
  // permerror. Flag it at the root; evaluation still proceeds on the first.
  if (depth === 0 && spfRecords.length > 1) {
    ctx.multipleRootRecords = true;
  }
  const spfRecord = spfRecords[0];

  const mechanisms = parseSpfMechanisms(spfRecord);
  const includes: SpfIncludeNode[] = [];

  // Find include targets and redirect
  const includeTargets: string[] = [];
  let redirect: string | null = null;
  let redirectCount = 0;
  let expCount = 0;

  for (const mech of mechanisms) {
    if (ctx.lookups > MAX_LOOKUPS) break;

    const bare = mech.replace(/^[+\-~?]/, "");
    if (bare.startsWith("include:")) {
      ctx.lookups++;
      const target = bare.slice("include:".length);
      if (hasMalformedMacro(target)) {
        ctx.malformedMacroTargets.push(mech);
      } else {
        includeTargets.push(target);
      }
    } else if (bare.startsWith("redirect=")) {
      ctx.lookups++;
      redirectCount++;
      const target = bare.slice("redirect=".length);
      if (hasMalformedMacro(target)) {
        ctx.malformedMacroTargets.push(mech);
      } else {
        redirect = target;
      }
    } else if (bare.startsWith("exp=")) {
      expCount++;
    } else if (bare.startsWith("a:") || bare === "a") {
      ctx.lookups++;
    } else if (bare.startsWith("mx:") || bare === "mx") {
      ctx.lookups++;
    } else if (bare.startsWith("ptr:") || bare === "ptr") {
      ctx.lookups++;
    } else if (bare.startsWith("exists:")) {
      ctx.lookups++;
      const target = bare.slice("exists:".length);
      if (hasMalformedMacro(target)) {
        ctx.malformedMacroTargets.push(mech);
      }
    }
  }

  if (redirectCount > 1) ctx.duplicateRedirect = true;
  if (expCount > 1) ctx.duplicateExp = true;

  // Resolve includes in parallel
  // ⚡ Bolt: Only recurse on includes if we haven't already exceeded the DNS lookup limit
  // Prevents cascading excessive parallel DNS queries for complex or malicious SPF trees
  const resolved =
    ctx.lookups > MAX_LOOKUPS
      ? []
      : await Promise.allSettled(
          includeTargets.map((target) =>
            resolveSpfTree(target, ctx, depth + 1, budget),
          ),
        );

  for (const result of resolved) {
    if (result.status === "fulfilled" && result.value) {
      includes.push(result.value);
    }
  }

  // Handle redirect (processed after all mechanisms)
  if (redirect && ctx.lookups <= MAX_LOOKUPS) {
    const redirectNode = await resolveSpfTree(redirect, ctx, depth + 1, budget);
    if (redirectNode) {
      includes.push(redirectNode);
    }
  }

  return { domain, record: spfRecord, mechanisms, includes };
}

// RFC 7208 §5.6: an ip4/ip6 mechanism's address must be a valid literal, with
// an optional CIDR prefix length in range 0-32 (ip4) / 0-128 (ip6).
function isValidIp4Address(addr: string): boolean {
  const parts = addr.split(".");
  return (
    parts.length === 4 &&
    parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)
  );
}

function isValidIp4Cidr(spec: string): boolean {
  const [addr, prefix, extra] = spec.split("/");
  if (extra !== undefined || !isValidIp4Address(addr)) return false;
  if (prefix === undefined) return true;
  if (!/^\d{1,2}$/.test(prefix)) return false;
  const len = Number(prefix);
  return len >= 0 && len <= 32;
}

function isValidIp6Address(addr: string): boolean {
  if (addr.length === 0) return false;
  const isHextet = (g: string) => /^[0-9a-fA-F]{1,4}$/.test(g);
  const groupCount = (groups: string[]): number | null => {
    let count = 0;
    for (let i = 0; i < groups.length; i++) {
      const g = groups[i];
      if (i === groups.length - 1 && g.includes(".")) {
        if (!isValidIp4Address(g)) return null;
        count += 2;
      } else {
        if (!isHextet(g)) return null;
        count += 1;
      }
    }
    return count;
  };
  const toGroups = (s: string): string[] => (s === "" ? [] : s.split(":"));

  const parts = addr.split("::");
  if (parts.length > 2) return false; // more than one "::" compression

  if (parts.length === 1) {
    const count = groupCount(toGroups(addr));
    return count === 8;
  }

  const [left, right] = parts;
  const leftGroups = toGroups(left);
  const rightGroups = toGroups(right);
  if (!leftGroups.every(isHextet)) return false;
  const rightCount = groupCount(rightGroups);
  if (rightCount === null) return false;
  // "::" must collapse at least one group, so the explicit groups on both
  // sides must leave room for it within the 8-group address.
  return leftGroups.length + rightCount <= 7;
}

function isValidIp6Cidr(spec: string): boolean {
  const [addr, prefix, extra] = spec.split("/");
  if (extra !== undefined || !isValidIp6Address(addr)) return false;
  if (prefix === undefined) return true;
  if (!/^\d{1,3}$/.test(prefix)) return false;
  const len = Number(prefix);
  return len >= 0 && len <= 128;
}

// RFC 7208 §7.1 macro-string grammar:
//   macro-expand  = ( "%{" macro-letter transformers *delimiter "}" )
//                   / "%%" / "%_" / "%-"
//   macro-letter  = "s" / "l" / "o" / "d" / "i" / "p" / "h" / "c" / "r" / "t" / "v"
//                   (upper-case forces URL-escaping and is equally valid)
//   transformers  = *DIGIT [ "r" ]
//   delimiter     = "." / "-" / "+" / "," / "/" / "_" / "="
// Any other use of "%" — a stray "%", an unterminated "%{", or an invalid
// macro-letter/transformer/delimiter — is a syntax error.
const MACRO_BODY_RE = /^[slodiphcrtvSLODIPHCRTV]\d*r?[.\-+,/_=]*$/;

function hasMalformedMacro(domainSpec: string): boolean {
  for (let i = 0; i < domainSpec.length; i++) {
    if (domainSpec[i] !== "%") continue;
    const next = domainSpec[i + 1];
    if (next === "%" || next === "_" || next === "-") {
      i++;
      continue;
    }
    if (next !== "{") return true; // stray '%'
    const close = domainSpec.indexOf("}", i + 2);
    if (close === -1) return true; // unterminated "%{"
    const body = domainSpec.slice(i + 2, close);
    if (!MACRO_BODY_RE.test(body)) return true;
    i = close;
  }
  return false;
}

function parseSpfMechanisms(record: string): string[] {
  return record
    .replace(/^v=spf1\s*/, "")
    .split(/\s+/)
    .filter((t) => t.length > 0);
}

// RFC 7208 §5 mechanisms and §6 modifiers. Strip optional qualifier prefix
// before matching so "+all", "-all", "~all", "?all" are all recognized.
function isKnownSpfTerm(term: string): boolean {
  const bare = term.replace(/^[+\-~?]/, "");
  return (
    bare === "all" ||
    bare.startsWith("include:") ||
    bare === "a" ||
    bare.startsWith("a:") ||
    bare.startsWith("a/") ||
    bare === "mx" ||
    bare.startsWith("mx:") ||
    bare.startsWith("mx/") ||
    bare === "ptr" ||
    bare.startsWith("ptr:") ||
    bare.startsWith("ip4:") ||
    bare.startsWith("ip6:") ||
    bare.startsWith("exists:") ||
    bare.startsWith("redirect=") ||
    bare.startsWith("exp=")
  );
}
