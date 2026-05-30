import type {
  BimiResult,
  DkimResult,
  DmarcResult,
  MtaStsResult,
  SecurityTxtResult,
  SpfResult,
  Status,
  TlsRptResult,
} from "../analyzers/types.js";

interface Protocols {
  dmarc: DmarcResult;
  spf: SpfResult;
  dkim: DkimResult;
  bimi: BimiResult;
  mta_sts: MtaStsResult;
  // Optional in this internal interface so older test fixtures (which
  // don't know about security_txt) keep typechecking against this shape.
  // The orchestrator always populates it; informational only — does not
  // affect grade resolution.
  security_txt?: SecurityTxtResult;
  // Optional for same reason — older fixtures don't include tls_rpt.
  tls_rpt?: TlsRptResult;
  [key: string]: unknown;
}

export interface ScoringFactor {
  protocol: "dmarc" | "spf" | "dkim" | "bimi" | "mta_sts";
  label: string;
  effect: number;
}

export interface Recommendation {
  priority: 1 | 2 | 3;
  protocol: "dmarc" | "spf" | "dkim" | "bimi" | "mta_sts";
  title: string;
  description: string;
  impact: string;
}

export interface GradeBreakdown {
  grade: string;
  tier: string;
  tierReason: string;
  modifier: number;
  modifierLabel: string;
  factors: ScoringFactor[];
  recommendations: Recommendation[];
  protocolSummaries: Record<string, { status: Status; summary: string }>;
}

// ⚡ Bolt Optimization: Use a simple loop instead of .reduce()
// Avoids function creation overhead and reduces GC pressure on a hot path.
function sumEffects(factors: ScoringFactor[]): number {
  let sum = 0;
  for (let i = 0; i < factors.length; i++) {
    sum += factors[i].effect;
  }
  return sum;
}

// ── Configurable rubric ────────────────────────────────────

// Self-hosters can tune these knobs via the SCORING_CONFIG wrangler var
// (see src/shared/scoring-config.ts). Every field defaults to dmarc.mx's
// shipped behavior, so an unset/absent config produces identical grades.
// Config holds only numbers/booleans — never user-supplied strings — so it
// introduces no new HTML-output surface.
export interface ScoringConfig {
  // Whether the A+ tier requires a BIMI record.
  requireBimiForAPlus: boolean;
  // Whether the A+ tier requires enforcing (non-testing) MTA-STS.
  requireMtaStsForAPlus: boolean;
  // SPF DNS lookups at or below this earn the efficiency bonus.
  spfEfficientLookupThreshold: number;
  // DKIM keys below this many bits incur the weak-key penalty.
  dkimKeyMinBits: number;
  // DMARC pct below this downgrades the effective enforcement tier.
  lowPctDowngradeThreshold: number;
  // This many found DKIM selectors (or more) earns the rotation bonus.
  dkimRotationSelectorCount: number;
}

export const DEFAULT_SCORING_CONFIG: ScoringConfig = {
  requireBimiForAPlus: true,
  requireMtaStsForAPlus: true,
  spfEfficientLookupThreshold: 5,
  dkimKeyMinBits: 2048,
  lowPctDowngradeThreshold: 10,
  dkimRotationSelectorCount: 2,
};

// ── Single decision engine ─────────────────────────────────

interface ScoringResult {
  grade: string;
  tier: string;
  tierReason: string;
  modifier: number;
  modifierLabel: string;
  factors: ScoringFactor[];
}

function resolveScoring(
  protocols: Protocols,
  config: ScoringConfig,
): ScoringResult {
  const { dmarc, spf, dkim, bimi, mta_sts } = protocols;
  const dmarcPolicy = dmarc.tags?.p?.toLowerCase() ?? null;

  // DNS lookup failure ≠ "no record" — avoid a false F when the resolver
  // returned SERVFAIL or timed out. Report D so the user knows something
  // went wrong but doesn't think they have no DMARC policy.
  if (dmarc.lookup_error) {
    return {
      grade: "D",
      tier: "D",
      tierReason: `DMARC lookup failed (${dmarc.lookup_error.code}) — policy could not be verified`,
      modifier: 0,
      modifierLabel: "",
      factors: [],
    };
  }

  // Gatekeeper: no DMARC or p=none is automatic F
  if (dmarc.status === "fail" || !dmarcPolicy || dmarcPolicy === "none") {
    const tierReason = !dmarcPolicy
      ? "No DMARC record found"
      : dmarcPolicy === "none"
        ? "DMARC policy is set to none (no enforcement)"
        : "DMARC record failed validation";
    return {
      grade: "F",
      tier: "F",
      tierReason,
      modifier: 0,
      modifierLabel: "",
      factors: [],
    };
  }

  const pct = dmarc.tags?.pct ? Number.parseInt(dmarc.tags.pct, 10) : 100;
  const hasSpf = spf.status !== "fail";
  const hasDkim = dkim.status !== "fail";
  const hasBimi = bimi.record !== null;
  const hasMtaSts = mta_sts.status === "pass";

  // pct below the downgrade threshold effectively drops the policy one tier
  // reject with low pct → treated as quarantine-equivalent
  // quarantine with low pct → treated as near-none (C-tier max)
  const effectivePolicy =
    pct < config.lowPctDowngradeThreshold
      ? dmarcPolicy === "reject"
        ? "quarantine"
        : "quarantine"
      : dmarcPolicy;

  // D tier: missing SPF or DKIM
  if (!hasSpf || !hasDkim) {
    const missing =
      !hasSpf && !hasDkim ? "SPF and DKIM are" : !hasSpf ? "SPF is" : "DKIM is";
    return {
      grade: "D",
      tier: "D",
      tierReason: `p=${dmarcPolicy} but ${missing} missing`,
      modifier: 0,
      modifierLabel: "",
      factors: [],
    };
  }

  // C tier: quarantine (or reject downgraded by low pct) with SPF + DKIM
  if (effectivePolicy === "quarantine") {
    const factors = [
      ...spfFactors(spf, config),
      ...dkimFactors(dkim, config),
      ...dmarcFactors(dmarc, config),
    ];
    const modifier = sumEffects(factors);
    const pctNote =
      pct < config.lowPctDowngradeThreshold
        ? ` (pct=${pct}% — effectively quarantine)`
        : "";
    return {
      grade: applyModifier("C", modifier),
      tier: "C",
      tierReason: `p=${dmarcPolicy}${pctNote} with SPF and DKIM passing`,
      modifier,
      modifierLabel: modifierToLabel(modifier),
      factors,
    };
  }

  // B/A tiers: reject with SPF + DKIM
  if (effectivePolicy === "reject") {
    const spfStrong = spf.lookups_used <= spf.lookup_limit;
    const hasExtras = hasBimi || hasMtaSts;

    // A+ tier: strong SPF + both BIMI and MTA-STS (enforcing)
    if (
      spfStrong &&
      (!config.requireBimiForAPlus || hasBimi) &&
      (!config.requireMtaStsForAPlus ||
        (hasMtaSts && mta_sts.policy?.mode !== "testing"))
    ) {
      const factors = [
        ...spfFactors(spf, config),
        ...dkimFactors(dkim, config),
        ...dmarcFactors(dmarc, config),
      ];
      const modifier = sumEffects(factors);
      return {
        grade: "A+",
        tier: "A+",
        tierReason:
          "p=reject with strong SPF, DKIM, BIMI, and MTA-STS — perfect score",
        modifier,
        modifierLabel: modifierToLabel(modifier),
        factors,
      };
    }

    // A tier: strong SPF + at least one extra
    if (spfStrong && hasExtras) {
      const factors = [
        ...spfFactors(spf, config),
        ...dkimFactors(dkim, config),
        ...dmarcFactors(dmarc, config),
        ...mtaStsFactors(mta_sts),
      ];
      const modifier = sumEffects(factors);
      return {
        grade: applyModifier("A", modifier),
        tier: "A",
        tierReason:
          "p=reject with strong SPF, DKIM, and " +
          (hasBimi ? "BIMI" : "MTA-STS"),
        modifier,
        modifierLabel: modifierToLabel(modifier),
        factors,
      };
    }

    // B tier
    const factors = [
      ...spfFactors(spf, config),
      ...dkimFactors(dkim, config),
      ...dmarcFactors(dmarc, config),
      ...mtaStsFactors(mta_sts),
    ];
    if (hasBimi) {
      factors.push({
        protocol: "bimi",
        label: "BIMI configured",
        effect: +1,
      });
    }
    if (hasMtaSts) {
      factors.push({
        protocol: "mta_sts",
        label: "MTA-STS configured",
        effect: +1,
      });
    }
    const modifier = sumEffects(factors);
    return {
      grade: applyModifier("B", modifier),
      tier: "B",
      tierReason: "p=reject with SPF and DKIM passing",
      modifier,
      modifierLabel: modifierToLabel(modifier),
      factors,
    };
  }

  // Fallback (shouldn't normally reach here)
  const factors = [
    ...spfFactors(spf, config),
    ...dkimFactors(dkim, config),
    ...dmarcFactors(dmarc, config),
  ];
  const modifier = sumEffects(factors);
  return {
    grade: applyModifier("C", modifier),
    tier: "C",
    tierReason: "Fallback — quarantine-level enforcement",
    modifier,
    modifierLabel: modifierToLabel(modifier),
    factors,
  };
}

// ── Public API (thin wrappers) ────────────────────────

export function computeGrade(
  protocols: Protocols,
  config: Partial<ScoringConfig> = {},
): string {
  return resolveScoring(protocols, { ...DEFAULT_SCORING_CONFIG, ...config })
    .grade;
}

export function computeGradeBreakdown(
  protocols: Protocols,
  config: Partial<ScoringConfig> = {},
): GradeBreakdown {
  const merged = { ...DEFAULT_SCORING_CONFIG, ...config };
  const scoring = resolveScoring(protocols, merged);
  const recommendations = generateRecommendations(
    scoring.tier,
    protocols,
    merged,
  );
  const protocolSummaries = buildProtocolSummaries(protocols);

  return {
    ...scoring,
    recommendations,
    protocolSummaries,
  };
}

// ── Modifier helpers ────────────────────────────────

function applyModifier(base: "A" | "B" | "C" | "D", modifier: number): string {
  if (modifier >= 1) return `${base}+`;
  if (modifier <= -1) return `${base}-`;
  return base;
}

function modifierToLabel(modifier: number): string {
  if (modifier > 1) return `+${modifier}`;
  if (modifier === 1) return "+";
  if (modifier < -1) return `−${Math.abs(modifier)}`;
  if (modifier === -1) return "−";
  return "";
}

// ── Factor helpers ────────────────────────────────

function spfFactors(spf: SpfResult, config: ScoringConfig): ScoringFactor[] {
  const factors: ScoringFactor[] = [];
  if (spf.lookups_used <= config.spfEfficientLookupThreshold) {
    factors.push({
      protocol: "spf",
      label: `${spf.lookups_used} DNS lookups (≤${config.spfEfficientLookupThreshold}, efficient)`,
      effect: +1,
    });
  }
  return factors;
}

function dmarcFactors(
  dmarc: DmarcResult,
  config: ScoringConfig,
): ScoringFactor[] {
  const factors: ScoringFactor[] = [];
  const pct = dmarc.tags?.pct ? Number.parseInt(dmarc.tags.pct, 10) : 100;
  if (pct >= config.lowPctDowngradeThreshold && pct < 100) {
    factors.push({
      protocol: "dmarc",
      label: `Policy applied to only ${pct}% of messages (pct=${pct})`,
      effect: -1,
    });
  }
  if (dmarc.tags?.rua) {
    factors.push({
      protocol: "dmarc",
      label: "Aggregate reporting (rua) configured",
      effect: +1,
    });
  } else if (!dmarc.tags?.rua && !dmarc.tags?.ruf) {
    factors.push({
      protocol: "dmarc",
      label: "No DMARC reporting configured — cannot monitor authentication",
      effect: -1,
    });
  }
  return factors;
}

function mtaStsFactors(mta_sts: MtaStsResult): ScoringFactor[] {
  const factors: ScoringFactor[] = [];
  if (mta_sts.status === "pass" && mta_sts.policy?.mode === "testing") {
    factors.push({
      protocol: "mta_sts",
      label: "MTA-STS in testing mode (not enforcing)",
      effect: -1,
    });
  }
  return factors;
}

function dkimFactors(dkim: DkimResult, config: ScoringConfig): ScoringFactor[] {
  const factors: ScoringFactor[] = [];

  // ⚡ Bolt Optimization: Use for...in instead of Object.entries().filter()
  // Reduces GC pressure on hot paths by avoiding array allocations for entries
  let foundCount = 0;
  const weakKeyNames: string[] = [];

  for (const name in dkim.selectors) {
    const s = dkim.selectors[name];
    if (s.found) {
      foundCount++;
      if (s.key_bits && s.key_bits < config.dkimKeyMinBits) {
        weakKeyNames.push(name);
      }
    }
  }

  if (weakKeyNames.length > 0) {
    factors.push({
      protocol: "dkim",
      label: `Key under ${config.dkimKeyMinBits} bits (${weakKeyNames.join(", ")})`,
      effect: -1,
    });
  }
  if (foundCount >= config.dkimRotationSelectorCount) {
    factors.push({
      protocol: "dkim",
      label: `${foundCount} selectors found (rotation ready)`,
      effect: +1,
    });
  }
  return factors;
}

// ── Protocol summaries ────────────────────────────

function buildProtocolSummaries(
  protocols: Protocols,
): GradeBreakdown["protocolSummaries"] {
  const { dmarc, spf, dkim, bimi, mta_sts, security_txt, tls_rpt } = protocols;
  const dmarcPolicy = dmarc.tags?.p ?? null;
  // ⚡ Bolt Optimization: Use a simple loop instead of Object.values().filter()
  // Reduces GC pressure on hot paths by avoiding array allocations
  let dkimFoundCount = 0;
  for (const name in dkim.selectors) {
    if (dkim.selectors[name].found) dkimFoundCount++;
  }

  const summaries: GradeBreakdown["protocolSummaries"] = {
    dmarc: {
      status: dmarc.status,
      summary: dmarcPolicy ? `p=${dmarcPolicy}` : "Not configured",
    },
    spf: {
      status: spf.status,
      summary:
        spf.status === "fail"
          ? "Not configured"
          : `${spf.lookups_used}/${spf.lookup_limit} lookups, ${spf.record?.includes("-all") ? "-all" : "~all"}`,
    },
    dkim: {
      status: dkim.status,
      summary:
        dkim.status === "fail"
          ? "Not configured"
          : `${dkimFoundCount} selector${dkimFoundCount !== 1 ? "s" : ""}`,
    },
    bimi: {
      status: bimi.status,
      summary: bimi.record
        ? bimi.tags?.a
          ? "Record + certificate"
          : "Record found (no certificate)"
        : "Not configured",
    },
    mta_sts: {
      status: mta_sts.status,
      summary:
        mta_sts.status === "pass"
          ? `mode=${mta_sts.policy?.mode ?? "unknown"}`
          : "Not configured",
    },
  };
  if (security_txt) {
    summaries.security_txt = {
      status: security_txt.status,
      summary: security_txt.fields
        ? `${security_txt.fields.contact.length} contact${security_txt.fields.contact.length === 1 ? "" : "s"}${security_txt.signed ? " (signed)" : ""}`
        : "Not published",
    };
  }
  if (tls_rpt) {
    summaries.tls_rpt = {
      status: tls_rpt.status,
      summary: tls_rpt.record
        ? tls_rpt.tags?.rua
          ? tls_rpt.tags.rua.split(",")[0].trim()
          : "Record found (no rua)"
        : "Not configured",
    };
  }
  return summaries;
}

// ── Recommendations ───────────────────────────────

function generateRecommendations(
  tier: string,
  protocols: Protocols,
  config: ScoringConfig,
): Recommendation[] {
  const { dmarc, spf, dkim, bimi, mta_sts } = protocols;
  const recs: Recommendation[] = [];
  const dmarcPolicy = dmarc.tags?.p?.toLowerCase() ?? null;
  const hasSpf = spf.status !== "fail";
  const hasDkim = dkim.status !== "fail";
  const hasBimi = bimi.record !== null;
  const hasMtaSts = mta_sts.status === "pass";

  if (tier === "F") {
    if (!dmarcPolicy || dmarcPolicy === "none") {
      recs.push({
        priority: 1,
        protocol: "dmarc",
        title: "Add a DMARC policy with p=reject",
        description:
          "DMARC is the foundation of email security. Start with p=quarantine if you need to monitor first, then move to p=reject.",
        impact: "Required to move above F",
      });
    }
    return recs;
  }

  // D tier: missing SPF or DKIM
  if (tier === "D") {
    if (!hasSpf) {
      recs.push({
        priority: 1,
        protocol: "spf",
        title: "Add an SPF record",
        description:
          "SPF tells receiving servers which IPs are allowed to send mail for your domain.",
        impact: "Would raise grade to C tier",
      });
    }
    if (!hasDkim) {
      recs.push({
        priority: 1,
        protocol: "dkim",
        title: "Set up DKIM signing",
        description:
          "DKIM cryptographically signs outgoing mail, proving it hasn't been tampered with.",
        impact:
          dmarcPolicy === "reject"
            ? "Would raise grade to B tier"
            : "Would raise grade to C tier",
      });
    }
  }

  // C tier: upgrade policy
  if (tier === "C" && dmarcPolicy === "quarantine") {
    recs.push({
      priority: 1,
      protocol: "dmarc",
      title: "Upgrade DMARC policy from quarantine to reject",
      description:
        "p=reject tells receivers to drop unauthenticated mail entirely, providing the strongest protection against spoofing.",
      impact: "Would raise grade from C to B tier",
    });
  }

  // DMARC improvements
  const pct = dmarc.tags?.pct ? Number.parseInt(dmarc.tags.pct, 10) : 100;
  if (pct < 100) {
    const lowPct = pct < config.lowPctDowngradeThreshold;
    recs.push({
      priority: lowPct ? 1 : 2,
      protocol: "dmarc",
      title: "Increase DMARC pct to 100%",
      description: `Only ${pct}% of failing messages are subject to your policy. Gradually increase pct to 100 for full enforcement.`,
      impact: lowPct
        ? "Would raise effective enforcement tier"
        : "Removes a scoring penalty",
    });
  }
  if (!dmarc.tags?.rua) {
    recs.push({
      priority: 2,
      protocol: "dmarc",
      title: "Add aggregate reporting (rua)",
      description:
        "Without rua, you have no visibility into who is sending mail as your domain or whether authentication is working.",
      impact: "Removes a scoring penalty and enables monitoring",
    });
  }

  // SPF improvements
  if (hasSpf && spf.lookups_used > config.spfEfficientLookupThreshold) {
    recs.push({
      priority: 3,
      protocol: "spf",
      title: "Reduce SPF DNS lookups",
      description: `Your SPF record uses ${spf.lookups_used} DNS lookups. Flatten includes or remove unused entries to get to ≤${config.spfEfficientLookupThreshold} for a scoring bonus.`,
      impact: "Adds a scoring bonus",
    });
  }

  // DKIM improvements
  // ⚡ Bolt Optimization: Use for...in instead of Object.entries().filter()
  // Reduces GC pressure on hot paths by avoiding array allocations for entries
  const weakKeyNames: string[] = [];
  let foundSelectorCount = 0;
  for (const name in dkim.selectors) {
    const s = dkim.selectors[name];
    if (s.found) {
      foundSelectorCount++;
      if (s.key_bits && s.key_bits < config.dkimKeyMinBits) {
        weakKeyNames.push(name);
      }
    }
  }

  if (weakKeyNames.length > 0) {
    const names = weakKeyNames.join(", ");
    recs.push({
      priority: 2,
      protocol: "dkim",
      title: `Upgrade DKIM key${weakKeyNames.length > 1 ? "s" : ""} to ${config.dkimKeyMinBits} bits`,
      description: `The ${names} selector${weakKeyNames.length > 1 ? "s use" : " uses"} a key under ${config.dkimKeyMinBits} bits. Rotate to a ${config.dkimKeyMinBits}-bit or larger key.`,
      impact: "Removes a scoring penalty",
    });
  }

  // MTA-STS testing mode
  if (hasMtaSts && mta_sts.policy?.mode === "testing") {
    recs.push({
      priority: 2,
      protocol: "mta_sts",
      title: "Switch MTA-STS from testing to enforce mode",
      description:
        "Testing mode reports TLS failures but doesn't enforce them. Switch to enforce for full protection.",
      impact: "Removes a scoring penalty",
    });
  }

  // BIMI certificate — suggest if BIMI configured but no VMC/CMC
  if (hasBimi && !bimi.tags?.a) {
    recs.push({
      priority: 3,
      protocol: "bimi",
      title: "Add a VMC or CMC certificate",
      description:
        "Gmail and Apple Mail require a Verified Mark Certificate (VMC) or Common Mark Certificate (CMC) to display your BIMI logo. Without one, your logo won't appear in most inboxes.",
      impact: "Enables logo display in major email clients",
    });
  }

  // Extras (BIMI / MTA-STS) — suggest if missing
  if (!hasBimi && (tier === "B" || tier === "A")) {
    recs.push({
      priority: 3,
      protocol: "bimi",
      title: "Add a BIMI record",
      description:
        "BIMI displays your brand logo in supporting email clients. Requires DMARC p=reject.",
      impact:
        tier === "A"
          ? "Required for A+"
          : "Adds a scoring bonus, path to A tier",
    });
  }
  if (!hasMtaSts && (tier === "B" || tier === "A")) {
    recs.push({
      priority: 3,
      protocol: "mta_sts",
      title: "Add MTA-STS",
      description:
        "MTA-STS enforces TLS encryption for inbound mail delivery, preventing downgrade attacks.",
      impact:
        tier === "A"
          ? "Required for A+"
          : "Adds a scoring bonus, path to A tier",
    });
  }

  // DKIM rotation
  if (hasDkim && foundSelectorCount < config.dkimRotationSelectorCount) {
    recs.push({
      priority: 3,
      protocol: "dkim",
      title: "Add a second DKIM selector",
      description:
        "Multiple selectors enable key rotation without downtime — publish a new key before retiring the old one.",
      impact: "Adds a scoring bonus",
    });
  }

  return recs;
}
