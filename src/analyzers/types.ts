export type Status = "pass" | "warn" | "fail" | "info";

export interface Validation {
  status: Status;
  message: string;
  /**
   * Site-relative deep link ("/learn/spf#lookup-limit") to the learn-page
   * section explaining how to fix this finding. Set only on the curated set
   * in src/shared/learn-anchors.ts; rendered as a "How to fix →" link (#524).
   */
  learnAnchor?: string;
}

export interface DmarcResult {
  status: Status;
  record: string | null;
  tags: Record<string, string> | null;
  validations: Validation[];
  lookup_error?: { code: string; message: string };
}

export interface SpfIncludeNode {
  domain: string;
  record: string | null;
  mechanisms: string[];
  includes: SpfIncludeNode[];
}

export interface SpfResult {
  status: Status;
  record: string | null;
  lookups_used: number;
  lookup_limit: number;
  include_tree: SpfIncludeNode | null;
  validations: Validation[];
  lookup_error?: { code: string; message: string };
}

export interface DkimSelectorResult {
  found: boolean;
  key_type?: string;
  key_bits?: number;
  testing?: boolean;
  revoked?: boolean;
}

export interface DkimResult {
  status: Status;
  selectors: Record<string, DkimSelectorResult>;
  validations: Validation[];
}

export interface BimiResult {
  status: Status;
  record: string | null;
  tags: Record<string, string> | null;
  validations: Validation[];
}

export interface MtaStsPolicy {
  version: string;
  mode: string;
  mx: string[];
  max_age: number;
}

export interface MtaStsResult {
  status: Status;
  dns_record: string | null;
  policy: MtaStsPolicy | null;
  validations: Validation[];
}

export interface EmailProvider {
  name: string;
  category: "security-gateway" | "email-platform" | "hosting";
}

export interface MxRecord {
  priority: number;
  exchange: string;
  provider?: EmailProvider;
}

export interface MxResult {
  status: Status;
  records: MxRecord[];
  providers: EmailProvider[];
  validations: Validation[];
  lookup_error?: { code: string; message: string };
}

export interface SecurityTxtFields {
  contact: string[];
  expires: string | null;
  encryption: string[];
  policy: string[];
  acknowledgments: string[];
  preferred_languages: string | null;
  canonical: string[];
  hiring: string[];
}

export interface SecurityTxtResult {
  status: Status;
  /** URL the file was actually fetched from (well-known or root fallback). */
  source_url: string | null;
  /** Whether the body carried PGP cleartext-signature armor. */
  signed: boolean;
  fields: SecurityTxtFields | null;
  validations: Validation[];
}

export interface TlsRptResult {
  status: Status;
  record: string | null;
  tags: Record<string, string> | null;
  validations: Validation[];
  lookup_error?: { code: string; message: string };
}

export interface ScanSummary {
  mx_records: number;
  mx_providers: string[];
  dmarc_policy: string | null;
  spf_result: Status;
  spf_lookups: string;
  dkim_selectors_found: number;
  bimi_enabled: boolean;
  mta_sts_mode: string | null;
}

export interface DnssecResult {
  status: Status;
  signed: boolean;
  validated: boolean;
  validations: Validation[];
  lookup_error?: { code: string; message: string };
}

export interface DaneTlsaRecord {
  usage: number;
  selector: number;
  matchingType: number;
  data: string;
}

export interface DaneHostResult {
  exchange: string;
  tlsaRecords: DaneTlsaRecord[];
  dnssecValidated: boolean;
}

export interface DaneResult {
  status: Status;
  hosts: DaneHostResult[];
  validations: Validation[];
  lookup_error?: { code: string; message: string };
}

/** Per-IP verdict from a DNSBL/IP-reputation check. */
export interface DnsblListing {
  /** The sending IP that was queried. */
  ip: string;
  /**
   * Where the IP was derived from, e.g. "SPF ip4", "A:mail.example.com",
   * "MX:mx.example.com". Never contains the DQS key.
   */
  source: string;
  /** "listed" = on the blocklist, "clean" = not listed, "error" = could not verify. */
  verdict: "listed" | "clean" | "error";
  /**
   * Human-readable Spamhaus zone labels for a listing (e.g. ["SBL", "XBL (CBL)"]).
   * Set only when verdict is "listed".
   */
  zones?: string[];
}

export interface DnsblResult {
  status: Status;
  /**
   * True only when a DQS key was present and the check actually ran. False on
   * the credential-gated no-op path (no DNSBL_DQS_KEY) — a clean, scored-out
   * informational result, never a fail.
   */
  enabled: boolean;
  /** Per-IP results for every IP actually queried (after the per-scan cap). */
  checked: DnsblListing[];
  /** Count of derivable sending IPs found before the per-scan cap was applied. */
  ips_found: number;
  /** Count of IPs actually queried (≤ ips_found, bounded by the per-scan cap). */
  ips_checked: number;
  validations: Validation[];
  lookup_error?: { code: string; message: string };
}

export interface ScanResult {
  domain: string;
  timestamp: string;
  grade: string;
  breakdown: import("../shared/scoring.js").GradeBreakdown;
  summary: ScanSummary;
  protocols: {
    mx: MxResult;
    dmarc: DmarcResult;
    spf: SpfResult;
    dkim: DkimResult;
    bimi: BimiResult;
    mta_sts: MtaStsResult;
    security_txt: SecurityTxtResult;
    tls_rpt?: TlsRptResult;
    dnssec?: DnssecResult;
    dane?: DaneResult;
    dnsbl?: DnsblResult;
  };
}
