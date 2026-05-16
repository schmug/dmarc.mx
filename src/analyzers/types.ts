export type Status = "pass" | "warn" | "fail" | "info";

export interface Validation {
  status: Status;
  message: string;
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
  };
}
