export type CheckStatus = "pass" | "warning" | "fail" | "info" | "unknown";

export type FindingSeverity = "critical" | "warning" | "success" | "info";

export interface DnsRecordView {
  name: string;
  type: string;
  value: string;
  ttl?: number;
}

export interface Finding {
  id: string;
  severity: FindingSeverity;
  title: string;
  detail: string;
  action?: string;
}

export interface CheckResult {
  status: CheckStatus;
  title: string;
  summary: string;
  details: Array<{ label: string; value: string }>;
  records: DnsRecordView[];
}

export interface DkimSelectorResult {
  selector: string;
  found: boolean;
  kind?: "TXT" | "CNAME";
  value?: string;
}

export interface ScanResult {
  domain: string;
  scannedAt: string;
  durationMs: number;
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  posture: "reject" | "quarantine" | "monitoring" | "missing" | "invalid";
  postureLabel: string;
  headline: string;
  summary: string;
  checks: {
    dmarc: CheckResult;
    spf: CheckResult;
    dkim: CheckResult;
    transport: CheckResult;
  };
  dkimSelectors: DkimSelectorResult[];
  findings: Finding[];
  metadata: {
    mxProviders: string[];
    nameservers: string[];
    hasBimi: boolean;
    hasMtaSts: boolean;
    hasTlsRpt: boolean;
  };
  disclaimer: string;
}

export interface ScanError {
  error: string;
  code: "INVALID_DOMAIN" | "METHOD_NOT_ALLOWED" | "BAD_REQUEST" | "UPSTREAM_ERROR" | "NOT_FOUND";
}
