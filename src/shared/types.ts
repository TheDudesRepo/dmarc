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
  remediation?: {
    summary: string;
    steps: string[];
    record?: {
      name: string;
      type: string;
      value: string;
    };
    caution?: string;
  };
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
  issue?: "revoked" | "unresolved-alias";
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
    dns: CheckResult;
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

export type DnsLookupType =
  | "A"
  | "AAAA"
  | "CAA"
  | "CNAME"
  | "MX"
  | "NS"
  | "PTR"
  | "SOA"
  | "SRV"
  | "TXT";

/** Includes analyzed lookup modes that are backed by one or more real DNS resource records. */
export type DnsLookupMode = DnsLookupType | "SPF";

export type SpfLookupStatus = "missing" | "multiple" | "invalid" | "warning" | "valid";

export interface SpfMechanismView {
  raw: string;
  qualifier: "+" | "-" | "~" | "?";
  name: string;
  domainSpec?: string;
  cidr4?: number;
  cidr6?: number;
  causesDnsLookup: boolean;
}

export interface SpfLookupEstimateView {
  count: number;
  exceedsLimit: boolean;
  truncated: boolean;
  expandedDomains: string[];
  issues: string[];
}

export interface SpfCorrectionGuidance {
  summary: string;
  steps: string[];
  caution?: string;
}

export interface SpfLookupAnalysis {
  status: SpfLookupStatus;
  recordCount: number;
  /** True only when one syntactically valid record has no confirmed lookup-limit violation. */
  valid: boolean;
  /** Syntax validity is reported separately because an otherwise valid record can exceed ten lookups. */
  syntaxValid: boolean;
  mechanisms: SpfMechanismView[];
  terminalPolicy: "+all" | "-all" | "~all" | "?all" | "none";
  lookupEstimate?: SpfLookupEstimateView;
  warnings: string[];
  errors: string[];
  issues: string[];
  correctionGuidance: SpfCorrectionGuidance;
}

export interface DnsLookupResult<TType extends DnsLookupMode = DnsLookupType> {
  input: string;
  queryName: string;
  canonicalName?: string;
  type: TType;
  scannedAt: string;
  durationMs: number;
  records: DnsRecordView[];
  summary: string;
  /** Present only for the analyzed SPF lookup mode; records remain truthful TXT evidence. */
  spfAnalysis?: SpfLookupAnalysis;
}

export type SnapshotRecordType = "A" | "AAAA" | "CAA" | "CNAME" | "MX" | "NS" | "SOA" | "TXT";
export type HostDiscoveryProfile = "core" | "extended";

export interface DnsSnapshotGroup {
  type: SnapshotRecordType;
  status: "found" | "empty" | "unavailable";
  records: DnsRecordView[];
  canonicalName?: string;
}

export interface SecurityDnsRecord {
  key: "dmarc" | "mta-sts" | "tls-rpt" | "bimi";
  label: string;
  ownerName: string;
  status: "found" | "empty" | "unavailable";
  records: DnsRecordView[];
  canonicalName?: string;
}

export interface DiscoveredDnsHost {
  hostname: string;
  source: "common-name" | "mail" | "nameserver";
  profile?: HostDiscoveryProfile;
  alias?: string;
  addresses: string[];
  /** Address RRsets that failed and therefore cannot be treated as empty. */
  unavailableAddressTypes?: Array<"A" | "AAAA">;
  reverseNames: string[];
  /** True when this answer matches the random-label wildcard probe for the same scan. */
  wildcardMatch?: boolean;
}

export interface DiscoveryFinding {
  id: string;
  severity: FindingSeverity;
  title: string;
  detail: string;
  steps: string[];
}

export interface DnsSnapshotResult {
  domain: string;
  scannedAt: string;
  durationMs: number;
  groups: DnsSnapshotGroup[];
  securityRecords: SecurityDnsRecord[];
  infrastructureHosts: DiscoveredDnsHost[];
  findings: DiscoveryFinding[];
  recordCount: number;
  unavailableCount: number;
  summary: string;
  disclaimer: string;
}

export interface HostDiscoveryResult {
  domain: string;
  profile: HostDiscoveryProfile;
  scannedAt: string;
  durationMs: number;
  testedNames: string[];
  hosts: DiscoveredDnsHost[];
  unavailableNames: string[];
  wildcardProbe: {
    hostname: string;
    detected: boolean;
    alias?: string;
    addresses: string[];
    unavailable: boolean;
  };
  summary: string;
  disclaimer: string;
}

export type IpVersion = 4 | 6;
export type IpClassificationKind =
  | "private"
  | "loopback"
  | "link-local"
  | "multicast"
  | "documentation"
  | "reserved"
  | "global";

export interface IpClassification {
  /** Classification of the supplied address, rather than every address covered by its prefix. */
  kind: IpClassificationKind;
  private: boolean;
  loopback: boolean;
  linkLocal: boolean;
  multicast: boolean;
  documentation: boolean;
  reserved: boolean;
  global: boolean;
}

export interface IpUsableRange {
  first: string;
  last: string;
  count: string;
  convention: "ipv4-traditional" | "ipv4-point-to-point" | "ipv4-host" | "ipv6-addresses";
}

export interface Ipv4NetworkDetails {
  netmask: string;
  wildcard: string;
  broadcast: string;
}

export interface IpNetworkCalculation {
  address: string;
  canonical: string;
  cidr: string;
  version: IpVersion;
  prefix: number;
  network: string;
  networkCidr: string;
  lastAddress: string;
  totalAddresses: string;
  isSingleAddress: boolean;
  classification: IpClassification;
  usable: IpUsableRange;
  ipv4?: Ipv4NetworkDetails;
}

export type EnrichmentEvidenceStatus = "found" | "not-found" | "indeterminate" | "not-requested";
export type EnrichmentStatus =
  | "not-requested"
  | "not-applicable"
  | "complete"
  | "partial"
  | "indeterminate";

export interface PtrEvidence {
  status: EnrichmentEvidenceStatus;
  owner?: string;
  canonicalOwner?: string;
  names: string[];
}

export interface CymruOriginRecord {
  /** First origin ASN, retained as a convenient primary value. See `asns` for MOAS results. */
  asn: string;
  asns: string[];
  prefix: string;
  country: string;
  registry: string;
  allocated: string;
}

export interface CymruOriginEvidence {
  status: EnrichmentEvidenceStatus;
  owner?: string;
  /** First valid row, retained for simple single-origin consumers. */
  record?: CymruOriginRecord;
  records?: CymruOriginRecord[];
}

export interface CymruAsNameEvidence {
  status: EnrichmentEvidenceStatus;
  asn?: string;
  owner?: string;
  name?: string;
}

export interface IpEnrichment {
  status: EnrichmentStatus;
  queryCount: number;
  ptr: PtrEvidence;
  origin: CymruOriginEvidence;
  asName?: CymruAsNameEvidence;
  asNames?: CymruAsNameEvidence[];
  asNamesTruncated?: boolean;
  reason?: string;
  attribution: {
    ptr: "Native DNS PTR";
    asn: {
      name: string;
      url: string;
    };
  };
}

export interface IpToolsResult extends IpNetworkCalculation {
  enrichment: IpEnrichment;
}
