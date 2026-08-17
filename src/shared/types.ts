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
  code:
    | "INVALID_DOMAIN"
    | "METHOD_NOT_ALLOWED"
    | "BAD_REQUEST"
    | "UPSTREAM_ERROR"
    | "NOT_FOUND"
    | "AUTHORIZATION_REQUIRED"
    | "RATE_LIMITED"
    | "UNSAFE_TARGET"
    | "SERVICE_UNAVAILABLE";
}

export type WebSecurityCheckStatus = "pass" | "warning" | "fail" | "not-applicable" | "unknown";

export type WebSecurityCheckId =
  | "https-enforcement"
  | "hsts"
  | "content-security-policy"
  | "frame-protection"
  | "mime-sniffing"
  | "referrer-policy"
  | "permissions-policy"
  | "cross-origin-isolation"
  | "cors-policy"
  | "http-methods"
  | "cookie-secure"
  | "cookie-httponly"
  | "cookie-samesite"
  | "cookie-scope-prefix"
  | "cache-control"
  | "technology-disclosure"
  | "error-handling"
  | "mixed-content"
  | "form-transport"
  | "subresource-integrity";

export interface WebSecurityCheck {
  id: WebSecurityCheckId;
  status: WebSecurityCheckStatus;
  title: string;
  summary: string;
  evidence: string[];
  remediation: string;
  owasp: {
    top10: string[];
    wstg: string[];
  };
}

export type TlsProtocolVersion = "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

export interface TlsCipherObservation {
  name: string;
  standardName?: string;
  version?: string;
  bits?: number;
}

export interface TlsProtocolObservation {
  version: TlsProtocolVersion;
  status: "supported" | "not-supported" | "unknown";
  cipher?: TlsCipherObservation;
  note?: string;
}

export interface TlsCertificateSummary {
  subject: string;
  issuer: string;
  subjectAltNames: string[];
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  serialNumber?: string;
  fingerprint256?: string;
  bits?: number;
  signatureAlgorithm?: string;
  ca?: boolean;
}

export interface TlsEndpointObservation {
  address: string;
  status: "ready" | "platform-blocked" | "unreachable" | "unavailable";
  summary: string;
  authorized?: boolean;
  authorizationError?: string;
  hostnameValid?: boolean;
  negotiatedProtocol?: string;
  cipher?: TlsCipherObservation;
  alpnProtocol?: string;
  ephemeralKey?: string;
  certificate?: TlsCertificateSummary;
  certificateChain: TlsCertificateSummary[];
  protocols: TlsProtocolObservation[];
  weakCipher: {
    status: "supported" | "not-supported" | "unknown";
    cipher?: TlsCipherObservation;
    note?: string;
  };
}

export interface TlsAssessment {
  status: "complete" | "partial" | "unavailable";
  grade: "A" | "B" | "C" | "D" | "F" | "N/A";
  summary: string;
  resolvedAddresses: string[];
  endpoints: TlsEndpointObservation[];
  endpointsTruncated: boolean;
  reportUrl: string;
  limitations: string[];
}

export interface WebScanQuota {
  limit: 5;
  remaining: number;
  resetAt: string;
  windowSeconds: 3600;
}

export const WEB_SECURITY_DISCLAIMER_VERSION = "2026-08-16" as const;

export const WEB_SECURITY_DISCLAIMER =
  "Authorized use only. By starting this scan, you certify that you own the target or have explicit permission to test it. The service makes a small number of DNS, HTTP, HTTPS, and TLS requests to the hostname entered, and target operators may log them. Do not use it to harass, disrupt, evade controls, or test systems without authorization. Results are automated, point-in-time observations; they may be incomplete or wrong and do not prove that a system is secure, vulnerable, or compliant. You are responsible for applicable law and third-party terms. Abuse may result in blocking and reporting.";

export interface WebSecurityScanResult {
  hostname: string;
  effectiveUrl: string;
  scannedAt: string;
  durationMs: number;
  score: number;
  grade: "A" | "B" | "C" | "D" | "F" | "N/A";
  headline: string;
  summary: string;
  tls: TlsAssessment;
  checks: WebSecurityCheck[];
  coverage: {
    evaluated: number;
    total: 20;
    unknown: number;
    notApplicable: number;
  };
  quota: WebScanQuota;
  requestBudget: {
    httpRequests: number;
    tlsConnections: number;
    maxResponseBytes: number;
    redirectHopsFollowed: number;
  };
  disclaimer: string;
}

export interface WebSecurityScanError extends ScanError {
  quota?: WebScanQuota;
}

export const SECURITY_ASSESSMENT_DISCLAIMER_VERSION = "2026-08-16-deep-v1" as const;

export const SECURITY_ASSESSMENT_DISCLAIMER =
  "Authorized use only. By starting this combined assessment, you certify that you own the target or have explicit permission to test it. The service performs the twenty bounded web-control observations plus a deep TLS assessment that may make hundreds of TLS handshakes, protocol and cipher negotiations, client simulations, and non-destructive cryptographic-flaw probes against public TCP port 443 endpoints. Target operators and Cloudflare's paid container platform may log this activity. The scanner does not submit credentials, change application data, crawl the site, execute denial-of-service tests, or send exploit payloads intended to alter the target. Do not use it to harass, disrupt, evade controls, or test systems without authorization. Results are automated, point-in-time observations; they may be incomplete or wrong and do not prove that a system is secure, vulnerable, or compliant. You are responsible for applicable law and third-party terms. Abuse may result in blocking and reporting.";

export type DeepTlsGradeValue = "A" | "B" | "C" | "D" | "F" | "N/A";
export type DeepTlsReportStatus = "complete" | "partial" | "unavailable";
export type DeepTlsSectionName =
  | "certificate"
  | "protocols"
  | "ciphers"
  | "keyExchange"
  | "features"
  | "clientSimulations"
  | "knownIssues";

export interface DeepTlsGradeCap {
  id: string;
  maxGrade: "B" | "C" | "D" | "F";
  reason: string;
}

export interface DeepTlsGrade {
  value: DeepTlsGradeValue;
  score: number | null;
  coverage: {
    evaluatedWeight: number;
    totalWeight: number;
  };
  methodology: "cresswell-tls-v1";
  caps: DeepTlsGradeCap[];
}

export interface DeepTlsObservation {
  id: string;
  sourceId?: string;
  status: "pass" | "warning" | "fail" | "info" | "unknown" | "not-tested";
  evidenceKind: "tested" | "inferred" | "not-testable";
  severity: "critical" | "high" | "medium" | "low" | "info" | "none";
  summary: string;
  details?: Record<string, string | number | boolean | string[] | null>;
}

export interface DeepTlsSection {
  status: DeepTlsReportStatus;
  grade: DeepTlsGrade;
  observations: DeepTlsObservation[];
}

export interface DeepTlsIssue {
  id: string;
  section: DeepTlsSectionName;
  observationId: string;
  severity: "critical" | "high" | "medium" | "low";
  evidenceKind: "tested" | "inferred" | "not-testable";
  summary: string;
}

export interface DeepTlsResponseV1 {
  schemaVersion: "tls-deep-v1";
  scanner: {
    engine: "testssl.sh";
    version: "3.2.4";
    commit: "97763a411c525720a5f9bd9d2cded416b10f210a";
    sourceUrl: "https://github.com/testssl/testssl.sh";
    license: "GPL-2.0-only";
    profileRevision: "safe-v1";
  };
  target: {
    hostname: string;
    address: string;
    addressFamily: 4 | 6;
    port: 443;
    sni: string;
    profile: "safe";
  };
  status: DeepTlsReportStatus;
  startedAt: string;
  durationMs: number;
  grade: DeepTlsGrade;
  budget: {
    deadlineMs: number;
    maxProcesses: 3;
    processesStarted: number;
    processesCompleted: number;
    maxConcurrentConnections: 5;
    maxConnections: 128;
    connectionsOpened: number;
    maxPhaseOutputBytes: 393_216;
    outputBytes: number;
    maxResponseBytes: 163_840;
  };
  phases: Array<{
    id: "identity" | "cryptography" | "compatibility";
    status: "complete" | "timed-out" | "failed" | "output-limit" | "unavailable";
    exitCode: number | null;
    durationMs: number;
    outputBytes: number;
  }>;
  sections: Record<DeepTlsSectionName, DeepTlsSection>;
  issues: DeepTlsIssue[];
  limitations: string[];
}

export interface DeepTlsAssessmentResult {
  status: DeepTlsReportStatus;
  grade: DeepTlsGrade;
  summary: string;
  resolvedAddresses: string[];
  endpoints: DeepTlsResponseV1[];
  endpointsTruncated: boolean;
  limitations: string[];
}

export type SecurityAssessmentWebResult = Omit<WebSecurityScanResult, "quota" | "tls">;

export interface SecurityAssessmentResult {
  schemaVersion: "security-assessment-v1";
  hostname: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  web: SecurityAssessmentWebResult;
  tls: DeepTlsAssessmentResult;
  disclaimer: string;
}

export type SecurityAssessmentJobStatus = "queued" | "running" | "complete" | "cancelled" | "failed";
export type SecurityAssessmentProgressPhase =
  | "queued"
  | "web-security"
  | "tls-validation"
  | "tls-scanning"
  | "finalizing"
  | "complete"
  | "cancelled"
  | "failed";

export interface SecurityAssessmentProgress {
  phase: SecurityAssessmentProgressPhase;
  message: string;
  completedEndpoints: number;
  totalEndpoints: number;
  percent?: number;
  updatedAt: string;
}

export interface SecurityAssessmentJobError {
  code:
    | "TARGET_CHANGED"
    | "TARGET_UNAVAILABLE"
    | "WEB_SCAN_FAILED"
    | "TLS_SCAN_FAILED"
    | "ORCHESTRATION_FAILED";
  message: string;
}

export interface SecurityAssessmentJobResource {
  jobId: string;
  hostname: string;
  status: SecurityAssessmentJobStatus;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  progress: SecurityAssessmentProgress;
  result?: SecurityAssessmentResult;
  error?: SecurityAssessmentJobError;
}

export interface SecurityAssessmentCreateResponse extends SecurityAssessmentJobResource {
  quota: WebScanQuota;
  reuse: "new" | "cache-hit" | "single-flight";
  pollAfterSeconds: number;
  /** Present only for the caller that created new work; never returned by status. */
  cancelToken?: string;
}

export interface SecurityAssessmentCancelResponse {
  cancelled: boolean;
  job: SecurityAssessmentJobResource;
}

export interface SecurityAssessmentApiError extends Omit<ScanError, "code"> {
  code:
    | ScanError["code"]
    | "JOB_NOT_FOUND"
    | "ORCHESTRATION_ERROR";
  quota?: WebScanQuota;
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
