import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  BarChart3,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleHelp,
  Clock3,
  Code2,
  Copy,
  Database,
  ExternalLink,
  FileSearch,
  Globe2,
  Info,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  MailCheck,
  Menu,
  Network,
  Radar,
  RefreshCw,
  Route,
  ServerCog,
  Shield,
  ShieldCheck,
  ShieldEllipsis,
  ShieldX,
  Sparkles,
  Waypoints,
  XCircle,
} from "lucide-react";
import { FormEvent, ReactNode, useEffect, useRef, useState } from "react";
import type {
  CheckResult,
  CheckStatus,
  DnsLookupResult,
  DnsLookupMode,
  DnsLookupType,
  Finding,
  FindingSeverity,
  ScanError,
  ScanResult,
  SpfLookupAnalysis,
} from "../shared/types";
import { DnsSurfaceScanner } from "./DnsSurfaceScanner";
import { IpNetworkTool } from "./IpNetworkTool";
import { WebSecurityScanner } from "./WebSecurityScanner";

const EXAMPLE_DOMAINS = ["google.com", "github.com", "cloudflare.com"];

export const DNS_LOOKUP_TYPES: readonly DnsLookupType[] = [
  "A",
  "AAAA",
  "MX",
  "NS",
  "TXT",
  "CNAME",
  "SOA",
  "CAA",
  "SRV",
  "PTR",
];

export const DNS_LOOKUP_MODES: readonly DnsLookupMode[] = ["SPF", ...DNS_LOOKUP_TYPES];

const DNS_LOOKUP_MODE_SET = new Set<string>(DNS_LOOKUP_MODES);

const DNS_LOOKUP_HINTS: Partial<Record<DnsLookupMode, string>> = {
  SPF: "Enter a sending domain or public SPF policy owner such as _spf.example.com. SPF is analyzed from TXT; obsolete RR type 99 is not queried.",
  TXT: "Use the exact owner name, such as selector._domainkey.example.com for a DKIM key.",
  CNAME: "Use the alias owner name, such as www.example.com.",
  SRV: "Service records use _service._protocol, such as _sip._tcp.example.com.",
  PTR: "Enter an IPv4 or IPv6 address; the server converts it to the reverse-DNS owner name.",
};

const DNS_LOOKUP_GUIDANCE: Record<DnsLookupMode, { present: string; empty: string }> = {
  SPF: {
    present: "Use the analyzer evidence below. Keep one policy, validate every sender, and keep the evaluated path within ten DNS lookups.",
    empty: "Do not guess an SPF value. Inventory every legitimate envelope-from sender, then publish one provider-reviewed v=spf1 TXT record.",
  },
  A: {
    present: "Confirm each address belongs to the intended web, application, or edge provider before changing it.",
    empty: "Only add an A record if this exact name needs IPv4 service; use the address supplied by the hosting provider.",
  },
  AAAA: {
    present: "Confirm IPv6 is intentionally enabled and the service is reachable and secured over every returned address.",
    empty: "AAAA is optional. Add it only when the service and network are ready to accept IPv6 traffic.",
  },
  MX: {
    present: "Compare priorities and hosts with the mail provider. A lone 0 . intentionally disables inbound mail.",
    empty: "If the domain receives mail, publish the provider's exact MX set; otherwise consider one explicit null MX (0 .).",
  },
  NS: {
    present: "At a delegated zone, compare this set with the registrar and DNS provider; ordinary hostnames may inherit authority.",
    empty: "No direct NS is normal for a hostname. Investigate only if this exact name should be a separately delegated zone.",
  },
  TXT: {
    present: "Review each value independently. Keep one SPF policy and one DMARC policy at their required owner names.",
    empty: "Verify the exact owner name first; TXT records are often published at prefixes such as _dmarc or selector._domainkey.",
  },
  CNAME: {
    present: "Confirm the canonical target is current and resolves to the terminal service records expected by the provider.",
    empty: "CNAME is optional. Do not add one where the same owner must retain independent MX, TXT, or other record data.",
  },
  SOA: {
    present: "At the zone apex, confirm the primary server and serial are consistent across the authoritative nameservers.",
    empty: "No direct SOA is normal for a hostname. Inspect the containing zone apex before treating this as a fault.",
  },
  CAA: {
    present: "Confirm every authorized certificate authority is intentional; restrictive CAA can block certificate renewal.",
    empty: "CAA is optional and may be inherited. Add it only after identifying every CA used for current and automated certificates.",
  },
  SRV: {
    present: "Compare priority, weight, port, and target with the application's service-discovery configuration.",
    empty: "SRV is service-specific. Publish only the exact _service._protocol owner and values required by that application.",
  },
  PTR: {
    present: "Confirm the reverse name resolves forward to the same address when the service depends on forward-confirmed reverse DNS.",
    empty: "PTR is controlled by the IP-address provider, not ordinary domain DNS; request the change from the ISP or hosting provider.",
  },
};

const CHECK_STATUS_SET = new Set(["pass", "warning", "fail", "info", "unknown"]);
const FINDING_SEVERITY_SET = new Set(["critical", "warning", "success", "info"]);
const SCAN_GRADE_SET = new Set(["A", "B", "C", "D", "F"]);
const SCAN_POSTURE_SET = new Set(["reject", "quarantine", "monitoring", "missing", "invalid"]);
const SCAN_ERROR_CODE_SET = new Set(["INVALID_DOMAIN", "METHOD_NOT_ALLOWED", "BAD_REQUEST", "UPSTREAM_ERROR", "NOT_FOUND"]);

export function isScanResult(value: unknown): value is ScanResult {
  if (!isObjectRecord(value)) return false;
  const checks = value.checks;
  const metadata = value.metadata;

  return (
    isBoundedString(value.domain, 253) &&
    isIsoDate(value.scannedAt) &&
    isFiniteNonnegative(value.durationMs) &&
    typeof value.score === "number" &&
    Number.isInteger(value.score) &&
    value.score >= 0 &&
    value.score <= 100 &&
    typeof value.grade === "string" &&
    SCAN_GRADE_SET.has(value.grade) &&
    typeof value.posture === "string" &&
    SCAN_POSTURE_SET.has(value.posture) &&
    isBoundedString(value.postureLabel, 256) &&
    isBoundedString(value.headline, 1_024) &&
    isBoundedString(value.summary, 4_096) &&
    isObjectRecord(checks) &&
    isCheckResult(checks.dmarc) &&
    isCheckResult(checks.spf) &&
    isCheckResult(checks.dkim) &&
    isCheckResult(checks.transport) &&
    isCheckResult(checks.dns) &&
    Array.isArray(value.dkimSelectors) &&
    value.dkimSelectors.length <= 64 &&
    value.dkimSelectors.every(isDkimSelectorResult) &&
    Array.isArray(value.findings) &&
    value.findings.length <= 256 &&
    value.findings.every(isFinding) &&
    isObjectRecord(metadata) &&
    isBoundedStringArray(metadata.mxProviders, 256, 253) &&
    isBoundedStringArray(metadata.nameservers, 256, 253) &&
    typeof metadata.hasBimi === "boolean" &&
    typeof metadata.hasMtaSts === "boolean" &&
    typeof metadata.hasTlsRpt === "boolean" &&
    isBoundedString(value.disclaimer, 8_192)
  );
}

function isCheckResult(value: unknown): value is CheckResult {
  if (!isObjectRecord(value)) return false;
  return (
    typeof value.status === "string" &&
    CHECK_STATUS_SET.has(value.status) &&
    isBoundedString(value.title, 512) &&
    isBoundedString(value.summary, 4_096) &&
    Array.isArray(value.details) &&
    value.details.length <= 128 &&
    value.details.every((detail) => (
      isObjectRecord(detail) &&
      isBoundedString(detail.label, 512) &&
      isBoundedString(detail.value, 8_192, true)
    )) &&
    Array.isArray(value.records) &&
    value.records.length <= 256 &&
    value.records.every(isDnsRecordView)
  );
}

function isDnsRecordView(value: unknown): boolean {
  if (!isObjectRecord(value)) return false;
  return (
    isBoundedString(value.name, 253) &&
    isBoundedString(value.type, 32) &&
    isBoundedString(value.value, 262_144, true) &&
    (
      value.ttl === undefined ||
      (typeof value.ttl === "number" && Number.isInteger(value.ttl) && value.ttl >= 0 && value.ttl <= 2 ** 32 - 1)
    )
  );
}

function isFinding(value: unknown): boolean {
  if (!isObjectRecord(value)) return false;
  return (
    isBoundedString(value.id, 256) &&
    typeof value.severity === "string" &&
    FINDING_SEVERITY_SET.has(value.severity) &&
    isBoundedString(value.title, 1_024) &&
    isBoundedString(value.detail, 8_192) &&
    (value.action === undefined || isBoundedString(value.action, 8_192)) &&
    (value.remediation === undefined || isRemediation(value.remediation))
  );
}

function isRemediation(value: unknown): boolean {
  if (!isObjectRecord(value)) return false;
  const record = value.record;
  return (
    isBoundedString(value.summary, 8_192) &&
    isBoundedStringArray(value.steps, 32, 8_192) &&
    (value.caution === undefined || isBoundedString(value.caution, 8_192)) &&
    (
      record === undefined ||
      (
        isObjectRecord(record) &&
        isBoundedString(record.name, 253) &&
        isBoundedString(record.type, 32) &&
        isBoundedString(record.value, 262_144, true)
      )
    )
  );
}

function isDkimSelectorResult(value: unknown): boolean {
  if (!isObjectRecord(value)) return false;
  return (
    isBoundedString(value.selector, 63) &&
    typeof value.found === "boolean" &&
    (value.kind === undefined || value.kind === "TXT" || value.kind === "CNAME") &&
    (value.value === undefined || isBoundedString(value.value, 262_144, true)) &&
    (
      value.issue === undefined ||
      value.issue === "revoked" ||
      value.issue === "unresolved-alias"
    )
  );
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isBoundedString(value: unknown, maxLength: number, allowEmpty = false): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) && value.length <= maxLength;
}

function isBoundedStringArray(value: unknown, maxItems: number, maxLength: number): value is string[] {
  return Array.isArray(value) && value.length <= maxItems && value.every((item) => isBoundedString(item, maxLength));
}

function isFiniteNonnegative(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function isIsoDate(value: unknown): value is string {
  return typeof value === "string" && value.length <= 64 && !Number.isNaN(Date.parse(value));
}

function isScanError(value: unknown): value is ScanError {
  return isObjectRecord(value) &&
    isBoundedString(value.error, 8_192) &&
    typeof value.code === "string" &&
    SCAN_ERROR_CODE_SET.has(value.code);
}

const SPF_LOOKUP_STATUS_SET = new Set(["missing", "multiple", "invalid", "warning", "valid"]);
const SPF_TERMINAL_POLICY_SET = new Set(["+all", "-all", "~all", "?all", "none"]);

export function isDnsLookupResult(
  value: unknown,
  expectedType?: DnsLookupMode,
): value is DnsLookupResult<DnsLookupMode> {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<DnsLookupResult<DnsLookupMode>>;
  return (
    typeof candidate.input === "string" &&
    candidate.input.length > 0 &&
    candidate.input.length <= 512 &&
    typeof candidate.queryName === "string" &&
    candidate.queryName.length > 0 &&
    candidate.queryName.length <= 253 &&
    (
      candidate.canonicalName === undefined ||
      (
        typeof candidate.canonicalName === "string" &&
        candidate.canonicalName.length > 0 &&
        candidate.canonicalName.length <= 253
      )
    ) &&
    typeof candidate.type === "string" &&
    DNS_LOOKUP_MODE_SET.has(candidate.type) &&
    (expectedType === undefined || candidate.type === expectedType) &&
    typeof candidate.scannedAt === "string" &&
    !Number.isNaN(Date.parse(candidate.scannedAt)) &&
    typeof candidate.durationMs === "number" &&
    Number.isFinite(candidate.durationMs) &&
    candidate.durationMs >= 0 &&
    typeof candidate.summary === "string" &&
    candidate.summary.length > 0 &&
    candidate.summary.length <= 2_048 &&
    Array.isArray(candidate.records) &&
    candidate.records.length <= 256 &&
    candidate.records.every((record) => (
      Boolean(record) &&
      typeof record === "object" &&
      typeof record.name === "string" &&
      record.name.length > 0 &&
      record.name.length <= 253 &&
      record.type === (candidate.type === "SPF" ? "TXT" : candidate.type) &&
      typeof record.value === "string" &&
      record.value.length <= 262_144 &&
      (
        record.ttl === undefined ||
        (
          typeof record.ttl === "number" &&
          Number.isInteger(record.ttl) &&
          record.ttl >= 0 &&
          record.ttl <= 2 ** 32 - 1
        )
      )
    )) &&
    (
      candidate.type === "SPF"
        ? isSpfLookupAnalysis(candidate.spfAnalysis)
        : candidate.spfAnalysis === undefined
    )
  );
}

function isSpfLookupAnalysis(value: unknown): value is SpfLookupAnalysis {
  if (!isObjectRecord(value)) return false;
  const estimate = value.lookupEstimate;
  const guidance = value.correctionGuidance;
  return (
    typeof value.status === "string" &&
    SPF_LOOKUP_STATUS_SET.has(value.status) &&
    typeof value.recordCount === "number" &&
    Number.isInteger(value.recordCount) &&
    value.recordCount >= 0 &&
    value.recordCount <= 256 &&
    typeof value.valid === "boolean" &&
    typeof value.syntaxValid === "boolean" &&
    Array.isArray(value.mechanisms) &&
    value.mechanisms.length <= 256 &&
    value.mechanisms.every((mechanism) => (
      isObjectRecord(mechanism) &&
      isBoundedString(mechanism.raw, 8_192) &&
      (mechanism.qualifier === "+" || mechanism.qualifier === "-" || mechanism.qualifier === "~" || mechanism.qualifier === "?") &&
      isBoundedString(mechanism.name, 64) &&
      (mechanism.domainSpec === undefined || isBoundedString(mechanism.domainSpec, 512)) &&
      (mechanism.cidr4 === undefined || (Number.isInteger(mechanism.cidr4) && Number(mechanism.cidr4) >= 0 && Number(mechanism.cidr4) <= 32)) &&
      (mechanism.cidr6 === undefined || (Number.isInteger(mechanism.cidr6) && Number(mechanism.cidr6) >= 0 && Number(mechanism.cidr6) <= 128)) &&
      typeof mechanism.causesDnsLookup === "boolean"
    )) &&
    typeof value.terminalPolicy === "string" &&
    SPF_TERMINAL_POLICY_SET.has(value.terminalPolicy) &&
    (
      estimate === undefined ||
      (
        isObjectRecord(estimate) &&
        typeof estimate.count === "number" &&
        Number.isInteger(estimate.count) &&
        estimate.count >= 0 &&
        estimate.count <= 10_000 &&
        typeof estimate.exceedsLimit === "boolean" &&
        typeof estimate.truncated === "boolean" &&
        isBoundedStringArray(estimate.expandedDomains, 256, 253) &&
        isBoundedStringArray(estimate.issues, 256, 8_192)
      )
    ) &&
    isBoundedStringArray(value.warnings, 256, 8_192) &&
    isBoundedStringArray(value.errors, 256, 8_192) &&
    isBoundedStringArray(value.issues, 256, 8_192) &&
    isObjectRecord(guidance) &&
    isBoundedString(guidance.summary, 8_192) &&
    isBoundedStringArray(guidance.steps, 32, 8_192) &&
    (guidance.caution === undefined || isBoundedString(guidance.caution, 8_192))
  );
}

function dnsLookupExample(type: DnsLookupMode, suggestedDomain: string): string {
  const domain = suggestedDomain || "example.com";
  if (type === "PTR") return "8.8.8.8";
  if (type === "TXT") return `selector._domainkey.${domain}`;
  if (type === "CNAME") return `www.${domain}`;
  if (type === "SRV") return `_sip._tcp.${domain}`;
  return domain;
}

function suggestedDnsLookupInput(type: DnsLookupMode, suggestedDomain: string): string {
  if (!suggestedDomain || type === "PTR") return "";
  if (type === "CNAME" || type === "SRV") {
    return dnsLookupExample(type, suggestedDomain);
  }
  return suggestedDomain;
}

function canPreserveLookupInput(value: string, currentType: DnsLookupMode, nextType: DnsLookupMode): boolean {
  if (!value) return false;
  if (currentType === "PTR" && nextType !== "PTR") return false;
  if (nextType !== "PTR") return true;
  return /^(?:\d{1,3}\.){3}\d{1,3}$/u.test(value) || value.includes(":") || /\.(?:in-addr|ip6)\.arpa\.?$/iu.test(value);
}

const statusIcons: Record<CheckStatus, ReactNode> = {
  pass: <CheckCircle2 aria-hidden="true" />,
  warning: <AlertTriangle aria-hidden="true" />,
  fail: <XCircle aria-hidden="true" />,
  info: <Info aria-hidden="true" />,
  unknown: <CircleHelp aria-hidden="true" />,
};

const severityIcons: Record<FindingSeverity, ReactNode> = {
  critical: <AlertCircle aria-hidden="true" />,
  warning: <AlertTriangle aria-hidden="true" />,
  success: <BadgeCheck aria-hidden="true" />,
  info: <Info aria-hidden="true" />,
};

function scrollToScanner() {
  document.getElementById("email-security")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function Brand() {
  return (
    <a className="brand" href="#top" aria-label="Cresswell Security Lab home">
      <span className="brand-mark" aria-hidden="true">
        <Radar />
      </span>
      <span>Cresswell <span>Security Lab</span></span>
    </a>
  );
}

function Header() {
  return (
    <header className="site-header">
      <div className="container header-inner">
        <Brand />
        <nav className="desktop-nav" aria-label="Primary navigation">
          <a href="#email-security">Email Security</a>
          <a href="#dns-intelligence">DNS &amp; OSINT</a>
          <a href="#network-intelligence">Network Intelligence</a>
          <a href="#web-security">Web &amp; TLS</a>
          <a href="#methodology">Methodology</a>
        </nav>
        <details className="mobile-nav">
          <summary><Menu aria-hidden="true" /> Explore</summary>
          <nav aria-label="Mobile navigation">
            <a href="#email-security" onClick={(event) => event.currentTarget.closest("details")?.removeAttribute("open")}>Email Security</a>
            <a href="#dns-intelligence" onClick={(event) => event.currentTarget.closest("details")?.removeAttribute("open")}>DNS &amp; OSINT</a>
            <a href="#network-intelligence" onClick={(event) => event.currentTarget.closest("details")?.removeAttribute("open")}>Network Intelligence</a>
            <a href="#web-security" onClick={(event) => event.currentTarget.closest("details")?.removeAttribute("open")}>Web &amp; TLS</a>
            <a href="#methodology" onClick={(event) => event.currentTarget.closest("details")?.removeAttribute("open")}>Methodology</a>
          </nav>
        </details>
        <button className="button button-small button-quiet" type="button" onClick={scrollToScanner}>
          Start assessment <ArrowRight aria-hidden="true" />
        </button>
      </div>
    </header>
  );
}

interface ScanFormProps {
  domain: string;
  onDomainChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  loading: boolean;
  compact?: boolean;
}

function ScanForm({ domain, onDomainChange, onSubmit, loading, compact = false }: ScanFormProps) {
  return (
    <form className={`scan-form ${compact ? "scan-form-compact" : ""}`} onSubmit={onSubmit}>
      <label htmlFor={compact ? "domain-results" : "domain"} className="sr-only">
        Domain name
      </label>
      <div className="input-wrap">
        <Globe2 aria-hidden="true" />
        <input
          id={compact ? "domain-results" : "domain"}
          name="domain"
          type="text"
          inputMode="url"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck="false"
          value={domain}
          onChange={(event) => onDomainChange(event.target.value)}
          placeholder="yourcompany.com"
          aria-describedby={compact ? undefined : "domain-help"}
          disabled={loading}
          required
        />
      </div>
      <button className="button button-primary scan-button" type="submit" disabled={loading || !domain.trim()}>
        {loading ? (
          <>
            <LoaderCircle className="spin" aria-hidden="true" /> Scanning
          </>
        ) : (
          <>
            <Radar aria-hidden="true" /> Scan domain
          </>
        )}
      </button>
    </form>
  );
}

function Hero({
  domain,
  setDomain,
  onSubmit,
  loading,
  error,
}: {
  domain: string;
  setDomain: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  loading: boolean;
  error: string | null;
}) {
  return (
    <section className="hero" id="email-security">
      <div className="hero-grid" aria-hidden="true" />
      <div className="orb orb-one" aria-hidden="true" />
      <div className="orb orb-two" aria-hidden="true" />
      <div className="container hero-inner">
        <div className="eyebrow"><span /> Cresswell Security Lab · public-surface assessment</div>
        <h1>See what the <em>internet sees.</em></h1>
        <p className="hero-copy">
          Measure the public security posture of a hostname across email authentication, DNS and OSINT,
          network intelligence, and web transport. Every result separates direct tests, bounded inferences,
          and evidence the platform could not observe.
        </p>
        <div className="hero-family-label"><MailCheck aria-hidden="true" /><span><strong>Email Security quick assessment</strong><small>Start with DMARC, SPF, discoverable DKIM, DNS health, and mail transport policy.</small></span></div>
        <div className="hero-scanner">
          <ScanForm
            domain={domain}
            onDomainChange={setDomain}
            onSubmit={onSubmit}
            loading={loading}
          />
          <div className="scan-meta" id="domain-help">
            <span><LockKeyhole aria-hidden="true" /> No account required</span>
            <span><Clock3 aria-hidden="true" /> Usually under 10 seconds</span>
            <span><Database aria-hidden="true" /> Public evidence</span>
          </div>
          {error && (
            <div className="form-error" role="alert">
              <AlertCircle aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}
        </div>
        <div className="examples" aria-label="Example domains">
          <span>Try an example</span>
          {EXAMPLE_DOMAINS.map((example) => (
            <button key={example} type="button" onClick={() => setDomain(example)} disabled={loading}>
              {example}
            </button>
          ))}
        </div>
      </div>
      <div className="container proof-strip" aria-label="Checks included">
        <span><MailCheck aria-hidden="true" /> Email Security</span>
        <span><Globe2 aria-hidden="true" /> DNS &amp; OSINT</span>
        <span><Network aria-hidden="true" /> Network Intelligence</span>
        <span><ShieldCheck aria-hidden="true" /> Web &amp; TLS</span>
        <span><FileSearch aria-hidden="true" /> Evidence-first reports</span>
      </div>
    </section>
  );
}

const SECURITY_FAMILIES = [
  {
    href: "#email-security",
    icon: <MailCheck />,
    number: "01",
    title: "Email Security",
    copy: "DMARC, SPF, discoverable DKIM, MX, MTA-STS, TLS reporting, and enforcement readiness.",
    badge: "Passive DNS",
  },
  {
    href: "#dns-intelligence",
    icon: <Globe2 />,
    number: "02",
    title: "DNS & OSINT",
    copy: "Record exploration, bounded SPF expansion, service discovery, and a mapped public DNS surface.",
    badge: "Passive-style",
  },
  {
    href: "#network-intelligence",
    icon: <Network />,
    number: "03",
    title: "Network Intelligence",
    copy: "Address classification, subnet arithmetic, reverse DNS, routing-origin evidence, and scope context.",
    badge: "Local + DNS",
  },
  {
    href: "#web-security",
    icon: <ShieldCheck />,
    number: "04",
    title: "Web & TLS",
    copy: "Authorized endpoint TLS analysis plus 20 OWASP-aligned browser and HTTP configuration checks.",
    badge: "Authorized active",
  },
] as const;

function SecurityFamilies() {
  return (
    <section className="security-families" aria-labelledby="security-families-title">
      <div className="container">
        <div className="security-families-heading">
          <div><div className="eyebrow"><span /> One public surface, four lenses</div><h2 id="security-families-title">A cohesive assessment workspace.</h2></div>
          <p>Move from a broad hostname to the exact evidence you need. Each family keeps its own safety boundary and explains what was measured.</p>
        </div>
        <div className="security-family-grid">
          {SECURITY_FAMILIES.map((family) => (
            <a href={family.href} key={family.title}>
              <span className="family-number">{family.number}</span>
              <span className="family-icon" aria-hidden="true">{family.icon}</span>
              <small>{family.badge}</small>
              <h3>{family.title}</h3>
              <p>{family.copy}</p>
              <strong>Open workspace <ArrowRight aria-hidden="true" /></strong>
            </a>
          ))}
        </div>
      </div>
    </section>
  );
}

function FamilyIntro({
  id,
  number,
  icon,
  eyebrow,
  title,
  copy,
  badges,
}: {
  id: string;
  number: string;
  icon: ReactNode;
  eyebrow: string;
  title: string;
  copy: string;
  badges: string[];
}) {
  return (
    <section className="family-intro" id={id} aria-labelledby={`${id}-title`}>
      <div className="container family-intro-inner">
        <div className="family-intro-index"><span>{number}</span>{icon}</div>
        <div><div className="eyebrow"><span /> {eyebrow}</div><h2 id={`${id}-title`}>{title}</h2><p>{copy}</p></div>
        <div className="family-intro-badges">{badges.map((badge) => <span key={badge}>{badge}</span>)}</div>
      </div>
    </section>
  );
}

function LoadingResults({ domain }: { domain: string }) {
  const steps = [
    { label: "Querying public DNS", icon: <Globe2 /> },
    { label: "Parsing authentication records", icon: <Code2 /> },
    { label: "Evaluating enforcement posture", icon: <ShieldEllipsis /> },
  ];

  return (
    <section className="loading-section" aria-live="polite" aria-busy="true">
      <div className="container">
        <div className="loading-card">
          <div className="scan-radar" aria-hidden="true">
            <span className="radar-line" />
            <Shield />
          </div>
          <div>
            <div className="eyebrow"><span /> Live DNS scan</div>
            <h2>Inspecting {domain || "your domain"}</h2>
            <p>We are checking independent DNS controls in parallel. No email is sent.</p>
            <div className="loading-steps">
              {steps.map((step, index) => (
                <div className={`loading-step loading-step-${index + 1}`} key={step.label}>
                  {step.icon}<span>{step.label}</span><span className="loading-dots" />
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function ScoreRing({ result }: { result: ScanResult }) {
  return (
    <div
      className={`score-ring score-${result.grade.toLowerCase()}`}
      role="img"
      aria-label={`Published email configuration score ${result.score} out of 100, grade ${result.grade}`}
    >
      <svg className="score-ring-graphic" viewBox="0 0 188 188" aria-hidden="true">
        <circle className="score-ring-track" cx="94" cy="94" r="84" />
        <circle
          className="score-ring-progress"
          cx="94"
          cy="94"
          r="84"
          pathLength="100"
          strokeDasharray={`${result.score} ${100 - result.score}`}
        />
        <circle className="score-ring-guide" cx="94" cy="94" r="70" />
      </svg>
      <div className="score-ring-inner">
        <span className="score-value">{result.score}</span>
        <span className="score-total">/ 100</span>
        <span className="score-grade">Grade {result.grade}</span>
      </div>
    </div>
  );
}

function PostureIcon({ posture }: { posture: ScanResult["posture"] }) {
  if (posture === "reject") return <ShieldCheck aria-hidden="true" />;
  if (posture === "quarantine") return <ShieldEllipsis aria-hidden="true" />;
  if (posture === "monitoring") return <FileSearch aria-hidden="true" />;
  return <ShieldX aria-hidden="true" />;
}

function CheckCard({
  icon,
  label,
  check,
  wide = false,
}: {
  icon: ReactNode;
  label: string;
  check: CheckResult;
  wide?: boolean;
}) {
  return (
    <article className={`check-card status-${check.status} ${wide ? "check-card-wide" : ""}`}>
      <div className="check-card-header">
        <span className="check-icon">{icon}</span>
        <span className={`status-badge status-${check.status}`}>
          {statusIcons[check.status]}
          {check.status === "pass" ? "Configured" : check.status}
        </span>
      </div>
      <div className="check-card-content">
        <div className="check-card-copy">
          <p className="check-label">{label}</p>
          <h3>{check.title}</h3>
          <p className="check-summary">{check.summary}</p>
        </div>
        {check.details.length > 0 && (
          <dl className="check-details">
            {check.details.map((detail) => (
              <div key={`${detail.label}-${detail.value}`}>
                <dt>{detail.label}</dt>
                <dd>{detail.value}</dd>
              </div>
            ))}
          </dl>
        )}
      </div>
    </article>
  );
}

function FindingRow({ finding, index }: { finding: Finding; index: number }) {
  const [copiedField, setCopiedField] = useState<"name" | "type" | "value" | null>(null);
  const [copyFailed, setCopyFailed] = useState(false);

  async function copyRemediationField(field: "name" | "type" | "value", value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedField(field);
      setCopyFailed(false);
      window.setTimeout(() => setCopiedField((current) => current === field ? null : current), 1800);
    } catch {
      setCopiedField(null);
      setCopyFailed(true);
      window.setTimeout(() => setCopyFailed(false), 2400);
    }
  }

  const remediationRecord = finding.remediation?.record;
  const remediationFields = remediationRecord
    ? [
        { key: "name" as const, label: "Host / name", value: remediationRecord.name },
        { key: "type" as const, label: "Record type", value: remediationRecord.type },
        { key: "value" as const, label: "Value", value: remediationRecord.value },
      ]
    : [];
  const copiedFieldLabel = remediationFields.find((field) => field.key === copiedField)?.label;
  const remediationCautionId = finding.remediation?.caution
    ? `${finding.id}-remediation-caution`
    : undefined;

  return (
    <li className={`finding finding-${finding.severity}`}>
      <span className="finding-index">{String(index + 1).padStart(2, "0")}</span>
      <span className="finding-icon">{severityIcons[finding.severity]}</span>
      <div className="finding-body">
        <div className="finding-heading">
          <h4>{finding.title}</h4>
          <span>{finding.severity}</span>
        </div>
        <p>{finding.detail}</p>
        {finding.action && (
          <div className="finding-action"><ChevronRight aria-hidden="true" /> {finding.action}</div>
        )}
        {finding.remediation && (
          <details className="remediation-panel">
            <summary>
              <span><ShieldCheck aria-hidden="true" /> How to fix</span>
              <ChevronRight className="remediation-chevron" aria-hidden="true" />
            </summary>
            <div className="remediation-content">
              <p className="remediation-summary">{finding.remediation.summary}</p>
              {finding.remediation.steps.length > 0 && (
                <ol className="remediation-steps" role="list">
                  {finding.remediation.steps.map((step, stepIndex) => (
                    <li key={`${finding.id}-step-${stepIndex}`}>{step}</li>
                  ))}
                </ol>
              )}
              {finding.remediation.caution && (
                <div className="remediation-caution" id={remediationCautionId} role="note">
                  <AlertTriangle aria-hidden="true" />
                  <div><strong>Before you publish</strong><span>{finding.remediation.caution}</span></div>
                </div>
              )}
              {remediationRecord && (
                <div
                  className="fix-record"
                  role="group"
                  aria-label="DNS record template"
                  aria-describedby={remediationCautionId}
                >
                  <div className="fix-record-heading">
                    <div>
                      <strong>DNS record template</strong>
                      <span>Review the steps and any caution before publishing.</span>
                    </div>
                    <Code2 aria-hidden="true" />
                  </div>
                  <dl>
                    {remediationFields.map((field) => (
                      <div className="fix-record-row" key={field.key}>
                        <dt>{field.label}</dt>
                        <dd>
                          <code>{field.value}</code>
                          <button
                            type="button"
                            className="copy-field-button"
                            onClick={() => void copyRemediationField(field.key, field.value)}
                            aria-label={`Copy ${field.label.toLowerCase()}`}
                          >
                            {copiedField === field.key ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                            <span>{copiedField === field.key ? "Copied" : "Copy"}</span>
                          </button>
                        </dd>
                      </div>
                    ))}
                  </dl>
                  <p className="fix-record-provider-note">
                    <Info aria-hidden="true" />
                    Some DNS dashboards expect a relative host such as <code>_dmarc</code> instead of the full name. Verify your provider’s behavior so it does not append the domain twice.
                  </p>
                  <span className="sr-only" aria-live="polite">
                    {copiedFieldLabel ? `${copiedFieldLabel} copied.` : ""}
                  </span>
                  {copyFailed && (
                    <p className="copy-error" role="alert">Copy failed. Select and copy the value manually.</p>
                  )}
                </div>
              )}
            </div>
          </details>
        )}
      </div>
    </li>
  );
}

function RecordsPanel({ result }: { result: ScanResult }) {
  const [copied, setCopied] = useState<string | null>(null);
  const checks = Object.values(result.checks);
  const records = Array.from(
    new Map(
      checks.flatMap((check) => check.records).map((record) => [
        JSON.stringify([record.name.toLowerCase(), record.type.toUpperCase(), record.value]),
        record,
      ] as const),
    ).values(),
  );

  async function copyRecord(value: string, key: string) {
    await navigator.clipboard.writeText(value);
    setCopied(key);
    window.setTimeout(() => setCopied(null), 1600);
  }

  if (records.length === 0) return null;

  return (
    <details className="records-panel">
      <summary>
        <span><Code2 aria-hidden="true" /> Raw DNS evidence</span>
        <span>{records.length} record{records.length === 1 ? "" : "s"}</span>
      </summary>
      <div className="record-list">
        {records.map((record, index) => {
          const key = `${record.name}-${record.type}-${index}`;
          return (
            <div className="record-row" key={key}>
              <div className="record-meta">
                <span>{record.type}</span>
                <strong>{record.name}</strong>
                {record.ttl && <small>TTL {record.ttl}s</small>}
              </div>
              <code>{record.value}</code>
              <button type="button" onClick={() => copyRecord(record.value, key)} aria-label={`Copy ${record.type} record`}>
                {copied === key ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
              </button>
            </div>
          );
        })}
      </div>
    </details>
  );
}

function EnforcementPath({ posture }: { posture: ScanResult["posture"] }) {
  const activeIndex = posture === "reject" ? 3 : posture === "quarantine" ? 2 : posture === "monitoring" ? 0 : -1;
  const stages = [
    { title: "Monitor", copy: "Collect aggregate reports" },
    { title: "Remediate", copy: "Align legitimate senders" },
    { title: "Quarantine", copy: "Contain failing traffic" },
    { title: "Reject", copy: "Block unauthorized use" },
  ];
  return (
    <div className="enforcement-path">
      {stages.map((stage, index) => (
        <div className={`path-stage ${index <= activeIndex ? "path-complete" : ""}`} key={stage.title}>
          <div className="path-marker">{index <= activeIndex ? <Check /> : index + 1}</div>
          <div><strong>{stage.title}</strong><span>{stage.copy}</span></div>
        </div>
      ))}
    </div>
  );
}

function Results({
  result,
  domain,
  setDomain,
  onSubmit,
  loading,
  error,
}: {
  result: ScanResult;
  domain: string;
  setDomain: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  loading: boolean;
  error: string | null;
}) {
  const criticalCount = result.findings.filter((finding) => finding.severity === "critical").length;
  const warningCount = result.findings.filter((finding) => finding.severity === "warning").length;

  return (
    <section className="results-section" id="results" aria-live="polite">
      <div className="container">
        <div className="results-toolbar">
          <div>
            <span className="results-kicker">Scan complete</span>
            <h2>{result.domain}</h2>
            <p>Public DNS snapshot · {new Date(result.scannedAt).toLocaleString()} · {(result.durationMs / 1000).toFixed(1)}s</p>
          </div>
          <ScanForm compact domain={domain} onDomainChange={setDomain} onSubmit={onSubmit} loading={loading} />
        </div>
        {error && (
          <div className="form-error results-error" role="alert">
            <AlertCircle aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}

        <div className="result-hero">
          <ScoreRing result={result} />
          <div className="result-hero-copy">
            <div className={`posture-pill posture-${result.posture}`}>
              <PostureIcon posture={result.posture} /> {result.postureLabel}
            </div>
            <h2>{result.headline}</h2>
            <p>{result.summary}</p>
            <div className="result-counts">
              <span className={criticalCount ? "count-critical" : "count-clear"}>
                {criticalCount ? <AlertCircle /> : <CheckCircle2 />}
                {criticalCount} critical
              </span>
              <span className={warningCount ? "count-warning" : "count-clear"}>
                {warningCount ? <AlertTriangle /> : <CheckCircle2 />}
                {warningCount} warning{warningCount === 1 ? "" : "s"}
              </span>
            </div>
          </div>
          <div className="snapshot-note">
            <Info aria-hidden="true" />
            <div>
              <strong>DNS posture, not enforcement approval</strong>
              <span>{result.disclaimer}</span>
            </div>
          </div>
        </div>

        <div className="section-heading section-heading-row">
          <div><span className="section-number">01</span><div><p>Control coverage</p><h2>Email and DNS at a glance</h2></div></div>
          <span className="section-caption">Five independent control groups</span>
        </div>
        <div className="checks-grid">
          <CheckCard icon={<ShieldCheck />} label="DMARC" check={result.checks.dmarc} />
          <CheckCard icon={<Network />} label="SPF" check={result.checks.spf} />
          <CheckCard icon={<KeyRound />} label="DKIM visibility" check={result.checks.dkim} />
          <CheckCard icon={<MailCheck />} label="Mail transport" check={result.checks.transport} />
          <CheckCard wide icon={<Globe2 />} label="DNS health" check={result.checks.dns} />
        </div>

        <div className="analysis-grid">
          <div className="findings-wrap">
            <div className="section-heading">
              <span className="section-number">02</span>
              <div><p>Prioritized analysis</p><h2>What to do next</h2></div>
            </div>
            <ol className="findings-list">
              {result.findings.map((finding, index) => <FindingRow key={finding.id} finding={finding} index={index} />)}
            </ol>
          </div>
          <aside className="side-analysis">
            <div className="section-heading">
              <span className="section-number">03</span>
              <div><p>Deployment path</p><h2>Road to enforcement</h2></div>
            </div>
            <EnforcementPath posture={result.posture} />
            <div className="metadata-card">
              <h3><ServerCog aria-hidden="true" /> Observed infrastructure</h3>
              <dl>
                <div><dt>MX hosts</dt><dd>{result.metadata.mxProviders.join(", ") || "Not identified"}</dd></div>
                <div><dt>Nameservers</dt><dd>{result.metadata.nameservers.slice(0, 3).join(", ") || "Not returned"}</dd></div>
                <div><dt>MTA-STS</dt><dd>{result.metadata.hasMtaSts ? "Published" : "Not detected"}</dd></div>
                <div><dt>TLS reporting</dt><dd>{result.metadata.hasTlsRpt ? "Published" : "Not detected"}</dd></div>
                <div><dt>BIMI</dt><dd>{result.metadata.hasBimi ? "Published" : "Not detected"}</dd></div>
              </dl>
            </div>
          </aside>
        </div>
        <RecordsPanel result={result} />
        <div className="rescan-row">
          <button className="button button-secondary" type="button" onClick={() => {
            window.scrollTo({ top: 0, behavior: "smooth" });
            window.setTimeout(() => document.getElementById("domain")?.focus(), 400);
          }}>
            <RefreshCw aria-hidden="true" /> Scan another domain
          </button>
        </div>
      </div>
    </section>
  );
}

function SpfAnalysisPanel({ analysis }: { analysis: SpfLookupAnalysis }) {
  const lookupCount = analysis.lookupEstimate?.count;
  const messages = [...analysis.errors, ...analysis.issues, ...analysis.warnings];
  const statusLabel: Record<SpfLookupAnalysis["status"], string> = {
    valid: "Valid",
    warning: "Review needed",
    invalid: "Invalid",
    multiple: "Permanent error",
    missing: "Not found",
  };

  return (
    <div className={`spf-analysis spf-analysis-${analysis.status}`}>
      <div className="spf-analysis-heading">
        <div>
          <span className="spf-analysis-kicker"><MailCheck aria-hidden="true" /> SPF policy analysis</span>
          <h4>{statusLabel[analysis.status]}</h4>
        </div>
        <span className="spf-status-pill">{statusLabel[analysis.status]}</span>
      </div>

      <div className="spf-metrics" aria-label="SPF analysis summary">
        <div><span>Policy records</span><strong>{analysis.recordCount}</strong></div>
        <div>
          <span>Lookup estimate</span>
          <strong>{lookupCount === undefined ? "—" : `${lookupCount} / 10`}</strong>
        </div>
        <div><span>Terminal policy</span><strong><code>{analysis.terminalPolicy}</code></strong></div>
      </div>

      {analysis.mechanisms.length > 0 && (
        <div className="spf-mechanisms">
          <strong>Evaluated mechanisms</strong>
          <div>
            {analysis.mechanisms.map((mechanism, index) => (
              <span className={mechanism.causesDnsLookup ? "spf-mechanism spf-mechanism-lookup" : "spf-mechanism"} key={`${mechanism.raw}-${index}`}>
                <code>{mechanism.raw}</code>
                {mechanism.causesDnsLookup && <small>DNS</small>}
              </span>
            ))}
          </div>
        </div>
      )}

      {analysis.lookupEstimate && analysis.lookupEstimate.expandedDomains.length > 0 && (
        <div className="spf-expanded-domains">
          <strong>Expanded include and redirect domains</strong>
          <p>{analysis.lookupEstimate.expandedDomains.join(" · ")}</p>
        </div>
      )}

      {messages.length > 0 && (
        <div className="spf-analysis-messages">
          <strong>Evidence to review</strong>
          <ul>{messages.map((message, index) => <li key={`${message}-${index}`}>{message}</li>)}</ul>
        </div>
      )}

      <div className="spf-correction-plan">
        <div><ServerCog aria-hidden="true" /><strong>How to correct or maintain it</strong></div>
        <p>{analysis.correctionGuidance.summary}</p>
        <ol>{analysis.correctionGuidance.steps.map((step, index) => <li key={`${step}-${index}`}>{step}</li>)}</ol>
        {analysis.correctionGuidance.caution && (
          <p className="spf-caution"><AlertTriangle aria-hidden="true" /> {analysis.correctionGuidance.caution}</p>
        )}
      </div>
    </div>
  );
}

export function AdvancedDnsExplorer({ suggestedDomain }: { suggestedDomain: string }) {
  const [lookupType, setLookupType] = useState<DnsLookupMode>("A");
  const [lookupInput, setLookupInput] = useState("");
  const [hasEditedInput, setHasEditedInput] = useState(false);
  const [lookupResult, setLookupResult] = useState<DnsLookupResult<DnsLookupMode> | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [copiedRecord, setCopiedRecord] = useState<string | null>(null);
  const [copyMessage, setCopyMessage] = useState("");
  const lookupControllerRef = useRef<AbortController | null>(null);
  const lookupRequestVersionRef = useRef(0);

  const cleanSuggestedDomain = suggestedDomain.trim();
  const example = dnsLookupExample(lookupType, cleanSuggestedDomain);
  const hint = DNS_LOOKUP_HINTS[lookupType] ?? "Enter the exact public DNS owner name you want to query.";

  useEffect(() => {
    lookupRequestVersionRef.current += 1;
    lookupControllerRef.current?.abort();
    lookupControllerRef.current = null;
    setLookupLoading(false);
    setLookupResult(null);
    setLookupError(null);
    setCopiedRecord(null);
    setCopyMessage("");
    if (!hasEditedInput && cleanSuggestedDomain) {
      setLookupInput(suggestedDnsLookupInput(lookupType, cleanSuggestedDomain));
    }
  }, [cleanSuggestedDomain]);

  useEffect(() => () => {
    lookupRequestVersionRef.current += 1;
    lookupControllerRef.current?.abort();
  }, []);

  function handleLookupTypeChange(nextType: DnsLookupMode) {
    lookupRequestVersionRef.current += 1;
    lookupControllerRef.current?.abort();
    lookupControllerRef.current = null;
    const currentInput = lookupInput.trim();
    const preserveCustomInput = hasEditedInput && canPreserveLookupInput(currentInput, lookupType, nextType);
    setLookupType(nextType);
    setLookupInput(preserveCustomInput ? lookupInput : suggestedDnsLookupInput(nextType, cleanSuggestedDomain));
    setHasEditedInput(preserveCustomInput);
    setLookupLoading(false);
    setLookupResult(null);
    setLookupError(null);
    setCopiedRecord(null);
    setCopyMessage("");
  }

  function useLookupValue(value: string) {
    lookupRequestVersionRef.current += 1;
    lookupControllerRef.current?.abort();
    lookupControllerRef.current = null;
    setLookupInput(value);
    setHasEditedInput(true);
    setLookupLoading(false);
    setLookupResult(null);
    setLookupError(null);
    setCopiedRecord(null);
    setCopyMessage("");
    document.getElementById("dns-lookup-name")?.focus();
  }

  async function copyLookupRecord(value: string, key: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedRecord(key);
      setCopyMessage("DNS record value copied.");
      window.setTimeout(() => setCopiedRecord((current) => current === key ? null : current), 1800);
      window.setTimeout(() => setCopyMessage(""), 2200);
    } catch {
      setCopiedRecord(null);
      setCopyMessage("Copy failed. Select and copy the value manually.");
      window.setTimeout(() => setCopyMessage(""), 2800);
    }
  }

  async function runLookup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = lookupInput.trim();
    if (!name) return;

    lookupControllerRef.current?.abort();
    const controller = new AbortController();
    lookupControllerRef.current = controller;
    const requestVersion = lookupRequestVersionRef.current + 1;
    lookupRequestVersionRef.current = requestVersion;
    const requestedType = lookupType;
    const timeout = window.setTimeout(() => controller.abort(), 15_000);
    setLookupLoading(true);
    setLookupError(null);
    setLookupResult(null);
    setCopyMessage("");

    try {
      const response = await fetch("/api/lookup", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ name, type: requestedType }),
        signal: controller.signal,
      });

      const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
      if (!contentType.includes("application/json")) {
        throw new Error("The DNS lookup API is unavailable. Please try again in a moment.");
      }

      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        throw new Error("The DNS lookup API returned an invalid response. Please try again.");
      }

      if (!response.ok || isScanError(payload)) {
        throw new Error(isScanError(payload) ? payload.error : "The DNS lookup could not be completed.");
      }
      if (!isDnsLookupResult(payload, requestedType)) {
        throw new Error("The DNS lookup API returned an incomplete response. Please try again.");
      }

      if (lookupRequestVersionRef.current !== requestVersion || lookupControllerRef.current !== controller) return;
      setLookupResult(payload);
    } catch (error) {
      if (lookupRequestVersionRef.current !== requestVersion || lookupControllerRef.current !== controller) return;
      setLookupError(
        error instanceof DOMException && error.name === "AbortError"
          ? "The DNS lookup timed out. No absence was inferred; please try again."
          : error instanceof Error
            ? error.message
            : "The DNS lookup could not be completed.",
      );
    } finally {
      window.clearTimeout(timeout);
      if (lookupRequestVersionRef.current === requestVersion && lookupControllerRef.current === controller) {
        lookupControllerRef.current = null;
        setLookupLoading(false);
      }
    }
  }

  const records = lookupResult
    ? Array.from(
        new Map(
          lookupResult.records.map((record) => [
            JSON.stringify([record.name.toLowerCase(), record.type.toUpperCase(), record.value]),
            record,
          ] as const),
        ).values(),
      )
    : [];

  return (
    <section className="dns-explorer-section" id="dns-explorer" aria-labelledby="dns-explorer-title">
      <div className="container">
        <div className="dns-explorer-heading">
          <div>
            <div className="eyebrow"><span /> DNS &amp; OSINT · exact lookup</div>
            <h2 id="dns-explorer-title">Inspect a record or analyze the bounded SPF path.</h2>
          </div>
          <p>
            Query a specific public DNS owner or select SPF for a recursive policy analysis with
            correction steps. These results remain separate from the Email Security score above.
          </p>
        </div>

        <div className="dns-explorer-card">
          <form className="dns-lookup-form" onSubmit={(event) => void runLookup(event)}>
            <div className="dns-lookup-field dns-type-field">
              <label htmlFor="dns-lookup-type">Record type</label>
              <select
                id="dns-lookup-type"
                value={lookupType}
                onChange={(event) => handleLookupTypeChange(event.target.value as DnsLookupMode)}
                disabled={lookupLoading}
              >
                <optgroup label="Email policy analysis">
                  <option value="SPF">SPF analyzer</option>
                </optgroup>
                <optgroup label="DNS record types">
                  {DNS_LOOKUP_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
                </optgroup>
              </select>
            </div>
            <div className="dns-lookup-field">
              <label htmlFor="dns-lookup-name">
                {lookupType === "PTR" ? "IP address" : lookupType === "SPF" ? "SPF domain or owner" : "DNS owner name"}
              </label>
              <div className="dns-name-input">
                <Globe2 aria-hidden="true" />
                <input
                  id="dns-lookup-name"
                  name="dns-lookup-name"
                  type="text"
                  inputMode="text"
                  autoCapitalize="none"
                  autoCorrect="off"
                  autoComplete="off"
                  spellCheck="false"
                  value={lookupInput}
                  onChange={(event) => {
                    setLookupInput(event.target.value);
                    setHasEditedInput(true);
                    setLookupResult(null);
                    setLookupError(null);
                    setCopiedRecord(null);
                    setCopyMessage("");
                  }}
                  placeholder={example}
                  aria-describedby="dns-lookup-help dns-lookup-scope"
                  disabled={lookupLoading}
                  required
                />
              </div>
            </div>
            <button className="button button-primary dns-lookup-button" type="submit" disabled={lookupLoading || !lookupInput.trim()}>
              {lookupLoading ? <LoaderCircle className="spin" aria-hidden="true" /> : <FileSearch aria-hidden="true" />}
              {lookupLoading ? (lookupType === "SPF" ? "Analyzing" : "Looking up") : (lookupType === "SPF" ? "Analyze SPF" : "Look up record")}
            </button>
          </form>

          <div className="dns-lookup-help" id="dns-lookup-help">
            <p>{hint}</p>
            <div className="dns-lookup-shortcuts" aria-label="Lookup input shortcuts">
              <span>Format example</span>
              <button type="button" onClick={() => useLookupValue(example)} disabled={lookupLoading}>
                <code>{example}</code>
              </button>
              {cleanSuggestedDomain && lookupType !== "PTR" && lookupInput !== cleanSuggestedDomain && (
                <button type="button" onClick={() => useLookupValue(cleanSuggestedDomain)} disabled={lookupLoading}>
                  Use scanned domain
                </button>
              )}
            </div>
          </div>

          {lookupError && (
            <div className="dns-lookup-error" role="alert">
              <AlertCircle aria-hidden="true" />
              <span>{lookupError}</span>
            </div>
          )}

          {lookupLoading && (
            <div className="dns-lookup-loading" role="status" aria-live="polite">
              <LoaderCircle className="spin" aria-hidden="true" />
              <div>
                <strong>{lookupType === "SPF" ? `Analyzing SPF for ${lookupInput}` : `Resolving ${lookupInput}`}</strong>
                <span>{lookupType === "SPF" ? "Following bounded include and redirect paths through public TXT records." : "Querying the selected public DNS record type."}</span>
              </div>
            </div>
          )}

          {lookupResult && !lookupLoading && (
            <div className="dns-lookup-result">
              <div className="dns-result-heading">
                <span className="dns-type-badge">{lookupResult.type}</span>
                <div>
                  <p>Query complete</p>
                  <h3>{lookupResult.queryName}</h3>
                </div>
                <span className="dns-result-meta">
                  {records.length} answer{records.length === 1 ? "" : "s"} · {(lookupResult.durationMs / 1000).toFixed(2)}s
                </span>
              </div>
              <p className="dns-result-summary" role="status" aria-live="polite">{lookupResult.summary}</p>
              {(lookupResult.input !== lookupResult.queryName || lookupResult.canonicalName) && (
                <div className="dns-query-translation">
                  <span>Entered</span><code>{lookupResult.input}</code>
                  {lookupResult.input !== lookupResult.queryName && (
                    <><ChevronRight aria-hidden="true" /><span>Queried</span><code>{lookupResult.queryName}</code></>
                  )}
                  {lookupResult.canonicalName && (
                    <><ChevronRight aria-hidden="true" /><span>Canonical target</span><code>{lookupResult.canonicalName}</code></>
                  )}
                </div>
              )}

              {records.length === 0 ? (
                <div className="dns-empty-state" role="status">
                  <CircleHelp aria-hidden="true" />
                  <div>
                    <strong>{lookupResult.type === "SPF" ? "No SPF policy was found in this domain's TXT records." : "No records were returned for this name and type."}</strong>
                    <span>
                      {lookupResult.type === "SPF"
                        ? "Do not publish a guessed record. First inventory every legitimate service that uses this domain in its envelope-from address."
                        : "An empty answer is not automatically a fault. The record may be optional, published at a different owner name, or intentionally absent."}
                    </span>
                  </div>
                </div>
              ) : (
                <div className="dns-answer-list" aria-label="Raw DNS answers">
                  <div className="dns-answer-label"><Code2 aria-hidden="true" /> Raw DNS evidence</div>
                  {records.map((record, index) => {
                    const key = `${record.name}-${record.type}-${record.value}-${index}`;
                    return (
                      <article className="dns-answer-row" key={key}>
                        <div className="dns-answer-owner">
                          <span>{record.type}</span>
                          <strong>{record.name}</strong>
                          <small>{record.ttl === undefined ? "TTL not provided" : `TTL ${record.ttl}s`}</small>
                        </div>
                        <code>{record.value}</code>
                        <button
                          type="button"
                          onClick={() => void copyLookupRecord(record.value, key)}
                          aria-label={`Copy ${record.type} record value for ${record.name}`}
                        >
                          {copiedRecord === key ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                          <span>{copiedRecord === key ? "Copied" : "Copy"}</span>
                        </button>
                      </article>
                    );
                  })}
                  {copyMessage && (
                    <span className="dns-copy-message" aria-live="polite">{copyMessage}</span>
                  )}
                </div>
              )}
              {lookupResult.type === "SPF" && lookupResult.spfAnalysis && (
                <SpfAnalysisPanel analysis={lookupResult.spfAnalysis} />
              )}
              <div className="dns-result-guidance">
                <Info aria-hidden="true" />
                <div>
                  <strong>{lookupResult.type === "SPF" ? "SPF safety note" : records.length > 0 ? "How to validate this answer" : "What to check before changing DNS"}</strong>
                  <span>{records.length > 0 ? DNS_LOOKUP_GUIDANCE[lookupResult.type].present : DNS_LOOKUP_GUIDANCE[lookupResult.type].empty}</span>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="dns-lookup-scope" id="dns-lookup-scope">
          <Info aria-hidden="true" />
          <p>
            This explorer performs point-in-time public DNS lookups and bounded SPF expansion only. It does not test SMTP,
            blocklists, worldwide propagation, port reachability, or other network services. SPF analysis is not a simulation
            for a particular sender IP and cannot replace real authentication results.
          </p>
        </div>
      </div>
    </section>
  );
}

function HowItWorks() {
  const steps = [
    {
      icon: <Globe2 />,
      number: "01",
      title: "Define the surface",
      copy: "Start with one public hostname or address. Each workspace applies a strict input and authorization boundary.",
    },
    {
      icon: <FileSearch />,
      number: "02",
      title: "Collect evidence",
      copy: "Run deterministic DNS analysis, local network calculations, or explicitly authorized web and TLS probes.",
    },
    {
      icon: <Route />,
      number: "03",
      title: "Prioritize safely",
      copy: "Turn observations into an ordered remediation path while separating direct tests, inferences, and unknowns.",
    },
  ];
  return (
    <section className="how-section" id="how-it-works">
      <div className="container">
        <div className="center-heading">
          <div className="eyebrow"><span /> One evidence model</div>
          <h2>From public surface to a defensible answer.</h2>
          <p>No mystery score and no implied coverage. Every recommendation stays tied to evidence the assessment could actually collect.</p>
        </div>
        <div className="steps-grid">
          {steps.map((step, index) => (
            <article className="step-card" key={step.number}>
              <span className="step-number">{step.number}</span>
              <span className="step-icon">{step.icon}</span>
              <h3>{step.title}</h3>
              <p>{step.copy}</p>
              {index < steps.length - 1 && <ArrowRight className="step-arrow" aria-hidden="true" />}
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

function Methodology() {
  const principles = [
    [<BadgeCheck />, "Evidence first", "Scores and grades are derived from bounded observations with raw records, endpoint details, or explicit unknown states."],
    [<Shield />, "Safe by default", "Passive tools stay passive-style; active web and TLS work requires authorization and server-enforced abuse controls."],
    [<Waypoints />, "Standards aligned", "Email, DNS, network, HTTP, OWASP, and TLS language follows the relevant standards without claiming compliance."],
  ] as const;
  return (
    <section className="methodology-section" id="methodology">
      <div className="container methodology-grid">
        <div>
          <div className="eyebrow"><span /> Methodology</div>
          <h2>Measurement before certainty.</h2>
          <p>
            Cresswell Security Lab uses deterministic checks and bounded active probes. It calls out
            uncertainty instead of turning unavailable evidence into a pass, a failure, or a compliance claim.
          </p>
          <a href="https://owasp.org/www-project-web-security-testing-guide/" target="_blank" rel="noreferrer">
            Explore the OWASP testing guide <ExternalLink aria-hidden="true" />
          </a>
        </div>
        <div className="principles-list">
          {principles.map(([icon, title, copy]) => (
            <article key={title}><span>{icon}</span><div><h3>{title}</h3><p>{copy}</p></div></article>
          ))}
        </div>
      </div>
    </section>
  );
}

function Roadmap() {
  return (
    <section className="roadmap-section" id="roadmap">
      <div className="container roadmap-card">
        <div>
          <div className="eyebrow eyebrow-light"><span /> Operational direction</div>
          <h2>Point-in-time evidence, designed to become a posture history.</h2>
          <p>
            The platform is structured for historical change detection, multi-domain portfolios,
            deeper authorized testing, and evidence-backed remediation workflows without weakening current safety boundaries.
          </p>
        </div>
        <div className="roadmap-visual" aria-hidden="true">
          <span><BarChart3 /></span><ChevronRight /><span><Sparkles /></span><ChevronRight /><span><ShieldCheck /></span>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer>
      <div className="container footer-inner">
        <div><Brand /><p>See what the internet sees.</p></div>
        <p>Cresswell Security Lab provides bounded technical observations, not proof of security, vulnerability, or compliance.</p>
        <a href="#top">Back to top <ArrowRight aria-hidden="true" /></a>
      </div>
    </footer>
  );
}

export default function App() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const initialScanStarted = useRef(false);
  const controllerRef = useRef<AbortController | null>(null);

  async function runScan(rawDomain: string) {
    const value = rawDomain.trim();
    if (!value) return;
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 20_000);
    setLoading(true);
    setError(null);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ domain: value }),
        signal: controller.signal,
      });

      const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
      if (!contentType.includes("application/json")) {
        throw new Error("The scanner API is unavailable. Verify that this site is deployed as a Cloudflare Worker, then try again.");
      }

      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        throw new Error("The scanner API returned an invalid response. Please try again in a moment.");
      }

      if (!response.ok || isScanError(payload)) {
        throw new Error(isScanError(payload) ? payload.error : "The scan could not be completed.");
      }
      if (!isScanResult(payload)) {
        throw new Error("The scanner API returned an incomplete response. Please try again in a moment.");
      }

      if (controllerRef.current !== controller) return;
      setDomain(payload.domain);
      setResult(payload);
      const url = new URL(window.location.href);
      url.searchParams.set("domain", payload.domain);
      window.history.replaceState({}, "", url);
      window.setTimeout(() => document.getElementById("results")?.scrollIntoView({ behavior: "smooth" }), 100);
    } catch (scanError) {
      if (controllerRef.current !== controller) return;
      if (scanError instanceof DOMException && scanError.name === "AbortError") {
        setError("The DNS scan timed out. Please try again in a moment.");
      } else {
        setError(scanError instanceof Error ? scanError.message : "The scan could not be completed.");
      }
      if (!result) window.setTimeout(scrollToScanner, 50);
    } finally {
      window.clearTimeout(timeout);
      if (controllerRef.current === controller) setLoading(false);
    }
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void runScan(domain);
  }

  useEffect(() => {
    if (initialScanStarted.current) return;
    initialScanStarted.current = true;
    const queryDomain = new URLSearchParams(window.location.search).get("domain");
    if (queryDomain) {
      setDomain(queryDomain);
      void runScan(queryDomain);
    }
  }, []);

  useEffect(() => {
    let robots = document.querySelector<HTMLMetaElement>('meta[name="robots"]');
    if (!robots) {
      robots = document.createElement("meta");
      robots.name = "robots";
      document.head.appendChild(robots);
    }
    robots.content = result ? "noindex, nofollow" : "index, follow";
  }, [result]);

  return (
    <div id="top">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <Header />
      <main id="main-content">
        <Hero domain={domain} setDomain={setDomain} onSubmit={handleSubmit} loading={loading} error={error} />
        {loading && <LoadingResults domain={domain} />}
        {result && !loading && (
          <Results
            result={result}
            domain={domain}
            setDomain={setDomain}
            onSubmit={handleSubmit}
            loading={loading}
            error={error}
          />
        )}
        <SecurityFamilies />
        <FamilyIntro
          id="dns-intelligence"
          number="02"
          icon={<Globe2 />}
          eyebrow="DNS & OSINT"
          title="Interrogate the public naming layer."
          copy="Resolve exact records, expand SPF safely, and map a bounded DNS surface without crawling services or guessing hidden names."
          badges={["Public DNS", "Bounded discovery", "Raw evidence"]}
        />
        <AdvancedDnsExplorer suggestedDomain={result?.domain ?? ""} />
        <DnsSurfaceScanner suggestedDomain={result?.domain ?? ""} />
        <FamilyIntro
          id="network-intelligence"
          number="03"
          icon={<Network />}
          eyebrow="Network Intelligence"
          title="Put an address in operational context."
          copy="Calculate exact networks and usable ranges, classify special-use space, and inspect reverse-DNS and routing-origin evidence for one address."
          badges={["No port scan", "Local arithmetic", "DNS enrichment"]}
        />
        <IpNetworkTool />
        <WebSecurityScanner suggestedDomain={result?.domain ?? ""} />
        <HowItWorks />
        <Methodology />
        <Roadmap />
      </main>
      <Footer />
    </div>
  );
}
