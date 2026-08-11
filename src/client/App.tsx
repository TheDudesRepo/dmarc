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
  Fingerprint,
  Globe2,
  Info,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  MailCheck,
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
  DnsLookupType,
  Finding,
  FindingSeverity,
  ScanError,
  ScanResult,
} from "../shared/types";

const EXAMPLE_DOMAINS = ["google.com", "github.com", "cloudflare.com"];

const COMMON_DNS_LOOKUP_TYPES: DnsLookupType[] = [
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

const ADVANCED_DNS_LOOKUP_TYPES: DnsLookupType[] = [
  "DNSKEY",
  "DS",
  "RRSIG",
  "NSEC",
  "NSEC3PARAM",
  "CERT",
  "LOC",
  "IPSECKEY",
  "TLSA",
];

const DNS_LOOKUP_HINTS: Partial<Record<DnsLookupType, string>> = {
  TXT: "Use the exact owner name, such as selector._domainkey.example.com for a DKIM key.",
  CNAME: "Use the alias owner name, such as www.example.com.",
  SRV: "Service records use _service._protocol, such as _sip._tcp.example.com.",
  PTR: "Enter an IPv4 or IPv6 address; the server converts it to the reverse-DNS owner name.",
  TLSA: "TLSA owners include port and protocol, such as _25._tcp.mx.example.com.",
  DNSKEY: "Use the zone name whose published DNSSEC keys you want to inspect.",
  DS: "Use the delegated child-zone name whose parent-published DS record you want to inspect.",
  RRSIG: "Use the exact owner name whose DNSSEC signatures you want to inspect.",
  NSEC: "Use an owner name in a DNSSEC-signed zone; an empty answer is not automatically an error.",
};

function isScanResult(value: unknown): value is ScanResult {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<ScanResult>;
  return (
    typeof candidate.domain === "string" &&
    typeof candidate.scannedAt === "string" &&
    typeof candidate.durationMs === "number" &&
    typeof candidate.score === "number" &&
    typeof candidate.grade === "string" &&
    typeof candidate.posture === "string" &&
    Boolean(
      candidate.checks?.dmarc &&
      candidate.checks?.spf &&
      candidate.checks?.dkim &&
      candidate.checks?.transport &&
      candidate.checks?.dns,
    ) &&
    Array.isArray(candidate.findings) &&
    Boolean(candidate.metadata)
  );
}

function isScanError(value: unknown): value is ScanError {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<ScanError>;
  return typeof candidate.error === "string" && typeof candidate.code === "string";
}

function isDnsLookupResult(value: unknown): value is DnsLookupResult {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<DnsLookupResult>;
  return (
    typeof candidate.input === "string" &&
    typeof candidate.queryName === "string" &&
    typeof candidate.type === "string" &&
    typeof candidate.scannedAt === "string" &&
    typeof candidate.durationMs === "number" &&
    typeof candidate.summary === "string" &&
    Array.isArray(candidate.records)
  );
}

function dnsLookupExample(type: DnsLookupType, suggestedDomain: string): string {
  const domain = suggestedDomain || "example.com";
  if (type === "PTR") return "192.0.2.25";
  if (type === "TXT") return `selector._domainkey.${domain}`;
  if (type === "CNAME") return `www.${domain}`;
  if (type === "SRV") return `_sip._tcp.${domain}`;
  if (type === "TLSA") return `_25._tcp.mx.${domain}`;
  return domain;
}

function suggestedDnsLookupInput(type: DnsLookupType, suggestedDomain: string): string {
  if (!suggestedDomain || type === "PTR") return "";
  if (type === "CNAME" || type === "SRV" || type === "TLSA") {
    return dnsLookupExample(type, suggestedDomain);
  }
  return suggestedDomain;
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
  document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function Brand() {
  return (
    <a className="brand" href="#top" aria-label="DMARC Ready home">
      <span className="brand-mark" aria-hidden="true">
        <ShieldCheck />
      </span>
      <span>DMARC<span>Ready</span></span>
    </a>
  );
}

function Header() {
  return (
    <header className="site-header">
      <div className="container header-inner">
        <Brand />
        <nav className="desktop-nav" aria-label="Primary navigation">
          <a href="#dns-explorer">DNS tools</a>
          <a href="#how-it-works">How it works</a>
          <a href="#methodology">Methodology</a>
          <a href="#roadmap">Roadmap</a>
        </nav>
        <button className="button button-small button-quiet" type="button" onClick={scrollToScanner}>
          Scan a domain <ArrowRight aria-hidden="true" />
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
    <section className="hero" id="scanner">
      <div className="hero-grid" aria-hidden="true" />
      <div className="orb orb-one" aria-hidden="true" />
      <div className="orb orb-two" aria-hidden="true" />
      <div className="container hero-inner">
        <div className="eyebrow"><span /> Free email authentication check</div>
        <h1>Know what stands between your domain and <em>enforcement.</em></h1>
        <p className="hero-copy">
          Inspect DMARC, SPF, discoverable DKIM, DNS health, and mail transport controls in seconds.
          Get a clear explanation of what is configured, what is exposed, and what to fix next.
        </p>
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
            <span><Database aria-hidden="true" /> Public DNS data only</span>
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
        <span><Fingerprint aria-hidden="true" /> DMARC policy</span>
        <span><Network aria-hidden="true" /> SPF policy</span>
        <span><KeyRound aria-hidden="true" /> DKIM discovery</span>
        <span><MailCheck aria-hidden="true" /> Transport security</span>
        <span><Globe2 aria-hidden="true" /> DNS health</span>
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
              {remediationRecord && (
                <div className="fix-record" role="group" aria-label="Copy-ready DNS record">
                  <div className="fix-record-heading">
                    <div>
                      <strong>Copy-ready DNS record</strong>
                      <span>Use these fields in your DNS provider.</span>
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
              {finding.remediation.caution && (
                <div className="remediation-caution" role="note">
                  <AlertTriangle aria-hidden="true" />
                  <div><strong>Before you publish</strong><span>{finding.remediation.caution}</span></div>
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

function AdvancedDnsExplorer({ suggestedDomain }: { suggestedDomain: string }) {
  const [lookupType, setLookupType] = useState<DnsLookupType>("A");
  const [lookupInput, setLookupInput] = useState("");
  const [hasEditedInput, setHasEditedInput] = useState(false);
  const [lookupResult, setLookupResult] = useState<DnsLookupResult | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [copiedRecord, setCopiedRecord] = useState<string | null>(null);
  const [copyMessage, setCopyMessage] = useState("");
  const lookupControllerRef = useRef<AbortController | null>(null);

  const cleanSuggestedDomain = suggestedDomain.trim();
  const example = dnsLookupExample(lookupType, cleanSuggestedDomain);
  const hint = DNS_LOOKUP_HINTS[lookupType] ?? "Enter the exact public DNS owner name you want to query.";

  useEffect(() => {
    if (!hasEditedInput && cleanSuggestedDomain) {
      setLookupInput(suggestedDnsLookupInput(lookupType, cleanSuggestedDomain));
    }
  }, [cleanSuggestedDomain, hasEditedInput, lookupType]);

  useEffect(() => () => lookupControllerRef.current?.abort(), []);

  function handleLookupTypeChange(nextType: DnsLookupType) {
    setLookupType(nextType);
    setLookupError(null);
    if (!hasEditedInput) {
      setLookupInput(suggestedDnsLookupInput(nextType, cleanSuggestedDomain));
    }
  }

  function useLookupValue(value: string) {
    setLookupInput(value);
    setHasEditedInput(true);
    setLookupError(null);
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
      if (!isDnsLookupResult(payload)) {
        throw new Error("The DNS lookup API returned an incomplete response. Please try again.");
      }

      if (lookupControllerRef.current !== controller) return;
      setLookupResult(payload);
    } catch (error) {
      if (lookupControllerRef.current !== controller) return;
      setLookupError(
        error instanceof DOMException && error.name === "AbortError"
          ? "The DNS lookup timed out. No absence was inferred; please try again."
          : error instanceof Error
            ? error.message
            : "The DNS lookup could not be completed.",
      );
    } finally {
      window.clearTimeout(timeout);
      if (lookupControllerRef.current === controller) setLookupLoading(false);
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
            <div className="eyebrow"><span /> Advanced DNS explorer</div>
            <h2 id="dns-explorer-title">Inspect the record behind the result.</h2>
          </div>
          <p>
            Query a specific public DNS owner and inspect the raw answer. This is a record lookup,
            separate from the domain readiness score above.
          </p>
        </div>

        <div className="dns-explorer-card">
          <form className="dns-lookup-form" onSubmit={(event) => void runLookup(event)}>
            <div className="dns-lookup-field dns-type-field">
              <label htmlFor="dns-lookup-type">Record type</label>
              <select
                id="dns-lookup-type"
                value={lookupType}
                onChange={(event) => handleLookupTypeChange(event.target.value as DnsLookupType)}
                disabled={lookupLoading}
              >
                <optgroup label="Common DNS records">
                  {COMMON_DNS_LOOKUP_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
                </optgroup>
                <optgroup label="DNSSEC and advanced records">
                  {ADVANCED_DNS_LOOKUP_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
                </optgroup>
              </select>
            </div>
            <div className="dns-lookup-field">
              <label htmlFor="dns-lookup-name">{lookupType === "PTR" ? "IP address" : "DNS owner name"}</label>
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
                    setLookupError(null);
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
              {lookupLoading ? "Looking up" : "Look up record"}
            </button>
          </form>

          <div className="dns-lookup-help" id="dns-lookup-help">
            <p>{hint}</p>
            <div className="dns-lookup-shortcuts" aria-label="Lookup input shortcuts">
              <span>Example</span>
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
              <div><strong>Resolving {lookupInput}</strong><span>Querying the selected public DNS record type.</span></div>
            </div>
          )}

          {lookupResult && !lookupLoading && (
            <div className="dns-lookup-result" aria-live="polite">
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
              <p className="dns-result-summary">{lookupResult.summary}</p>
              {lookupResult.input !== lookupResult.queryName && (
                <div className="dns-query-translation">
                  <span>Entered</span><code>{lookupResult.input}</code><ChevronRight aria-hidden="true" />
                  <span>Queried</span><code>{lookupResult.queryName}</code>
                </div>
              )}

              {records.length === 0 ? (
                <div className="dns-empty-state" role="status">
                  <CircleHelp aria-hidden="true" />
                  <div>
                    <strong>No records were returned for this name and type.</strong>
                    <span>An empty answer is not automatically a fault. The record may be optional, published at a different owner name, or intentionally absent.</span>
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
                  <span className="sr-only" aria-live="polite">{copyMessage}</span>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="dns-lookup-scope" id="dns-lookup-scope">
          <Info aria-hidden="true" />
          <p>
            This explorer performs point-in-time public DNS record lookups only. It does not test SMTP,
            blocklists, worldwide propagation, port reachability, or other network services.
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
      title: "Resolve",
      copy: "Query authoritative public records through encrypted DNS. Nothing is installed and no email is sent.",
    },
    {
      icon: <FileSearch />,
      number: "02",
      title: "Explain",
      copy: "Parse policy tags, alignment modes, reporting destinations, SPF paths, and discoverable supporting controls.",
    },
    {
      icon: <Route />,
      number: "03",
      title: "Prioritize",
      copy: "Turn protocol details into an ordered remediation path while clearly separating evidence from assumptions.",
    },
  ];
  return (
    <section className="how-section" id="how-it-works">
      <div className="container">
        <div className="center-heading">
          <div className="eyebrow"><span /> Clear by design</div>
          <h2>From DNS records to a usable answer.</h2>
          <p>No wall of XML. No mystery score. Every recommendation is tied to evidence found during the scan.</p>
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
    [<BadgeCheck />, "Evidence first", "Scores are derived from observable DNS configuration, with raw records available for inspection."],
    [<Shield />, "Safe by default", "A DNS snapshot never claims a domain is safe to enforce without aggregate-report history."],
    [<Waypoints />, "Standards aligned", "Analysis follows current DMARC deployment concepts while preserving compatibility with deployed records."],
  ] as const;
  return (
    <section className="methodology-section" id="methodology">
      <div className="container methodology-grid">
        <div>
          <div className="eyebrow"><span /> Methodology</div>
          <h2>Built for decisions—not just dashboards.</h2>
          <p>
            This first release is intentionally deterministic. It evaluates public configuration and
            calls out uncertainty instead of pretending a DNS record proves every legitimate sender is aligned.
          </p>
          <a href="https://datatracker.ietf.org/doc/rfc9989/" target="_blank" rel="noreferrer">
            Read the current DMARC standard <ExternalLink aria-hidden="true" />
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
          <div className="eyebrow eyebrow-light"><span /> Coming next</div>
          <h2>A scanner today. An enforcement copilot tomorrow.</h2>
          <p>
            Planned capabilities include DMARC aggregate-report ingestion, sender ownership workflows,
            historical change detection, multi-domain portfolios, and guided movement to quarantine.
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
        <div><Brand /><p>Clear evidence. Safer enforcement.</p></div>
        <p>DMARC Ready provides technical analysis, not a guarantee of mail delivery or security.</p>
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
        <AdvancedDnsExplorer suggestedDomain={result?.domain ?? ""} />
        <HowItWorks />
        <Methodology />
        <Roadmap />
      </main>
      <Footer />
    </div>
  );
}
