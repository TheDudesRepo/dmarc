import {
  AlertCircle,
  AlertTriangle,
  BadgeCheck,
  Check,
  CircleHelp,
  Clock3,
  Copy,
  ExternalLink,
  FileSearch,
  Globe2,
  Info,
  LoaderCircle,
  LockKeyhole,
  Radar,
  ServerCog,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import type {
  TlsAssessment,
  TlsCertificateSummary,
  TlsCipherObservation,
  TlsEndpointObservation,
  TlsProtocolObservation,
  WebScanQuota,
  WebSecurityCheck,
  WebSecurityCheckId,
  WebSecurityCheckStatus,
  WebSecurityScanError,
  WebSecurityScanResult,
} from "../shared/types";
import {
  WEB_SECURITY_DISCLAIMER,
  WEB_SECURITY_DISCLAIMER_VERSION,
} from "../shared/types";

export const WEB_SECURITY_CHECK_IDS = [
  "https-enforcement",
  "hsts",
  "content-security-policy",
  "frame-protection",
  "mime-sniffing",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-isolation",
  "cors-policy",
  "http-methods",
  "cookie-secure",
  "cookie-httponly",
  "cookie-samesite",
  "cookie-scope-prefix",
  "cache-control",
  "technology-disclosure",
  "error-handling",
  "mixed-content",
  "form-transport",
  "subresource-integrity",
] as const satisfies readonly WebSecurityCheckId[];

const WEB_SECURITY_CHECK_ID_SET = new Set<string>(WEB_SECURITY_CHECK_IDS);
const CHECK_STATUS_SET = new Set<WebSecurityCheckStatus>([
  "pass",
  "warning",
  "fail",
  "not-applicable",
  "unknown",
]);
const TLS_STATUS_SET = new Set(["complete", "partial", "unavailable"]);
const TLS_GRADE_SET = new Set(["A", "B", "C", "D", "F", "N/A"]);
const GRADE_SET = new Set(["A", "B", "C", "D", "F", "N/A"]);
const TLS_ENDPOINT_STATUS_SET = new Set(["ready", "platform-blocked", "unreachable", "unavailable"]);
const TLS_PROTOCOL_STATUS_SET = new Set(["supported", "not-supported", "unknown"]);
const TLS_PROTOCOL_VERSION_SET = new Set(["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]);
const WEAK_CIPHER_STATUS_SET = new Set(["supported", "not-supported", "unknown"]);
const WEB_SCAN_ERROR_CODE_SET = new Set([
  "INVALID_DOMAIN",
  "METHOD_NOT_ALLOWED",
  "BAD_REQUEST",
  "UPSTREAM_ERROR",
  "NOT_FOUND",
  "AUTHORIZATION_REQUIRED",
  "RATE_LIMITED",
  "UNSAFE_TARGET",
  "SERVICE_UNAVAILABLE",
]);
const NON_PUBLIC_HOST_SUFFIXES = new Set([
  "local",
  "localhost",
  "internal",
  "invalid",
  "test",
  "home",
  "lan",
  "localdomain",
  "onion",
]);
type CheckFilter = "all" | "attention" | "pass" | "other";

const checkStatusIcons: Record<WebSecurityCheckStatus, ReactNode> = {
  pass: <BadgeCheck aria-hidden="true" />,
  warning: <AlertTriangle aria-hidden="true" />,
  fail: <XCircle aria-hidden="true" />,
  "not-applicable": <Info aria-hidden="true" />,
  unknown: <CircleHelp aria-hidden="true" />,
};

interface WebSecurityScannerProps {
  suggestedDomain: string;
}

export function WebSecurityScanner({ suggestedDomain }: WebSecurityScannerProps) {
  const [hostname, setHostname] = useState("");
  const [hasEditedHostname, setHasEditedHostname] = useState(false);
  const [authorizedUse, setAuthorizedUse] = useState(false);
  const [result, setResult] = useState<WebSecurityScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [quota, setQuota] = useState<WebScanQuota | null>(null);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const [filter, setFilter] = useState<CheckFilter>("all");
  const [clock, setClock] = useState(() => Date.now());
  const controllerRef = useRef<AbortController | null>(null);
  const requestVersionRef = useRef(0);
  const cleanSuggestedDomain = suggestedDomain.trim();

  const quotaResetTime = quota ? Date.parse(quota.resetAt) : Number.NaN;
  const rateLimited = Boolean(
    quota && quota.remaining === 0 && Number.isFinite(quotaResetTime) && quotaResetTime > clock,
  );

  useEffect(() => {
    if (hasEditedHostname) return;
    requestVersionRef.current += 1;
    controllerRef.current?.abort();
    controllerRef.current = null;
    setLoading(false);
    setResult(null);
    setError(null);
    setAuthorizedUse(false);
    setCopyState("idle");
    setFilter("all");
    if (cleanSuggestedDomain) setHostname(cleanSuggestedDomain);
  }, [cleanSuggestedDomain, hasEditedHostname]);

  useEffect(() => () => {
    requestVersionRef.current += 1;
    controllerRef.current?.abort();
  }, []);

  useEffect(() => {
    if (!quota || !Number.isFinite(quotaResetTime) || quotaResetTime <= clock) return;
    const timer = window.setInterval(() => setClock(Date.now()), 15_000);
    return () => window.clearInterval(timer);
  }, [quota?.resetAt, clock >= quotaResetTime]);

  useEffect(() => {
    if (!quota || !Number.isFinite(quotaResetTime) || quotaResetTime > clock) return;
    const wasBlocked = quota.remaining === 0;
    setQuota(null);
    if (wasBlocked) setError(null);
  }, [clock, quota?.remaining, quota?.resetAt]);

  function resetForHostname(value: string) {
    requestVersionRef.current += 1;
    controllerRef.current?.abort();
    controllerRef.current = null;
    setHostname(value);
    setHasEditedHostname(true);
    setAuthorizedUse(false);
    setResult(null);
    setError(null);
    setLoading(false);
    setCopyState("idle");
    setFilter("all");
  }

  async function runWebSecurityScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = hostname.trim();
    if (!target || !authorizedUse || rateLimited) return;

    requestVersionRef.current += 1;
    const requestVersion = requestVersionRef.current;
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 45_000);
    setLoading(true);
    setResult(null);
    setError(null);
    setCopyState("idle");
    setFilter("all");

    try {
      const response = await fetch("/api/web-security", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({
          hostname: target,
          authorizedUse: true,
          disclaimerVersion: WEB_SECURITY_DISCLAIMER_VERSION,
        }),
        signal: controller.signal,
      });
      const payload: unknown = await response.json().catch(() => null);
      if (requestVersionRef.current !== requestVersion || controllerRef.current !== controller) return;
      const responseQuota = quotaFromHeaders(response.headers);
      if (responseQuota) {
        setQuota(responseQuota);
        setClock(Date.now());
      }

      if (response.status === 429) {
        const scanError = isWebSecurityScanError(payload) ? payload : null;
        const nextQuota = scanError?.quota ?? responseQuota;
        if (nextQuota) {
          setQuota(nextQuota);
          setClock(Date.now());
        }
        throw new Error(
          scanError?.error
            ?? rateLimitMessage(nextQuota)
            ?? "The hourly scan limit has been reached for this network. Please try again later.",
        );
      }

      if (!response.ok) {
        throw new Error(
          isWebSecurityScanError(payload)
            ? payload.error
            : "The web-security scanner is temporarily unavailable.",
        );
      }
      if (!isWebSecurityScanResult(payload, target)) {
        throw new Error("The web-security API returned an invalid response. Please try again.");
      }

      setHostname(payload.hostname);
      setResult(payload);
      setQuota(payload.quota);
      setClock(Date.now());
      window.setTimeout(() => {
        const resultsElement = document.getElementById("web-security-results");
        resultsElement?.focus({ preventScroll: true });
        if (typeof resultsElement?.scrollIntoView === "function") {
          resultsElement.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }, 100);
    } catch (caught) {
      if (requestVersionRef.current !== requestVersion || controllerRef.current !== controller) return;
      setError(
        caught instanceof DOMException && caught.name === "AbortError"
          ? "The web-security scan timed out. Unfinished checks remain unknown; please try again."
          : caught instanceof Error
            ? caught.message
            : "The web-security scan could not be completed.",
      );
    } finally {
      window.clearTimeout(timeout);
      if (requestVersionRef.current === requestVersion && controllerRef.current === controller) {
        controllerRef.current = null;
        setLoading(false);
      }
    }
  }

  async function copyJson() {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(result, null, 2));
      setCopyState("copied");
      window.setTimeout(() => setCopyState("idle"), 1_800);
    } catch {
      setCopyState("failed");
      window.setTimeout(() => setCopyState("idle"), 2_600);
    }
  }

  const filteredChecks = useMemo(() => {
    if (!result) return [];
    if (filter === "attention") return result.checks.filter((check) => check.status === "fail" || check.status === "warning");
    if (filter === "pass") return result.checks.filter((check) => check.status === "pass");
    if (filter === "other") return result.checks.filter((check) => check.status === "unknown" || check.status === "not-applicable");
    return result.checks;
  }, [filter, result]);

  const statusCounts = useMemo(() => countStatuses(result?.checks ?? []), [result]);

  return (
    <section className="web-security-section" id="web-security" aria-labelledby="web-security-title">
      <div className="container">
        <div className="web-security-heading">
          <div>
            <div className="eyebrow"><span /> TLS and web security</div>
            <h2 id="web-security-title">Inspect TLS and 20 OWASP-aligned controls.</h2>
          </div>
          <p>
            Review certificate and protocol evidence plus a fixed set of non-destructive HTTP configuration checks.
            The scan does not test credentials, injection, authorization, or business logic.
          </p>
        </div>

        <div className="web-security-card">
          <form className="web-security-form" onSubmit={(event) => void runWebSecurityScan(event)}>
            <div className="web-security-input">
              <label htmlFor="web-security-hostname">Public website hostname</label>
              <div>
                <Globe2 aria-hidden="true" />
                <input
                  id="web-security-hostname"
                  type="text"
                  inputMode="url"
                  value={hostname}
                  onChange={(event) => resetForHostname(event.target.value)}
                  placeholder="www.example.com"
                  autoCapitalize="none"
                  autoCorrect="off"
                  autoComplete="off"
                  spellCheck="false"
                  aria-describedby="web-security-input-help web-security-consent-copy web-security-quota"
                  required
                />
              </div>
              <p id="web-security-input-help">Hostname only. URLs, paths, credentials, custom ports, and IP addresses are rejected.</p>
            </div>
            <button
              className="button button-primary web-security-submit"
              type="submit"
              disabled={loading || !hostname.trim() || !authorizedUse || rateLimited}
            >
              {loading ? <LoaderCircle className="spin" aria-hidden="true" /> : <Radar aria-hidden="true" />}
              {loading ? "Assessing website" : rateLimited ? "Hourly limit reached" : "Run security scan"}
            </button>

            <label className="web-security-consent">
              <input
                type="checkbox"
                checked={authorizedUse}
                onChange={(event) => setAuthorizedUse(event.target.checked)}
                disabled={loading || rateLimited}
                aria-describedby="web-security-consent-copy web-security-acceptable-use"
              />
              <span>
                <strong>I confirm I own or administer this hostname, or have explicit permission to assess it.</strong>
                <small id="web-security-consent-copy">
                  Do not scan systems without authorization. This assessment sends a small, fixed set of TLS and HTTP requests.
                </small>
              </span>
            </label>
          </form>

          <div className={`web-security-quota ${rateLimited ? "web-security-quota-blocked" : ""}`} id="web-security-quota" aria-live="polite">
            <Clock3 aria-hidden="true" />
            <span>{quotaText(quota, rateLimited, clock)}</span>
          </div>

          <div className="web-security-responsible-use" id="web-security-acceptable-use">
            <LockKeyhole aria-hidden="true" />
            <div>
              <strong>Authorized-use notice · version {WEB_SECURITY_DISCLAIMER_VERSION}</strong>
              <p>{WEB_SECURITY_DISCLAIMER}</p>
              <small>Shared networks share the five-scan hourly quota.</small>
            </div>
          </div>

          {loading && (
            <div className="web-security-loading" role="status" aria-live="polite">
              <LoaderCircle className="spin" aria-hidden="true" />
              <div>
                <strong>Assessing {hostname}</strong>
                <span>Validating the destination, collecting bounded TLS evidence, and reviewing twenty fixed web controls.</span>
              </div>
            </div>
          )}

          {error && (
            <div className="web-security-error" role="alert">
              <AlertCircle aria-hidden="true" />
              <div>
                <strong>{rateLimited ? "Hourly limit reached" : "Scan could not complete"}</strong>
                <span>{error}</span>
              </div>
            </div>
          )}

          {result && !loading && (
            <div
              className="web-security-results"
              id="web-security-results"
              role="region"
              aria-labelledby="web-security-result-title"
              tabIndex={-1}
            >
              <p className="sr-only" role="status" aria-live="polite">
                Web-security scan complete for {result.hostname}.
              </p>
              <div className="web-security-result-bar">
                <div>
                  <span>Observed website</span>
                  <h3 id="web-security-result-title">{result.hostname}</h3>
                  <a href={result.effectiveUrl} target="_blank" rel="noreferrer">
                    {result.effectiveUrl} <ExternalLink aria-hidden="true" />
                  </a>
                </div>
                <button type="button" onClick={() => void copyJson()}>
                  {copyState === "copied" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                  {copyState === "copied" ? "Copied JSON" : copyState === "failed" ? "Copy failed" : "Copy JSON"}
                </button>
              </div>

              <div className="web-security-summary">
                <div className={`web-security-grade grade-${gradeClass(result.grade)}`}>
                  <span>Web configuration</span><strong>{result.grade}</strong><small>{result.score} / 100</small>
                </div>
                <div className={`web-security-grade tls-${result.tls.status} grade-${gradeClass(result.tls.grade)}`}>
                  <span>Bounded TLS posture</span><strong>{result.tls.grade}</strong><small>{formatLabel(result.tls.status)}</small>
                </div>
                <div><span>Controls passed</span><strong>{statusCounts.pass} / 20</strong><small>{statusCounts.fail} failed · {statusCounts.warning} warnings</small></div>
                <div><span>Scan duration</span><strong>{formatDuration(result.durationMs)}</strong><small>{new Date(result.scannedAt).toLocaleString()}</small></div>
              </div>

              <div className="web-security-headline">
                <ShieldCheck aria-hidden="true" />
                <div><strong>{result.headline}</strong><p>{result.summary}</p></div>
              </div>

              <TlsPanel tls={result.tls} />

              <div className="web-checks-block">
                <div className="web-checks-heading">
                  <div><FileSearch aria-hidden="true" /><span><small>Fixed assessment scope</small><strong>20 OWASP-aligned configuration checks</strong></span></div>
                  <p>These checks cover observable transport and browser-facing controls, not the full OWASP Top 10.</p>
                </div>
                <div className="web-check-filters" aria-label="Filter web-security checks">
                  <FilterButton current={filter} value="all" onChange={setFilter}>All 20</FilterButton>
                  <FilterButton current={filter} value="attention" onChange={setFilter}>Needs attention ({statusCounts.fail + statusCounts.warning})</FilterButton>
                  <FilterButton current={filter} value="pass" onChange={setFilter}>Passed ({statusCounts.pass})</FilterButton>
                  <FilterButton current={filter} value="other" onChange={setFilter}>Unknown / N/A ({statusCounts.unknown + statusCounts["not-applicable"]})</FilterButton>
                </div>
                <div className="web-check-list">
                  {filteredChecks.map((check) => <WebCheckRow check={check} key={check.id} />)}
                </div>
              </div>

              <div className="web-security-budget">
                <ServerCog aria-hidden="true" />
                <div>
                  <strong>Bounded request budget</strong>
                  <span>
                    {result.requestBudget.httpRequests} HTTP requests · {result.requestBudget.tlsConnections} TLS connections · {result.requestBudget.redirectHopsFollowed} redirects · {formatBytes(result.requestBudget.maxResponseBytes)} response cap
                  </span>
                </div>
              </div>

              <div className="web-security-disclaimer">
                <CircleHelp aria-hidden="true" />
                <div><strong>Assessment boundary</strong><p>{result.disclaimer}</p></div>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function FilterButton({
  children,
  current,
  value,
  onChange,
}: {
  children: ReactNode;
  current: CheckFilter;
  value: CheckFilter;
  onChange: (value: CheckFilter) => void;
}) {
  return (
    <button
      type="button"
      className={current === value ? "active" : ""}
      aria-pressed={current === value}
      onClick={() => onChange(value)}
    >
      {children}
    </button>
  );
}

function WebCheckRow({ check }: { check: WebSecurityCheck }) {
  return (
    <article className={`web-check-row web-check-${check.status}`}>
      <span className="web-check-icon">{checkStatusIcons[check.status]}</span>
      <div className="web-check-body">
        <div className="web-check-title">
          <div><code>{check.id}</code><h4>{check.title}</h4></div>
          <span>{formatLabel(check.status)}</span>
        </div>
        <p>{check.summary}</p>
        {check.evidence.length > 0 && (
          <div className="web-check-evidence">
            <strong>Observed evidence</strong>
            <ul>{check.evidence.map((evidence, index) => <li key={`${check.id}-evidence-${index}`}>{evidence}</li>)}</ul>
          </div>
        )}
        <div className="web-check-remediation"><ShieldCheck aria-hidden="true" /><span><strong>Recommended action</strong>{check.remediation}</span></div>
        <div className="web-check-standards">
          {[...check.owasp.top10, ...check.owasp.wstg].map((standard, index) => <span key={`${check.id}-${standard}-${index}`}>{standard}</span>)}
        </div>
      </div>
    </article>
  );
}

function TlsPanel({ tls }: { tls: TlsAssessment }) {
  return (
    <div className={`tls-panel tls-panel-${tls.status} tls-panel-grade-${gradeClass(tls.grade)}`}>
      <div className="tls-panel-heading">
        <div><ShieldCheck aria-hidden="true" /><span><small>TLS assessment</small><strong>{formatLabel(tls.status)} evidence · Grade {tls.grade}</strong></span></div>
        <span>{tls.endpoints.length} endpoint{tls.endpoints.length === 1 ? "" : "s"}</span>
      </div>
      <p className="tls-panel-summary">{tls.summary}</p>

      {tls.status === "partial" && (
        <div className="tls-state-note tls-state-partial"><AlertTriangle aria-hidden="true" /><span>Some TLS evidence is indeterminate. Unknown probes are not counted as failures.</span></div>
      )}
      {tls.status === "unavailable" && (
        <div className="tls-state-note tls-state-unavailable"><CircleHelp aria-hidden="true" /><span>Raw TLS evidence was unavailable from the scanner network. HTTPS reachability may still be reported by the web checks.</span></div>
      )}

      <div className="tls-endpoint-list">
        {tls.endpoints.map((endpoint, index) => <TlsEndpoint endpoint={endpoint} key={`${endpoint.address}-${index}`} />)}
      </div>

      <div className="tls-limitations">
        <Info aria-hidden="true" />
        <div>
          <strong>Scope and limitations</strong>
          <ul>{tls.limitations.map((limitation, index) => <li key={`tls-limitation-${index}`}>{limitation}</li>)}</ul>
          <a href={tls.reportUrl} target="_blank" rel="noreferrer">Run a separate SSL Labs assessment <ExternalLink aria-hidden="true" /></a>
        </div>
      </div>
    </div>
  );
}

function TlsEndpoint({ endpoint }: { endpoint: TlsEndpointObservation }) {
  return (
    <details className={`tls-endpoint tls-endpoint-${endpoint.status}`}>
      <summary>
        <span><Globe2 aria-hidden="true" /><strong>{endpoint.address}</strong></span>
        <span>{formatLabel(endpoint.status)}</span>
      </summary>
      <div className="tls-endpoint-content">
        <p>{endpoint.summary}</p>
        {endpoint.certificate && <CertificateSummary certificate={endpoint.certificate} />}
        <div className="tls-protocols" aria-label={`TLS protocols observed for ${endpoint.address}`}>
          {endpoint.protocols.map((protocol) => <ProtocolCard protocol={protocol} key={protocol.version} />)}
        </div>
        <dl className="tls-endpoint-details">
          <Detail label="Trust" value={endpoint.authorized === undefined ? "Unknown" : endpoint.authorized ? "Trusted" : endpoint.authorizationError ?? "Not trusted"} />
          <Detail label="Hostname" value={endpoint.hostnameValid === undefined ? "Unknown" : endpoint.hostnameValid ? "Matches" : "Mismatch"} />
          <Detail label="Negotiated" value={endpoint.negotiatedProtocol ?? "Unknown"} />
          <Detail label="ALPN" value={endpoint.alpnProtocol || "Not observed"} />
          <Detail label="Cipher" value={formatCipher(endpoint.cipher)} />
          <Detail label="Ephemeral key" value={endpoint.ephemeralKey ?? "Not observed"} />
          <Detail label="Legacy CBC profile" value={formatLabel(endpoint.weakCipher.status)} />
          <Detail label="Certificate chain" value={`${endpoint.certificateChain.length} certificate${endpoint.certificateChain.length === 1 ? "" : "s"}`} />
        </dl>
        {endpoint.certificateChain.length > 0 && (
          <details className="tls-chain">
            <summary>Inspect the bounded certificate chain ({endpoint.certificateChain.length})</summary>
            <div className="tls-chain-list">
              {endpoint.certificateChain.map((certificate, index) => (
                <article key={`${certificate.fingerprint256 ?? certificate.serialNumber ?? certificate.subject}-${index}`}>
                  <span>{index === 0 ? "Leaf certificate" : `Chain certificate ${index + 1}`}</span>
                  <strong>{certificate.subject || "Subject not reported"}</strong>
                  <dl>
                    <div><dt>Issuer</dt><dd>{certificate.issuer || "Not reported"}</dd></div>
                    <div><dt>Validity</dt><dd>{formatCertificateValidity(certificate)}</dd></div>
                    <div><dt>Key</dt><dd>{certificate.bits === undefined ? "Not reported" : `${certificate.bits} bits`}</dd></div>
                    <div><dt>Signature</dt><dd>{certificate.signatureAlgorithm ?? "Not reported"}</dd></div>
                    <div><dt>Serial</dt><dd><code>{certificate.serialNumber ?? "Not reported"}</code></dd></div>
                    <div><dt>SHA-256</dt><dd><code>{certificate.fingerprint256 ?? "Not reported"}</code></dd></div>
                  </dl>
                </article>
              ))}
            </div>
          </details>
        )}
        {endpoint.weakCipher.note && <p className="tls-endpoint-note">{endpoint.weakCipher.note}</p>}
      </div>
    </details>
  );
}

function CertificateSummary({ certificate }: { certificate: TlsCertificateSummary }) {
  return (
    <div className="tls-certificate">
      <div><span>Subject</span><strong>{certificate.subject || "Not reported"}</strong></div>
      <div><span>Issuer</span><strong>{certificate.issuer || "Not reported"}</strong></div>
      <div><span>Valid from</span><strong>{certificate.validFrom ? new Date(certificate.validFrom).toLocaleDateString() : "Not reported"}</strong></div>
      <div><span>Valid until</span><strong>{certificate.validTo ? new Date(certificate.validTo).toLocaleDateString() : "Not reported"}</strong></div>
      <div><span>Remaining</span><strong>{certificate.daysRemaining === undefined ? "Unknown" : `${certificate.daysRemaining} days`}</strong></div>
      <div><span>Public key</span><strong>{certificate.bits === undefined ? "Not reported" : `${certificate.bits} bits`}</strong></div>
      <div><span>Signature</span><strong>{certificate.signatureAlgorithm ?? "Not reported"}</strong></div>
      <div><span>Serial number</span><code>{certificate.serialNumber ?? "Not reported"}</code></div>
      <div className="tls-certificate-wide"><span>Subject alternative names</span><strong>{certificate.subjectAltNames.join(", ") || "Not reported"}</strong></div>
      {certificate.fingerprint256 && <div className="tls-certificate-wide"><span>SHA-256 fingerprint</span><code>{certificate.fingerprint256}</code></div>}
    </div>
  );
}

function ProtocolCard({ protocol }: { protocol: TlsProtocolObservation }) {
  const legacy = protocol.version === "TLSv1" || protocol.version === "TLSv1.1";
  const tone = protocol.status === "unknown"
    ? "unknown"
    : legacy
      ? protocol.status === "supported" ? "warning" : "positive"
      : protocol.status === "supported" ? "positive" : "neutral";
  return (
    <div className={`tls-protocol tls-protocol-${tone}`}>
      <span>{protocol.version}</span>
      <strong>{formatLabel(protocol.status)}</strong>
      <small>{protocol.cipher ? formatCipher(protocol.cipher) : protocol.note ?? "No cipher evidence"}</small>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function countStatuses(checks: readonly WebSecurityCheck[]): Record<WebSecurityCheckStatus, number> {
  return checks.reduce<Record<WebSecurityCheckStatus, number>>((counts, check) => {
    counts[check.status] += 1;
    return counts;
  }, { pass: 0, warning: 0, fail: 0, "not-applicable": 0, unknown: 0 });
}

function formatLabel(value: string): string {
  return value.replaceAll("-", " ").replace(/\b\w/gu, (letter) => letter.toUpperCase());
}

function gradeClass(grade: TlsAssessment["grade"] | WebSecurityScanResult["grade"]): string {
  return grade === "N/A" ? "na" : grade.toLowerCase();
}

function formatDuration(durationMs: number): string {
  return durationMs < 1_000 ? `${Math.round(durationMs)}ms` : `${(durationMs / 1_000).toFixed(1)}s`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1_024) return `${bytes} B`;
  return `${(bytes / 1_024).toFixed(bytes % 1_024 === 0 ? 0 : 1)} KB`;
}

function formatCipher(cipher: TlsCipherObservation | undefined): string {
  if (!cipher) return "Not observed";
  return `${cipher.standardName ?? cipher.name}${cipher.bits ? ` · ${cipher.bits}-bit` : ""}`;
}

function formatCertificateValidity(certificate: TlsCertificateSummary): string {
  if (!certificate.validFrom && !certificate.validTo) return "Not reported";
  const from = certificate.validFrom ? new Date(certificate.validFrom).toLocaleDateString() : "Unknown";
  const to = certificate.validTo ? new Date(certificate.validTo).toLocaleDateString() : "Unknown";
  return `${from} to ${to}`;
}

function quotaText(quota: WebScanQuota | null, blocked: boolean, now: number): string {
  if (!quota) return "Limit: 5 web-security scans per public IP address in each rolling hour.";
  const reset = new Date(quota.resetAt);
  if (blocked) {
    const minutes = Math.max(1, Math.ceil((reset.getTime() - now) / 60_000));
    return `0 of 5 scans remaining. The next scan becomes available in about ${minutes} minute${minutes === 1 ? "" : "s"} (${reset.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}).`;
  }
  return `${quota.remaining} of ${quota.limit} scans remaining. The next used slot expires at ${reset.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}.`;
}

function rateLimitMessage(quota: WebScanQuota | null): string | null {
  if (!quota) return null;
  return `The hourly scan limit has been reached for this network. Try again after ${new Date(quota.resetAt).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}.`;
}

function quotaFromHeaders(headers: Headers): WebScanQuota | null {
  const limit = Number(headers.get("RateLimit-Limit"));
  const remaining = Number(headers.get("RateLimit-Remaining"));
  const rawReset = headers.get("RateLimit-Reset");
  if (limit !== 5 || !Number.isInteger(remaining) || remaining < 0 || remaining > 5 || !rawReset) return null;
  try {
    const resetNumber = Number(rawReset);
    const resetAt = Number.isFinite(resetNumber)
      ? new Date(resetNumber > 10_000_000_000 ? resetNumber : resetNumber * 1_000).toISOString()
      : new Date(rawReset).toISOString();
    return isQuota({ limit, remaining, resetAt, windowSeconds: 3600 })
      ? { limit: 5, remaining, resetAt, windowSeconds: 3600 }
      : null;
  } catch {
    return null;
  }
}

export function isWebSecurityScanResult(
  value: unknown,
  expectedHostname?: string,
): value is WebSecurityScanResult {
  if (!isObject(value)) return false;
  const hostname = canonicalizePublicHostname(value.hostname);
  const expected = expectedHostname === undefined ? undefined : canonicalizePublicHostname(expectedHostname);
  const checks = value.checks;
  const coverage = value.coverage;
  const requestBudget = value.requestBudget;
  if (
    hostname === null
    || value.hostname !== hostname
    || (expectedHostname !== undefined && (expected === null || hostname !== expected))
    || !isSafeHttpsUrl(value.effectiveUrl, hostname)
    || !isIsoDate(value.scannedAt)
    || !isFiniteNumber(value.durationMs, 0, 300_000)
    || !isInteger(value.score, 0, 100)
    || typeof value.grade !== "string"
    || !GRADE_SET.has(value.grade)
    || !isText(value.headline, 1_024)
    || !isText(value.summary, 8_192)
    || !isTlsAssessment(value.tls, hostname)
    || !Array.isArray(checks)
    || checks.length !== WEB_SECURITY_CHECK_IDS.length
    || !checks.every(isWebSecurityCheck)
    || new Set(checks.map((check) => check.id)).size !== WEB_SECURITY_CHECK_IDS.length
    || !WEB_SECURITY_CHECK_IDS.every((id) => checks.some((check) => check.id === id))
    || !isObject(coverage)
    || coverage.total !== 20
    || !isInteger(coverage.evaluated, 0, 20)
    || !isInteger(coverage.unknown, 0, 20)
    || !isInteger(coverage.notApplicable, 0, 20)
    || coverage.unknown !== checks.filter((check) => check.status === "unknown").length
    || coverage.notApplicable !== checks.filter((check) => check.status === "not-applicable").length
    || coverage.evaluated !== 20 - coverage.unknown - coverage.notApplicable
    || !isQuota(value.quota)
    || !isObject(requestBudget)
    || !isInteger(requestBudget.httpRequests, 0, 6)
    || !isInteger(requestBudget.tlsConnections, 0, 12)
    || requestBudget.maxResponseBytes !== 131_072
    || !isInteger(requestBudget.redirectHopsFollowed, 0, 2)
    || value.disclaimer !== WEB_SECURITY_DISCLAIMER
  ) return false;
  return true;
}

export function isWebSecurityScanError(value: unknown): value is WebSecurityScanError {
  if (!isObject(value)) return false;
  return isText(value.error, 8_192)
    && typeof value.code === "string"
    && WEB_SCAN_ERROR_CODE_SET.has(value.code)
    && (value.quota === undefined || isQuota(value.quota));
}

function isWebSecurityCheck(value: unknown): value is WebSecurityCheck {
  if (!isObject(value)) return false;
  return typeof value.id === "string"
    && WEB_SECURITY_CHECK_ID_SET.has(value.id)
    && typeof value.status === "string"
    && CHECK_STATUS_SET.has(value.status as WebSecurityCheckStatus)
    && isText(value.title, 512)
    && isText(value.summary, 8_192)
    && isTextArray(value.evidence, 12, 512)
    && isText(value.remediation, 8_192)
    && isObject(value.owasp)
    && isTextArray(value.owasp.top10, 16, 256)
    && isTextArray(value.owasp.wstg, 16, 256);
}

function isTlsAssessment(value: unknown, hostname: string): value is TlsAssessment {
  if (!isObject(value)) return false;
  if (
    !Array.isArray(value.resolvedAddresses)
    || value.resolvedAddresses.length > 16
    || !value.resolvedAddresses.every(isCanonicalIpAddress)
    || new Set(value.resolvedAddresses).size !== value.resolvedAddresses.length
  ) return false;
  const resolvedAddresses = value.resolvedAddresses as string[];
  return typeof value.status === "string"
    && TLS_STATUS_SET.has(value.status)
    && typeof value.grade === "string"
    && TLS_GRADE_SET.has(value.grade)
    && isText(value.summary, 8_192)
    && Array.isArray(value.endpoints)
    && value.endpoints.length <= 2
    && value.endpoints.every((endpoint) => isTlsEndpoint(endpoint, resolvedAddresses))
    && new Set(value.endpoints.map((endpoint) => isObject(endpoint) ? endpoint.address : undefined)).size === value.endpoints.length
    && typeof value.endpointsTruncated === "boolean"
    && isSafeSslLabsUrl(value.reportUrl, hostname)
    && isTextArray(value.limitations, 16, 4_096);
}

function isTlsEndpoint(
  value: unknown,
  resolvedAddresses: readonly string[],
): value is TlsEndpointObservation {
  if (!isObject(value)) return false;
  return isCanonicalIpAddress(value.address)
    && resolvedAddresses.includes(value.address)
    && typeof value.status === "string"
    && TLS_ENDPOINT_STATUS_SET.has(value.status)
    && isText(value.summary, 4_096)
    && (value.authorized === undefined || typeof value.authorized === "boolean")
    && (value.authorizationError === undefined || isText(value.authorizationError, 512))
    && (value.hostnameValid === undefined || typeof value.hostnameValid === "boolean")
    && (value.negotiatedProtocol === undefined || isText(value.negotiatedProtocol, 64))
    && (value.cipher === undefined || isTlsCipher(value.cipher))
    && (value.alpnProtocol === undefined || isText(value.alpnProtocol, 64))
    && (value.ephemeralKey === undefined || isText(value.ephemeralKey, 256))
    && (value.certificate === undefined || isCertificate(value.certificate))
    && Array.isArray(value.certificateChain)
    && value.certificateChain.length <= 6
    && value.certificateChain.every(isCertificate)
    && Array.isArray(value.protocols)
    && value.protocols.length === TLS_PROTOCOL_VERSION_SET.size
    && value.protocols.every(isTlsProtocol)
    && new Set(value.protocols.map((protocol) => protocol.version)).size === TLS_PROTOCOL_VERSION_SET.size
    && isObject(value.weakCipher)
    && typeof value.weakCipher.status === "string"
    && WEAK_CIPHER_STATUS_SET.has(value.weakCipher.status)
    && (value.weakCipher.cipher === undefined || isTlsCipher(value.weakCipher.cipher))
    && (value.weakCipher.note === undefined || isText(value.weakCipher.note, 1_024));
}

function isTlsProtocol(value: unknown): value is TlsProtocolObservation {
  if (!isObject(value)) return false;
  return typeof value.version === "string"
    && TLS_PROTOCOL_VERSION_SET.has(value.version)
    && typeof value.status === "string"
    && TLS_PROTOCOL_STATUS_SET.has(value.status)
    && (value.cipher === undefined || isTlsCipher(value.cipher))
    && (value.note === undefined || isText(value.note, 1_024));
}

function isTlsCipher(value: unknown): value is TlsCipherObservation {
  if (!isObject(value)) return false;
  return isText(value.name, 256)
    && (value.standardName === undefined || isText(value.standardName, 256))
    && (value.version === undefined || isText(value.version, 64))
    && (value.bits === undefined || isInteger(value.bits, 0, 65_536));
}

function isCertificate(value: unknown): value is TlsCertificateSummary {
  if (!isObject(value)) return false;
  return isText(value.subject, 2_048, true)
    && isText(value.issuer, 2_048, true)
    && isTextArray(value.subjectAltNames, 64, 253)
    && (value.validFrom === undefined || isIsoDate(value.validFrom))
    && (value.validTo === undefined || isIsoDate(value.validTo))
    && (value.daysRemaining === undefined || isInteger(value.daysRemaining, -100_000, 100_000))
    && (value.serialNumber === undefined || isText(value.serialNumber, 256))
    && (value.fingerprint256 === undefined || isText(value.fingerprint256, 512))
    && (value.bits === undefined || isInteger(value.bits, 0, 65_536))
    && (value.signatureAlgorithm === undefined || isText(value.signatureAlgorithm, 256))
    && (value.ca === undefined || typeof value.ca === "boolean");
}

function isQuota(value: unknown): value is WebScanQuota {
  return isObject(value)
    && value.limit === 5
    && isInteger(value.remaining, 0, 5)
    && isIsoDate(value.resetAt)
    && value.windowSeconds === 3600;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isText(value: unknown, maxLength: number, allowEmpty = false): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) && value.length <= maxLength;
}

function isTextArray(value: unknown, maxItems: number, maxLength: number): value is string[] {
  return Array.isArray(value)
    && value.length <= maxItems
    && value.every((item) => isText(item, maxLength));
}

function isInteger(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= minimum && value <= maximum;
}

function isFiniteNumber(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= minimum && value <= maximum;
}

function isIsoDate(value: unknown): value is string {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    && !Number.isNaN(Date.parse(value));
}

function isSafeHttpsUrl(value: unknown, expectedHostname?: string): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 4_096) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:"
      && !url.username
      && !url.password
      && !url.hash
      && (!url.port || url.port === "443")
      && (expectedHostname === undefined || isAllowedResultHostname(expectedHostname, url.hostname));
  } catch {
    return false;
  }
}

function isSafeSslLabsUrl(value: unknown, expectedHostname: string): value is string {
  if (!isSafeHttpsUrl(value)) return false;
  const url = new URL(value);
  return url.hostname === "www.ssllabs.com"
    && url.pathname === "/ssltest/analyze.html"
    && url.searchParams.getAll("d").length === 1
    && url.searchParams.get("d") === expectedHostname;
}

function canonicalizePublicHostname(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 253 || /[\\/@:?#%*\s]/u.test(trimmed)) return null;
  const withoutTrailingDot = trimmed.endsWith(".") ? trimmed.slice(0, -1) : trimmed;
  try {
    const hostname = new URL(`https://${withoutTrailingDot}`).hostname.toLowerCase();
    const labels = hostname.split(".");
    if (
      hostname.length > 253
      || labels.length < 2
      || labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))
      || !/[a-z]/u.test(labels.at(-1) ?? "")
      || NON_PUBLIC_HOST_SUFFIXES.has(labels.at(-1) ?? "")
      || isCanonicalIpAddress(hostname)
    ) return null;
    return hostname;
  } catch {
    return null;
  }
}

function isAllowedResultHostname(original: string, candidate: string): boolean {
  if (candidate === original) return true;
  return original.startsWith("www.")
    ? candidate === original.slice(4)
    : candidate === `www.${original}`;
}

function isCanonicalIpAddress(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 64 || /[\s%\[\]]/u.test(value)) {
    return false;
  }
  const ipv4 = value.split(".");
  if (ipv4.length === 4) {
    return ipv4.every((part) => /^\d{1,3}$/u.test(part)
      && Number(part) <= 255
      && String(Number(part)) === part);
  }
  if (!value.includes(":")) return false;
  try {
    return new URL(`https://[${value}]/`).hostname === `[${value.toLowerCase()}]`;
  } catch {
    return false;
  }
}
