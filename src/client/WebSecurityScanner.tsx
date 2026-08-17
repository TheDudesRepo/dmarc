import {
  AlertCircle,
  AlertTriangle,
  BadgeCheck,
  Bug,
  Check,
  ChevronRight,
  CircleHelp,
  Clock3,
  ExternalLink,
  FileJson,
  FileSearch,
  Fingerprint,
  Gauge,
  Globe2,
  Info,
  Layers3,
  ListChecks,
  LoaderCircle,
  LockKeyhole,
  Printer,
  Radar,
  ServerCog,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Waypoints,
  XCircle,
} from "lucide-react";
import { FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import type {
  DeepTlsAssessmentResult,
  DeepTlsGrade,
  DeepTlsGradeValue,
  DeepTlsIssue,
  DeepTlsObservation,
  DeepTlsResponseV1,
  DeepTlsSection,
  DeepTlsSectionName,
  SecurityAssessmentApiError,
  SecurityAssessmentCreateResponse,
  SecurityAssessmentJobResource,
  SecurityAssessmentProgressPhase,
  SecurityAssessmentResult,
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
  SECURITY_ASSESSMENT_DISCLAIMER,
  SECURITY_ASSESSMENT_DISCLAIMER_VERSION,
  WEB_SECURITY_DISCLAIMER,
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

/** Covers the bounded eight-job queue plus four sequential endpoint phases with cold-start margin. */
export const SECURITY_ASSESSMENT_CLIENT_WAIT_MS = 2 * 60 * 60 * 1_000;

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
const SECURITY_JOB_STATUS_SET = new Set(["queued", "running", "complete", "cancelled", "failed"]);
const SECURITY_PROGRESS_PHASE_SET = new Set<SecurityAssessmentProgressPhase>([
  "queued",
  "web-security",
  "tls-validation",
  "tls-scanning",
  "finalizing",
  "complete",
  "cancelled",
  "failed",
]);
const SECURITY_REUSE_SET = new Set(["new", "cache-hit", "single-flight"]);
const DEEP_TLS_STATUS_SET = new Set(["complete", "partial", "unavailable"]);
const DEEP_TLS_SECTION_NAMES = [
  "certificate",
  "protocols",
  "ciphers",
  "keyExchange",
  "features",
  "clientSimulations",
  "knownIssues",
] as const satisfies readonly DeepTlsSectionName[];
const DEEP_OBSERVATION_STATUS_SET = new Set(["pass", "warning", "fail", "info", "unknown", "not-tested"]);
const DEEP_EVIDENCE_KIND_SET = new Set(["tested", "inferred", "not-testable"]);
const DEEP_SEVERITY_SET = new Set(["critical", "high", "medium", "low", "info", "none"]);
const DEEP_PHASE_ID_SET = new Set(["identity", "cryptography", "compatibility"]);
const DEEP_PHASE_STATUS_SET = new Set(["complete", "timed-out", "failed", "output-limit", "unavailable"]);
const SECURITY_JOB_ERROR_CODE_SET = new Set([
  "TARGET_CHANGED",
  "TARGET_UNAVAILABLE",
  "WEB_SCAN_FAILED",
  "TLS_SCAN_FAILED",
  "ORCHESTRATION_FAILED",
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
type ReportActionState = "idle" | "copied" | "shared" | "failed";
type ReportPriority = "critical" | "high" | "medium" | "low" | "passed" | "unknown";
type EvidenceGrade = DeepTlsGradeValue;

interface ReportIssue {
  id: string;
  priority: ReportPriority;
  title: string;
  detail: string;
  source: "TLS" | "Web";
  endpoint?: string;
}

interface SectionGrade {
  id: "certificate" | "protocols" | "key-exchange" | "ciphers";
  label: string;
  grade: EvidenceGrade;
  summary: string;
}

interface TlsInventoryItem {
  id: string;
  label: string;
  method: "tested" | "inferred" | "not-testable";
  status: "pass" | "warning" | "fail" | "unknown" | "info";
  observed: string;
  interpretation: string;
}

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
  const [result, setResult] = useState<SecurityAssessmentResult | null>(null);
  const [job, setJob] = useState<SecurityAssessmentJobResource | null>(null);
  const [reuse, setReuse] = useState<SecurityAssessmentCreateResponse["reuse"] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [quota, setQuota] = useState<WebScanQuota | null>(null);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const [shareState, setShareState] = useState<ReportActionState>("idle");
  const [filter, setFilter] = useState<CheckFilter>("all");
  const [activeEndpoint, setActiveEndpoint] = useState(0);
  const [clock, setClock] = useState(() => Date.now());
  const controllerRef = useRef<AbortController | null>(null);
  const jobIdRef = useRef<string | null>(null);
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
    jobIdRef.current = null;
    setLoading(false);
    setResult(null);
    setJob(null);
    setReuse(null);
    setError(null);
    setAuthorizedUse(false);
    setCopyState("idle");
    setShareState("idle");
    setFilter("all");
    setActiveEndpoint(0);
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
    jobIdRef.current = null;
    setHostname(value);
    setHasEditedHostname(true);
    setAuthorizedUse(false);
    setResult(null);
    setJob(null);
    setReuse(null);
    setError(null);
    setLoading(false);
    setCopyState("idle");
    setShareState("idle");
    setFilter("all");
    setActiveEndpoint(0);
  }

  async function runSecurityAssessment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = canonicalizePublicHostname(hostname.trim());
    if (!authorizedUse || rateLimited) return;
    if (!target) {
      setError("Enter one public hostname only. URLs, credentials, paths, ports, and IP addresses are not accepted.");
      return;
    }

    requestVersionRef.current += 1;
    const requestVersion = requestVersionRef.current;
    controllerRef.current?.abort();
    jobIdRef.current = null;
    const controller = new AbortController();
    controllerRef.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), SECURITY_ASSESSMENT_CLIENT_WAIT_MS);
    setLoading(true);
    setResult(null);
    setJob(null);
    setReuse(null);
    setError(null);
    setCopyState("idle");
    setShareState("idle");
    setFilter("all");
    setActiveEndpoint(0);
    setHostname(target);

    try {
      const response = await fetch("/api/security-assessments", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({
          hostname: target,
          authorizedUse: true,
          disclaimerVersion: SECURITY_ASSESSMENT_DISCLAIMER_VERSION,
        }),
        cache: "no-store",
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
        const scanError = isSecurityAssessmentApiError(payload) ? payload : null;
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
          isSecurityAssessmentApiError(payload)
            ? payload.error
            : "The combined security assessment is temporarily unavailable.",
        );
      }
      if (!isSecurityAssessmentCreateResponse(payload, target)) {
        throw new Error("The assessment API returned an invalid job response. Please try again.");
      }

      setHostname(payload.hostname);
      setJob(payload);
      setReuse(payload.reuse);
      setQuota(payload.quota);
      setClock(Date.now());
      jobIdRef.current = payload.jobId;

      let currentJob: SecurityAssessmentJobResource = payload;
      let pollAfterSeconds = Math.max(1, payload.pollAfterSeconds);
      while (currentJob.status === "queued" || currentJob.status === "running") {
        await abortableDelay(pollAfterSeconds * 1_000, controller.signal);
        const pollResponse = await fetch(
          `/api/security-assessments/${encodeURIComponent(payload.jobId)}`,
          {
            method: "GET",
            headers: { accept: "application/json" },
            cache: "no-store",
            signal: controller.signal,
          },
        );
        const pollPayload: unknown = await pollResponse.json().catch(() => null);
        if (requestVersionRef.current !== requestVersion || controllerRef.current !== controller) return;
        if (pollResponse.status === 429) {
          const retryDelay = retryAfterSeconds(pollResponse.headers);
          if (retryDelay === null) {
            throw new Error("Assessment status is temporarily rate-limited. Please try again shortly.");
          }
          pollAfterSeconds = retryDelay;
          continue;
        }
        if (!pollResponse.ok) {
          throw new Error(
            isSecurityAssessmentApiError(pollPayload)
              ? pollPayload.error
              : "The assessment job could not be retrieved. Please start a new assessment.",
          );
        }
        if (!isSecurityAssessmentJobResource(pollPayload, target, payload.jobId)) {
          throw new Error("The assessment API returned an invalid status response. Please try again.");
        }
        if (pollPayload.status === "running" && Date.now() - Date.parse(pollPayload.updatedAt) > 25 * 60_000) {
          throw new Error("The running assessment stopped reporting progress for 25 minutes. Start a new assessment to check for a reusable result.");
        }
        if (Date.now() >= Date.parse(pollPayload.expiresAt)) {
          throw new Error("The assessment job expired before a report was available. Please start a new assessment.");
        }
        currentJob = pollPayload;
        setJob(currentJob);
        pollAfterSeconds = retryAfterSeconds(pollResponse.headers) ?? Math.max(1, payload.pollAfterSeconds);
      }

      jobIdRef.current = null;
      if (currentJob.status === "failed") {
        throw new Error(currentJob.error?.message ?? "The combined assessment failed before a report was available.");
      }
      if (currentJob.status === "cancelled") {
        throw new Error("The assessment was cancelled before a report was available.");
      }
      if (currentJob.status !== "complete" || !currentJob.result) {
        throw new Error("The assessment ended without a complete report resource.");
      }

      setResult(currentJob.result);
      setActiveEndpoint(0);
      window.setTimeout(() => focusAssessmentResults(), 100);
    } catch (caught) {
      if (requestVersionRef.current !== requestVersion || controllerRef.current !== controller) return;
      setError(
        caught instanceof DOMException && caught.name === "AbortError"
          ? "The assessment stopped before completion. No unfinished test is presented as a finding; please try again."
          : caught instanceof Error
            ? caught.message
            : "The security assessment could not be completed.",
      );
    } finally {
      window.clearTimeout(timeout);
      if (requestVersionRef.current === requestVersion && controllerRef.current === controller) {
        controllerRef.current = null;
        setLoading(false);
      }
    }
  }

  function stopWaiting() {
    if (!loading) return;
    requestVersionRef.current += 1;
    controllerRef.current?.abort();
    controllerRef.current = null;
    jobIdRef.current = null;
    setLoading(false);
    setError("Stopped waiting in this browser. The bounded assessment may finish in the background and can be reused by a later request.");
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

  async function shareReport() {
    if (!result) return;
    const issues = buildAssessmentIssues(result);
    const urgent = issues.filter((issue) => issue.priority === "critical" || issue.priority === "high").length;
    const text = `${result.hostname} security snapshot: web grade ${result.web.grade}, TLS grade ${result.tls.grade.value}, ${urgent} critical/high-priority observation${urgent === 1 ? "" : "s"}.`;
    const url = `${window.location.origin}${window.location.pathname}#web-security`;
    try {
      if (typeof navigator.share === "function") {
        await navigator.share({ title: `Security report for ${result.hostname}`, text, url });
        setShareState("shared");
      } else {
        await navigator.clipboard.writeText(`${text}\n${url}`);
        setShareState("copied");
      }
      window.setTimeout(() => setShareState("idle"), 2_000);
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      setShareState("failed");
      window.setTimeout(() => setShareState("idle"), 2_600);
    }
  }

  function printReport() {
    setFilter("all");
    window.setTimeout(() => window.print(), 0);
  }

  const filteredChecks = useMemo(() => {
    if (!result) return [];
    if (filter === "attention") return result.web.checks.filter((check) => check.status === "fail" || check.status === "warning");
    if (filter === "pass") return result.web.checks.filter((check) => check.status === "pass");
    if (filter === "other") return result.web.checks.filter((check) => check.status === "unknown" || check.status === "not-applicable");
    return result.web.checks;
  }, [filter, result]);

  const statusCounts = useMemo(() => countStatuses(result?.web.checks ?? []), [result]);
  const reportIssues = useMemo(() => result ? buildAssessmentIssues(result) : [], [result]);
  const priorityCounts = useMemo(() => countReportPriorities(reportIssues), [reportIssues]);

  return (
    <section className="web-security-section" id="web-security" aria-labelledby="web-security-title">
      <div className="container">
        <div className="web-security-heading">
          <div>
            <div className="eyebrow"><span /> Web &amp; TLS · authorized active assessment</div>
            <h2 id="web-security-title">Inspect the transport edge, then go deeper.</h2>
          </div>
          <p>
            Build an endpoint-level TLS report and a separate set of 20 non-destructive, OWASP-aligned HTTP controls.
            No credentials, injection payloads, authorization tests, or business-logic probes are sent.
          </p>
        </div>

        <div className="web-security-card">
          <form className="web-security-form" onSubmit={(event) => void runSecurityAssessment(event)}>
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
                  aria-invalid={error?.startsWith("Enter one public hostname only.") ?? false}
                  aria-errormessage={error?.startsWith("Enter one public hostname only.") ? "web-security-error" : undefined}
                  disabled={loading}
                  required
                />
              </div>
              <p id="web-security-input-help">Hostname only. URLs, paths, credentials, custom ports, and IP addresses are rejected.</p>
            </div>
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
                  Do not scan systems without authorization. This assessment runs bounded HTTP observations and a deeper TLS handshake inventory.
                </small>
              </span>
            </label>
            <div className="web-security-submit-row">
              <button
                className="button button-primary web-security-submit"
                type="submit"
                disabled={loading || !hostname.trim() || !authorizedUse || rateLimited}
              >
                {loading ? <LoaderCircle className="spin" aria-hidden="true" /> : <Radar aria-hidden="true" />}
                {loading ? "Assessment running" : rateLimited ? "Hourly limit reached" : "Run combined assessment"}
              </button>
            </div>
          </form>

          <div className={`web-security-quota ${rateLimited ? "web-security-quota-blocked" : ""}`} id="web-security-quota" aria-live="polite">
            <Clock3 aria-hidden="true" />
            <span>{quotaText(quota, rateLimited, clock)}</span>
          </div>

          <div className="web-security-responsible-use" id="web-security-acceptable-use">
            <LockKeyhole aria-hidden="true" />
            <div>
              <strong>Authorized-use notice · version {SECURITY_ASSESSMENT_DISCLAIMER_VERSION}</strong>
              <p>{SECURITY_ASSESSMENT_DISCLAIMER}</p>
              <small>Shared networks share the five-scan hourly quota.</small>
            </div>
          </div>

          {loading && <ScanProgress hostname={hostname} job={job} reuse={reuse} onStop={stopWaiting} />}

          {error && (
            <div className="web-security-error" id="web-security-error" role="alert">
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
                Combined security assessment complete for {result.hostname}.
              </p>
              <ReportHeader
                result={result}
                reuse={reuse}
                copyState={copyState}
                shareState={shareState}
                onCopy={() => void copyJson()}
                onShare={() => void shareReport()}
                onPrint={printReport}
              />

              <ReportOverview
                result={result}
                statusCounts={statusCounts}
                priorityCounts={priorityCounts}
                issues={reportIssues}
              />

              <DeepTlsReport
                tls={result.tls}
                activeEndpoint={activeEndpoint}
                onEndpointChange={setActiveEndpoint}
              />

              <section className="web-checks-block" aria-labelledby="web-checks-title">
                <div className="web-checks-heading">
                  <div><FileSearch aria-hidden="true" /><span><small>Fixed assessment scope</small><h4 id="web-checks-title">20 OWASP-aligned configuration checks</h4></span></div>
                  <p>These checks cover observable transport and browser-facing controls. They are aligned to OWASP guidance, but they are not a claim that the full OWASP Top 10 was penetration-tested.</p>
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
              </section>

              <div className="web-security-budget">
                <ServerCog aria-hidden="true" />
                <div>
                  <strong>Bounded request budget</strong>
                  <span>
                    Web phase: {result.web.requestBudget.httpRequests} HTTP requests · {result.web.requestBudget.redirectHopsFollowed} redirects · {formatBytes(result.web.requestBudget.maxResponseBytes)} response cap. Deep TLS connection budgets are reported per selected endpoint above.
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

const SCAN_PHASES = [
  { id: "queued", label: "Queued", detail: "The authorization, target, and shared hourly quota were accepted." },
  { id: "web-security", label: "Web controls", detail: "Twenty bounded HTTP and browser-facing observations are collected." },
  { id: "tls-validation", label: "Endpoint safety", detail: "Fresh public addresses are validated before container access." },
  { id: "tls-scanning", label: "Deep TLS", detail: "Selected endpoints receive the fixed protocol, cipher, and compatibility profile." },
  { id: "finalizing", label: "Finalizing", detail: "Evidence, limitations, grades, and priorities are assembled." },
] as const satisfies ReadonlyArray<{ id: SecurityAssessmentProgressPhase; label: string; detail: string }>;

function ScanProgress({
  hostname,
  job,
  reuse,
  onStop,
}: {
  hostname: string;
  job: SecurityAssessmentJobResource | null;
  reuse: SecurityAssessmentCreateResponse["reuse"] | null;
  onStop: () => void;
}) {
  const currentPhase = job?.progress.phase ?? "queued";
  const phaseIndex = Math.max(0, SCAN_PHASES.findIndex((phase) => phase.id === currentPhase));
  const measuredPercent = job?.progress.percent ?? (
    job && job.progress.totalEndpoints > 0
      ? Math.round((job.progress.completedEndpoints / job.progress.totalEndpoints) * 100)
      : null
  );
  const endpointAnnouncement = job && job.progress.totalEndpoints > 0
    ? `${job.progress.completedEndpoints} of ${job.progress.totalEndpoints} selected TLS endpoints finished.`
    : "Endpoint totals are not available yet.";
  return (
    <div className="web-scan-progress" aria-busy="true">
      <p className="sr-only" role="status" aria-live="polite">{job?.progress.message ?? "Creating a bounded assessment job."} {endpointAnnouncement}</p>
      <div className="web-scan-progress-head">
        <span className="web-scan-progress-radar"><Radar aria-hidden="true" /><i /></span>
        <div>
          <small>Bounded assessment in progress</small>
          <strong>Inspecting {hostname}</strong>
          <span>{job?.progress.message ?? "Creating a bounded assessment job…"}</span>
        </div>
        <LoaderCircle className="spin" aria-hidden="true" />
      </div>
      <progress
        className="web-scan-progress-track"
        aria-label="Assessment progress"
        max={100}
        {...(measuredPercent === null ? {} : { value: measuredPercent })}
      >
        {measuredPercent ?? 0}%
      </progress>
      <ol className="web-scan-progress-steps">
        {SCAN_PHASES.map((phase, index) => {
          const state = index < phaseIndex ? "complete" : index === phaseIndex ? "current" : "queued";
          return (
            <li className={`phase-${state}`} key={phase.label}>
              <span>{state === "complete" ? <Check aria-hidden="true" /> : index + 1}</span>
              <div><strong>{phase.label}</strong><small>{phase.detail}</small></div>
            </li>
          );
        })}
      </ol>
      <div className="web-scan-progress-foot">
        <p>
          {job && job.progress.totalEndpoints > 0
            ? endpointAnnouncement
            : "Endpoint totals appear after fresh target validation. No test is marked complete from elapsed time alone."}
          {reuse === "cache-hit" ? " A valid cached report is being retrieved." : reuse === "single-flight" ? " This request joined an assessment already in progress." : ""}
        </p>
        <button type="button" onClick={onStop}>Stop waiting</button>
      </div>
    </div>
  );
}

function ReportHeader({
  result,
  reuse,
  copyState,
  shareState,
  onCopy,
  onShare,
  onPrint,
}: {
  result: SecurityAssessmentResult;
  reuse: SecurityAssessmentCreateResponse["reuse"] | null;
  copyState: "idle" | "copied" | "failed";
  shareState: ReportActionState;
  onCopy: () => void;
  onShare: () => void;
  onPrint: () => void;
}) {
  return (
    <header className="security-report-header">
      <div className="security-report-identity">
        <div className="security-report-kicker"><ShieldCheck aria-hidden="true" /> Security posture report</div>
        <h3 id="web-security-result-title">{result.hostname}</h3>
        <div className="security-report-meta">
          <a href={result.web.effectiveUrl} target="_blank" rel="noreferrer">
            {result.web.effectiveUrl} <ExternalLink aria-hidden="true" />
          </a>
          <span><Clock3 aria-hidden="true" /> {new Date(result.completedAt).toLocaleString()}</span>
          <span><Gauge aria-hidden="true" /> Completed in {formatDuration(result.durationMs)}</span>
          {reuse === "cache-hit" && <span><Clock3 aria-hidden="true" /> Reused valid cached report</span>}
          {reuse === "single-flight" && <span><Waypoints aria-hidden="true" /> Joined existing assessment</span>}
        </div>
      </div>
      <div className="security-report-actions" aria-label="Report actions">
        <button type="button" onClick={onShare}>
          {shareState === "shared" || shareState === "copied" ? <Check aria-hidden="true" /> : <Share2 aria-hidden="true" />}
          {shareState === "shared" ? "Shared" : shareState === "copied" ? "Summary copied" : shareState === "failed" ? "Share failed" : "Share summary"}
        </button>
        <button type="button" onClick={onCopy}>
          {copyState === "copied" ? <Check aria-hidden="true" /> : <FileJson aria-hidden="true" />}
          {copyState === "copied" ? "JSON copied" : copyState === "failed" ? "Copy failed" : "Copy JSON"}
        </button>
        <button type="button" onClick={onPrint}><Printer aria-hidden="true" /> Print report</button>
      </div>
    </header>
  );
}

function ReportOverview({
  result,
  statusCounts,
  priorityCounts,
  issues,
}: {
  result: SecurityAssessmentResult;
  statusCounts: Record<WebSecurityCheckStatus, number>;
  priorityCounts: Record<ReportPriority, number>;
  issues: ReportIssue[];
}) {
  const topIssues = issues.filter((issue) => issue.priority !== "passed").slice(0, 6);
  return (
    <section className="security-overview" aria-labelledby="security-overview-title">
      <div className="security-overview-heading">
        <div><small>Executive summary</small><h4 id="security-overview-title">Observable security posture</h4></div>
        <span>{result.web.coverage.evaluated} of 20 web controls evaluated</span>
      </div>
      <div className="security-scoreboard">
        <GradeDial label="Web configuration" grade={result.web.grade} score={result.web.score} detail="Weighted evaluated controls" />
        <GradeDial label="TLS posture" grade={result.tls.grade.value} score={result.tls.grade.score ?? undefined} detail={`${formatLabel(result.tls.status)} endpoint evidence`} />
        <div className="security-severity-grid" aria-label="Issue priority summary">
          <SeverityMetric label="Critical" value={priorityCounts.critical} priority="critical" />
          <SeverityMetric label="High" value={priorityCounts.high} priority="high" />
          <SeverityMetric label="Medium" value={priorityCounts.medium} priority="medium" />
          <SeverityMetric label="Low" value={priorityCounts.low} priority="low" />
          <SeverityMetric label="Passed" value={priorityCounts.passed} priority="passed" />
          <SeverityMetric label="Unknown" value={priorityCounts.unknown} priority="unknown" />
        </div>
      </div>
      <div className={`security-overview-headline grade-${gradeClass(result.web.grade)}`}>
        <ShieldAlert aria-hidden="true" />
        <div><strong>{result.web.headline}</strong><p>{result.tls.summary}</p></div>
        <dl>
          <div><dt>Passed</dt><dd>{statusCounts.pass}</dd></div>
          <div><dt>Warnings</dt><dd>{statusCounts.warning}</dd></div>
          <div><dt>Failed</dt><dd>{statusCounts.fail}</dd></div>
          <div><dt>Unknown / N/A</dt><dd>{statusCounts.unknown + statusCounts["not-applicable"]}</dd></div>
        </dl>
      </div>
      <div className="security-priority-list">
        <div className="security-priority-title"><Bug aria-hidden="true" /><span><small>Prioritized observations</small><strong>Issues to review first</strong></span></div>
        {topIssues.length > 0 ? (
          <ol>
            {topIssues.map((issue) => (
              <li key={`${issue.source}-${issue.id}-${issue.endpoint ?? "all"}`}>
                <PriorityBadge priority={issue.priority} />
                <div><strong>{issue.title}</strong><p>{issue.detail}</p><small>{issue.source}{issue.endpoint ? ` · ${issue.endpoint}` : ""}</small></div>
              </li>
            ))}
          </ol>
        ) : <p className="security-empty-state"><BadgeCheck aria-hidden="true" /> No failed or indeterminate observation was returned by this bounded scan.</p>}
      </div>
    </section>
  );
}

function GradeDial({ label, grade, score, detail }: { label: string; grade: EvidenceGrade; score?: number; detail: string }) {
  return (
    <div className={`security-grade-dial grade-${gradeClass(grade)}`}>
      <div><span>{grade}</span></div>
      <strong>{label}</strong>
      <small>{score === undefined ? detail : `${score}/100 · ${detail}`}</small>
    </div>
  );
}

function SeverityMetric({ label, value, priority }: { label: string; value: number; priority: ReportPriority }) {
  return <div className={`severity-metric severity-${priority}`}><span>{label}</span><strong>{value}</strong></div>;
}

function PriorityBadge({ priority }: { priority: ReportPriority }) {
  return <span className={`priority-badge priority-${priority}`}>{formatLabel(priority)}</span>;
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
          <div><code>{check.id}</code><h5>{check.title}</h5></div>
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

const DEEP_COMPONENT_SECTIONS = [
  { section: "certificate", label: "Certificate" },
  { section: "protocols", label: "Protocols" },
  { section: "keyExchange", label: "Key exchange" },
  { section: "ciphers", label: "Cipher suites" },
] as const satisfies ReadonlyArray<{ section: DeepTlsSectionName; label: string }>;

function DeepTlsReport({
  tls,
  activeEndpoint,
  onEndpointChange,
}: {
  tls: DeepTlsAssessmentResult;
  activeEndpoint: number;
  onEndpointChange: (index: number) => void;
}) {
  const selected = Math.min(activeEndpoint, Math.max(0, tls.endpoints.length - 1));
  const selectedEndpoint = tls.endpoints[selected];
  const testedAddresses = new Set(tls.endpoints.map((endpoint) => endpoint.target.address));
  const untestedAddresses = tls.resolvedAddresses.filter((address) => !testedAddresses.has(address));

  function selectAndFocusEndpoint(index: number) {
    onEndpointChange(index);
    document.getElementById(`deep-tls-endpoint-tab-${index}`)?.focus();
  }

  function moveEndpoint(current: number, direction: -1 | 1) {
    if (tls.endpoints.length < 2) return;
    selectAndFocusEndpoint((current + direction + tls.endpoints.length) % tls.endpoints.length);
  }

  return (
    <section className={`tls-report tls-report-${tls.status} tls-report-grade-${gradeClass(tls.grade.value)}`} aria-labelledby="tls-report-title">
      <header className="tls-report-heading">
        <div>
          <span className="tls-report-icon"><LockKeyhole aria-hidden="true" /></span>
          <span><small>Deep transport assessment</small><h4 id="tls-report-title">TLS endpoint laboratory</h4></span>
        </div>
        <GradeSummary grade={tls.grade} label="Overall TLS" />
      </header>

      <div className="tls-scope-warning">
        <Info aria-hidden="true" />
        <div>
          <strong>Measurement boundary is part of the result</strong>
          <p>{tls.summary} The safe profile uses non-destructive negotiations and fixed cryptographic-flaw probes; a complete result is not proof of application security or compliance.</p>
          {tls.limitations.length > 0 && <ul>{tls.limitations.map((limitation, index) => <li key={`tls-limit-${index}`}>{limitation}</li>)}</ul>}
        </div>
      </div>

      <div className="tls-engine-attribution">
        <ServerCog aria-hidden="true" />
        <span>
          Evidence engine: <a href="https://github.com/testssl/testssl.sh" target="_blank" rel="noreferrer">testssl.sh 3.2.4 <ExternalLink aria-hidden="true" /></a>
          {" "}· GPL-2.0-only · fixed Cresswell safe-v1 profile
        </span>
      </div>

      <AggregateTlsGrades tls={tls} />

      {tls.grade.caps.length > 0 && (
        <div className="tls-grade-caps" role="note" aria-label="TLS grade caps applied">
          <ShieldAlert aria-hidden="true" />
          <div>
            <strong>Grade caps applied</strong>
            <ul>{tls.grade.caps.map((cap) => <li key={cap.id}><span>Maximum {cap.maxGrade}</span>{cap.reason}</li>)}</ul>
          </div>
        </div>
      )}

      {tls.status !== "complete" && (
        <div className={`tls-evidence-state tls-evidence-${tls.status}`}>
          {tls.status === "partial" ? <AlertTriangle aria-hidden="true" /> : <CircleHelp aria-hidden="true" />}
          <span>{tls.status === "partial" ? "Some selected endpoints or fixed test phases were incomplete. Unknown evidence is not graded as a failure." : "Deep TLS evidence was unavailable. No TLS vulnerability is inferred from this state."}</span>
        </div>
      )}

      <div className="tls-endpoint-summary-block">
        <div className="report-subheading"><Waypoints aria-hidden="true" /><span><small>Endpoint coverage</small><h5>Resolved and selected destinations</h5></span></div>
        <div className="tls-endpoint-summary-table deep-endpoint-summary" role="table" aria-label="Deep TLS endpoint summary" tabIndex={0}>
          <div role="row" className="table-head"><span role="columnheader">Endpoint</span><span role="columnheader">State</span><span role="columnheader">TLS grade</span><span role="columnheader">Issues</span><span role="columnheader">Action</span></div>
          {tls.endpoints.map((endpoint, index) => (
            <div role="row" key={`${endpoint.target.address}-summary`}>
              <span role="cell"><strong>{endpoint.target.address}</strong><small>IPv{endpoint.target.addressFamily} · port {endpoint.target.port}</small></span>
              <span role="cell"><DeepStatusPill status={endpoint.status} /></span>
              <span role="cell"><strong>{endpoint.grade.value}</strong><small>{formatGradeScore(endpoint.grade)}</small></span>
              <span role="cell"><strong>{endpoint.issues.length}</strong><small>{summarizeIssueSeverities(endpoint.issues)}</small></span>
              <span role="cell"><button type="button" onClick={() => onEndpointChange(index)} aria-pressed={selected === index}>Inspect <ChevronRight aria-hidden="true" /></button></span>
            </div>
          ))}
          {untestedAddresses.map((address) => (
            <div role="row" key={`${address}-not-selected`} className="deep-endpoint-not-selected">
              <span role="cell"><strong>{address}</strong><small>IPv{address.includes(":") ? 6 : 4} · port 443</small></span>
              <span role="cell"><DeepStatusPill status="not-tested" /></span>
              <span role="cell"><strong>N/A</strong><small>Not graded</small></span>
              <span role="cell"><strong>—</strong><small>No active evidence</small></span>
              <span role="cell"><small>Outside the capped, family-balanced endpoint selection.</small></span>
            </div>
          ))}
          {tls.resolvedAddresses.length === 0 && <div className="table-empty">No deep endpoint report was returned.</div>}
        </div>
        <p className="tls-resolution-note">
          {tls.resolvedAddresses.length} public address{tls.resolvedAddresses.length === 1 ? "" : "es"} resolved · {tls.endpoints.length} selected for deep testing
          {tls.endpointsTruncated ? " · endpoint selection was capped" : ""}
          {untestedAddresses.length > 0 ? ` · ${untestedAddresses.length} resolved address${untestedAddresses.length === 1 ? " was" : "es were"} not tested` : ""}
        </p>
      </div>

      {tls.endpoints.length > 0 && (
        <>
          <div className="tls-endpoint-tabs" role="tablist" aria-label="Deep TLS endpoints">
            {tls.endpoints.map((endpoint, index) => (
              <button
                key={endpoint.target.address}
                id={`deep-tls-endpoint-tab-${index}`}
                type="button"
                role="tab"
                aria-controls={`deep-tls-endpoint-panel-${index}`}
                aria-selected={selected === index}
                tabIndex={selected === index ? 0 : -1}
                className={selected === index ? "active" : ""}
                onClick={() => onEndpointChange(index)}
                onKeyDown={(event) => {
                  if (event.key === "ArrowRight" || event.key === "ArrowDown") {
                    event.preventDefault();
                    moveEndpoint(index, 1);
                  } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
                    event.preventDefault();
                    moveEndpoint(index, -1);
                  } else if (event.key === "Home") {
                    event.preventDefault();
                    selectAndFocusEndpoint(0);
                  } else if (event.key === "End") {
                    event.preventDefault();
                    selectAndFocusEndpoint(tls.endpoints.length - 1);
                  }
                }}
              >
                IPv{endpoint.target.addressFamily} <strong>{endpoint.target.address}</strong><span>{endpoint.grade.value}</span>
              </button>
            ))}
          </div>
          <div className="tls-endpoint-panels">
            {tls.endpoints.map((endpoint, index) => (
              <div
                key={endpoint.target.address}
                id={`deep-tls-endpoint-panel-${index}`}
                role="tabpanel"
                aria-labelledby={`deep-tls-endpoint-tab-${index}`}
                hidden={selected !== index}
                className="tls-endpoint-panel"
              >
                <DeepTlsEndpointReport endpoint={endpoint} />
              </div>
            ))}
          </div>
        </>
      )}

      {!selectedEndpoint && (
        <div className="tls-no-endpoints"><CircleHelp aria-hidden="true" /><div><strong>No endpoint detail was available</strong><p>The scanner did not receive enough safe, public target evidence to start a deep endpoint scan.</p></div></div>
      )}
    </section>
  );
}

function GradeSummary({ grade, label }: { grade: DeepTlsGrade; label: string }) {
  return (
    <span className={`deep-grade-summary grade-${gradeClass(grade.value)}`}>
      <strong>{grade.value}</strong><span>{label}</span><small>{formatGradeScore(grade)}</small>
    </span>
  );
}

function AggregateTlsGrades({ tls }: { tls: DeepTlsAssessmentResult }) {
  return (
    <div className="deep-component-grades" aria-label="TLS component grades">
      {DEEP_COMPONENT_SECTIONS.map(({ section, label }) => {
        const grade = aggregateSectionGrade(tls.endpoints, section);
        return (
          <div className={`grade-${gradeClass(grade.value)}`} key={section}>
            <span>{grade.value}</span>
            <div><strong>{label}</strong><small>{formatGradeScore(grade)} · {formatLabel(aggregateSectionStatus(tls.endpoints, section))}</small></div>
          </div>
        );
      })}
    </div>
  );
}

function DeepTlsEndpointReport({ endpoint }: { endpoint: DeepTlsResponseV1 }) {
  return (
    <article className={`tls-endpoint-report tls-endpoint-${endpoint.status}`}>
      <header>
        <div><Globe2 aria-hidden="true" /><span><small>Selected endpoint</small><h5>{endpoint.target.address}</h5></span></div>
        <p>
          {endpoint.target.hostname} · SNI {endpoint.target.sni} · {formatDuration(endpoint.durationMs)} ·{" "}
          <a href={endpoint.scanner.sourceUrl} target="_blank" rel="noreferrer">
            {endpoint.scanner.engine} {endpoint.scanner.version} <ExternalLink aria-hidden="true" />
          </a>{" "}· {endpoint.scanner.license}
        </p>
      </header>

      <div className="tls-section-grades" aria-label={`TLS component grades for ${endpoint.target.address}`}>
        {DEEP_COMPONENT_SECTIONS.map(({ section, label }) => (
          <div className={`grade-${gradeClass(endpoint.sections[section].grade.value)}`} key={section}>
            <span>{endpoint.sections[section].grade.value}</span>
            <div><strong>{label}</strong><small>{formatGradeScore(endpoint.sections[section].grade)} · {formatLabel(endpoint.sections[section].status)}</small></div>
          </div>
        ))}
      </div>

      <div className="tls-endpoint-facts">
        <div><span>Engine</span><strong>{endpoint.scanner.engine} {endpoint.scanner.version}</strong><small>{endpoint.scanner.profileRevision}</small></div>
        <div><span>Connection budget</span><strong>{endpoint.budget.connectionsOpened} / {endpoint.budget.maxConnections}</strong><small>Max {endpoint.budget.maxConcurrentConnections} concurrent</small></div>
        <div><span>Phase runners</span><strong>{endpoint.budget.processesCompleted} / {endpoint.budget.processesStarted}</strong><small>{endpoint.budget.maxProcesses} fixed parents · 48 UID-wide process ceiling</small></div>
        <div><span>Coverage</span><strong>{endpoint.grade.coverage.evaluatedWeight} / {endpoint.grade.coverage.totalWeight}</strong><small>Weighted evidence</small></div>
        <div><span>Schema</span><strong>{endpoint.schemaVersion}</strong><small>{endpoint.grade.methodology}</small></div>
      </div>

      <DeepRemediation issues={endpoint.issues} sections={endpoint.sections} />
      <DeepCertificateEvidence section={endpoint.sections.certificate} />
      <DeepObservationMatrix section={endpoint.sections.protocols} title="Protocol support matrix" eyebrow="Version negotiation" icon={<Layers3 aria-hidden="true" />} />
      <DeepObservationMatrix section={endpoint.sections.ciphers} title="Cipher-suite matrix" eyebrow="Negotiated cryptography" icon={<ListChecks aria-hidden="true" />} />
      <DeepObservationMatrix section={endpoint.sections.keyExchange} title="Named groups and signature algorithms" eyebrow="Key exchange" icon={<Waypoints aria-hidden="true" />} />
      <DeepObservationMatrix section={endpoint.sections.features} title="Protocol details and features" eyebrow="ALPN, SNI, OCSP, sessions, tickets, FS, AEAD and CBC" icon={<Fingerprint aria-hidden="true" />} />
      <DeepObservationMatrix section={endpoint.sections.clientSimulations} title="Client compatibility" eyebrow="Fixed client simulations" icon={<Gauge aria-hidden="true" />} />
      <DeepObservationMatrix section={endpoint.sections.knownIssues} title="Known-vulnerability inventory" eyebrow="Safe cryptographic-flaw probes" icon={<Bug aria-hidden="true" />} inventory />

      <section className="deep-scan-phases" aria-label="Scanner phase completion">
        <div className="report-subheading"><ServerCog aria-hidden="true" /><span><small>Execution evidence</small><h6>Bounded scanner phases</h6></span></div>
        <div>{endpoint.phases.map((phase) => <span key={phase.id}><DeepStatusPill status={phase.status} /><strong>{formatLabel(phase.id)}</strong><small>{formatDuration(phase.durationMs)} · {formatBytes(phase.outputBytes)}</small></span>)}</div>
      </section>

      <div className="deep-endpoint-limitations">
        <CircleHelp aria-hidden="true" />
        <div><strong>Endpoint limitations</strong>{endpoint.limitations.length > 0 ? <ul>{endpoint.limitations.map((limitation, index) => <li key={`endpoint-limit-${index}`}>{limitation}</li>)}</ul> : <p>No endpoint-specific limitation was reported beyond the global assessment boundary.</p>}</div>
      </div>
    </article>
  );
}

function DeepRemediation({
  issues,
  sections,
}: {
  issues: DeepTlsIssue[];
  sections: Record<DeepTlsSectionName, DeepTlsSection>;
}) {
  const sorted = [...issues].sort((left, right) => priorityRank(deepSeverityPriority(left.severity)) - priorityRank(deepSeverityPriority(right.severity)));
  return (
    <section className="deep-remediation" aria-label="Prioritized TLS remediation">
      <div className="report-subheading"><ShieldAlert aria-hidden="true" /><span><small>Prioritized remediation</small><h6>Address measured risk first</h6></span></div>
      {sorted.length > 0 ? <ol>{sorted.map((issue) => {
        const observation = sections[issue.section].observations.find((item) => item.id === issue.observationId);
        return (
          <li key={`${issue.section}-${issue.id}`}>
            <PriorityBadge priority={deepSeverityPriority(issue.severity)} />
            <div><strong>{issue.summary}</strong><p>{observation?.summary}</p><small>{formatLabel(issue.section)} · {formatLabel(issue.evidenceKind)}</small></div>
            <span>{sectionRemediation(issue.section)}</span>
          </li>
        );
      })}</ol> : <p className="security-empty-state"><BadgeCheck aria-hidden="true" /> No critical-through-low TLS issue was emitted by the completed evidence.</p>}
    </section>
  );
}

function DeepCertificateEvidence({ section }: { section: DeepTlsSection }) {
  return (
    <section className="tls-certificate-section deep-certificate-section" aria-label="Certificate evidence">
      <div className="report-subheading"><Fingerprint aria-hidden="true" /><span><small>Identity, trust, chain presentation and validity</small><h6>Certificate evidence</h6></span></div>
      {section.observations.length > 0 ? (
        <div className="deep-certificate-evidence">
          {section.observations.map((observation) => (
            <div key={observation.id}>
              <DeepObservationCard observation={observation} />
            </div>
          ))}
        </div>
      ) : <DeepSectionEmpty section={section} />}
    </section>
  );
}

function DeepObservationMatrix({
  section,
  title,
  eyebrow,
  icon,
  inventory = false,
}: {
  section: DeepTlsSection;
  title: string;
  eyebrow: string;
  icon: ReactNode;
  inventory?: boolean;
}) {
  return (
    <section className={`tls-matrix-section deep-observation-section ${inventory ? "deep-known-issues" : ""}`} aria-label={title}>
      <div className="report-subheading">{icon}<span><small>{eyebrow}</small><h6>{title}</h6></span><GradeSummary grade={section.grade} label={formatLabel(section.status)} /></div>
      {inventory && <p className="tls-test-inventory-note">Every row identifies whether it was directly tested, inferred from bounded evidence, or not testable in the safe profile. “Not tested” is not a pass.</p>}
      {section.observations.length > 0 ? (
        <div className="tls-data-table deep-observation-table" role="table" aria-label={`${title} evidence`} tabIndex={0}>
          <div role="row" className="table-head"><span role="columnheader">Test</span><span role="columnheader">Result</span><span role="columnheader">Measurement</span><span role="columnheader">Evidence details</span></div>
          {section.observations.map((observation) => (
            <div role="row" key={observation.id}>
              <span role="cell"><strong>{observationLabel(observation)}</strong><small>{observation.sourceId ?? observation.id}</small></span>
              <span role="cell"><DeepStatusPill status={observation.status} /><small>{formatLabel(observation.severity)}</small></span>
              <span role="cell"><EvidenceBadge kind={observation.evidenceKind} /><small>{observation.summary}</small></span>
              <span role="cell"><ObservationDetails details={observation.details} /></span>
            </div>
          ))}
        </div>
      ) : <DeepSectionEmpty section={section} />}
    </section>
  );
}

function DeepObservationCard({ observation }: { observation: DeepTlsObservation }) {
  return (
    <article className={`deep-observation-card observation-${observation.status}`}>
      <div><span><DeepStatusPill status={observation.status} /><EvidenceBadge kind={observation.evidenceKind} /></span><strong>{observationLabel(observation)}</strong><small>{observation.summary}</small></div>
      <ObservationDetails details={observation.details} />
    </article>
  );
}

function DeepSectionEmpty({ section }: { section: DeepTlsSection }) {
  return <div className="tls-evidence-empty"><CircleHelp aria-hidden="true" /><span>No normalized observation rows were returned for this {formatLabel(section.status)} section. This absence is not treated as a pass.</span></div>;
}

function EvidenceBadge({ kind }: { kind: DeepTlsObservation["evidenceKind"] }) {
  return <span className={`inventory-method method-${kind}`}>{formatLabel(kind)}</span>;
}

function ObservationDetails({ details }: { details?: DeepTlsObservation["details"] }) {
  if (!details || Object.keys(details).length === 0) return <span className="deep-no-details">No additional normalized detail</span>;
  return (
    <dl className="deep-observation-details">
      {Object.entries(details).map(([key, value]) => (
        <div key={key}><dt>{formatObservationKey(key)}</dt><dd>{formatObservationValue(value)}</dd></div>
      ))}
    </dl>
  );
}

function DeepStatusPill({ status }: { status: string }) {
  return <span className={`status-pill status-${status}`}>{formatLabel(status)}</span>;
}

export function TlsReport({
  tls,
  activeEndpoint,
  onEndpointChange,
}: {
  tls: TlsAssessment;
  activeEndpoint: number;
  onEndpointChange: (index: number) => void;
}) {
  const selected = Math.min(activeEndpoint, Math.max(0, tls.endpoints.length - 1));
  return (
    <section className={`tls-report tls-report-${tls.status} tls-report-grade-${gradeClass(tls.grade)}`} aria-labelledby="tls-report-title">
      <header className="tls-report-heading">
        <div>
          <span className="tls-report-icon"><LockKeyhole aria-hidden="true" /></span>
          <div><small>Transport security laboratory</small><h4 id="tls-report-title">TLS endpoint analysis</h4><p>{tls.summary}</p></div>
        </div>
        <GradeDial label="Overall TLS" grade={tls.grade} detail={`${formatLabel(tls.status)} evidence`} />
      </header>

      <div className="tls-scope-warning">
        <Info aria-hidden="true" />
        <div>
          <strong>Read this assessment boundary before acting</strong>
          <ul>{tls.limitations.map((limitation, index) => <li key={`tls-limitation-${index}`}>{limitation}</li>)}</ul>
          <a href={tls.reportUrl} target="_blank" rel="noreferrer">Compare with a separate SSL Labs assessment <ExternalLink aria-hidden="true" /></a>
        </div>
      </div>

      {tls.status !== "complete" && (
        <div className={`tls-evidence-state tls-evidence-${tls.status}`}>
          {tls.status === "partial" ? <AlertTriangle aria-hidden="true" /> : <CircleHelp aria-hidden="true" />}
          <span>{tls.status === "partial"
            ? "Some endpoint evidence is indeterminate. Unknown probes are never converted into failures."
            : "Raw TLS evidence was unavailable from this scanner network. HTTPS configuration checks may still have completed."}</span>
        </div>
      )}

      <EndpointSummaryTable tls={tls} activeEndpoint={selected} onEndpointChange={onEndpointChange} />

      {tls.endpoints.length > 0 ? (
        <>
          <div className="tls-endpoint-tabs" role="tablist" aria-label="TLS endpoints">
            {tls.endpoints.map((endpoint, index) => (
              <button
                type="button"
                role="tab"
                id={`tls-endpoint-tab-${index}`}
                aria-controls={`tls-endpoint-panel-${index}`}
                aria-selected={selected === index}
                tabIndex={selected === index ? 0 : -1}
                className={selected === index ? "active" : ""}
                onClick={() => onEndpointChange(index)}
                key={`${endpoint.address}-${index}`}
              >
                <span>{endpoint.address.includes(":") ? "IPv6" : "IPv4"}</span>
                <strong>{endpoint.address}</strong>
                <small>{formatLabel(endpoint.status)}</small>
              </button>
            ))}
          </div>
          <div className="tls-endpoint-panels">
            {tls.endpoints.map((endpoint, index) => (
              <div
                role="tabpanel"
                id={`tls-endpoint-panel-${index}`}
                aria-labelledby={`tls-endpoint-tab-${index}`}
                hidden={selected !== index}
                className="tls-endpoint-panel"
                key={`${endpoint.address}-panel-${index}`}
              >
                <TlsEndpointReport endpoint={endpoint} />
              </div>
            ))}
          </div>
        </>
      ) : (
        <div className="tls-no-endpoints"><CircleHelp aria-hidden="true" /><div><strong>No endpoint detail was available</strong><p>The scanner did not receive enough raw TLS evidence to build endpoint matrices.</p></div></div>
      )}
    </section>
  );
}

function EndpointSummaryTable({
  tls,
  activeEndpoint,
  onEndpointChange,
}: {
  tls: TlsAssessment;
  activeEndpoint: number;
  onEndpointChange: (index: number) => void;
}) {
  return (
    <div className="tls-endpoint-summary-block">
      <div className="report-subheading"><Waypoints aria-hidden="true" /><span><small>Endpoint coverage</small><strong>Resolved and tested destinations</strong></span></div>
      <div className="tls-endpoint-summary-table" role="table" aria-label="TLS endpoint summary">
        <div role="row" className="table-head"><span role="columnheader">Endpoint</span><span role="columnheader">State</span><span role="columnheader">Certificate</span><span role="columnheader">Protocol</span><span role="columnheader">Action</span></div>
        {tls.endpoints.map((endpoint, index) => (
          <div role="row" key={`${endpoint.address}-summary`}>
            <span role="cell"><strong>{endpoint.address}</strong><small>{endpoint.address.includes(":") ? "IPv6" : "IPv4"}</small></span>
            <span role="cell"><StatusPill status={endpoint.status === "ready" ? "pass" : "unknown"} label={formatLabel(endpoint.status)} /></span>
            <span role="cell">{certificateState(endpoint)}</span>
            <span role="cell">{endpoint.negotiatedProtocol ?? "Not observed"}</span>
            <span role="cell"><button type="button" onClick={() => onEndpointChange(index)} aria-pressed={activeEndpoint === index}>Inspect <ChevronRight aria-hidden="true" /></button></span>
          </div>
        ))}
        {tls.endpoints.length === 0 && <div className="table-empty">No raw TLS endpoint rows were available.</div>}
      </div>
      <p className="tls-resolution-note">{tls.resolvedAddresses.length} validated address{tls.resolvedAddresses.length === 1 ? "" : "es"} resolved · {tls.endpoints.length} representative endpoint{tls.endpoints.length === 1 ? "" : "s"} displayed{tls.endpointsTruncated ? " · endpoint testing was capped" : ""}</p>
    </div>
  );
}

function TlsEndpointReport({ endpoint }: { endpoint: TlsEndpointObservation }) {
  const sectionGrades = deriveSectionGrades(endpoint);
  const inventory = buildTlsInventory(endpoint);
  const endpointIssues = buildTlsEndpointIssues(endpoint);
  return (
    <article className={`tls-endpoint-report tls-endpoint-${endpoint.status}`}>
      <header>
        <div><Globe2 aria-hidden="true" /><span><small>Selected endpoint</small><h5>{endpoint.address}</h5></span></div>
        <StatusPill status={endpoint.status === "ready" ? "pass" : "unknown"} label={formatLabel(endpoint.status)} />
        <p>{endpoint.summary}</p>
      </header>

      <div className="tls-section-grades" aria-label="TLS component grades">
        {sectionGrades.map((section) => (
          <div className={`grade-${gradeClass(section.grade)}`} key={section.id}>
            <span>{section.label}</span><strong>{section.grade}</strong><small>{section.summary}</small>
          </div>
        ))}
      </div>

      <div className="tls-endpoint-facts">
        <Detail label="Trust" value={endpoint.authorized === undefined ? "Unknown" : endpoint.authorized ? "Trusted" : endpoint.authorizationError ?? "Not trusted"} />
        <Detail label="Hostname" value={endpoint.hostnameValid === undefined ? "Unknown" : endpoint.hostnameValid ? "Matches" : "Mismatch"} />
        <Detail label="Negotiated protocol" value={endpoint.negotiatedProtocol ?? "Unknown"} />
        <Detail label="ALPN" value={endpoint.alpnProtocol || "Not observed"} />
        <Detail label="Negotiated cipher" value={formatCipher(endpoint.cipher)} />
        <Detail label="Key exchange" value={endpoint.ephemeralKey ?? "Not observed"} />
        <Detail label="Legacy CBC profile" value={formatLabel(endpoint.weakCipher.status)} />
        <Detail label="Certificate path" value={`${endpoint.certificateChain.length} certificate${endpoint.certificateChain.length === 1 ? "" : "s"}`} />
      </div>

      <EndpointIssueSummary issues={endpointIssues} />
      <CertificatePath endpoint={endpoint} />
      <ProtocolMatrix endpoint={endpoint} />
      <CipherMatrix endpoint={endpoint} />
      <TlsInventory items={inventory} />
    </article>
  );
}

function EndpointIssueSummary({ issues }: { issues: ReportIssue[] }) {
  const actionable = issues.filter((issue) => issue.priority !== "passed");
  return (
    <section className="tls-endpoint-issues" aria-label="Endpoint priorities">
      <div className="report-subheading"><ShieldAlert aria-hidden="true" /><span><small>Endpoint priorities</small><strong>What needs attention</strong></span></div>
      {actionable.length > 0 ? (
        <div className="tls-endpoint-issue-list">
          {actionable.map((issue) => (
            <div key={issue.id}><PriorityBadge priority={issue.priority} /><span><strong>{issue.title}</strong><small>{issue.detail}</small></span></div>
          ))}
        </div>
      ) : <p className="security-empty-state"><BadgeCheck aria-hidden="true" /> No endpoint-specific issue was identified by the fixed probes.</p>}
    </section>
  );
}

function CertificatePath({ endpoint }: { endpoint: TlsEndpointObservation }) {
  return (
    <section className="tls-certificate-section" aria-label="Certificate and path">
      <div className="report-subheading"><Fingerprint aria-hidden="true" /><span><small>Identity and trust</small><strong>Certificate and path</strong></span></div>
      {endpoint.certificate ? <CertificateSummary certificate={endpoint.certificate} /> : (
        <div className="tls-evidence-empty"><CircleHelp aria-hidden="true" /><span>No leaf certificate evidence was returned for this endpoint.</span></div>
      )}
      {endpoint.certificateChain.length > 0 && (
        <ol className="tls-certificate-path">
          {endpoint.certificateChain.map((certificate, index) => (
            <li key={`${certificate.fingerprint256 ?? certificate.serialNumber ?? certificate.subject}-${index}`}>
              <span className="tls-path-node">{index + 1}</span>
              <article>
                <header><span>{index === 0 ? "Leaf" : index === endpoint.certificateChain.length - 1 ? "Root / terminal" : "Intermediate"}</span><strong>{certificate.subject || "Subject not reported"}</strong></header>
                <dl>
                  <div><dt>Issuer</dt><dd>{certificate.issuer || "Not reported"}</dd></div>
                  <div><dt>Validity</dt><dd>{formatCertificateValidity(certificate)}</dd></div>
                  <div><dt>Public key</dt><dd>{certificate.bits === undefined ? "Not reported" : `${certificate.bits} bits`}</dd></div>
                  <div><dt>Signature</dt><dd>{certificate.signatureAlgorithm ?? "Not reported"}</dd></div>
                  <div><dt>Serial</dt><dd><code>{certificate.serialNumber ?? "Not reported"}</code></dd></div>
                  <div><dt>SHA-256</dt><dd><code>{certificate.fingerprint256 ?? "Not reported"}</code></dd></div>
                </dl>
              </article>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function ProtocolMatrix({ endpoint }: { endpoint: TlsEndpointObservation }) {
  return (
    <section className="tls-matrix-section" aria-label="Protocol support matrix">
      <div className="report-subheading"><Layers3 aria-hidden="true" /><span><small>Version negotiation</small><strong>Protocol support matrix</strong></span></div>
      <div className="tls-data-table tls-protocol-matrix" role="table" aria-label={`Protocol support for ${endpoint.address}`}>
        <div role="row" className="table-head"><span role="columnheader">Protocol</span><span role="columnheader">Observed</span><span role="columnheader">Cipher</span><span role="columnheader">Security interpretation</span></div>
        {endpoint.protocols.map((protocol) => {
          const legacy = protocol.version === "TLSv1" || protocol.version === "TLSv1.1";
          const status = protocol.status === "unknown" ? "unknown" : legacy
            ? protocol.status === "supported" ? "fail" : "pass"
            : protocol.status === "supported" ? "pass" : "warning";
          return (
            <div role="row" key={protocol.version}>
              <span role="cell"><strong>{protocol.version}</strong><small>{legacy ? "Legacy" : "Modern"}</small></span>
              <span role="cell"><StatusPill status={status} label={formatLabel(protocol.status)} /></span>
              <span role="cell"><code>{protocol.cipher ? formatCipher(protocol.cipher) : "—"}</code></span>
              <span role="cell">{protocolInterpretation(protocol)}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function CipherMatrix({ endpoint }: { endpoint: TlsEndpointObservation }) {
  const weakStatus = endpoint.weakCipher.status === "supported" ? "fail" : endpoint.weakCipher.status === "not-supported" ? "pass" : "unknown";
  return (
    <section className="tls-matrix-section" aria-label="Cipher and key-exchange evidence">
      <div className="report-subheading"><ListChecks aria-hidden="true" /><span><small>Negotiated cryptography</small><strong>Cipher and key-exchange evidence</strong></span></div>
      <div className="tls-cipher-summary">
        <div><span>Default negotiation</span><strong>{formatCipher(endpoint.cipher)}</strong><small>{endpoint.negotiatedProtocol ?? "Protocol unknown"}</small></div>
        <div><span>Key exchange</span><strong>{endpoint.ephemeralKey ?? "Not observed"}</strong><small>{endpoint.ephemeralKey ? "Ephemeral-key evidence returned" : "Forward secrecy could not be inferred"}</small></div>
        <div className={`cipher-${weakStatus}`}><span>Legacy RSA/CBC probe</span><strong>{formatLabel(endpoint.weakCipher.status)}</strong><small>{endpoint.weakCipher.cipher ? formatCipher(endpoint.weakCipher.cipher) : endpoint.weakCipher.note ?? "No evidence"}</small></div>
      </div>
      <div className="tls-data-table tls-cipher-matrix" role="table" aria-label={`Cipher observations for ${endpoint.address}`}>
        <div role="row" className="table-head"><span role="columnheader">Profile</span><span role="columnheader">Result</span><span role="columnheader">Cipher</span><span role="columnheader">Key exchange / note</span></div>
        {endpoint.protocols.map((protocol) => (
          <div role="row" key={`cipher-${protocol.version}`}>
            <span role="cell"><strong>{protocol.version}</strong></span>
            <span role="cell">{formatLabel(protocol.status)}</span>
            <span role="cell"><code>{protocol.cipher ? formatCipher(protocol.cipher) : "Not negotiated"}</code></span>
            <span role="cell">{protocol.note ?? (protocol.cipher ? "Fixed version profile negotiated." : "No cipher evidence returned.")}</span>
          </div>
        ))}
        <div role="row">
          <span role="cell"><strong>Legacy CBC</strong></span>
          <span role="cell"><StatusPill status={weakStatus} label={formatLabel(endpoint.weakCipher.status)} /></span>
          <span role="cell"><code>{formatCipher(endpoint.weakCipher.cipher)}</code></span>
          <span role="cell">{endpoint.weakCipher.note ?? "Fixed legacy profile observation."}</span>
        </div>
      </div>
    </section>
  );
}

function TlsInventory({ items }: { items: TlsInventoryItem[] }) {
  return (
    <section className="tls-test-inventory" aria-label="Fixed TLS test inventory">
      <div className="report-subheading"><Radar aria-hidden="true" /><span><small>Fixed test inventory</small><strong>What was tested or inferred</strong></span></div>
      <p className="tls-test-inventory-note">This inventory distinguishes direct fixed probes from bounded inferences. It is not a general vulnerability scan.</p>
      <div className="tls-test-inventory-grid">
        {items.map((item) => (
          <article className={`inventory-${item.status}`} key={item.id}>
            <div className="inventory-badges">
              <span className={`inventory-method method-${item.method}`}>{formatLabel(item.method)}</span>
              <StatusPill status={item.status} label={inventoryStatusLabel(item.status)} />
            </div>
            <h6>{item.label}</h6>
            <strong>{item.observed}</strong>
            <p>{item.interpretation}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

function StatusPill({ status, label }: { status: TlsInventoryItem["status"]; label: string }) {
  return <span className={`status-pill status-${status}`}>{label}</span>;
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

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function certificateState(endpoint: TlsEndpointObservation): string {
  if (!endpoint.certificate) return "Not observed";
  if (endpoint.hostnameValid === false) return "Hostname mismatch";
  if (endpoint.authorized === false) return "Not trusted";
  if ((endpoint.certificate.daysRemaining ?? 1) < 0) return "Expired";
  return endpoint.authorized ? "Trusted" : "Evidence returned";
}

function deriveSectionGrades(endpoint: TlsEndpointObservation): SectionGrade[] {
  if (endpoint.status !== "ready") {
    return [
      { id: "certificate", label: "Certificate", grade: "N/A", summary: "Evidence unavailable" },
      { id: "protocols", label: "Protocols", grade: "N/A", summary: "Evidence unavailable" },
      { id: "key-exchange", label: "Key exchange", grade: "N/A", summary: "Evidence unavailable" },
      { id: "ciphers", label: "Cipher profile", grade: "N/A", summary: "Evidence unavailable" },
    ];
  }

  let certificateGrade: EvidenceGrade = "A";
  let certificateSummary = "Trusted, matching leaf observed";
  if (!endpoint.certificate) {
    certificateGrade = "N/A";
    certificateSummary = "No leaf evidence";
  } else if (endpoint.authorized === false || endpoint.hostnameValid === false || (endpoint.certificate.daysRemaining ?? 1) < 0) {
    certificateGrade = "F";
    certificateSummary = "Trust, name, or validity failure";
  } else if ((endpoint.certificate.daysRemaining ?? 365) < 14) {
    certificateGrade = "D";
    certificateSummary = "Certificate expires within 14 days";
  } else if ((endpoint.certificate.daysRemaining ?? 365) < 30) {
    certificateGrade = "C";
    certificateSummary = "Certificate expires within 30 days";
  } else if ((endpoint.certificate.daysRemaining ?? 365) < 60) {
    certificateGrade = "B";
    certificateSummary = "Certificate renewal approaching";
  } else if (endpoint.authorized === undefined || endpoint.hostnameValid === undefined) {
    certificateGrade = "N/A";
    certificateSummary = "Trust or hostname evidence incomplete";
  }

  const protocol = new Map(endpoint.protocols.map((item) => [item.version, item.status]));
  let protocolGrade: EvidenceGrade = "A";
  let protocolSummary = "Modern versions accepted; legacy rejected";
  if (endpoint.protocols.every((item) => item.status === "unknown")) {
    protocolGrade = "N/A";
    protocolSummary = "Version probes unavailable";
  } else if (protocol.get("TLSv1") === "supported") {
    protocolGrade = "F";
    protocolSummary = "TLS 1.0 accepted";
  } else if (protocol.get("TLSv1.1") === "supported" || protocol.get("TLSv1.2") === "not-supported") {
    protocolGrade = "D";
    protocolSummary = protocol.get("TLSv1.1") === "supported" ? "TLS 1.1 accepted" : "TLS 1.2 not accepted";
  } else if (protocol.get("TLSv1.3") === "not-supported") {
    protocolGrade = "B";
    protocolSummary = "TLS 1.3 not accepted";
  } else if ([...protocol.values()].some((status) => status === "unknown")) {
    protocolGrade = "N/A";
    protocolSummary = "One or more version probes unknown";
  }

  const keyGrade: EvidenceGrade = endpoint.ephemeralKey ? "A" : "N/A";
  const keySummary = endpoint.ephemeralKey ? "Ephemeral key observed" : "Forward secrecy not inferred";
  const cipherGrade: EvidenceGrade = endpoint.weakCipher.status === "supported"
    ? "D"
    : endpoint.weakCipher.status === "not-supported" && endpoint.cipher
      ? "A"
      : endpoint.cipher ? "B" : "N/A";
  const cipherSummary = endpoint.weakCipher.status === "supported"
    ? "Legacy CBC profile accepted"
    : endpoint.weakCipher.status === "not-supported"
      ? "Legacy CBC profile rejected"
      : "Legacy profile evidence unknown";

  return [
    { id: "certificate", label: "Certificate", grade: certificateGrade, summary: certificateSummary },
    { id: "protocols", label: "Protocols", grade: protocolGrade, summary: protocolSummary },
    { id: "key-exchange", label: "Key exchange", grade: keyGrade, summary: keySummary },
    { id: "ciphers", label: "Cipher profile", grade: cipherGrade, summary: cipherSummary },
  ];
}

function buildTlsEndpointIssues(endpoint: TlsEndpointObservation): ReportIssue[] {
  const issues: ReportIssue[] = [];
  const add = (id: string, priority: ReportPriority, title: string, detail: string) => issues.push({ id, priority, title, detail, source: "TLS", endpoint: endpoint.address });
  if (endpoint.status !== "ready") {
    add("endpoint-evidence", "unknown", "TLS endpoint evidence unavailable", endpoint.summary);
    return issues;
  }
  add("certificate-trust", endpoint.authorized === false ? "critical" : endpoint.authorized === true ? "passed" : "unknown", endpoint.authorized === false ? "Certificate path is not trusted" : "Certificate trust", endpoint.authorized === false ? endpoint.authorizationError ?? "The runtime did not authorize the certificate path." : endpoint.authorized === true ? "The runtime authorized the observed certificate path." : "Trust evidence was not returned.");
  add("hostname-match", endpoint.hostnameValid === false ? "critical" : endpoint.hostnameValid === true ? "passed" : "unknown", endpoint.hostnameValid === false ? "Certificate hostname mismatch" : "Certificate hostname", endpoint.hostnameValid === false ? "The leaf certificate did not match the requested hostname." : endpoint.hostnameValid === true ? "The observed leaf certificate matched the requested hostname." : "Hostname-match evidence was not returned.");
  if (!endpoint.certificate) {
    add("certificate-missing", "unknown", "Leaf certificate unavailable", "Certificate dates, names, and fingerprint could not be reviewed.");
  } else {
    const days = endpoint.certificate.daysRemaining;
    add("certificate-validity", days === undefined ? "unknown" : days < 0 ? "critical" : days < 14 ? "high" : days < 30 ? "medium" : "passed", days !== undefined && days < 0 ? "Certificate expired" : "Certificate validity", days === undefined ? "The expiry interval was unavailable." : days < 0 ? `The certificate expired ${Math.abs(days)} day${Math.abs(days) === 1 ? "" : "s"} ago.` : `${days} day${days === 1 ? "" : "s"} remain before expiry.`);
  }
  for (const version of ["TLSv1", "TLSv1.1"] as const) {
    const probe = endpoint.protocols.find((item) => item.version === version);
    add(`protocol-${version}`, probe?.status === "supported" ? "high" : probe?.status === "not-supported" ? "passed" : "unknown", probe?.status === "supported" ? `${version} legacy protocol accepted` : `${version} legacy protocol`, probe?.status === "supported" ? "Disable this obsolete protocol unless an explicitly documented compatibility exception applies." : probe?.note ?? `The fixed ${version} profile was ${probe?.status === "not-supported" ? "rejected" : "not determined"}.`);
  }
  const tls12 = endpoint.protocols.find((item) => item.version === "TLSv1.2");
  const tls13 = endpoint.protocols.find((item) => item.version === "TLSv1.3");
  add("protocol-tls12", tls12?.status === "supported" ? "passed" : tls12?.status === "not-supported" ? "medium" : "unknown", "TLS 1.2 support", tls12?.note ?? `TLS 1.2 was ${tls12?.status === "supported" ? "accepted" : tls12?.status === "not-supported" ? "not accepted" : "not determined"}.`);
  add("protocol-tls13", tls13?.status === "supported" ? "passed" : tls13?.status === "not-supported" ? "low" : "unknown", "TLS 1.3 support", tls13?.note ?? `TLS 1.3 was ${tls13?.status === "supported" ? "accepted" : tls13?.status === "not-supported" ? "not accepted" : "not determined"}.`);
  add("legacy-cbc", endpoint.weakCipher.status === "supported" ? "high" : endpoint.weakCipher.status === "not-supported" ? "passed" : "unknown", endpoint.weakCipher.status === "supported" ? "Legacy RSA/CBC profile accepted" : "Legacy RSA/CBC profile", endpoint.weakCipher.note ?? "Fixed legacy cipher evidence was returned.");
  add("forward-secrecy", endpoint.ephemeralKey ? "passed" : "unknown", "Forward-secrecy evidence", endpoint.ephemeralKey ?? "No ephemeral-key evidence was returned by the default handshake.");
  return issues;
}

const HIGH_IMPACT_WEB_CHECKS = new Set<WebSecurityCheckId>([
  "https-enforcement",
  "content-security-policy",
  "frame-protection",
  "cors-policy",
  "cookie-secure",
  "cookie-httponly",
  "cookie-samesite",
  "mixed-content",
  "form-transport",
]);

function buildAssessmentIssues(result: SecurityAssessmentResult): ReportIssue[] {
  const tlsIssues = result.tls.endpoints.flatMap((endpoint) => {
    const emitted = new Map(endpoint.issues.map((issue) => [`${issue.section}:${issue.observationId}`, issue]));
    return DEEP_TLS_SECTION_NAMES.flatMap((sectionName) => (
      endpoint.sections[sectionName].observations
        .filter((observation) => (
          observation.status !== "info" || emitted.has(`${sectionName}:${observation.id}`)
        ))
        .map<ReportIssue>((observation) => {
          const issue = emitted.get(`${sectionName}:${observation.id}`);
          const priority: ReportPriority = issue
            ? deepSeverityPriority(issue.severity)
            : observation.status === "pass"
              ? "passed"
              : observation.status === "unknown" || observation.status === "not-tested"
                ? "unknown"
                : observation.status === "fail"
                  ? observation.severity === "critical" ? "critical" : "high"
                  : observation.status === "warning" ? "medium" : "low";
          return {
            id: `${sectionName}:${observation.id}`,
            priority,
            title: observationLabel(observation),
            detail: issue?.summary ?? observation.summary,
            source: "TLS",
            endpoint: endpoint.target.address,
          };
        })
    ));
  });
  const webIssues = result.web.checks.map<ReportIssue>((check) => {
    const priority: ReportPriority = check.status === "pass"
      ? "passed"
      : check.status === "unknown" || check.status === "not-applicable"
        ? "unknown"
        : check.status === "fail"
          ? HIGH_IMPACT_WEB_CHECKS.has(check.id) ? "high" : "medium"
          : HIGH_IMPACT_WEB_CHECKS.has(check.id) ? "medium" : "low";
    return { id: check.id, priority, title: check.title, detail: check.summary, source: "Web" };
  });
  return [...tlsIssues, ...webIssues].sort((left, right) => priorityRank(left.priority) - priorityRank(right.priority));
}

function deepSeverityPriority(severity: DeepTlsIssue["severity"]): ReportPriority {
  return severity;
}

function aggregateSectionGrade(endpoints: readonly DeepTlsResponseV1[], section: DeepTlsSectionName): DeepTlsGrade {
  if (endpoints.length === 0) return emptyDeepGrade();
  const measured = endpoints
    .map((endpoint) => endpoint.sections[section].grade)
    .filter((grade) => grade.value !== "N/A");
  if (measured.length === 0) return emptyDeepGrade();
  const ranked = [...measured]
    .sort((left, right) => deepGradeRank(right.value) - deepGradeRank(left.value));
  return ranked[0] ?? emptyDeepGrade();
}

function aggregateSectionStatus(endpoints: readonly DeepTlsResponseV1[], section: DeepTlsSectionName): DeepTlsSection["status"] {
  if (endpoints.length === 0 || endpoints.every((endpoint) => endpoint.sections[section].status === "unavailable")) return "unavailable";
  if (endpoints.every((endpoint) => endpoint.sections[section].status === "complete")) return "complete";
  return "partial";
}

function emptyDeepGrade(): DeepTlsGrade {
  return { value: "N/A", score: null, coverage: { evaluatedWeight: 0, totalWeight: 0 }, methodology: "cresswell-tls-v1", caps: [] };
}

function deepGradeRank(grade: DeepTlsGradeValue): number {
  return ({ A: 0, B: 1, C: 2, D: 3, F: 4, "N/A": 5 })[grade];
}

function formatGradeScore(grade: DeepTlsGrade): string {
  if (grade.score === null) return "Not graded";
  return `${grade.score}/100`;
}

function summarizeIssueSeverities(issues: readonly DeepTlsIssue[]): string {
  if (issues.length === 0) return "No graded issues";
  const counts = issues.reduce<Record<DeepTlsIssue["severity"], number>>((result, issue) => {
    result[issue.severity] += 1;
    return result;
  }, { critical: 0, high: 0, medium: 0, low: 0 });
  return (["critical", "high", "medium", "low"] as const)
    .filter((severity) => counts[severity] > 0)
    .map((severity) => `${counts[severity]} ${severity}`)
    .join(" · ");
}

function observationLabel(observation: DeepTlsObservation): string {
  return formatObservationKey(observation.sourceId ?? observation.id.split(":").at(-1) ?? observation.id);
}

function formatObservationKey(value: string): string {
  return value
    .replace(/^clientsimulation-/u, "Client: ")
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b(?:tls|ssl|ocsp|alpn|npn|cve|cwe|rsa|cbc|aead|sha)(?=\b)/giu, (part) => part.toUpperCase())
    .replace(/\b\w/gu, (letter) => letter.toUpperCase());
}

function formatObservationValue(value: string | number | boolean | string[] | null): string {
  if (value === null) return "Not reported";
  if (Array.isArray(value)) return value.length > 0 ? value.join(", ") : "None reported";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function sectionRemediation(section: DeepTlsSectionName): string {
  const copy: Record<DeepTlsSectionName, string> = {
    certificate: "Correct identity, trust, chain order, or renewal automation; then verify the full path from an external client.",
    protocols: "Disable obsolete versions and retain TLS 1.2/1.3 only after documenting required client compatibility.",
    ciphers: "Remove failed or weak suites and prefer authenticated AEAD suites with forward secrecy.",
    keyExchange: "Prefer current ECDHE groups and signature algorithms; preserve a reviewed compatibility fallback only where required.",
    features: "Review the measured feature configuration and confirm resumption, stapling, negotiation, and fallback controls intentionally match policy.",
    clientSimulations: "Map failed simulations to supported user agents before changing compatibility policy.",
    knownIssues: "Follow the measured issue and vendor guidance; retest after patching or configuration changes.",
  };
  return copy[section];
}

export function buildReportIssues(result: WebSecurityScanResult): ReportIssue[] {
  const tlsIssues = result.tls.endpoints.flatMap(buildTlsEndpointIssues);
  const webIssues = result.checks.map<ReportIssue>((check) => {
    const priority: ReportPriority = check.status === "pass"
      ? "passed"
      : check.status === "unknown" || check.status === "not-applicable"
        ? "unknown"
        : check.status === "fail"
          ? HIGH_IMPACT_WEB_CHECKS.has(check.id) ? "high" : "medium"
          : HIGH_IMPACT_WEB_CHECKS.has(check.id) ? "medium" : "low";
    return { id: check.id, priority, title: check.title, detail: check.summary, source: "Web" };
  });
  return [...tlsIssues, ...webIssues].sort((left, right) => priorityRank(left.priority) - priorityRank(right.priority));
}

function countReportPriorities(issues: readonly ReportIssue[]): Record<ReportPriority, number> {
  return issues.reduce<Record<ReportPriority, number>>((counts, issue) => {
    counts[issue.priority] += 1;
    return counts;
  }, { critical: 0, high: 0, medium: 0, low: 0, passed: 0, unknown: 0 });
}

function priorityRank(priority: ReportPriority): number {
  return ({ critical: 0, high: 1, medium: 2, low: 3, unknown: 4, passed: 5 })[priority];
}

function buildTlsInventory(endpoint: TlsEndpointObservation): TlsInventoryItem[] {
  const protocolItems: TlsInventoryItem[] = endpoint.protocols.map((protocol) => {
    const legacy = protocol.version === "TLSv1" || protocol.version === "TLSv1.1";
    const status = protocol.status === "unknown" ? "unknown" : legacy
      ? protocol.status === "supported" ? "fail" : "pass"
      : protocol.status === "supported" ? "pass" : "warning";
    return {
      id: `inventory-${protocol.version}`,
      label: `${protocol.version} negotiation`,
      method: "tested",
      status,
      observed: formatLabel(protocol.status),
      interpretation: protocolInterpretation(protocol),
    };
  });
  const weakStatus = endpoint.weakCipher.status === "supported" ? "fail" : endpoint.weakCipher.status === "not-supported" ? "pass" : "unknown";
  return [
    { id: "inventory-trust", label: "Certificate trust", method: "tested", status: endpoint.authorized === true ? "pass" : endpoint.authorized === false ? "fail" : "unknown", observed: endpoint.authorized === true ? "Trusted" : endpoint.authorizationError ?? "Unknown", interpretation: "Runtime path authorization was observed during the default handshake." },
    { id: "inventory-hostname", label: "Hostname match", method: "tested", status: endpoint.hostnameValid === true ? "pass" : endpoint.hostnameValid === false ? "fail" : "unknown", observed: endpoint.hostnameValid === true ? "Matches" : endpoint.hostnameValid === false ? "Mismatch" : "Unknown", interpretation: "The leaf identity was checked against the requested hostname." },
    ...protocolItems,
    { id: "inventory-cbc", label: "Legacy RSA/CBC profile", method: "tested", status: weakStatus, observed: formatLabel(endpoint.weakCipher.status), interpretation: endpoint.weakCipher.note ?? "One fixed legacy cipher profile was offered." },
    { id: "inventory-alpn", label: "Application protocol negotiation", method: "tested", status: endpoint.alpnProtocol ? "info" : "unknown", observed: endpoint.alpnProtocol || "Not observed", interpretation: "The default handshake offered HTTP/2 and HTTP/1.1 through ALPN." },
    { id: "inventory-sni", label: "Server Name Indication", method: "inferred", status: endpoint.status === "ready" ? "info" : "unknown", observed: endpoint.status === "ready" ? "Hostname sent" : "Unknown", interpretation: "The scanner sent SNI; whether the endpoint requires SNI was not separately tested." },
    { id: "inventory-fs", label: "Forward secrecy", method: "inferred", status: endpoint.ephemeralKey ? "pass" : "unknown", observed: endpoint.ephemeralKey ?? "Not inferred", interpretation: "This inference uses ephemeral-key information from the default handshake only." },
    { id: "inventory-ocsp", label: "OCSP stapling", method: "not-testable", status: "unknown", observed: "Not tested", interpretation: "The current bounded evidence contract does not report OCSP stapling." },
    { id: "inventory-resumption", label: "Session resumption and tickets", method: "not-testable", status: "unknown", observed: "Not tested", interpretation: "The scanner does not perform repeat handshakes for session-resumption behavior." },
    { id: "inventory-renegotiation", label: "Secure renegotiation", method: "not-testable", status: "unknown", observed: "Not tested", interpretation: "Renegotiation is outside the current fixed probe inventory." },
    { id: "inventory-compression", label: "TLS compression", method: "not-testable", status: "unknown", observed: "Not tested", interpretation: "Compression behavior is not exposed by the current bounded evidence contract." },
  ];
}

function protocolInterpretation(protocol: TlsProtocolObservation): string {
  const legacy = protocol.version === "TLSv1" || protocol.version === "TLSv1.1";
  if (protocol.status === "unknown") return protocol.note ?? "The fixed version probe was indeterminate.";
  if (legacy) return protocol.status === "supported"
    ? "Obsolete protocol support increases downgrade and compatibility risk."
    : "The obsolete fixed protocol profile was rejected.";
  if (protocol.status === "supported") return `${protocol.version} negotiated successfully with the fixed client profile.`;
  return protocol.version === "TLSv1.3"
    ? "TLS 1.3 was not negotiated; this is a modernization opportunity, not automatically a vulnerability."
    : "TLS 1.2 was not negotiated by the fixed profile; review compatibility and configuration.";
}

function inventoryStatusLabel(status: TlsInventoryItem["status"]): string {
  return ({ pass: "Pass", warning: "Review", fail: "Finding", unknown: "Unknown", info: "Observed" })[status];
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
  if (!quota) return "Limit: 5 combined security assessments per public IP address in each rolling hour.";
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
    const resetDelaySeconds = Number(rawReset);
    if (!Number.isInteger(resetDelaySeconds) || resetDelaySeconds < 0) return null;
    const resetAt = new Date(Date.now() + resetDelaySeconds * 1_000).toISOString();
    return isQuota({ limit, remaining, resetAt, windowSeconds: 3600 })
      ? { limit: 5, remaining, resetAt, windowSeconds: 3600 }
      : null;
  } catch {
    return null;
  }
}

async function abortableDelay(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) throw new DOMException("Aborted", "AbortError");
  await new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, Math.max(0, milliseconds));
    const abort = () => {
      window.clearTimeout(timer);
      reject(new DOMException("Aborted", "AbortError"));
    };
    signal.addEventListener("abort", abort, { once: true });
  });
}

function retryAfterSeconds(headers: Headers): number | null {
  const value = headers.get("Retry-After");
  if (!value) return null;
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= 1 && seconds <= 60 ? Math.ceil(seconds) : null;
}

function focusAssessmentResults() {
  const resultsElement = document.getElementById("web-security-results");
  resultsElement?.focus({ preventScroll: true });
  if (typeof resultsElement?.scrollIntoView === "function") {
    resultsElement.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

export function isSecurityAssessmentCreateResponse(
  value: unknown,
  expectedHostname?: string,
): value is SecurityAssessmentCreateResponse {
  if (!isSecurityAssessmentJobResource(value, expectedHostname, undefined, true)) return false;
  const candidate = value as unknown as Record<string, unknown>;
  if (!hasOnlyKeys(candidate, [
    "jobId", "hostname", "status", "createdAt", "updatedAt", "expiresAt", "progress", "result", "error",
    "quota", "reuse", "pollAfterSeconds", "cancelToken",
  ])) return false;
  return isQuota(candidate.quota)
    && typeof candidate.reuse === "string"
    && SECURITY_REUSE_SET.has(candidate.reuse)
    && isInteger(candidate.pollAfterSeconds, 0, 30)
    && (candidate.cancelToken === undefined || (
      candidate.reuse === "new" && isOpaqueCapability(candidate.cancelToken)
    ));
}

export function isSecurityAssessmentJobResource(
  value: unknown,
  expectedHostname?: string,
  expectedJobId?: string,
  allowCreateFields = false,
): value is SecurityAssessmentJobResource {
  if (!isObject(value) || !hasOnlyKeys(value, [
    "jobId", "hostname", "status", "createdAt", "updatedAt", "expiresAt", "progress", "result", "error",
    ...(allowCreateFields ? ["quota", "reuse", "pollAfterSeconds", "cancelToken"] : []),
  ])) return false;
  const expected = expectedHostname === undefined ? undefined : canonicalizePublicHostname(expectedHostname);
  const hostname = canonicalizePublicHostname(value.hostname);
  if (
    !isSecurityJobId(value.jobId)
    || (expectedJobId !== undefined && value.jobId !== expectedJobId)
    || hostname === null
    || value.hostname !== hostname
    || (expectedHostname !== undefined && (expected === null || expected !== hostname))
    || typeof value.status !== "string"
    || !SECURITY_JOB_STATUS_SET.has(value.status)
    || !isIsoDate(value.createdAt)
    || !isIsoDate(value.updatedAt)
    || !isIsoDate(value.expiresAt)
    || Date.parse(value.createdAt) > Date.parse(value.updatedAt)
    || Date.parse(value.updatedAt) > Date.parse(value.expiresAt)
    || !isSecurityProgress(value.progress, value.status as SecurityAssessmentJobResource["status"], value.createdAt, value.expiresAt)
  ) return false;
  if (value.status === "complete") {
    return value.error === undefined && isSecurityAssessmentResult(value.result, hostname);
  }
  if (value.status === "failed") {
    return value.result === undefined && isSecurityJobError(value.error);
  }
  return value.result === undefined && value.error === undefined;
}

export function isSecurityAssessmentApiError(value: unknown): value is SecurityAssessmentApiError {
  if (!isObject(value) || !hasOnlyKeys(value, ["error", "code", "quota"])) return false;
  const codes = new Set([...WEB_SCAN_ERROR_CODE_SET, "JOB_NOT_FOUND", "ORCHESTRATION_ERROR"]);
  return isText(value.error, 8_192)
    && typeof value.code === "string"
    && codes.has(value.code)
    && (value.quota === undefined || isQuota(value.quota));
}

export function isSecurityAssessmentResult(
  value: unknown,
  expectedHostname?: string,
): value is SecurityAssessmentResult {
  if (!isObject(value) || !hasExactKeys(value, [
    "schemaVersion", "hostname", "startedAt", "completedAt", "durationMs", "web", "tls", "disclaimer",
  ])) return false;
  const expected = expectedHostname === undefined ? undefined : canonicalizePublicHostname(expectedHostname);
  const hostname = canonicalizePublicHostname(value.hostname);
  return value.schemaVersion === "security-assessment-v1"
    && hostname !== null
    && value.hostname === hostname
    && (expectedHostname === undefined || (expected !== null && expected === hostname))
    && isIsoDate(value.startedAt)
    && isIsoDate(value.completedAt)
    && Date.parse(value.startedAt) <= Date.parse(value.completedAt)
    && isInteger(value.durationMs, 0, 86_400_000)
    && isSecurityAssessmentWebResult(value.web, hostname)
    && isDeepTlsAssessmentResult(value.tls, hostname)
    && value.disclaimer === SECURITY_ASSESSMENT_DISCLAIMER;
}

function isSecurityProgress(
  value: unknown,
  jobStatus: SecurityAssessmentJobResource["status"],
  createdAt: string,
  expiresAt: string,
): boolean {
  if (!isObject(value) || !hasOnlyKeys(value, [
    "phase", "message", "completedEndpoints", "totalEndpoints", "percent", "updatedAt",
  ])) return false;
  if (
    typeof value.phase !== "string"
    || !SECURITY_PROGRESS_PHASE_SET.has(value.phase as SecurityAssessmentProgressPhase)
    || !isText(value.message, 512)
    || !isInteger(value.completedEndpoints, 0, 4)
    || !isInteger(value.totalEndpoints, 0, 4)
    || value.completedEndpoints > value.totalEndpoints
    || (value.percent !== undefined && !isInteger(value.percent, 0, 100))
    || !isIsoDate(value.updatedAt)
    || Date.parse(value.updatedAt) < Date.parse(createdAt)
    || Date.parse(value.updatedAt) > Date.parse(expiresAt)
  ) return false;
  const phasesByStatus: Record<SecurityAssessmentJobResource["status"], readonly SecurityAssessmentProgressPhase[]> = {
    queued: ["queued"],
    running: ["web-security", "tls-validation", "tls-scanning", "finalizing"],
    complete: ["complete"],
    cancelled: ["cancelled"],
    failed: ["failed"],
  };
  return phasesByStatus[jobStatus].includes(value.phase as SecurityAssessmentProgressPhase);
}

function isSecurityJobError(value: unknown): boolean {
  return isObject(value)
    && hasExactKeys(value, ["code", "message"])
    && typeof value.code === "string"
    && SECURITY_JOB_ERROR_CODE_SET.has(value.code)
    && isText(value.message, 512);
}

function isSecurityAssessmentWebResult(value: unknown, hostname: string): boolean {
  if (!isObject(value) || !hasExactKeys(value, [
    "hostname", "effectiveUrl", "scannedAt", "durationMs", "score", "grade", "headline", "summary", "checks",
    "coverage", "requestBudget", "disclaimer",
  ])) return false;
  const checks = value.checks;
  const coverage = value.coverage;
  const requestBudget = value.requestBudget;
  return value.hostname === hostname
    && isSafeHttpsUrl(value.effectiveUrl, hostname)
    && isIsoDate(value.scannedAt)
    && isFiniteNumber(value.durationMs, 0, 300_000)
    && isInteger(value.score, 0, 100)
    && typeof value.grade === "string"
    && GRADE_SET.has(value.grade)
    && isText(value.headline, 1_024)
    && isText(value.summary, 8_192)
    && Array.isArray(checks)
    && checks.length === WEB_SECURITY_CHECK_IDS.length
    && checks.every(isWebSecurityCheck)
    && new Set(checks.map((check) => check.id)).size === WEB_SECURITY_CHECK_IDS.length
    && WEB_SECURITY_CHECK_IDS.every((id) => checks.some((check) => check.id === id))
    && isObject(coverage)
    && hasExactKeys(coverage, ["total", "evaluated", "unknown", "notApplicable"])
    && coverage.total === 20
    && isInteger(coverage.evaluated, 0, 20)
    && isInteger(coverage.unknown, 0, 20)
    && isInteger(coverage.notApplicable, 0, 20)
    && coverage.unknown === checks.filter((check) => check.status === "unknown").length
    && coverage.notApplicable === checks.filter((check) => check.status === "not-applicable").length
    && coverage.evaluated === 20 - coverage.unknown - coverage.notApplicable
    && isObject(requestBudget)
    && hasExactKeys(requestBudget, ["httpRequests", "tlsConnections", "maxResponseBytes", "redirectHopsFollowed"])
    && isInteger(requestBudget.httpRequests, 0, 6)
    && requestBudget.tlsConnections === 0
    && requestBudget.maxResponseBytes === 131_072
    && isInteger(requestBudget.redirectHopsFollowed, 0, 2)
    && value.disclaimer === WEB_SECURITY_DISCLAIMER;
}

function isDeepTlsAssessmentResult(value: unknown, hostname: string): value is DeepTlsAssessmentResult {
  if (!isObject(value) || !hasExactKeys(value, [
    "status", "grade", "summary", "resolvedAddresses", "endpoints", "endpointsTruncated", "limitations",
  ])) return false;
  if (
    typeof value.status !== "string"
    || !DEEP_TLS_STATUS_SET.has(value.status)
    || !isDeepTlsGrade(value.grade)
    || !isText(value.summary, 2_048)
    || !Array.isArray(value.resolvedAddresses)
    || value.resolvedAddresses.length > 16
    || !value.resolvedAddresses.every(isPublicDeepAddress)
    || new Set(value.resolvedAddresses).size !== value.resolvedAddresses.length
    || !Array.isArray(value.endpoints)
    || value.endpoints.length > 4
    || typeof value.endpointsTruncated !== "boolean"
    || !isTextArray(value.limitations, 64, 2_048)
  ) return false;
  const resolvedAddresses = value.resolvedAddresses as string[];
  return value.endpoints.every((endpoint) => isDeepTlsResponse(endpoint, hostname, resolvedAddresses))
    && new Set(value.endpoints.map((endpoint) => (endpoint as DeepTlsResponseV1).target.address)).size === value.endpoints.length;
}

function isDeepTlsResponse(value: unknown, hostname: string, resolvedAddresses: readonly string[]): value is DeepTlsResponseV1 {
  if (!isObject(value) || !hasExactKeys(value, [
    "schemaVersion", "scanner", "target", "status", "startedAt", "durationMs", "grade", "budget", "phases",
    "sections", "issues", "limitations",
  ])) return false;
  if (!isObject(value.scanner) || !hasExactKeys(value.scanner, ["engine", "version", "commit", "sourceUrl", "license", "profileRevision"])) return false;
  if (
    value.schemaVersion !== "tls-deep-v1"
    || value.scanner.engine !== "testssl.sh"
    || value.scanner.version !== "3.2.4"
    || value.scanner.commit !== "97763a411c525720a5f9bd9d2cded416b10f210a"
    || value.scanner.sourceUrl !== "https://github.com/testssl/testssl.sh"
    || value.scanner.license !== "GPL-2.0-only"
    || value.scanner.profileRevision !== "safe-v1"
  ) return false;
  if (!isObject(value.target) || !hasExactKeys(value.target, ["hostname", "address", "addressFamily", "port", "sni", "profile"])) return false;
  if (
    value.target.hostname !== hostname
    || !isPublicDeepAddress(value.target.address)
    || !resolvedAddresses.includes(value.target.address as string)
    || (value.target.addressFamily !== 4 && value.target.addressFamily !== 6)
    || (value.target.addressFamily === 4) !== !(value.target.address as string).includes(":")
    || value.target.port !== 443
    || value.target.sni !== hostname
    || value.target.profile !== "safe"
  ) return false;
  return typeof value.status === "string"
    && DEEP_TLS_STATUS_SET.has(value.status)
    && isIsoDate(value.startedAt)
    && isInteger(value.durationMs, 0, 210_000)
    && isDeepTlsGrade(value.grade)
    && isDeepTlsBudget(value.budget)
    && isDeepTlsPhases(value.phases)
    && isDeepTlsSections(value.sections)
    && isDeepTlsIssues(value.issues, value.sections as Record<DeepTlsSectionName, DeepTlsSection>)
    && isTextArray(value.limitations, 64, 2_048);
}

function isDeepTlsBudget(value: unknown): boolean {
  return isObject(value)
    && hasExactKeys(value, [
      "deadlineMs", "maxProcesses", "processesStarted", "processesCompleted", "maxConcurrentConnections",
      "maxConnections", "connectionsOpened", "maxPhaseOutputBytes", "outputBytes", "maxResponseBytes",
    ])
    && value.deadlineMs === 180_000
    && value.maxProcesses === 3
    && isInteger(value.processesStarted, 0, 3)
    && isInteger(value.processesCompleted, 0, value.processesStarted as number)
    && value.maxConcurrentConnections === 5
    && value.maxConnections === 128
    && isInteger(value.connectionsOpened, 0, 128)
    && value.maxPhaseOutputBytes === 393_216
    && isInteger(value.outputBytes, 0, 3 * 393_216)
    && value.maxResponseBytes === 163_840;
}

function isDeepTlsPhases(value: unknown): boolean {
  if (!Array.isArray(value) || value.length > 3) return false;
  return value.every((phase) => (
    isObject(phase)
    && hasExactKeys(phase, ["id", "status", "exitCode", "durationMs", "outputBytes"])
    && typeof phase.id === "string"
    && DEEP_PHASE_ID_SET.has(phase.id)
    && typeof phase.status === "string"
    && DEEP_PHASE_STATUS_SET.has(phase.status)
    && (phase.exitCode === null || isInteger(phase.exitCode, 0, 255))
    && isInteger(phase.durationMs, 0, 210_000)
    && isInteger(phase.outputBytes, 0, 393_216)
  )) && new Set(value.map((phase) => (phase as { id: string }).id)).size === value.length;
}

function isDeepTlsSections(value: unknown): value is Record<DeepTlsSectionName, DeepTlsSection> {
  return isObject(value)
    && hasExactKeys(value, [...DEEP_TLS_SECTION_NAMES])
    && DEEP_TLS_SECTION_NAMES.every((name) => isDeepTlsSection(value[name]));
}

function isDeepTlsSection(value: unknown): value is DeepTlsSection {
  if (!isObject(value) || !hasExactKeys(value, ["status", "grade", "observations"])) return false;
  if (
    typeof value.status !== "string"
    || !DEEP_TLS_STATUS_SET.has(value.status)
    || !isDeepTlsGrade(value.grade)
    || !Array.isArray(value.observations)
    || value.observations.length > 128
    || !value.observations.every(isDeepTlsObservation)
  ) return false;
  return new Set(value.observations.map((observation) => observation.id)).size === value.observations.length;
}

function isDeepTlsObservation(value: unknown): value is DeepTlsObservation {
  if (!isObject(value) || !hasOnlyKeys(value, ["id", "sourceId", "status", "evidenceKind", "severity", "summary", "details"])) return false;
  return isDeepIdentifier(value.id)
    && (value.sourceId === undefined || isText(value.sourceId, 128))
    && typeof value.status === "string"
    && DEEP_OBSERVATION_STATUS_SET.has(value.status)
    && typeof value.evidenceKind === "string"
    && DEEP_EVIDENCE_KIND_SET.has(value.evidenceKind)
    && typeof value.severity === "string"
    && DEEP_SEVERITY_SET.has(value.severity)
    && isText(value.summary, 2_048)
    && (value.details === undefined || isDeepTlsDetails(value.details));
}

function isDeepTlsDetails(value: unknown): boolean {
  if (!isObject(value) || Object.keys(value).length > 16) return false;
  return Object.entries(value).every(([key, detail]) => (
    isDeepIdentifier(key)
    && (
      detail === null
      || typeof detail === "boolean"
      || (typeof detail === "number" && Number.isSafeInteger(detail))
      || isText(detail, 512)
      || (Array.isArray(detail) && detail.length <= 128 && detail.every((item) => isText(item, 512)))
    )
  ));
}

function isDeepTlsIssues(value: unknown, sections: Record<DeepTlsSectionName, DeepTlsSection>): value is DeepTlsIssue[] {
  if (!Array.isArray(value) || value.length > 256) return false;
  return value.every((issue) => (
    isObject(issue)
    && hasExactKeys(issue, ["id", "section", "observationId", "severity", "evidenceKind", "summary"])
    && isDeepIdentifier(issue.id)
    && typeof issue.section === "string"
    && DEEP_TLS_SECTION_NAMES.includes(issue.section as DeepTlsSectionName)
    && isDeepIdentifier(issue.observationId)
    && typeof issue.severity === "string"
    && ["critical", "high", "medium", "low"].includes(issue.severity)
    && typeof issue.evidenceKind === "string"
    && DEEP_EVIDENCE_KIND_SET.has(issue.evidenceKind)
    && isText(issue.summary, 2_048)
    && sections[issue.section as DeepTlsSectionName].observations.some((observation) => observation.id === issue.observationId)
  ));
}

function isDeepTlsGrade(value: unknown): value is DeepTlsGrade {
  if (!isObject(value) || !hasExactKeys(value, ["value", "score", "coverage", "methodology", "caps"])) return false;
  if (
    typeof value.value !== "string"
    || !TLS_GRADE_SET.has(value.value)
    || value.methodology !== "cresswell-tls-v1"
    || !isObject(value.coverage)
    || !hasExactKeys(value.coverage, ["evaluatedWeight", "totalWeight"])
    || !isInteger(value.coverage.totalWeight, 0, 100_000)
    || !isInteger(value.coverage.evaluatedWeight, 0, value.coverage.totalWeight as number)
    || !Array.isArray(value.caps)
    || value.caps.length > 128
    || !value.caps.every((cap) => (
      isObject(cap)
      && hasExactKeys(cap, ["id", "maxGrade", "reason"])
      && isDeepIdentifier(cap.id)
      && typeof cap.maxGrade === "string"
      && ["B", "C", "D", "F"].includes(cap.maxGrade)
      && isText(cap.reason, 2_048)
    ))
  ) return false;
  return value.value === "N/A"
    ? value.score === null
    : isFiniteNumber(value.score, 0, 100);
}

function isSecurityJobId(value: unknown): value is string {
  return typeof value === "string" && /^sa_[a-f0-9]{48}$/u.test(value);
}

function isOpaqueCapability(value: unknown): value is string {
  return typeof value === "string" && /^sc_[a-f0-9]{64}$/u.test(value);
}

function isDeepIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 128 && /^[A-Za-z0-9._:-]+$/u.test(value);
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const allowed = new Set(keys);
  return Object.keys(value).every((key) => allowed.has(key));
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
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
  if (!isObject(value) || !hasExactKeys(value, [
    "id", "status", "title", "summary", "evidence", "remediation", "owasp",
  ])) return false;
  return typeof value.id === "string"
    && WEB_SECURITY_CHECK_ID_SET.has(value.id)
    && typeof value.status === "string"
    && CHECK_STATUS_SET.has(value.status as WebSecurityCheckStatus)
    && isText(value.title, 512)
    && isText(value.summary, 8_192)
    && isTextArray(value.evidence, 12, 512)
    && isText(value.remediation, 8_192)
    && isObject(value.owasp)
    && hasExactKeys(value.owasp, ["top10", "wstg"])
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
    && hasExactKeys(value, ["limit", "remaining", "resetAt", "windowSeconds"])
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

function isPublicDeepAddress(value: unknown): value is string {
  if (!isCanonicalIpAddress(value)) return false;
  if (!value.includes(":")) {
    const address = parseIpv4BigInt(value);
    const blocked = [
      ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
      ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.2.0", 24], ["192.88.99.0", 24],
      ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
      ["224.0.0.0", 4], ["240.0.0.0", 4],
    ] as const;
    if (blocked.some(([base, prefix]) => inPrefix(address, parseIpv4BigInt(base), prefix, 32))) return false;
    if (inPrefix(address, parseIpv4BigInt("192.0.0.0"), 24, 32)) {
      return address === parseIpv4BigInt("192.0.0.9") || address === parseIpv4BigInt("192.0.0.10");
    }
    return true;
  }
  const address = parseIpv6BigInt(value);
  if (address === null) return false;
  if (
    inPrefix(address, 0xfcn << 120n, 7, 128)
    || address === 0n
    || address === 1n
    || inPrefix(address, 0xfe80n << 112n, 10, 128)
    || inPrefix(address, 0xffn << 120n, 8, 128)
    || inPrefix(address, 0x20010db8n << 96n, 32, 128)
    || inPrefix(address, 0x3fff0n << 108n, 20, 128)
  ) return false;
  const globalException = inPrefix(address, 0x0064ff9bn << 96n, 96, 128)
    || address === ((0x20010001n << 96n) | 1n)
    || address === ((0x20010001n << 96n) | 2n)
    || address === ((0x20010001n << 96n) | 3n)
    || inPrefix(address, 0x20010003n << 96n, 32, 128)
    || inPrefix(address, 0x200100040112n << 80n, 48, 128)
    || inPrefix(address, 0x20010020n << 96n, 28, 128)
    || inPrefix(address, 0x20010030n << 96n, 28, 128);
  const globallyRoutable = globalException || (
    inPrefix(address, 0x2n << 124n, 3, 128)
    && !inPrefix(address, 0x200100n << 104n, 23, 128)
  );
  if (!globallyRoutable) return false;
  return !(
    inPrefix(address, 0x0064ff9bn << 96n, 96, 128)
    || inPrefix(address, 0x2002n << 112n, 16, 128)
    || inPrefix(address, 0x20010000n << 96n, 32, 128)
    || inPrefix(address, 0n, 96, 128)
    || inPrefix(address, 0xffffn << 32n, 96, 128)
  );
}

function parseIpv4BigInt(value: string): bigint {
  return value.split(".").reduce((result, part) => (result << 8n) | BigInt(part), 0n);
}

function parseIpv6BigInt(input: string): bigint | null {
  let value = input.toLowerCase();
  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    const ipv4Text = value.slice(lastColon + 1);
    if (!isCanonicalIpAddress(ipv4Text)) return null;
    const ipv4 = parseIpv4BigInt(ipv4Text);
    value = `${value.slice(0, lastColon)}:${((ipv4 >> 16n) & 0xffffn).toString(16)}:${(ipv4 & 0xffffn).toString(16)}`;
  }
  const pieces = value.split("::");
  if (pieces.length > 2) return null;
  const left = pieces[0] ? pieces[0].split(":") : [];
  const right = pieces.length === 2 && pieces[1] ? pieces[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((pieces.length === 1 && missing !== 0) || (pieces.length === 2 && missing < 1)) return null;
  const groups = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/u.test(group))) return null;
  return groups.reduce((result, group) => (result << 16n) | BigInt(`0x${group}`), 0n);
}

function inPrefix(value: bigint, base: bigint, prefix: number, width: number): boolean {
  const shift = BigInt(width - prefix);
  return value >> shift === base >> shift;
}
