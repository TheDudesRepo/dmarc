import {
  SECURITY_ASSESSMENT_DISCLAIMER_VERSION,
  WEB_SECURITY_DISCLAIMER_VERSION,
  type ScanError,
  type SecurityAssessmentApiError,
  type SecurityAssessmentCreateResponse,
  type WebScanQuota,
  type WebSecurityScanError,
} from "../shared/types";
import {
  createDnsSnapshot,
  discoverCommonHosts,
  DiscoveryUpstreamError,
  normalizeHostDiscoveryProfile,
} from "./discovery";
import { DomainValidationError, normalizeDomain } from "./domain";
import { inspectIpNetwork, IpToolsValidationError } from "./ip-tools";
import { lookupDns, LookupUpstreamError, LookupValidationError } from "./lookup";
import {
  createPinnedHttpFetcher,
} from "./pinned-http";
import {
  canonicalizeClientIp,
  digestClientIp,
  type PollRateLimitDecision,
  type RateLimitDecision,
  RateLimitConfigurationError,
} from "./rate-limiter";
import { scanDomain, ScanUpstreamError } from "./scanner";
import {
  cancelSecurityAssessmentJob,
  createSecurityAssessmentJob,
  digestSecurityAssessmentCancelToken,
  generateSecurityAssessmentCancelToken,
  generateSecurityAssessmentJobId,
  getSecurityAssessmentJob,
  SECURITY_ASSESSMENT_CANCEL_TOKEN_PATTERN,
  SECURITY_ASSESSMENT_POLL_SECONDS,
  SecurityAssessmentConfigurationError,
  SecurityAssessmentNotFoundError,
  type SecurityAssessmentBindings,
} from "./security-assessment";
import {
  resolvePublicHost,
  ScanTargetResolutionError,
  UnsafeScanTargetError,
} from "./target-safety";
import {
  scanWebSecurity,
  WebSecurityTargetError,
  WebSecurityUpstreamError,
  type WebSecurityScanExecution,
} from "./web-security";

export { WebScanRateLimiter } from "./rate-limiter";
export { ContainerProxy } from "@cloudflare/containers";
export { DeepTlsScanner } from "./deep-tls-scanner";
export { SecurityAssessmentCoordinator, SecurityAssessmentWorkflow } from "./security-assessment";

export interface Env extends SecurityAssessmentBindings {
  ASSETS: Fetcher;
  VERSION_METADATA?: WorkerVersionMetadata;
  WEB_SCAN_RATE_LIMITER: DurableObjectNamespace;
  WEB_SCAN_RATE_LIMIT_SECRET?: string;
}

export { WEB_SECURITY_DISCLAIMER_VERSION } from "../shared/types";
export { SECURITY_ASSESSMENT_DISCLAIMER_VERSION } from "../shared/types";

const API_SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "Cache-Control": "no-store, max-age=0",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

const MAX_REQUEST_BODY_BYTES = 2_048;

type WebSecurityScanner = (hostname: string) => Promise<WebSecurityScanExecution>;
type WebSecurityQuotaConsumer = (request: Request, env: Env) => Promise<RateLimitDecision>;
type SecurityAssessmentPollQuotaConsumer = (request: Request, env: Env) => Promise<PollRateLimitDecision>;
type SecurityAssessmentCreator = typeof createSecurityAssessmentJob;
type SecurityAssessmentGetter = typeof getSecurityAssessmentJob;
type SecurityAssessmentCanceller = typeof cancelSecurityAssessmentJob;

export interface WorkerDependencies {
  scanWebSecurity: WebSecurityScanner;
  consumeWebScanQuota: WebSecurityQuotaConsumer;
  consumeSecurityAssessmentPollQuota: SecurityAssessmentPollQuotaConsumer;
  resolvePublicHost: typeof resolvePublicHost;
  createSecurityAssessmentJob: SecurityAssessmentCreator;
  getSecurityAssessmentJob: SecurityAssessmentGetter;
  cancelSecurityAssessmentJob: SecurityAssessmentCanceller;
  generateSecurityAssessmentJobId: typeof generateSecurityAssessmentJobId;
  generateSecurityAssessmentCancelToken: typeof generateSecurityAssessmentCancelToken;
  digestSecurityAssessmentCancelToken: typeof digestSecurityAssessmentCancelToken;
  now: () => number;
}

export function createWorker(overrides: Partial<WorkerDependencies> = {}) {
  const dependencies: WorkerDependencies = {
    scanWebSecurity: createPinnedLegacyWebSecurityScanner(),
    consumeWebScanQuota,
    consumeSecurityAssessmentPollQuota,
    resolvePublicHost,
    createSecurityAssessmentJob,
    getSecurityAssessmentJob,
    cancelSecurityAssessmentJob,
    generateSecurityAssessmentJobId,
    generateSecurityAssessmentCancelToken,
    digestSecurityAssessmentCancelToken,
    now: Date.now,
    ...overrides,
  };

  return {
    async fetch(request: Request, env: Env): Promise<Response> {
      const url = new URL(request.url);

      if (!url.pathname.startsWith("/api/")) {
        return env.ASSETS.fetch(request);
      }

      if (url.pathname === "/api/health") {
        if (request.method !== "GET") return methodNotAllowed(["GET"]);
        return jsonResponse({
          status: "ok",
          service: "cresswell-security-lab",
          version: "0.5.0",
          deploymentId: env.VERSION_METADATA?.id ?? null,
        });
      }

      if (url.pathname === "/api/scan") {
        if (request.method === "OPTIONS") return methodNotAllowed(["POST"]);
        if (request.method !== "POST") return methodNotAllowed(["POST"]);
        return handleScan(request);
      }

      if (url.pathname === "/api/lookup") {
        if (request.method === "OPTIONS") return methodNotAllowed(["POST"]);
        if (request.method !== "POST") return methodNotAllowed(["POST"]);
        return handleLookup(request);
      }

      if (url.pathname === "/api/dns-snapshot") {
        if (request.method === "OPTIONS") return methodNotAllowed(["POST"]);
        if (request.method !== "POST") return methodNotAllowed(["POST"]);
        return handleDnsSnapshot(request);
      }

      if (url.pathname === "/api/host-discovery") {
        if (request.method === "OPTIONS") return methodNotAllowed(["POST"]);
        if (request.method !== "POST") return methodNotAllowed(["POST"]);
        return handleHostDiscovery(request);
      }

      if (url.pathname === "/api/ip-network") {
        if (request.method === "OPTIONS") return methodNotAllowed(["POST"]);
        if (request.method !== "POST") return methodNotAllowed(["POST"]);
        return handleIpNetwork(request);
      }

      if (url.pathname === "/api/web-security") {
        if (request.method === "OPTIONS") return methodNotAllowed(["POST"]);
        if (request.method !== "POST") return methodNotAllowed(["POST"]);
        return handleWebSecurity(request, env, dependencies);
      }

      if (url.pathname === "/api/security-assessments") {
        if (request.method === "OPTIONS") return methodNotAllowed(["POST"]);
        if (request.method !== "POST") return methodNotAllowed(["POST"]);
        return handleSecurityAssessmentCreate(request, env, dependencies);
      }

      if (url.pathname.startsWith("/api/security-assessments/")) {
        return handleSecurityAssessmentJob(request, url, env, dependencies);
      }

      return errorResponse("API route not found.", "NOT_FOUND", 404);
    },
  };
}

/** Keep the compatibility route on an exact-IP socket transport with no hostname-fetch fallback. */
export function createPinnedLegacyWebSecurityScanner(
  scanner: typeof scanWebSecurity = scanWebSecurity,
  fetcherFactory: () => ReturnType<typeof createPinnedHttpFetcher> = createPinnedHttpFetcher,
): WebSecurityScanner {
  return (hostname) => scanner(hostname, { fetcher: fetcherFactory() });
}

export default createWorker();

async function handleScan(request: Request): Promise<Response> {
  const parsed = await readJsonObject(request, ["domain"], "a domain field");
  if (!parsed.ok) return parsed.response;

  try {
    const domain = normalizeDomain(parsed.payload.domain);
    const result = await scanDomain(domain);
    return jsonResponse(result);
  } catch (error) {
    if (error instanceof DomainValidationError) {
      return errorResponse(error.message, "INVALID_DOMAIN", 400);
    }
    if (error instanceof ScanUpstreamError) {
      return errorResponse("DNS data is temporarily unavailable. Please try again.", "UPSTREAM_ERROR", 502);
    }
    return errorResponse("The scan could not be completed. Please try again.", "UPSTREAM_ERROR", 502);
  }
}

async function handleLookup(request: Request): Promise<Response> {
  const parsed = await readJsonObject(request, ["name", "type"], "name and type fields");
  if (!parsed.ok) return parsed.response;

  try {
    const result = await lookupDns(parsed.payload.name, parsed.payload.type);
    return jsonResponse(result);
  } catch (error) {
    if (error instanceof LookupValidationError) {
      return errorResponse(error.message, "BAD_REQUEST", 400);
    }
    if (error instanceof LookupUpstreamError) {
      return errorResponse("DNS data is temporarily unavailable. Please try again.", "UPSTREAM_ERROR", 502);
    }
    return errorResponse("The DNS lookup could not be completed. Please try again.", "UPSTREAM_ERROR", 502);
  }
}

async function handleDnsSnapshot(request: Request): Promise<Response> {
  const parsed = await readJsonObject(request, ["domain"], "a domain field");
  if (!parsed.ok) return parsed.response;

  try {
    const domain = normalizeDomain(parsed.payload.domain);
    return jsonResponse(await createDnsSnapshot(domain));
  } catch (error) {
    if (error instanceof DomainValidationError) {
      return errorResponse(error.message, "INVALID_DOMAIN", 400);
    }
    if (error instanceof DiscoveryUpstreamError) {
      return errorResponse("DNS data is temporarily unavailable. Please try again.", "UPSTREAM_ERROR", 502);
    }
    return errorResponse("The DNS snapshot could not be completed. Please try again.", "UPSTREAM_ERROR", 502);
  }
}

async function handleHostDiscovery(request: Request): Promise<Response> {
  const parsed = await readJsonObject(request, ["domain", "profile"], "domain and profile fields");
  if (!parsed.ok) return parsed.response;

  let domain: string;
  try {
    domain = normalizeDomain(parsed.payload.domain);
  } catch (error) {
    if (error instanceof DomainValidationError) {
      return errorResponse(error.message, "INVALID_DOMAIN", 400);
    }
    return errorResponse("Host discovery could not be completed. Please try again.", "UPSTREAM_ERROR", 502);
  }

  let profile: ReturnType<typeof normalizeHostDiscoveryProfile>;
  try {
    profile = normalizeHostDiscoveryProfile(parsed.payload.profile);
  } catch {
    return errorResponse("Profile must be core or extended.", "BAD_REQUEST", 400);
  }

  try {
    return jsonResponse(await discoverCommonHosts(domain, profile));
  } catch {
    return errorResponse("Host discovery could not be completed. Please try again.", "UPSTREAM_ERROR", 502);
  }
}

async function handleIpNetwork(request: Request): Promise<Response> {
  const parsed = await readJsonObject(request, ["input"], "an input field");
  if (!parsed.ok) return parsed.response;

  try {
    const result = await inspectIpNetwork(parsed.payload.input, {
      enrich: true,
      includeAsName: true,
    });
    return jsonResponse(result);
  } catch (error) {
    if (error instanceof IpToolsValidationError) {
      return errorResponse(error.message, "BAD_REQUEST", 400);
    }
    return errorResponse("The IP or subnet calculation could not be completed. Please try again.", "UPSTREAM_ERROR", 502);
  }
}

async function handleSecurityAssessmentCreate(
  request: Request,
  env: Env,
  dependencies: WorkerDependencies,
): Promise<Response> {
  const parsed = await readJsonObject(
    request,
    ["hostname", "authorizedUse", "disclaimerVersion"],
    "hostname, authorizedUse, and disclaimerVersion fields",
  );
  if (!parsed.ok) return parsed.response;
  if (!hasExactObjectKeys(parsed.payload, ["hostname", "authorizedUse", "disclaimerVersion"])) {
    return errorResponse("The assessment request contained unsupported fields.", "BAD_REQUEST", 400);
  }
  if (
    parsed.payload.authorizedUse !== true
    || parsed.payload.disclaimerVersion !== SECURITY_ASSESSMENT_DISCLAIMER_VERSION
  ) {
    return errorResponse(
      "Confirm target ownership or explicit permission and accept the current deep-assessment notice.",
      "AUTHORIZATION_REQUIRED",
      403,
    );
  }

  let hostname: string;
  try {
    hostname = normalizeDomain(parsed.payload.hostname);
  } catch (error) {
    return errorResponse(
      error instanceof DomainValidationError ? error.message : "The hostname is invalid.",
      "INVALID_DOMAIN",
      400,
    );
  }

  let decision: RateLimitDecision;
  try {
    decision = await dependencies.consumeWebScanQuota(request, env);
  } catch {
    return errorResponse(
      "Security assessment orchestration is temporarily unavailable. Please try again later.",
      "SERVICE_UNAVAILABLE",
      503,
    );
  }
  const rateHeaders = webScanRateHeaders(
    decision.quota,
    decision.allowed ? undefined : decision.retryAfterSeconds,
    dependencies.now(),
  );
  if (!decision.allowed) {
    return securityAssessmentErrorResponse(
      "This client has used its five security assessments in the rolling one-hour window.",
      "RATE_LIMITED",
      429,
      decision.quota,
      rateHeaders,
    );
  }

  let addresses: string[];
  try {
    addresses = await dependencies.resolvePublicHost(hostname);
  } catch (error) {
    if (error instanceof UnsafeScanTargetError) {
      return securityAssessmentErrorResponse(error.message, "UNSAFE_TARGET", 400, decision.quota, rateHeaders);
    }
    if (error instanceof ScanTargetResolutionError) {
      return securityAssessmentErrorResponse(
        "The target could not be resolved safely right now.",
        "UPSTREAM_ERROR",
        502,
        decision.quota,
        rateHeaders,
      );
    }
    return securityAssessmentErrorResponse(
      "The target could not be validated for an isolated assessment.",
      "UPSTREAM_ERROR",
      502,
      decision.quota,
      rateHeaders,
    );
  }

  const jobId = dependencies.generateSecurityAssessmentJobId();
  const cancelToken = dependencies.generateSecurityAssessmentCancelToken();
  try {
    const cancelTokenHash = await dependencies.digestSecurityAssessmentCancelToken(cancelToken);
    const created = await dependencies.createSecurityAssessmentJob(env, {
      jobId,
      hostname,
      addresses,
      createdAt: new Date(dependencies.now()).toISOString(),
      cancelTokenHash,
    });
    const body: SecurityAssessmentCreateResponse = {
      ...created.job,
      quota: decision.quota,
      reuse: created.reuse,
      pollAfterSeconds: created.pollAfterSeconds,
      ...(created.reuse === "new" ? { cancelToken } : {}),
    };
    const headers = new Headers(rateHeaders);
    headers.set("Location", `/api/security-assessments/${created.job.jobId}`);
    if (!isAssessmentTerminal(created.job.status)) {
      headers.set("Retry-After", String(created.pollAfterSeconds || SECURITY_ASSESSMENT_POLL_SECONDS));
    }
    return jsonResponse(body, isAssessmentTerminal(created.job.status) ? 200 : 202, headers);
  } catch {
    return securityAssessmentErrorResponse(
      "The isolated assessment job could not be created. Please try again later.",
      "ORCHESTRATION_ERROR",
      503,
      decision.quota,
      rateHeaders,
    );
  }
}

async function handleSecurityAssessmentJob(
  request: Request,
  url: URL,
  env: Env,
  dependencies: WorkerDependencies,
): Promise<Response> {
  const match = /^\/api\/security-assessments\/(sa_[a-f0-9]{48})$/u.exec(url.pathname);
  if (!match) return securityAssessmentErrorResponse("Assessment job not found.", "JOB_NOT_FOUND", 404);
  if (request.method === "OPTIONS") return methodNotAllowed(["GET", "DELETE"]);
  if (request.method !== "GET" && request.method !== "DELETE") return methodNotAllowed(["GET", "DELETE"]);
  const fetchSite = request.headers.get("sec-fetch-site")?.toLowerCase();
  if (fetchSite !== undefined && fetchSite !== "same-origin" && fetchSite !== "none") {
    return securityAssessmentErrorResponse(
      "Cross-site browser requests cannot access assessment capabilities.",
      "BAD_REQUEST",
      403,
    );
  }
  const jobId = match[1] ?? "";

  let pollDecision: PollRateLimitDecision;
  try {
    pollDecision = await dependencies.consumeSecurityAssessmentPollQuota(request, env);
  } catch {
    return securityAssessmentErrorResponse(
      "Security assessment status is temporarily unavailable. Please try again later.",
      "SERVICE_UNAVAILABLE",
      503,
    );
  }
  const pollHeaders = assessmentPollRateHeaders(pollDecision);
  if (!pollDecision.allowed) {
    return securityAssessmentErrorResponse(
      "This client is checking assessment status too frequently. Wait before polling again.",
      "RATE_LIMITED",
      429,
      undefined,
      pollHeaders,
    );
  }

  try {
    if (request.method === "GET") {
      const job = await dependencies.getSecurityAssessmentJob(env, jobId);
      const headers = new Headers(pollHeaders);
      if (!isAssessmentTerminal(job.status)) headers.set("Retry-After", String(SECURITY_ASSESSMENT_POLL_SECONDS));
      return jsonResponse(job, 200, headers);
    }

    const cancelToken = request.headers.get("x-assessment-cancel-token") ?? "";
    if (!SECURITY_ASSESSMENT_CANCEL_TOKEN_PATTERN.test(cancelToken)) {
      return securityAssessmentErrorResponse("Assessment job not found.", "JOB_NOT_FOUND", 404);
    }
    const cancelTokenHash = await dependencies.digestSecurityAssessmentCancelToken(cancelToken);
    const cancelled = await dependencies.cancelSecurityAssessmentJob(env, jobId, cancelTokenHash);
    return jsonResponse(cancelled, 200, pollHeaders);
  } catch (error) {
    if (error instanceof SecurityAssessmentNotFoundError) {
      return securityAssessmentErrorResponse("Assessment job not found.", "JOB_NOT_FOUND", 404, undefined, pollHeaders);
    }
    if (error instanceof SecurityAssessmentConfigurationError) {
      return securityAssessmentErrorResponse(
        "Security assessment orchestration is temporarily unavailable.",
        "ORCHESTRATION_ERROR",
        503,
        undefined,
        pollHeaders,
      );
    }
    return securityAssessmentErrorResponse(
      "Security assessment orchestration is temporarily unavailable.",
      "ORCHESTRATION_ERROR",
      503,
      undefined,
      pollHeaders,
    );
  }
}

async function handleWebSecurity(
  request: Request,
  env: Env,
  dependencies: WorkerDependencies,
): Promise<Response> {
  const parsed = await readJsonObject(
    request,
    ["hostname", "authorizedUse", "disclaimerVersion"],
    "hostname, authorizedUse, and disclaimerVersion fields",
  );
  if (!parsed.ok) return parsed.response;

  if (
    parsed.payload.authorizedUse !== true
    || parsed.payload.disclaimerVersion !== WEB_SECURITY_DISCLAIMER_VERSION
  ) {
    return errorResponse(
      "Confirm that you are authorized to assess this hostname and accept the current acceptable-use notice.",
      "AUTHORIZATION_REQUIRED",
      403,
    );
  }

  let hostname: string;
  try {
    hostname = normalizeDomain(parsed.payload.hostname);
  } catch (error) {
    if (error instanceof DomainValidationError) {
      return errorResponse(error.message, "INVALID_DOMAIN", 400);
    }
    return errorResponse("The hostname is invalid.", "INVALID_DOMAIN", 400);
  }

  let decision: RateLimitDecision;
  try {
    decision = await dependencies.consumeWebScanQuota(request, env);
  } catch {
    return errorResponse(
      "Web security scanning is temporarily unavailable. Please try again later.",
      "SERVICE_UNAVAILABLE",
      503,
    );
  }

  const rateHeaders = webScanRateHeaders(
    decision.quota,
    decision.allowed ? undefined : decision.retryAfterSeconds,
    dependencies.now(),
  );
  if (!decision.allowed) {
    return webSecurityErrorResponse(
      "This client has used its five web security scans in the rolling one-hour window.",
      "RATE_LIMITED",
      429,
      decision.quota,
      rateHeaders,
    );
  }

  try {
    const result = await dependencies.scanWebSecurity(hostname);
    return jsonResponse({ ...result, quota: decision.quota }, 200, rateHeaders);
  } catch (error) {
    if (error instanceof WebSecurityTargetError) {
      return webSecurityErrorResponse(error.message, "UNSAFE_TARGET", 400, decision.quota, rateHeaders);
    }
    if (error instanceof WebSecurityUpstreamError) {
      return webSecurityErrorResponse(
        "The target could not be assessed right now. Please try again later.",
        "UPSTREAM_ERROR",
        502,
        decision.quota,
        rateHeaders,
      );
    }
    return webSecurityErrorResponse(
      "The web security scan could not be completed. Please try again later.",
      "UPSTREAM_ERROR",
      502,
      decision.quota,
      rateHeaders,
    );
  }
}

/** Consume one exact rolling-window slot for the trusted Cloudflare client IP. */
export async function consumeWebScanQuota(request: Request, env: Env): Promise<RateLimitDecision> {
  const clientIp = canonicalizeClientIp(request.headers.get("cf-connecting-ip"));
  const digest = await digestClientIp(clientIp, env.WEB_SCAN_RATE_LIMIT_SECRET);
  const namespace = env.WEB_SCAN_RATE_LIMITER;
  if (!namespace || typeof namespace.idFromName !== "function" || typeof namespace.get !== "function") {
    throw new RateLimitConfigurationError("The scan rate limiter is not configured.");
  }

  const id = namespace.idFromName(digest);
  const stub = namespace.get(id);
  const response = await stub.fetch("https://web-scan-rate-limit.internal/consume", { method: "POST" });
  if (!response.ok) {
    throw new RateLimitConfigurationError("The scan rate limiter is unavailable.");
  }

  const payload = await response.json() as unknown;
  if (!isRateLimitDecision(payload)) {
    throw new RateLimitConfigurationError("The scan rate limiter returned an invalid response.");
  }
  return payload;
}

/** Bound bearer status and cancellation requests before they reach the global coordinator. */
export async function consumeSecurityAssessmentPollQuota(
  request: Request,
  env: Env,
): Promise<PollRateLimitDecision> {
  const clientIp = canonicalizeClientIp(request.headers.get("cf-connecting-ip"));
  const digest = await digestClientIp(clientIp, env.WEB_SCAN_RATE_LIMIT_SECRET);
  const namespace = env.WEB_SCAN_RATE_LIMITER;
  if (!namespace || typeof namespace.idFromName !== "function" || typeof namespace.get !== "function") {
    throw new RateLimitConfigurationError("The assessment status limiter is not configured.");
  }

  const response = await namespace.get(namespace.idFromName(digest)).fetch(
    "https://web-scan-rate-limit.internal/poll",
    { method: "POST" },
  );
  if (!response.ok) throw new RateLimitConfigurationError("The assessment status limiter is unavailable.");
  const payload = await response.json() as unknown;
  if (!isPollRateLimitDecision(payload)) {
    throw new RateLimitConfigurationError("The assessment status limiter returned an invalid response.");
  }
  return payload;
}

type JsonObjectResult =
  | { ok: true; payload: Record<string, unknown> }
  | { ok: false; response: Response };

async function readJsonObject(
  request: Request,
  requiredFields: readonly string[],
  fieldDescription: string,
): Promise<JsonObjectResult> {
  const contentType = request.headers.get("content-type")
    ?.split(";", 1)[0]
    ?.trim()
    .toLowerCase() ?? "";
  if (contentType !== "application/json") {
    await cancelRequestBody(request.body);
    return {
      ok: false,
      response: errorResponse(`Send a JSON body containing ${fieldDescription}.`, "BAD_REQUEST", 400),
    };
  }

  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BODY_BYTES) {
    await cancelRequestBody(request.body);
    return { ok: false, response: errorResponse("Request body is too large.", "BAD_REQUEST", 413) };
  }

  let payload: unknown;
  try {
    const body = await readBoundedRequestBody(request.body);
    if (body.tooLarge) {
      return { ok: false, response: errorResponse("Request body is too large.", "BAD_REQUEST", 413) };
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(body.bytes);
    payload = JSON.parse(text) as unknown;
  } catch {
    return {
      ok: false,
      response: errorResponse("Request body must be valid JSON.", "BAD_REQUEST", 400),
    };
  }

  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    requiredFields.some((field) => !(field in payload))
  ) {
    return {
      ok: false,
      response: errorResponse(`JSON body must contain ${fieldDescription}.`, "BAD_REQUEST", 400),
    };
  }

  return { ok: true, payload: payload as Record<string, unknown> };
}

type BoundedBodyRead =
  | { tooLarge: false; bytes: Uint8Array }
  | { tooLarge: true };

async function readBoundedRequestBody(body: ReadableStream<Uint8Array> | null): Promise<BoundedBodyRead> {
  if (body === null) return { tooLarge: false, bytes: new Uint8Array() };

  const reader = body.getReader();
  const bytes = new Uint8Array(MAX_REQUEST_BODY_BYTES + 1);
  let byteLength = 0;

  try {
    while (byteLength <= MAX_REQUEST_BODY_BYTES) {
      const { done, value } = await reader.read();
      if (done) {
        return { tooLarge: false, bytes: bytes.slice(0, byteLength) };
      }
      if (value.byteLength === 0) continue;

      const available = bytes.byteLength - byteLength;
      const copyLength = Math.min(value.byteLength, available);
      bytes.set(value.subarray(0, copyLength), byteLength);
      byteLength += copyLength;

      if (byteLength > MAX_REQUEST_BODY_BYTES || copyLength < value.byteLength) {
        await cancelBodyReader(reader);
        return { tooLarge: true };
      }
    }
  } finally {
    reader.releaseLock();
  }

  return { tooLarge: true };
}

async function cancelRequestBody(body: ReadableStream<Uint8Array> | null): Promise<void> {
  if (body === null || body.locked) return;
  try {
    await body.cancel();
  } catch {
    // Cancellation is best-effort; the request is still rejected before dispatch.
  }
}

async function cancelBodyReader(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<void> {
  try {
    await reader.cancel();
  } catch {
    // Cancellation is best-effort; the request is still rejected before dispatch.
  }
}

function methodNotAllowed(allowed: string[]): Response {
  const response = errorResponse("Method not allowed.", "METHOD_NOT_ALLOWED", 405);
  response.headers.set("Allow", allowed.join(", "));
  return response;
}

function errorResponse(error: string, code: ScanError["code"], status: number): Response {
  return jsonResponse({ error, code } satisfies ScanError, status);
}

function webSecurityErrorResponse(
  error: string,
  code: WebSecurityScanError["code"],
  status: number,
  quota: WebScanQuota,
  extraHeaders: HeadersInit,
): Response {
  return jsonResponse({ error, code, quota } satisfies WebSecurityScanError, status, extraHeaders);
}

function securityAssessmentErrorResponse(
  error: string,
  code: SecurityAssessmentApiError["code"],
  status: number,
  quota?: WebScanQuota,
  extraHeaders?: HeadersInit,
): Response {
  return jsonResponse({ error, code, ...(quota ? { quota } : {}) } satisfies SecurityAssessmentApiError, status, extraHeaders);
}

function jsonResponse(body: unknown, status = 200, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(API_SECURITY_HEADERS);
  if (extraHeaders !== undefined) {
    new Headers(extraHeaders).forEach((value, name) => headers.set(name, value));
  }
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

function webScanRateHeaders(quota: WebScanQuota, retryAfterSeconds?: number, now = Date.now()): Headers {
  const resetDelaySeconds = Math.max(0, Math.ceil((Date.parse(quota.resetAt) - now) / 1_000));
  const headers = new Headers({
    "RateLimit-Limit": String(quota.limit),
    "RateLimit-Remaining": String(quota.remaining),
    "RateLimit-Reset": String(resetDelaySeconds),
  });
  if (retryAfterSeconds !== undefined) {
    headers.set("Retry-After", String(retryAfterSeconds));
  }
  return headers;
}

function assessmentPollRateHeaders(decision: PollRateLimitDecision): Headers {
  const headers = new Headers({
    "RateLimit-Limit": String(decision.limit),
    "RateLimit-Remaining": String(decision.remaining),
    "RateLimit-Reset": String(decision.resetAfterSeconds),
  });
  if (!decision.allowed) headers.set("Retry-After", String(decision.retryAfterSeconds));
  return headers;
}

function isPollRateLimitDecision(value: unknown): value is PollRateLimitDecision {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Partial<PollRateLimitDecision>;
  return candidate.limit === 60
    && typeof candidate.allowed === "boolean"
    && Number.isInteger(candidate.remaining)
    && Number(candidate.remaining) >= 0
    && Number(candidate.remaining) <= 60
    && Number.isInteger(candidate.retryAfterSeconds)
    && Number(candidate.retryAfterSeconds) >= 0
    && Number.isInteger(candidate.resetAfterSeconds)
    && Number(candidate.resetAfterSeconds) >= 0
    && Number(candidate.resetAfterSeconds) <= 60
    && (candidate.allowed ? candidate.retryAfterSeconds === 0 : candidate.retryAfterSeconds !== 0);
}

function isRateLimitDecision(value: unknown): value is RateLimitDecision {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Partial<RateLimitDecision>;
  const retryAfterSeconds = candidate.retryAfterSeconds;
  if (
    typeof candidate.allowed !== "boolean"
    || typeof retryAfterSeconds !== "number"
    || !Number.isInteger(retryAfterSeconds)
    || retryAfterSeconds < 0
    || !Array.isArray(candidate.timestamps)
    || candidate.timestamps.length < 1
    || candidate.timestamps.length > 5
    || candidate.timestamps.some((timestamp) => !Number.isInteger(timestamp) || timestamp < 0)
    || candidate.timestamps.some((timestamp, index, values) => index > 0 && timestamp < (values[index - 1] ?? 0))
  ) {
    return false;
  }

  const quota = candidate.quota;
  if (!(
    quota
    && quota.limit === 5
    && Number.isInteger(quota.remaining)
    && quota.remaining >= 0
    && quota.remaining <= 5
    && quota.windowSeconds === 3600
    && typeof quota.resetAt === "string"
    && Number.isFinite(Date.parse(quota.resetAt))
  )) {
    return false;
  }

  const expectedResetAt = new Date((candidate.timestamps[0] ?? 0) + 3_600_000).toISOString();
  return quota.remaining === 5 - candidate.timestamps.length
    && quota.resetAt === expectedResetAt
    && (candidate.allowed ? retryAfterSeconds === 0 : retryAfterSeconds >= 1)
    && (candidate.allowed || candidate.timestamps.length === 5);
}

function hasExactObjectKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => key in value);
}

function isAssessmentTerminal(status: string): boolean {
  return status === "complete" || status === "cancelled" || status === "failed";
}
