import {
  WEB_SECURITY_DISCLAIMER,
  type TlsAssessment,
  type WebSecurityCheck,
  type WebSecurityCheckId,
  type WebSecurityCheckStatus,
  type WebSecurityScanResult,
} from "../shared/types";
import { calculateIpNetwork } from "./ip-tools";
import { DnsClient } from "./dns";
import { DomainValidationError, normalizeDomain } from "./domain";
import type { TlsScanExecution } from "./tls-scanner";

const MAX_HTTP_REQUESTS = 6;
const MAX_REDIRECT_HOPS = 2;
const MAX_RESPONSE_BYTES = 131_072;
const MAX_RESOLVED_ADDRESSES = 16;
const MAX_URL_LENGTH = 4_096;
const MAX_HEADER_VALUE_LENGTH = 8_192;
const MAX_EVIDENCE_ITEMS = 12;
const MAX_EVIDENCE_LENGTH = 512;
const MAX_HTML_TAGS = 512;
const FETCH_TIMEOUT_MS = 2_500;
const MAX_SCAN_DURATION_MS = 30_000;
const DNS_GUARD_TIMEOUT_MS = 1_500;
const TEST_ORIGIN = "https://scanner.invalid";
const SCANNER_USER_AGENT =
  "Cresswell-Security-Lab-WebScanner/0.5 (+https://dmarc.cresswell.rocks/security)";

export { WEB_SECURITY_DISCLAIMER } from "../shared/types";

export type WebSecurityScanExecution = Omit<WebSecurityScanResult, "quota">;

export interface WebSecurityScanOptions {
  resolver?: WebSecurityResolver;
  fetcher?: WebSecurityFetcher;
  tlsScanner?: WebSecurityTlsScanner;
  now?: () => number;
  nonce?: () => string;
}

export type WebSecurityResolver = (hostname: string) => Promise<readonly string[]>;

export type WebSecurityFetcher = (
  input: string,
  init: RequestInit,
  target: { hostname: string; validatedAddresses: readonly string[] },
) => Promise<Response>;

export type WebSecurityTlsScanner = (
  hostname: string,
  addresses: readonly string[],
) => Promise<TlsScanExecution>;

export class WebSecurityTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WebSecurityTargetError";
  }
}

export class WebSecurityUpstreamError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WebSecurityUpstreamError";
  }
}

interface ProbeContext {
  readonly originalHostname: string;
  readonly resolver: WebSecurityResolver;
  readonly fetcher: WebSecurityFetcher;
  readonly now: () => number;
  readonly deadlineAt: number;
  httpRequests: number;
  redirectHopsFollowed: number;
}

interface ProbeHop {
  url: string;
  status: number;
  location?: string;
}

interface ProbeChainResult {
  startUrl: string;
  effectiveUrl: string;
  response?: Response;
  hops: ProbeHop[];
  failure?: "fetch" | "unsafe-redirect" | "cross-host-redirect" | "redirect-limit" | "request-budget";
  failureDetail?: string;
}

interface BoundedBody {
  html?: string;
  isHtml: boolean;
  truncated: boolean;
}

interface BoundedTextBody {
  text?: string;
  truncated: boolean;
}

interface ErrorProbeResult {
  response?: Response;
  body: BoundedTextBody;
  failure?: "fetch" | "request-budget";
}

interface HeaderValue {
  value?: string;
  truncated: boolean;
}

interface ParsedCookie {
  name: string;
  attributes: Map<string, string | true>;
  authLike: boolean;
}

interface CookieEvidence {
  cookies: ParsedCookie[];
  truncated: boolean;
  available: boolean;
}

interface ParsedForm {
  action: string;
  method: string;
  hasPassword: boolean;
}

interface HtmlEvidence {
  forms: ParsedForm[];
  orphanPasswordInput: boolean;
  mixedContent: string[];
  externalExecutables: string[];
  missingIntegrity: string[];
  generators: string[];
  limited: boolean;
}

interface CheckDefinition {
  title: string;
  weight: number;
  remediation: string;
  top10: string[];
  wstg: string[];
}

const CHECK_ORDER: readonly WebSecurityCheckId[] = [
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
] as const;

const CHECK_DEFINITIONS: Readonly<Record<WebSecurityCheckId, CheckDefinition>> = {
  "https-enforcement": {
    title: "HTTPS enforcement",
    weight: 16,
    remediation: "Serve the application only over valid HTTPS and permanently redirect cleartext HTTP to the same approved HTTPS hostname.",
    top10: ["A04:2025 Cryptographic Failures"],
    wstg: ["WSTG-CRYP-03"],
  },
  hsts: {
    title: "HTTP Strict Transport Security",
    weight: 8,
    remediation: "After confirming every covered hostname supports HTTPS, publish HSTS with an appropriate max-age and consider includeSubDomains.",
    top10: ["A02:2025 Security Misconfiguration", "A04:2025 Cryptographic Failures"],
    wstg: ["WSTG-CONF-07"],
  },
  "content-security-policy": {
    title: "Content Security Policy",
    weight: 10,
    remediation: "Deploy an enforced, application-specific CSP. Prefer nonces or hashes and restrict scripts, objects, base URIs, and framing.",
    top10: ["A02:2025 Security Misconfiguration", "A05:2025 Injection"],
    wstg: ["WSTG-CONF-12"],
  },
  "frame-protection": {
    title: "Frame embedding protection",
    weight: 5,
    remediation: "Set CSP frame-ancestors to the exact allowed parents; use X-Frame-Options as a legacy fallback where appropriate.",
    top10: ["A01:2025 Broken Access Control", "A02:2025 Security Misconfiguration"],
    wstg: ["WSTG-CLNT-09"],
  },
  "mime-sniffing": {
    title: "MIME sniffing protection",
    weight: 3,
    remediation: "Return X-Content-Type-Options: nosniff and accurate Content-Type headers.",
    top10: ["A02:2025 Security Misconfiguration"],
    wstg: ["WSTG-CONF-02"],
  },
  "referrer-policy": {
    title: "Referrer information policy",
    weight: 3,
    remediation: "Choose a Referrer-Policy that does not send sensitive paths or query strings across origins.",
    top10: ["A02:2025 Security Misconfiguration"],
    wstg: ["WSTG-CONF-02"],
  },
  "permissions-policy": {
    title: "Browser capability policy",
    weight: 1,
    remediation: "Use Permissions-Policy to disable browser capabilities the application does not need.",
    top10: ["A02:2025 Security Misconfiguration"],
    wstg: ["WSTG-CONF-02"],
  },
  "cross-origin-isolation": {
    title: "Cross-origin isolation headers",
    weight: 2,
    remediation: "Where isolation is required, deploy compatible COOP and COEP policies and use CORP or CORS on embedded resources.",
    top10: ["A01:2025 Broken Access Control", "A02:2025 Security Misconfiguration"],
    wstg: ["WSTG-CLNT-07"],
  },
  "cors-policy": {
    title: "Cross-origin resource sharing",
    weight: 8,
    remediation: "Allow only required origins, never reflect arbitrary origins with credentials, and emit Vary: Origin for dynamic decisions.",
    top10: ["A01:2025 Broken Access Control"],
    wstg: ["WSTG-CLNT-07"],
  },
  "http-methods": {
    title: "HTTP method exposure",
    weight: 3,
    remediation: "Disable TRACE and CONNECT on ordinary web endpoints and require authorization for every state-changing method.",
    top10: ["A01:2025 Broken Access Control", "A02:2025 Security Misconfiguration"],
    wstg: ["WSTG-CONF-06"],
  },
  "cookie-secure": {
    title: "Secure cookie transport",
    weight: 7,
    remediation: "Mark security-sensitive cookies Secure so browsers never send them over cleartext HTTP.",
    top10: ["A04:2025 Cryptographic Failures", "A07:2025 Authentication Failures"],
    wstg: ["WSTG-SESS-02"],
  },
  "cookie-httponly": {
    title: "HttpOnly cookie protection",
    weight: 6,
    remediation: "Mark session and authentication cookies HttpOnly unless client-side script access is explicitly required and reviewed.",
    top10: ["A07:2025 Authentication Failures"],
    wstg: ["WSTG-SESS-02"],
  },
  "cookie-samesite": {
    title: "SameSite cookie policy",
    weight: 6,
    remediation: "Set an explicit SameSite policy for security-sensitive cookies; SameSite=None also requires Secure.",
    top10: ["A01:2025 Broken Access Control", "A07:2025 Authentication Failures"],
    wstg: ["WSTG-SESS-02"],
  },
  "cookie-scope-prefix": {
    title: "Cookie scope and prefixes",
    weight: 4,
    remediation: "Narrow cookie Domain and Path scope and use valid __Host- or __Secure- prefixes for sensitive cookies where possible.",
    top10: ["A01:2025 Broken Access Control", "A07:2025 Authentication Failures"],
    wstg: ["WSTG-SESS-02"],
  },
  "cache-control": {
    title: "Sensitive response caching",
    weight: 3,
    remediation: "Return private or no-store directives on responses containing credentials, sessions, or user-specific sensitive data.",
    top10: ["A02:2025 Security Misconfiguration", "A04:2025 Cryptographic Failures"],
    wstg: ["WSTG-AUTHN-06"],
  },
  "technology-disclosure": {
    title: "Technology disclosure",
    weight: 1,
    remediation: "Remove unnecessary framework, runtime, and precise version banners from public responses.",
    top10: ["A02:2025 Security Misconfiguration"],
    wstg: ["WSTG-INFO-02", "WSTG-INFO-08"],
  },
  "error-handling": {
    title: "Error information exposure",
    weight: 1,
    remediation: "Return generic public errors, keep stack traces and internal paths in protected logs, and handle exceptional conditions securely.",
    top10: ["A10:2025 Mishandling of Exceptional Conditions"],
    wstg: ["WSTG-ERRH-01", "WSTG-ERRH-02"],
  },
  "mixed-content": {
    title: "Mixed-content references",
    weight: 5,
    remediation: "Load scripts, styles, frames, forms, and media over HTTPS and remove hard-coded cleartext resource URLs.",
    top10: ["A04:2025 Cryptographic Failures"],
    wstg: ["WSTG-CRYP-03"],
  },
  "form-transport": {
    title: "Credential form transport",
    weight: 4,
    remediation: "Submit credential forms with POST to an approved HTTPS endpoint and avoid placing credentials in URLs.",
    top10: ["A04:2025 Cryptographic Failures", "A07:2025 Authentication Failures"],
    wstg: ["WSTG-CRYP-03", "WSTG-AUTHN-01"],
  },
  "subresource-integrity": {
    title: "Third-party subresource integrity",
    weight: 4,
    remediation: "Pin eligible third-party scripts and styles with integrity metadata and an appropriate crossorigin mode, or self-host reviewed assets.",
    top10: ["A03:2025 Software Supply Chain Failures", "A08:2025 Software or Data Integrity Failures"],
    wstg: ["WSTG-CLNT-12"],
  },
};

export async function scanWebSecurity(
  hostname: string,
  options: WebSecurityScanOptions = {},
): Promise<WebSecurityScanExecution> {
  try {
    hostname = normalizeDomain(hostname);
  } catch (error) {
    if (error instanceof DomainValidationError) throw new WebSecurityTargetError(error.message);
    throw new WebSecurityTargetError("The target hostname is invalid.");
  }
  const now = options.now ?? Date.now;
  const startedAt = now();
  const scannedAt = new Date(startedAt).toISOString();
  const deadlineAt = startedAt + MAX_SCAN_DURATION_MS;
  const resolver = options.resolver ?? defaultResolveHost;
  const fetcher = options.fetcher ?? ((input, init) => fetch(input, init));
  const initialAddresses = await resolveAndValidatePublicHost(hostname, resolver, {
    now,
    deadlineAt,
  });
  const tlsExecution = options.tlsScanner
    ? await runTlsScan(hostname, initialAddresses, options.tlsScanner)
    : {
      connectionCount: 0,
      assessment: unavailableTlsAssessment(hostname, initialAddresses),
    };
  const context: ProbeContext = {
    originalHostname: hostname,
    resolver,
    fetcher,
    now,
    deadlineAt,
    httpRequests: 0,
    redirectHopsFollowed: 0,
  };

  const httpProbe = await probeRedirectChain(
    new URL(`http://${hostname}/`),
    "HEAD",
    context,
    0,
    false,
  );
  const httpsProbe = await probeRedirectChain(
    new URL(`https://${hostname}/`),
    "GET",
    context,
    MAX_REDIRECT_HOPS,
    true,
  );
  const boundedBody = httpsProbe.response
    ? await readBoundedHtml(httpsProbe.response, context)
    : { isHtml: false, truncated: false } satisfies BoundedBody;
  const htmlEvidence = boundedBody.html === undefined
    ? emptyHtmlEvidence()
    : inspectHtml(boundedBody.html, new URL(httpsProbe.effectiveUrl), boundedBody.truncated);
  const cookieEvidence = httpsProbe.response
    ? parseCookies(httpsProbe.response.headers)
    : { cookies: [], truncated: false, available: false };
  const optionsProbe = await probeOptions(httpsProbe, context);
  const errorProbe = await probeErrorHandling(httpsProbe, context, options.nonce ?? generateProbeNonce);
  const checks = buildChecks({
    httpProbe,
    httpsProbe,
    optionsProbe,
    body: boundedBody,
    html: htmlEvidence,
    cookies: cookieEvidence,
    errorProbe,
  });
  const scoreResult = scoreChecks(checks);
  const headline = scoreResult.grade === "N/A"
    ? "The web hardening grade is incomplete"
    : scoreResult.score >= 90
      ? "Strong observable web hardening"
      : scoreResult.score >= 70
        ? "Several web hardening controls need review"
        : "Important web hardening gaps were observed";
  const summary = buildSummary(checks, scoreResult);

  return {
    hostname,
    effectiveUrl: httpsProbe.effectiveUrl,
    scannedAt,
    durationMs: Math.max(1, Math.round(now() - startedAt)),
    score: scoreResult.score,
    grade: scoreResult.grade,
    headline,
    summary,
    tls: tlsExecution.assessment,
    checks,
    coverage: {
      evaluated: scoreResult.evaluated,
      total: 20,
      unknown: scoreResult.unknown,
      notApplicable: scoreResult.notApplicable,
    },
    requestBudget: {
      httpRequests: context.httpRequests,
      tlsConnections: tlsExecution.connectionCount,
      maxResponseBytes: MAX_RESPONSE_BYTES,
      redirectHopsFollowed: context.redirectHopsFollowed,
    },
    disclaimer: WEB_SECURITY_DISCLAIMER,
  };
}

async function defaultResolveHost(hostname: string): Promise<readonly string[]> {
  const dns = new DnsClient({ timeoutMs: DNS_GUARD_TIMEOUT_MS });
  try {
    const [ipv4, ipv6] = await Promise.all([
      dns.query(hostname, "A"),
      dns.query(hostname, "AAAA"),
    ]);
    return [...ipv4, ...ipv6].map((answer) => answer.data);
  } catch {
    throw new WebSecurityUpstreamError("The target address could not be resolved safely.");
  }
}

async function resolveAndValidatePublicHost(
  hostname: string,
  resolver: WebSecurityResolver,
  timing?: { now: () => number; deadlineAt: number },
): Promise<string[]> {
  let addresses: readonly string[];
  try {
    if (timing) {
      const remaining = timing.deadlineAt - timing.now();
      if (remaining <= 0) throw new RequestBudgetError();
      addresses = await beforeDeadline(
        resolver(hostname),
        Math.min(DNS_GUARD_TIMEOUT_MS, remaining),
      );
    } else {
      addresses = await resolver(hostname);
    }
  } catch (error) {
    if (
      error instanceof RequestBudgetError
      || error instanceof WebSecurityTargetError
      || error instanceof WebSecurityUpstreamError
    ) throw error;
    throw new WebSecurityUpstreamError("The target address could not be resolved safely.");
  }

  if (addresses.length > MAX_RESOLVED_ADDRESSES) {
    throw new WebSecurityTargetError("The target returned too many addresses for a bounded scan.");
  }

  const unique: string[] = [];
  const seen = new Set<string>();
  for (const value of addresses) {
    const address = value.trim();
    if (!address) continue;
    let calculation: ReturnType<typeof calculateIpNetwork>;
    try {
      calculation = calculateIpNetwork(address);
    } catch {
      throw new WebSecurityTargetError("The target returned an invalid address.");
    }
    if (!calculation.isSingleAddress || !calculation.classification.global || isTransitionAddress(calculation.address)) {
      throw new WebSecurityTargetError("The target resolves to a non-public or transition address that cannot be scanned.");
    }
    if (!seen.has(calculation.address)) {
      seen.add(calculation.address);
      unique.push(calculation.address);
    }
  }
  if (unique.length === 0) {
    throw new WebSecurityUpstreamError("The target did not resolve to a public address.");
  }
  if (unique.length > MAX_RESOLVED_ADDRESSES) {
    throw new WebSecurityTargetError("The target returned too many addresses for a bounded scan.");
  }
  return unique.sort();
}

function isTransitionAddress(canonicalAddress: string): boolean {
  // The IP calculator correctly rejects private, mapped, Teredo, and 6to4
  // addresses. NAT64 is globally routable in general but is excluded here
  // because it can translate an apparently public IPv6 destination to a
  // special-use IPv4 address outside the scanner's validation boundary.
  return canonicalAddress.toLowerCase().startsWith("64:ff9b:");
}

async function runTlsScan(
  hostname: string,
  addresses: readonly string[],
  scanner: WebSecurityTlsScanner,
): Promise<TlsScanExecution> {
  try {
    return await scanner(hostname, addresses);
  } catch {
    return {
      connectionCount: 0,
      assessment: unavailableTlsAssessment(hostname, addresses),
    };
  }
}

function unavailableTlsAssessment(hostname: string, addresses: readonly string[]): TlsAssessment {
  return {
    status: "unavailable",
    grade: "N/A",
    summary: "The bounded TLS snapshot was unavailable; this is not evidence of a TLS failure.",
    resolvedAddresses: [...addresses],
    endpoints: [],
    endpointsTruncated: false,
    reportUrl: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(hostname)}&hideResults=on`,
    limitations: [
      "The TLS snapshot is bounded and is not an SSL Labs-equivalent assessment.",
      "Unavailable TLS evidence is never converted into a failed security finding.",
    ],
  };
}

async function probeRedirectChain(
  startUrl: URL,
  method: "GET" | "HEAD",
  context: ProbeContext,
  maxHops: number,
  sendTestOrigin: boolean,
): Promise<ProbeChainResult> {
  let current = new URL(startUrl);
  const seen = new Set<string>();
  const hops: ProbeHop[] = [];

  for (let redirects = 0; ; redirects += 1) {
    current.hash = "";
    if (current.href.length > MAX_URL_LENGTH) {
      return chainFailure(startUrl, current, hops, "unsafe-redirect", "The redirect URL exceeded the safety limit.");
    }
    if (seen.has(current.href)) {
      return chainFailure(startUrl, current, hops, "unsafe-redirect", "A redirect loop was detected.");
    }
    seen.add(current.href);

    let response: Response;
    try {
      response = await guardedFetch(current, method, context, sendTestOrigin);
    } catch (error) {
      if (error instanceof WebSecurityTargetError || error instanceof WebSecurityUpstreamError) throw error;
      const failure = error instanceof RequestBudgetError ? "request-budget" : "fetch";
      return chainFailure(startUrl, current, hops, failure, "The target did not complete the bounded HTTP request.");
    }

    const locationHeader = boundedHeader(response.headers, "location", MAX_URL_LENGTH);
    const location = locationHeader.value;
    hops.push({
      url: current.href,
      status: response.status,
      ...(location ? { location: sanitizeEvidence(location) } : {}),
    });
    if (!isRedirectStatus(response.status) || !location) {
      return {
        startUrl: startUrl.href,
        effectiveUrl: current.href,
        response,
        hops,
      };
    }

    if (locationHeader.truncated) {
      await cancelBody(response);
      return chainFailure(startUrl, current, hops, "unsafe-redirect", "The redirect location exceeded the safety limit.");
    }

    const destination = parseSafeRedirect(current, location, context.originalHostname);
    if (!destination.ok) {
      await cancelBody(response);
      return chainFailure(startUrl, current, hops, destination.kind, destination.reason);
    }

    if (redirects >= maxHops) {
      await cancelBody(response);
      return chainFailure(startUrl, current, hops, "redirect-limit", "The redirect chain exceeded the bounded hop limit.");
    }

    await cancelBody(response);
    current = destination.url;
    context.redirectHopsFollowed += 1;
  }
}

async function guardedFetch(
  url: URL,
  method: "GET" | "HEAD" | "OPTIONS",
  context: ProbeContext,
  sendTestOrigin: boolean,
): Promise<Response> {
  if (context.httpRequests >= MAX_HTTP_REQUESTS) throw new RequestBudgetError();
  const validatedAddresses = await resolveAndValidatePublicHost(url.hostname, context.resolver, context);
  const availableForFetch = context.deadlineAt - context.now() - DNS_GUARD_TIMEOUT_MS;
  if (availableForFetch <= 0) throw new RequestBudgetError();
  context.httpRequests += 1;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Math.min(FETCH_TIMEOUT_MS, availableForFetch));
  let response: Response | undefined;
  let fetchError: unknown;
  try {
    response = await context.fetcher(url.href, {
      method,
      redirect: "manual",
      cache: "no-store",
      signal: controller.signal,
      headers: {
        Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
        "User-Agent": SCANNER_USER_AGENT,
        ...(sendTestOrigin ? { Origin: TEST_ORIGIN } : {}),
      },
    }, {
      hostname: url.hostname,
      validatedAddresses,
    });
  } catch (error) {
    fetchError = error;
  } finally {
    clearTimeout(timeout);
  }

  let confirmedAddresses: string[];
  try {
    confirmedAddresses = await resolveAndValidatePublicHost(url.hostname, context.resolver, context);
  } catch (error) {
    if (response) await cancelBody(response);
    throw error;
  }
  if (!sameAddressSet(validatedAddresses, confirmedAddresses)) {
    if (response) await cancelBody(response);
    throw new WebSecurityTargetError(
      "The target's DNS address set changed during a request, so the scan stopped to prevent DNS rebinding.",
    );
  }
  if (fetchError !== undefined) throw fetchError;
  if (!response) throw new WebSecurityUpstreamError("The target returned no HTTP response.");
  return response;
}

async function probeOptions(
  httpsProbe: ProbeChainResult,
  context: ProbeContext,
): Promise<ProbeChainResult | undefined> {
  if (!httpsProbe.response || httpsProbe.failure || !httpsProbe.effectiveUrl.startsWith("https://")) return undefined;
  const url = new URL(httpsProbe.effectiveUrl);
  try {
    const response = await guardedFetch(url, "OPTIONS", context, true);
    const result: ProbeChainResult = {
      startUrl: url.href,
      effectiveUrl: url.href,
      response,
      hops: [{ url: url.href, status: response.status }],
    };
    await cancelBody(response);
    return result;
  } catch (error) {
    if (error instanceof WebSecurityTargetError || error instanceof WebSecurityUpstreamError) throw error;
    return chainFailure(url, url, [], error instanceof RequestBudgetError ? "request-budget" : "fetch", "The OPTIONS observation was unavailable.");
  }
}

function parseSafeRedirect(
  current: URL,
  location: string,
  originalHostname: string,
): { ok: true; url: URL } | {
  ok: false;
  kind: "unsafe-redirect" | "cross-host-redirect";
  reason: string;
} {
  let destination: URL;
  try {
    destination = new URL(location, current);
  } catch {
    return { ok: false, kind: "unsafe-redirect", reason: "The target returned an invalid redirect location." };
  }
  destination.hash = "";
  if (destination.protocol !== "http:" && destination.protocol !== "https:") {
    return { ok: false, kind: "unsafe-redirect", reason: "The redirect used a protocol outside the HTTP scan scope." };
  }
  if (current.protocol === "https:" && destination.protocol !== "https:") {
    return { ok: false, kind: "unsafe-redirect", reason: "The redirect attempted to downgrade an HTTPS request." };
  }
  if (destination.username || destination.password || destination.port) {
    return { ok: false, kind: "unsafe-redirect", reason: "The redirect included credentials or a non-standard port." };
  }
  if (isAddressLiteral(destination.hostname) || isSpecialUseHostname(destination.hostname)) {
    return {
      ok: false,
      kind: "unsafe-redirect",
      reason: "The redirect targeted an IP literal or special-use hostname and was not followed.",
    };
  }
  if (!isAllowedRedirectHostname(originalHostname, destination.hostname.toLowerCase())) {
    return {
      ok: false,
      kind: "cross-host-redirect",
      reason: "The redirect left the exact hostname or its www counterpart and was not followed.",
    };
  }
  if (destination.href.length > MAX_URL_LENGTH) {
    return { ok: false, kind: "unsafe-redirect", reason: "The redirect URL exceeded the safety limit." };
  }
  return { ok: true, url: destination };
}

function isAllowedRedirectHostname(original: string, candidate: string): boolean {
  const normalized = original.toLowerCase();
  if (candidate === normalized) return true;
  return normalized.startsWith("www.")
    ? candidate === normalized.slice(4)
    : candidate === `www.${normalized}`;
}

function isAddressLiteral(hostname: string): boolean {
  const value = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  try {
    return calculateIpNetwork(value).isSingleAddress;
  } catch {
    return false;
  }
}

function isSpecialUseHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/\.$/u, "");
  return ["localhost", "local", "internal", "invalid", "test", "example", "home", "lan", "localdomain", "onion"]
    .some((suffix) => normalized === suffix || normalized.endsWith(`.${suffix}`));
}

function isRedirectStatus(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function chainFailure(
  start: URL,
  current: URL,
  hops: ProbeHop[],
  failure: NonNullable<ProbeChainResult["failure"]>,
  failureDetail: string,
): ProbeChainResult {
  return {
    startUrl: start.href,
    effectiveUrl: current.href,
    hops,
    failure,
    failureDetail,
  };
}

class RequestBudgetError extends Error {}

async function cancelBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // A body that has already closed does not need any further work.
  }
}

async function readBoundedHtml(response: Response, context: ProbeContext): Promise<BoundedBody> {
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  const isHtml = contentType.includes("text/html") || contentType.includes("application/xhtml+xml");
  if (!isHtml || !response.body) {
    await cancelBody(response);
    return { isHtml, truncated: false };
  }
  const body = await readBoundedTextStream(response, context);
  return { html: body.text ?? "", isHtml: true, truncated: body.truncated };
}

function buildChecks(input: {
  httpProbe: ProbeChainResult;
  httpsProbe: ProbeChainResult;
  optionsProbe?: ProbeChainResult;
  body: BoundedBody;
  html: HtmlEvidence;
  cookies: CookieEvidence;
  errorProbe: ErrorProbeResult;
}): WebSecurityCheck[] {
  const response = input.httpsProbe.response;
  const checks = new Map<WebSecurityCheckId, WebSecurityCheck>();
  const add = (check: WebSecurityCheck) => checks.set(check.id, check);

  add(checkHttpsEnforcement(input.httpProbe, input.httpsProbe));
  add(checkHsts(response));
  add(checkCsp(response));
  add(checkFrameProtection(response));
  add(checkMimeSniffing(response));
  add(checkReferrerPolicy(response));
  add(checkPermissionsPolicy(response));
  add(checkCrossOriginIsolation(response));
  add(checkCors(response));
  add(checkHttpMethods(input.optionsProbe));
  add(checkCookieSecure(input.cookies));
  add(checkCookieHttpOnly(input.cookies));
  add(checkCookieSameSite(input.cookies));
  add(checkCookieScope(input.cookies));
  add(checkCacheControl(response, input.cookies, input.html));
  add(checkTechnologyDisclosure(response, input.html));
  add(checkErrorHandling(input.errorProbe));
  add(checkMixedContent(response, input.body, input.html));
  add(checkFormTransport(response, input.httpsProbe.effectiveUrl, input.body, input.html));
  add(checkSubresourceIntegrity(response, input.body, input.html));

  return CHECK_ORDER.map((id) => {
    const check = checks.get(id);
    if (check) return check;
    return makeCheck(id, "unknown", "The check did not produce bounded evidence.");
  });
}

function checkHttpsEnforcement(
  httpProbe: ProbeChainResult,
  httpsProbe: ProbeChainResult,
): WebSecurityCheck {
  const evidence = [
    ...summarizeChain("HTTP", httpProbe),
    ...summarizeChain("HTTPS", httpsProbe),
  ];
  const httpFirst = httpProbe.hops[0];
  if (!httpsProbe.response) {
    if (httpFirst && httpFirst.status >= 200 && httpFirst.status < 300) {
      return makeCheck(
        "https-enforcement",
        "fail",
        "The cleartext HTTP endpoint returned content and the HTTPS root response was unavailable.",
        evidence,
      );
    }
    if (httpProbe.failure === "unsafe-redirect") {
      return makeCheck(
        "https-enforcement",
        "fail",
        httpProbe.failureDetail ?? "The cleartext redirect was unsafe.",
        evidence,
      );
    }
    if (httpsProbe.failure === "unsafe-redirect") {
      return makeCheck(
        "https-enforcement",
        "fail",
        httpsProbe.failureDetail ?? "The HTTPS endpoint returned an unsafe redirect.",
        evidence,
      );
    }
    if (httpsProbe.failure === "cross-host-redirect") {
      return makeCheck(
        "https-enforcement",
        "warning",
        "The HTTPS root redirected to a different public hostname that this bounded scan did not follow.",
        evidence,
      );
    }
    if (httpProbe.failure === "cross-host-redirect") {
      return makeCheck(
        "https-enforcement",
        "warning",
        "Cleartext HTTP redirected to a different public hostname that this bounded scan did not follow.",
        evidence,
      );
    }
    return makeCheck(
      "https-enforcement",
      "unknown",
      "The HTTPS root response was unavailable, so transport enforcement could not be verified.",
      evidence,
    );
  }

  const reachedHttps = httpProbe.hops.some((hop) => hop.url.startsWith("https://"))
    || redirectLocationUsesHttps(httpFirst);
  if (httpFirst && httpFirst.status >= 200 && httpFirst.status < 300) {
    return makeCheck(
      "https-enforcement",
      "fail",
      "The cleartext HTTP endpoint returned content instead of an HTTPS upgrade.",
      evidence,
    );
  }
  if (httpProbe.failure === "cross-host-redirect") {
    return makeCheck(
      "https-enforcement",
      "warning",
      "Cleartext HTTP redirected to a different public hostname that this bounded scan did not follow.",
      evidence,
    );
  }
  if (httpProbe.failure === "unsafe-redirect") {
    return makeCheck(
      "https-enforcement",
      "fail",
      httpProbe.failureDetail ?? "The cleartext redirect was unsafe.",
      evidence,
    );
  }
  if (httpFirst && reachedHttps && (httpFirst.status === 301 || httpFirst.status === 308)) {
    return makeCheck(
      "https-enforcement",
      "pass",
      "HTTPS was reachable and cleartext HTTP used a permanent upgrade within the approved hostname boundary.",
      evidence,
    );
  }
  if (httpFirst && reachedHttps && isRedirectStatus(httpFirst.status)) {
    return makeCheck(
      "https-enforcement",
      "warning",
      "HTTPS was reachable, but the cleartext upgrade was temporary or indirect.",
      evidence,
    );
  }
  if (
    httpProbe.failure === "fetch"
    || httpProbe.failure === "request-budget"
    || httpFirst?.status === 405
    || httpFirst?.status === 429
    || httpFirst?.status === 501
    || (httpFirst !== undefined && httpFirst.status >= 500)
  ) {
    return makeCheck(
      "https-enforcement",
      "unknown",
      "HTTPS was reachable, but the bounded HEAD observation did not provide reliable cleartext redirect evidence.",
      evidence,
    );
  }
  return makeCheck(
    "https-enforcement",
    "warning",
    "HTTPS was reachable, but a permanent cleartext-to-HTTPS upgrade was not confirmed.",
    evidence,
  );
}

function checkHsts(response: Response | undefined): WebSecurityCheck {
  if (!response) return unavailableHeaderCheck("hsts");
  const header = boundedHeader(response.headers, "strict-transport-security");
  if (!header.value) {
    return makeCheck("hsts", "warning", "No HSTS policy was observed on the HTTPS response.");
  }
  const directives = parseDirectives(header.value);
  const maxAgeText = directives.get("max-age");
  const maxAge = typeof maxAgeText === "string" && /^\d+$/u.test(maxAgeText)
    ? Number(maxAgeText)
    : Number.NaN;
  const evidence = [sanitizeEvidence(`Strict-Transport-Security: ${header.value}`)];
  if (!Number.isSafeInteger(maxAge) || maxAge < 0) {
    return makeCheck("hsts", "fail", "The HSTS max-age directive was missing or invalid.", evidence);
  }
  if (maxAge === 0) {
    return makeCheck("hsts", "fail", "The HSTS policy explicitly disables transport pinning with max-age=0.", evidence);
  }
  if (header.truncated) {
    return makeCheck("hsts", "unknown", "The HSTS header exceeded the evidence limit and was not fully evaluated.", evidence);
  }
  if (maxAge >= 31_536_000 && directives.has("includesubdomains")) {
    return makeCheck("hsts", "pass", "HSTS uses at least a one-year lifetime and covers subdomains.", evidence);
  }
  return makeCheck(
    "hsts",
    "warning",
    maxAge < 15_552_000
      ? "HSTS was present, but its lifetime was shorter than six months."
      : "HSTS was present, but it did not combine a one-year lifetime with includeSubDomains.",
    evidence,
  );
}

function checkCsp(response: Response | undefined): WebSecurityCheck {
  if (!response) return unavailableHeaderCheck("content-security-policy");
  const enforced = boundedHeader(response.headers, "content-security-policy");
  const reportOnly = boundedHeader(response.headers, "content-security-policy-report-only");
  if (!enforced.value) {
    return makeCheck(
      "content-security-policy",
      "warning",
      reportOnly.value
        ? "Only a report-only CSP was observed; it does not enforce browser restrictions."
        : "No enforced Content-Security-Policy header was observed.",
      reportOnly.value ? [sanitizeEvidence(`Report-Only: ${reportOnly.value}`)] : [],
    );
  }

  const directives = parseCsp(enforced.value);
  const scriptSources = directives.get("script-src") ?? directives.get("default-src") ?? [];
  const defaultSources = directives.get("default-src") ?? [];
  const weaknesses: string[] = [];
  if (scriptSources.includes("'unsafe-eval'")) weaknesses.push("script execution permits 'unsafe-eval'");
  if (scriptSources.includes("'unsafe-inline'") && !scriptSources.some(isNonceOrHashSource)) {
    weaknesses.push("inline script is allowed without an observed nonce or hash");
  }
  if (scriptSources.includes("*") || defaultSources.includes("*")) weaknesses.push("a wildcard source is allowed");
  if (!directives.has("object-src") && !directives.has("default-src")) weaknesses.push("object sources are not bounded");
  if (!directives.has("base-uri")) weaknesses.push("base-uri is not restricted");
  if (!directives.has("frame-ancestors")) weaknesses.push("frame-ancestors is not declared");
  const evidence = [sanitizeEvidence(`Content-Security-Policy: ${enforced.value}`)];
  if (enforced.truncated) {
    return makeCheck("content-security-policy", "unknown", "The CSP exceeded the evidence limit and could not be fully evaluated.", evidence);
  }
  if (weaknesses.length > 0) {
    return makeCheck(
      "content-security-policy",
      "warning",
      `An enforced CSP was present, but ${weaknesses.join("; ")}.`,
      evidence,
    );
  }
  return makeCheck("content-security-policy", "pass", "An enforced CSP was present without the bounded high-risk patterns tested here.", evidence);
}

function checkFrameProtection(response: Response | undefined): WebSecurityCheck {
  if (!response) return unavailableHeaderCheck("frame-protection");
  const csp = boundedHeader(response.headers, "content-security-policy");
  const xfo = boundedHeader(response.headers, "x-frame-options");
  const ancestors = csp.value ? parseCsp(csp.value).get("frame-ancestors") : undefined;
  const evidence = [
    ...(ancestors ? [sanitizeEvidence(`CSP frame-ancestors ${ancestors.join(" ")}`)] : []),
    ...(xfo.value ? [sanitizeEvidence(`X-Frame-Options: ${xfo.value}`)] : []),
  ];
  if (ancestors?.includes("*")) {
    return makeCheck("frame-protection", "fail", "CSP frame-ancestors permits every framing origin.", evidence);
  }
  if (ancestors && ancestors.length > 0) {
    return makeCheck("frame-protection", "pass", "CSP explicitly controls which origins may frame the page.", evidence);
  }
  const normalized = xfo.value?.trim().toUpperCase();
  if (normalized === "DENY" || normalized === "SAMEORIGIN") {
    return makeCheck("frame-protection", "pass", "A valid legacy frame-embedding restriction was observed.", evidence);
  }
  if (normalized?.startsWith("ALLOW-FROM")) {
    return makeCheck("frame-protection", "warning", "X-Frame-Options uses obsolete ALLOW-FROM syntax.", evidence);
  }
  return makeCheck("frame-protection", "warning", "No effective frame-embedding restriction was observed.", evidence);
}

function checkMimeSniffing(response: Response | undefined): WebSecurityCheck {
  if (!response) return unavailableHeaderCheck("mime-sniffing");
  const header = boundedHeader(response.headers, "x-content-type-options");
  return header.value?.trim().toLowerCase() === "nosniff"
    ? makeCheck("mime-sniffing", "pass", "X-Content-Type-Options is set to nosniff.", ["X-Content-Type-Options: nosniff"])
    : makeCheck("mime-sniffing", "warning", "X-Content-Type-Options: nosniff was not observed.", header.value ? [sanitizeEvidence(header.value)] : []);
}

function checkReferrerPolicy(response: Response | undefined): WebSecurityCheck {
  if (!response) return unavailableHeaderCheck("referrer-policy");
  const header = boundedHeader(response.headers, "referrer-policy");
  if (!header.value) return makeCheck("referrer-policy", "warning", "No explicit Referrer-Policy was observed.");
  const policies = header.value.toLowerCase().split(",").map((value) => value.trim()).filter(Boolean);
  const effective = policies.at(-1) ?? "";
  const evidence = [sanitizeEvidence(`Referrer-Policy: ${header.value}`)];
  if (effective === "unsafe-url") {
    return makeCheck("referrer-policy", "fail", "The effective Referrer-Policy sends full URLs to other origins.", evidence);
  }
  if (["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"].includes(effective)) {
    return makeCheck("referrer-policy", "pass", "The effective referrer policy limits cross-origin URL disclosure.", evidence);
  }
  return makeCheck("referrer-policy", "warning", "A referrer policy was present but allows more cross-origin detail than the strongest common policies.", evidence);
}

function checkPermissionsPolicy(response: Response | undefined): WebSecurityCheck {
  if (!response) return unavailableHeaderCheck("permissions-policy");
  const header = boundedHeader(response.headers, "permissions-policy");
  if (!header.value) return makeCheck("permissions-policy", "warning", "No Permissions-Policy header was observed.");
  const restricted = ["camera", "microphone", "geolocation", "payment", "usb"]
    .filter((capability) => new RegExp(`(?:^|,)\\s*${capability}\\s*=\\s*\\(\\s*\\)`, "iu").test(header.value ?? ""));
  const evidence = [sanitizeEvidence(`Permissions-Policy: ${header.value}`)];
  if (header.truncated) return makeCheck("permissions-policy", "unknown", "The Permissions-Policy header was too large to evaluate fully.", evidence);
  return restricted.length > 0
    ? makeCheck("permissions-policy", "pass", `The policy explicitly disables ${restricted.join(", ")}.`, evidence)
    : makeCheck("permissions-policy", "warning", "A policy was present, but none of the bounded sensitive capabilities were explicitly disabled.", evidence);
}

function checkCrossOriginIsolation(response: Response | undefined): WebSecurityCheck {
  if (!response) return unavailableHeaderCheck("cross-origin-isolation");
  const coop = boundedHeader(response.headers, "cross-origin-opener-policy").value?.toLowerCase();
  const coep = boundedHeader(response.headers, "cross-origin-embedder-policy").value?.toLowerCase();
  const corp = boundedHeader(response.headers, "cross-origin-resource-policy").value?.toLowerCase();
  const evidence = [
    ...(coop ? [sanitizeEvidence(`COOP: ${coop}`)] : []),
    ...(coep ? [sanitizeEvidence(`COEP: ${coep}`)] : []),
    ...(corp ? [sanitizeEvidence(`CORP: ${corp}`)] : []),
  ];
  if (!coop && !coep && !corp) {
    return makeCheck(
      "cross-origin-isolation",
      "not-applicable",
      "No cross-origin isolation headers were observed; whether isolation is required depends on application features.",
    );
  }
  if (coop === "same-origin" && (coep === "require-corp" || coep === "credentialless")) {
    return makeCheck("cross-origin-isolation", "pass", "Compatible COOP and COEP document-isolation policies were observed.", evidence);
  }
  return makeCheck("cross-origin-isolation", "warning", "Cross-origin isolation headers were present but did not form a complete same-origin isolation policy.", evidence);
}

function checkCors(response: Response | undefined): WebSecurityCheck {
  if (!response) return unavailableHeaderCheck("cors-policy");
  const allowOrigin = boundedHeader(response.headers, "access-control-allow-origin");
  const credentials = boundedHeader(response.headers, "access-control-allow-credentials").value?.trim().toLowerCase() === "true";
  const vary = boundedHeader(response.headers, "vary").value?.toLowerCase() ?? "";
  if (!allowOrigin.value) {
    return makeCheck("cors-policy", "pass", "The root response did not grant cross-origin reads to the scanner's test origin.");
  }
  const normalized = allowOrigin.value.trim();
  const evidence = [
    sanitizeEvidence(`Access-Control-Allow-Origin: ${normalized}`),
    ...(credentials ? ["Access-Control-Allow-Credentials: true"] : []),
    ...(vary ? [sanitizeEvidence(`Vary: ${vary}`)] : []),
  ];
  if (normalized === TEST_ORIGIN && credentials) {
    return makeCheck("cors-policy", "fail", "The response reflected an arbitrary test origin while allowing credentials.", evidence);
  }
  if (normalized === TEST_ORIGIN) {
    return makeCheck(
      "cors-policy",
      "warning",
      vary.split(",").some((value) => value.trim() === "origin")
        ? "The response reflected the arbitrary test origin without credentials; confirm that the data is intended to be public."
        : "The response reflected the arbitrary test origin and did not declare Vary: Origin.",
      evidence,
    );
  }
  if (normalized === "*") {
    return credentials
      ? makeCheck("cors-policy", "fail", "The response combines a wildcard origin with credential permission, an invalid and unsafe CORS policy.", evidence)
      : makeCheck("cors-policy", "warning", "The root response allows every origin; this may be correct only for intentionally public data.", evidence);
  }
  return makeCheck("cors-policy", "pass", "The response did not grant the scanner's arbitrary test origin access.", evidence);
}

function checkHttpMethods(optionsProbe: ProbeChainResult | undefined): WebSecurityCheck {
  if (!optionsProbe || optionsProbe.failure || !optionsProbe.response) {
    return makeCheck("http-methods", "unknown", "The bounded OPTIONS observation was unavailable; no methods were inferred.");
  }
  const response = optionsProbe.response;
  if (response.status === 405 || response.status === 501) {
    return makeCheck(
      "http-methods",
      "unknown",
      `The root endpoint rejected OPTIONS with HTTP ${response.status}; this does not prove that TRACE or CONNECT is disabled.`,
      [`HTTP ${response.status}`],
    );
  }
  const allow = boundedHeader(response.headers, "allow");
  const corsMethods = boundedHeader(response.headers, "access-control-allow-methods");
  const raw = [allow.value, corsMethods.value].filter((value): value is string => Boolean(value)).join(",");
  if (!raw) {
    return makeCheck("http-methods", "unknown", "The OPTIONS response did not declare an Allow method set.", [`HTTP ${response.status}`]);
  }
  const methods = [...new Set(raw.split(",").map((method) => method.trim().toUpperCase()).filter(Boolean))];
  const evidence = [sanitizeEvidence(`Declared methods: ${methods.join(", ")}`)];
  if (methods.includes("TRACE") || methods.includes("CONNECT")) {
    return makeCheck("http-methods", "fail", "TRACE or CONNECT was declared on the ordinary web root.", evidence);
  }
  if (methods.some((method) => ["PUT", "PATCH", "DELETE"].includes(method))) {
    return makeCheck("http-methods", "warning", "State-changing methods were declared; authorization cannot be verified by this non-invasive scan.", evidence);
  }
  return makeCheck("http-methods", "pass", "Only ordinary retrieval or preflight methods were declared by the root endpoint.", evidence);
}

function checkCookieSecure(evidence: CookieEvidence): WebSecurityCheck {
  const cookies = cookiesForSecurityEvaluation(evidence);
  if (cookies.length === 0) return noCookieCheck("cookie-secure", evidence);
  const missing = cookies.filter((cookie) => !cookie.attributes.has("secure"));
  if (missing.length > 0) {
    return makeCheck(
      "cookie-secure",
      missing.some((cookie) => cookie.authLike) ? "fail" : "warning",
      `${missing.length} observed ${plural(missing.length, "cookie was", "cookies were")} not marked Secure.`,
      cookieNames(missing),
    );
  }
  if (evidence.truncated) return truncatedCookieCheck("cookie-secure");
  return makeCheck("cookie-secure", "pass", "Every security-relevant cookie observed on the root response was marked Secure.", cookieNames(cookies));
}

function checkCookieHttpOnly(evidence: CookieEvidence): WebSecurityCheck {
  const cookies = cookiesForSecurityEvaluation(evidence);
  if (cookies.length === 0) return noCookieCheck("cookie-httponly", evidence);
  const missing = cookies.filter((cookie) => !cookie.attributes.has("httponly"));
  if (missing.length > 0) {
    return makeCheck(
      "cookie-httponly",
      missing.some((cookie) => cookie.authLike) ? "fail" : "warning",
      `${missing.length} observed ${plural(missing.length, "cookie was", "cookies were")} not marked HttpOnly.`,
      cookieNames(missing),
    );
  }
  if (evidence.truncated) return truncatedCookieCheck("cookie-httponly");
  return makeCheck("cookie-httponly", "pass", "Every security-relevant cookie observed on the root response was marked HttpOnly.", cookieNames(cookies));
}

function checkCookieSameSite(evidence: CookieEvidence): WebSecurityCheck {
  const cookies = cookiesForSecurityEvaluation(evidence);
  if (cookies.length === 0) return noCookieCheck("cookie-samesite", evidence);
  const invalidNone = cookies.filter((cookie) =>
    String(cookie.attributes.get("samesite") ?? "").toLowerCase() === "none"
      && !cookie.attributes.has("secure"));
  if (invalidNone.length > 0) {
    return makeCheck(
      "cookie-samesite",
      "fail",
      "A SameSite=None cookie was observed without the required Secure attribute.",
      cookieNames(invalidNone),
    );
  }
  const missing = cookies.filter((cookie) => !cookie.attributes.has("samesite"));
  const invalid = cookies.filter((cookie) => {
    const value = String(cookie.attributes.get("samesite") ?? "").toLowerCase();
    return value !== "" && !["strict", "lax", "none"].includes(value);
  });
  if (invalid.length > 0) {
    return makeCheck("cookie-samesite", "fail", "An invalid SameSite attribute was observed.", cookieNames(invalid));
  }
  if (missing.length > 0) {
    return makeCheck(
      "cookie-samesite",
      "warning",
      `${missing.length} security-relevant ${plural(missing.length, "cookie has", "cookies have")} no explicit SameSite policy.`,
      cookieNames(missing),
    );
  }
  if (evidence.truncated) return truncatedCookieCheck("cookie-samesite");
  return makeCheck("cookie-samesite", "pass", "Every security-relevant cookie observed on the root response had a valid explicit SameSite policy.", cookieNames(cookies));
}

function checkCookieScope(evidence: CookieEvidence): WebSecurityCheck {
  const cookies = cookiesForSecurityEvaluation(evidence);
  if (cookies.length === 0) return noCookieCheck("cookie-scope-prefix", evidence);
  const invalidPrefixes = cookies.filter((cookie) => {
    const lower = cookie.name.toLowerCase();
    if (lower.startsWith("__host-")) {
      return !cookie.attributes.has("secure")
        || cookie.attributes.has("domain")
        || cookie.attributes.get("path") !== "/";
    }
    return lower.startsWith("__secure-") && !cookie.attributes.has("secure");
  });
  if (invalidPrefixes.length > 0) {
    return makeCheck("cookie-scope-prefix", "fail", "A cookie used a security prefix without satisfying that prefix's browser requirements.", cookieNames(invalidPrefixes));
  }
  const broad = cookies.filter((cookie) => cookie.attributes.has("domain"));
  if (broad.length > 0) {
    return makeCheck(
      "cookie-scope-prefix",
      "warning",
      "A security-relevant cookie used a Domain attribute and is therefore available to more hosts than a host-only cookie.",
      cookieNames(broad),
    );
  }
  if (evidence.truncated) return truncatedCookieCheck("cookie-scope-prefix");
  return makeCheck("cookie-scope-prefix", "pass", "The security-relevant cookies observed were host-only and used any security prefixes consistently.", cookieNames(cookies));
}

function checkCacheControl(
  response: Response | undefined,
  cookies: CookieEvidence,
  html: HtmlEvidence,
): WebSecurityCheck {
  if (!response) return unavailableHeaderCheck("cache-control");
  const hasSensitiveSignal = cookies.cookies.some((cookie) => cookie.authLike)
    || html.forms.some((form) => form.hasPassword)
    || html.orphanPasswordInput;
  if (!hasSensitiveSignal) {
    return makeCheck(
      "cache-control",
      "not-applicable",
      "The anonymous root response did not expose a bounded session or credential-form signal that would require a sensitive-cache judgment.",
    );
  }
  const cacheControl = boundedHeader(response.headers, "cache-control");
  const pragma = boundedHeader(response.headers, "pragma");
  const directives = cacheControl.value ? parseDirectives(cacheControl.value) : new Map<string, string | true>();
  const evidence = [
    ...(cacheControl.value ? [sanitizeEvidence(`Cache-Control: ${cacheControl.value}`)] : []),
    ...(pragma.value ? [sanitizeEvidence(`Pragma: ${pragma.value}`)] : []),
  ];
  if (cacheControl.truncated || pragma.truncated) {
    return makeCheck("cache-control", "unknown", "A cache policy header exceeded the evidence limit.", evidence);
  }
  if (directives.has("public") || directives.has("s-maxage")) {
    return makeCheck("cache-control", "fail", "A response with a session or credential signal explicitly permits shared caching.", evidence);
  }
  if (directives.has("no-store") || directives.has("private")) {
    return makeCheck("cache-control", "pass", "The response uses a private or no-store cache policy for the observed sensitive signal.", evidence);
  }
  return makeCheck("cache-control", "warning", "A response with a session or credential signal lacked an explicit private or no-store policy.", evidence);
}

function checkTechnologyDisclosure(
  response: Response | undefined,
  html: HtmlEvidence,
): WebSecurityCheck {
  if (!response) return unavailableHeaderCheck("technology-disclosure");
  const banners: string[] = [];
  for (const name of ["server", "x-powered-by", "x-aspnet-version", "x-runtime"] as const) {
    const header = boundedHeader(response.headers, name);
    if (header.value) banners.push(sanitizeEvidence(`${name}: ${header.value}`));
  }
  banners.push(...html.generators.map((value) => sanitizeEvidence(`generator: ${value}`)));
  if (banners.length === 0) {
    return html.limited
      ? makeCheck("technology-disclosure", "unknown", "No technology banner was found, but the HTML evidence was incomplete.")
      : makeCheck("technology-disclosure", "pass", "No common framework, runtime, version, or generator banner was observed.");
  }
  const precise = banners.some((value) => /(?:^|[\s/])v?\d+(?:\.\d+){1,3}(?:\b|$)/u.test(value));
  const powered = banners.some((value) => /^(?:x-powered-by|x-aspnet-version|x-runtime|generator):/iu.test(value));
  return makeCheck(
    "technology-disclosure",
    precise || powered ? "warning" : "pass",
    precise || powered
      ? "The response disclosed framework, runtime, generator, or version information that may be unnecessary."
      : "Only a generic server banner was observed; no precise technology version was exposed.",
    banners,
  );
}

function checkErrorHandling(probe: ErrorProbeResult): WebSecurityCheck {
  if (!probe.response || probe.failure) {
    return makeCheck("error-handling", "unknown", "The generated-nonce not-found observation was unavailable.");
  }
  const text = probe.body.text ?? "";
  const evidence = [`Generated-nonce probe returned HTTP ${probe.response.status}`];
  if (containsInternalErrorEvidence(text)) {
    return makeCheck(
      "error-handling",
      "fail",
      "The generated-nonce response exposed a bounded stack-trace, exception, or internal-path pattern.",
      evidence,
    );
  }
  if (probe.body.truncated) {
    return makeCheck("error-handling", "unknown", "The generated-nonce response exceeded the body or time limit and could not be fully evaluated.", evidence);
  }
  if (probe.response.status === 404 || probe.response.status === 410) {
    return makeCheck("error-handling", "pass", "A generated, non-existent path returned a bounded not-found response without the internal error patterns tested.", evidence);
  }
  if (probe.response.status >= 500) {
    return makeCheck("error-handling", "warning", "A generated, non-existent path triggered a server error even though no internal detail pattern was observed.", evidence);
  }
  if (probe.response.status >= 200 && probe.response.status < 400) {
    return makeCheck("error-handling", "warning", "A generated, non-existent path returned success or redirect behavior, so not-found handling was not confirmed.", evidence);
  }
  return makeCheck("error-handling", "unknown", "The generated-nonce response did not provide reliable public error-handling evidence.", evidence);
}

function checkMixedContent(
  response: Response | undefined,
  body: BoundedBody,
  html: HtmlEvidence,
): WebSecurityCheck {
  if (!response) return makeCheck("mixed-content", "unknown", "The HTTPS document was unavailable.");
  if (!body.isHtml) return makeCheck("mixed-content", "not-applicable", "The root response was not an HTML document.");
  if (html.mixedContent.length > 0) {
    return makeCheck(
      "mixed-content",
      "fail",
      "The HTTPS document contained explicit cleartext HTTP subresource references.",
      html.mixedContent,
    );
  }
  if (html.limited) {
    return makeCheck("mixed-content", "unknown", "No mixed-content reference was found in the bounded portion, but the HTML evidence was incomplete.");
  }
  return makeCheck("mixed-content", "pass", "No explicit cleartext HTTP subresource reference was found in the bounded HTML document.");
}

function checkFormTransport(
  response: Response | undefined,
  effectiveUrl: string,
  body: BoundedBody,
  html: HtmlEvidence,
): WebSecurityCheck {
  if (!response) return makeCheck("form-transport", "unknown", "The HTTPS document was unavailable.");
  if (!body.isHtml) return makeCheck("form-transport", "not-applicable", "The root response was not an HTML document.");
  const credentialForms = html.forms.filter((form) => form.hasPassword);
  if (credentialForms.length === 0 && !html.orphanPasswordInput) {
    return html.limited
      ? makeCheck("form-transport", "unknown", "No credential form was found in the bounded portion, but the HTML evidence was incomplete.")
      : makeCheck("form-transport", "not-applicable", "No password input was observed in the bounded HTML document.");
  }

  const unsafe = credentialForms.filter((form) => form.method !== "post" || !form.action.startsWith("https://"));
  if (unsafe.length > 0) {
    return makeCheck(
      "form-transport",
      "fail",
      "A password form used a non-POST method, an invalid action, or a non-HTTPS destination.",
      unsafe.map((form) => sanitizeEvidence(`${form.method.toUpperCase()} ${form.action}`)),
    );
  }
  const pageOrigin = new URL(effectiveUrl).origin;
  const crossOrigin = credentialForms.filter((form) => {
    try {
      return new URL(form.action).origin !== pageOrigin;
    } catch {
      return true;
    }
  });
  if (crossOrigin.length > 0 || html.orphanPasswordInput) {
    return makeCheck(
      "form-transport",
      "warning",
      crossOrigin.length > 0
        ? "A password form submits over HTTPS to another origin; authorization and trust require manual review."
        : "A password input was not associated with a bounded form element, so its submission path is unclear.",
      crossOrigin.map((form) => sanitizeEvidence(`${form.method.toUpperCase()} ${form.action}`)),
    );
  }
  if (html.limited) {
    return makeCheck("form-transport", "unknown", "Observed password forms used same-origin HTTPS POST, but the HTML evidence was incomplete.");
  }
  return makeCheck("form-transport", "pass", "Observed password forms used same-origin HTTPS POST destinations.");
}

function checkSubresourceIntegrity(
  response: Response | undefined,
  body: BoundedBody,
  html: HtmlEvidence,
): WebSecurityCheck {
  if (!response) return makeCheck("subresource-integrity", "unknown", "The HTTPS document was unavailable.");
  if (!body.isHtml) return makeCheck("subresource-integrity", "not-applicable", "The root response was not an HTML document.");
  if (html.externalExecutables.length === 0) {
    return html.limited
      ? makeCheck("subresource-integrity", "unknown", "No eligible third-party executable resource was found in the bounded portion, but the HTML evidence was incomplete.")
      : makeCheck("subresource-integrity", "not-applicable", "No eligible third-party script or stylesheet was observed.");
  }
  if (html.missingIntegrity.length > 0) {
    return makeCheck(
      "subresource-integrity",
      "warning",
      "At least one eligible third-party script or stylesheet lacked integrity metadata.",
      html.missingIntegrity,
    );
  }
  if (html.limited) {
    return makeCheck("subresource-integrity", "unknown", "Observed third-party executable resources used integrity metadata, but the HTML evidence was incomplete.");
  }
  return makeCheck(
    "subresource-integrity",
    "pass",
    "Every eligible third-party script and stylesheet observed in the bounded HTML used integrity metadata.",
    html.externalExecutables,
  );
}

function emptyHtmlEvidence(): HtmlEvidence {
  return {
    forms: [],
    orphanPasswordInput: false,
    mixedContent: [],
    externalExecutables: [],
    missingIntegrity: [],
    generators: [],
    limited: false,
  };
}

function inspectHtml(html: string, documentUrl: URL, bodyTruncated: boolean): HtmlEvidence {
  const result = emptyHtmlEvidence();
  result.limited = bodyTruncated
    || /<\/?(?:form|input|script|link|iframe|img|audio|video|source|meta)\b[^>]{4096}/iu.test(html);
  const tagPattern = /<\/?(?:form|input|script|link|iframe|img|audio|video|source|meta)\b[^>]{0,4096}>/giu;
  let currentForm: ParsedForm | undefined;
  let tags = 0;

  for (const match of html.matchAll(tagPattern)) {
    tags += 1;
    if (tags > MAX_HTML_TAGS) {
      result.limited = true;
      break;
    }
    const rawTag = match[0];
    const closing = /^<\//u.test(rawTag);
    const name = /^<\/?\s*([a-z]+)/iu.exec(rawTag)?.[1]?.toLowerCase();
    if (!name) continue;
    if (closing) {
      if (name === "form") currentForm = undefined;
      continue;
    }
    const attributes = parseHtmlAttributes(rawTag);
    if (name === "form") {
      const rawAction = attributes.get("action") ?? documentUrl.href;
      const action = resolveHtmlUrl(rawAction, documentUrl) ?? "invalid-action";
      currentForm = {
        action,
        method: (attributes.get("method") ?? "get").trim().toLowerCase(),
        hasPassword: false,
      };
      result.forms.push(currentForm);
      continue;
    }
    if (name === "input" && (attributes.get("type") ?? "text").trim().toLowerCase() === "password") {
      if (currentForm) currentForm.hasPassword = true;
      else result.orphanPasswordInput = true;
      continue;
    }
    if (name === "meta" && attributes.get("name")?.trim().toLowerCase() === "generator") {
      const generator = attributes.get("content")?.trim();
      if (generator) result.generators.push(generator);
      continue;
    }

    const resourceValues = htmlResourceValues(name, attributes);
    for (const value of resourceValues) {
      const absolute = resolveHtmlUrl(value, documentUrl);
      if (absolute?.startsWith("http://")) result.mixedContent.push(sanitizeEvidence(absolute));
    }
    const executable = executableResource(name, attributes, documentUrl);
    if (executable && new URL(executable).origin !== documentUrl.origin) {
      result.externalExecutables.push(sanitizeEvidence(executable));
      if (!attributes.has("integrity")) result.missingIntegrity.push(sanitizeEvidence(executable));
    }
  }

  result.mixedContent = uniqueLimited(result.mixedContent);
  result.externalExecutables = uniqueLimited(result.externalExecutables);
  result.missingIntegrity = uniqueLimited(result.missingIntegrity);
  result.generators = uniqueLimited(result.generators);
  return result;
}

function parseHtmlAttributes(tag: string): Map<string, string> {
  const attributes = new Map<string, string>();
  const opening = /^<\/?\s*[a-z][a-z0-9:-]*/iu.exec(tag)?.[0].length ?? 0;
  const body = tag.slice(opening, -1);
  const pattern = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/gu;
  let count = 0;
  for (const match of body.matchAll(pattern)) {
    count += 1;
    if (count > 64) break;
    const name = match[1]?.toLowerCase();
    if (!name || attributes.has(name)) continue;
    attributes.set(name, decodeHtmlAttribute(match[2] ?? match[3] ?? match[4] ?? ""));
  }
  return attributes;
}

function decodeHtmlAttribute(value: string): string {
  return value
    .replace(/&amp;/giu, "&")
    .replace(/&quot;/giu, '"')
    .replace(/&#(?:x27|39);/giu, "'")
    .replace(/&lt;/giu, "<")
    .replace(/&gt;/giu, ">");
}

function htmlResourceValues(name: string, attributes: Map<string, string>): string[] {
  const values: string[] = [];
  const primary = name === "link" ? attributes.get("href") : attributes.get("src");
  if (primary) values.push(primary);
  const srcset = attributes.get("srcset");
  if (srcset) {
    for (const candidate of srcset.split(",").slice(0, 32)) {
      const value = candidate.trim().split(/\s+/u)[0];
      if (value) values.push(value);
    }
  }
  return values;
}

function executableResource(
  name: string,
  attributes: Map<string, string>,
  documentUrl: URL,
): string | undefined {
  if (name === "script") return resolveHtmlUrl(attributes.get("src") ?? "", documentUrl);
  if (name !== "link") return undefined;
  const rel = (attributes.get("rel") ?? "").toLowerCase().split(/\s+/u);
  if (!rel.includes("stylesheet")) return undefined;
  return resolveHtmlUrl(attributes.get("href") ?? "", documentUrl);
}

function resolveHtmlUrl(value: string, documentUrl: URL): string | undefined {
  const trimmed = value.trim();
  if (!trimmed) return documentUrl.href;
  try {
    const url = new URL(trimmed, documentUrl);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : undefined;
  } catch {
    return undefined;
  }
}

async function probeErrorHandling(
  httpsProbe: ProbeChainResult,
  context: ProbeContext,
  nonceFactory: () => string,
): Promise<ErrorProbeResult> {
  if (!httpsProbe.response || httpsProbe.failure || !httpsProbe.effectiveUrl.startsWith("https://")) {
    return { body: { truncated: false }, failure: "fetch" };
  }
  const origin = new URL(httpsProbe.effectiveUrl).origin;
  const nonce = boundedNonce(nonceFactory());
  const url = new URL(`/.well-known/dmarc-ready-probe-${nonce}`, `${origin}/`);
  try {
    const response = await guardedFetch(url, "GET", context, false);
    const body = await readBoundedErrorText(response, context);
    return { response, body };
  } catch (error) {
    if (error instanceof WebSecurityTargetError || error instanceof WebSecurityUpstreamError) throw error;
    return {
      body: { truncated: false },
      failure: error instanceof RequestBudgetError ? "request-budget" : "fetch",
    };
  }
}

function generateProbeNonce(): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function boundedNonce(value: string): string {
  const safe = value.toLowerCase().replace(/[^a-z0-9-]/gu, "").slice(0, 48);
  return safe.length >= 8 ? safe : generateProbeNonce();
}

async function readBoundedErrorText(
  response: Response,
  context: ProbeContext,
): Promise<BoundedTextBody> {
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (
    response.body
    && contentType
    && !contentType.startsWith("text/")
    && !contentType.includes("json")
    && !contentType.includes("xml")
    && !contentType.includes("javascript")
  ) {
    await cancelBody(response);
    return { truncated: false };
  }
  return readBoundedTextStream(response, context);
}

async function readBoundedTextStream(
  response: Response,
  context: ProbeContext,
): Promise<BoundedTextBody> {
  if (!response.body) return { text: "", truncated: false };
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const bodyDeadline = Math.min(context.deadlineAt, context.now() + FETCH_TIMEOUT_MS);
  let text = "";
  let bytes = 0;
  let truncated = false;
  try {
    try {
      for (;;) {
        const remainingTime = bodyDeadline - context.now();
        if (remainingTime <= 0) {
          truncated = true;
          break;
        }
        const read = await readStreamChunk(reader, remainingTime);
        if (read === undefined) {
          truncated = true;
          break;
        }
        if (read.done) break;
        const remainingBytes = MAX_RESPONSE_BYTES - bytes;
        if (remainingBytes <= 0) {
          truncated = true;
          break;
        }
        const accepted = read.value.byteLength > remainingBytes
          ? read.value.subarray(0, remainingBytes)
          : read.value;
        text += decoder.decode(accepted, { stream: true });
        bytes += accepted.byteLength;
        if (accepted.byteLength < read.value.byteLength) {
          truncated = true;
          break;
        }
      }
    } catch {
      truncated = true;
    }
    text += decoder.decode();
  } finally {
    if (truncated) {
      try {
        await reader.cancel();
      } catch {
        // The platform can close the stream before cancellation completes.
      }
    } else {
      reader.releaseLock();
    }
  }
  return { text, truncated };
}

async function readStreamChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  timeoutMs: number,
): Promise<ReadableStreamReadResult<Uint8Array> | undefined> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      reader.read(),
      new Promise<undefined>((resolve) => {
        timeout = setTimeout(() => resolve(undefined), Math.max(1, timeoutMs));
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

function parseCookies(headers: Headers): CookieEvidence {
  const values = getSetCookieValues(headers);
  const cookies: ParsedCookie[] = [];
  let truncated = values.length > 32;
  for (const rawValue of values.slice(0, 32)) {
    const header = rawValue.slice(0, MAX_HEADER_VALUE_LENGTH);
    if (header.length < rawValue.length) truncated = true;
    const segments = header.split(";");
    const pair = segments.shift()?.trim() ?? "";
    const separator = pair.indexOf("=");
    if (separator <= 0) continue;
    const name = pair.slice(0, separator).trim().slice(0, 128);
    if (!name) continue;
    const attributes = new Map<string, string | true>();
    for (const segment of segments.slice(0, 32)) {
      const index = segment.indexOf("=");
      const attributeName = (index === -1 ? segment : segment.slice(0, index)).trim().toLowerCase();
      if (!attributeName || attributes.has(attributeName)) continue;
      attributes.set(
        attributeName,
        index === -1 ? true : segment.slice(index + 1).trim().slice(0, 512),
      );
    }
    cookies.push({
      name,
      attributes,
      authLike: /(?:auth|session|sessid|token|jwt|login|remember|csrf|xsrf|(?:^|[._-])sid(?:$|[._-]))/iu.test(name),
    });
  }
  return { cookies, truncated, available: true };
}

function getSetCookieValues(headers: Headers): string[] {
  const extended = headers as Headers & { getSetCookie?: () => string[] };
  if (typeof extended.getSetCookie === "function") {
    try {
      const values = extended.getSetCookie.call(headers);
      if (Array.isArray(values) && values.length > 0) return values;
    } catch {
      // Fall back to the combined representation below.
    }
  }
  const combined = headers.get("set-cookie");
  return combined
    ? combined.split(/,(?=\s*[!#$%&'*+.^_`|~0-9A-Za-z-]+=)/gu).map((value) => value.trim()).filter(Boolean)
    : [];
}

function cookiesForSecurityEvaluation(evidence: CookieEvidence): ParsedCookie[] {
  return evidence.cookies.filter((cookie) =>
    cookie.authLike || cookie.name.toLowerCase().startsWith("__host-") || cookie.name.toLowerCase().startsWith("__secure-"));
}

function cookieNames(cookies: readonly ParsedCookie[]): string[] {
  return uniqueLimited(cookies.map((cookie) => sanitizeEvidence(`Cookie: ${cookie.name}`)));
}

function noCookieCheck(id: WebSecurityCheckId, evidence: CookieEvidence): WebSecurityCheck {
  if (!evidence.available) {
    return makeCheck(id, "unknown", "The HTTPS response was unavailable, so cookie attributes were not evaluated.");
  }
  return evidence.truncated
    ? truncatedCookieCheck(id)
    : makeCheck(
      id,
      "not-applicable",
      evidence.cookies.length > 0
        ? "Cookies were set, but no session or security-prefixed cookie was observed on the anonymous root response."
        : "No session or security cookie was observed on the anonymous root response.",
    );
}

function truncatedCookieCheck(id: WebSecurityCheckId): WebSecurityCheck {
  return makeCheck(id, "unknown", "Cookie evidence exceeded the bounded header or count limit and could not be fully evaluated.");
}

function scoreChecks(checks: readonly WebSecurityCheck[]): {
  score: number;
  grade: WebSecurityScanExecution["grade"];
  evaluated: number;
  unknown: number;
  notApplicable: number;
  weightedCoverageSufficient: boolean;
  criticalEvidenceComplete: boolean;
} {
  let earnedWeight = 0;
  let evaluatedWeight = 0;
  let applicableWeight = 0;
  let evaluated = 0;
  let unknown = 0;
  let notApplicable = 0;
  for (const check of checks) {
    const weight = CHECK_DEFINITIONS[check.id].weight;
    if (check.status === "unknown") {
      unknown += 1;
      applicableWeight += weight;
      continue;
    }
    if (check.status === "not-applicable") {
      notApplicable += 1;
      continue;
    }
    applicableWeight += weight;
    evaluated += 1;
    evaluatedWeight += weight;
    earnedWeight += weight * (check.status === "pass" ? 1 : check.status === "warning" ? 0.5 : 0);
  }
  const score = evaluatedWeight > 0 ? Math.round((earnedWeight / evaluatedWeight) * 100) : 0;
  const weightedCoverageSufficient = applicableWeight > 0 && evaluatedWeight / applicableWeight >= 0.7;
  const criticalEvidenceComplete = ([
    "https-enforcement",
    "hsts",
    "content-security-policy",
  ] as const).every((id) => {
    const criticalCheck = checks.find((check) => check.id === id);
    return criticalCheck !== undefined && criticalCheck.status !== "unknown";
  });
  const transportFailure = checks.some((check) => check.id === "https-enforcement" && check.status === "fail");
  return {
    score,
    grade: transportFailure
      ? "F"
      : weightedCoverageSufficient && criticalEvidenceComplete ? scoreGrade(score) : "N/A",
    evaluated,
    unknown,
    notApplicable,
    weightedCoverageSufficient,
    criticalEvidenceComplete,
  };
}

function scoreGrade(score: number): Exclude<WebSecurityScanExecution["grade"], "N/A"> {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function buildSummary(
  checks: readonly WebSecurityCheck[],
  score: ReturnType<typeof scoreChecks>,
): string {
  const passed = checks.filter((check) => check.status === "pass").length;
  const warnings = checks.filter((check) => check.status === "warning").length;
  const failed = checks.filter((check) => check.status === "fail").length;
  const coverage = `${score.evaluated} evaluated, ${score.unknown} unknown, and ${score.notApplicable} not applicable`;
  if (score.grade === "N/A") {
    const reason = !score.criticalEvidenceComplete
      ? "A letter grade requires bounded HTTPS enforcement, HSTS, and CSP evidence"
      : !score.weightedCoverageSufficient
        ? "Less than 70% of applicable check weight had bounded evidence"
        : "The available evidence was insufficient for a letter grade";
    return `${coverage}. ${reason}, so no letter grade was assigned. Findings: ${passed} passed, ${warnings} warnings, ${failed} failed.`;
  }
  return `${coverage}. The score uses only evaluated, applicable checks: ${passed} passed, ${warnings} warnings, and ${failed} failed.`;
}

function makeCheck(
  id: WebSecurityCheckId,
  status: WebSecurityCheckStatus,
  summary: string,
  evidence: readonly string[] = [],
): WebSecurityCheck {
  const definition = CHECK_DEFINITIONS[id];
  return {
    id,
    status,
    title: definition.title,
    summary: sanitizeEvidence(summary),
    evidence: uniqueLimited(evidence.map(sanitizeEvidence)),
    remediation: definition.remediation,
    owasp: {
      top10: [...definition.top10],
      wstg: [...definition.wstg],
    },
  };
}

function unavailableHeaderCheck(id: WebSecurityCheckId): WebSecurityCheck {
  return makeCheck(id, "unknown", "The HTTPS response was unavailable, so this header-based check was not evaluated.");
}

function boundedHeader(
  headers: Headers,
  name: string,
  maximum = MAX_HEADER_VALUE_LENGTH,
): HeaderValue {
  const raw = headers.get(name);
  if (raw === null) return { truncated: false };
  const normalized = raw.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/gu, " ");
  return {
    value: normalized.slice(0, maximum),
    truncated: normalized.length > maximum,
  };
}

function parseDirectives(value: string): Map<string, string | true> {
  const directives = new Map<string, string | true>();
  for (const segment of value.split(";").slice(0, 128)) {
    const trimmed = segment.trim();
    if (!trimmed) continue;
    const separator = trimmed.indexOf("=");
    const name = (separator === -1 ? trimmed : trimmed.slice(0, separator)).trim().toLowerCase();
    if (!name || directives.has(name)) continue;
    directives.set(
      name,
      separator === -1 ? true : trimmed.slice(separator + 1).trim().replace(/^"|"$/gu, ""),
    );
  }
  return directives;
}

function parseCsp(value: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const segment of value.split(";").slice(0, 128)) {
    const parts = segment.trim().toLowerCase().split(/\s+/u).filter(Boolean);
    const name = parts.shift();
    if (name && !directives.has(name)) directives.set(name, parts);
  }
  return directives;
}

function isNonceOrHashSource(value: string): boolean {
  return /^'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'$/u.test(value);
}

function summarizeChain(label: string, result: ProbeChainResult): string[] {
  const evidence = result.hops.map((hop) => {
    const location = hop.location ? ` -> ${hop.location}` : "";
    return sanitizeEvidence(`${label}: HTTP ${hop.status} ${hop.url}${location}`);
  });
  if (result.failureDetail) evidence.push(sanitizeEvidence(`${label}: ${result.failureDetail}`));
  return uniqueLimited(evidence);
}

function redirectLocationUsesHttps(hop: ProbeHop | undefined): boolean {
  if (!hop?.location) return false;
  try {
    return new URL(hop.location, hop.url).protocol === "https:";
  } catch {
    return false;
  }
}

function containsInternalErrorEvidence(value: string): boolean {
  return /(?:Traceback \(most recent call last\)|\b(?:Fatal error|Unhandled (?:exception|rejection))\b|\bat\s+[\w$.<>]+\s+\([^\r\n)]{1,256}:\d+:\d+\)|\/(?:var\/www|usr\/src|home\/[a-z0-9_.-]+)\/[^\s<>]{1,256}|[A-Z]:\\[^\r\n<>]{1,256}:\d+|\bSQLSTATE\[[A-Z0-9]+\])/iu.test(value);
}

function sanitizeEvidence(value: string): string {
  const normalized = value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  return normalized.length > MAX_EVIDENCE_LENGTH
    ? `${normalized.slice(0, MAX_EVIDENCE_LENGTH - 1)}…`
    : normalized;
}

function uniqueLimited(values: readonly string[]): string[] {
  return [...new Set(values.filter(Boolean))].slice(0, MAX_EVIDENCE_ITEMS);
}

function sameAddressSet(first: readonly string[], second: readonly string[]): boolean {
  return first.length === second.length && first.every((address, index) => address === second[index]);
}

async function beforeDeadline<T>(
  operation: Promise<T>,
  timeoutMs: number,
): Promise<T> {
  if (timeoutMs <= 0) throw new RequestBudgetError();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new RequestBudgetError()), Math.max(1, timeoutMs));
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

function plural(count: number, singular: string, pluralValue: string): string {
  return count === 1 ? singular : pluralValue;
}
