import {
  checkServerIdentity,
  connect,
  type ConnectionOptions,
  type DetailedPeerCertificate,
  type PeerCertificate,
} from "node:tls";
import type {
  TlsAssessment,
  TlsCertificateSummary,
  TlsCipherObservation,
  TlsEndpointObservation,
  TlsProtocolObservation,
  TlsProtocolVersion,
} from "../shared/types";

const TLS_PROTOCOLS: readonly TlsProtocolVersion[] = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
const MAX_TLS_ENDPOINTS = 2;
const MAX_REPORTED_ADDRESSES = 32;
const MAX_CERTIFICATE_CHAIN = 6;
const TLS_TIMEOUT_MS = 3_500;

export interface TlsConnectionEvidence {
  authorized: boolean;
  authorizationError?: string;
  hostnameValid: boolean;
  protocol?: string;
  cipher?: TlsCipherObservation;
  alpnProtocol?: string;
  ephemeralKey?: string;
  certificate?: TlsCertificateSummary;
  certificateChain: TlsCertificateSummary[];
}

export interface TlsConnectorInput {
  hostname: string;
  address: string;
  protocol?: TlsProtocolVersion;
  weakCipherOnly?: boolean;
  signal?: AbortSignal;
}

export type TlsConnector = (input: TlsConnectorInput) => Promise<TlsConnectionEvidence>;

export class TlsProbeError extends Error {
  constructor(
    readonly kind: "platform-blocked" | "timeout" | "rejected" | "unreachable" | "unavailable",
    message: string,
  ) {
    super(message);
    this.name = "TlsProbeError";
  }
}

export interface TlsScanExecution {
  assessment: TlsAssessment;
  connectionCount: number;
}

export async function scanTlsConfiguration(
  hostname: string,
  resolvedAddresses: readonly string[],
  options: { connector?: TlsConnector; now?: () => number } = {},
): Promise<TlsScanExecution> {
  const connector = options.connector ?? connectTls;
  const uniqueAddresses = [...new Set(resolvedAddresses)];
  const selectedAddresses = selectTlsEndpoints(uniqueAddresses);
  const endpoints: TlsEndpointObservation[] = [];
  let connectionCount = 0;

  // Endpoints are intentionally sequential. Each ready endpoint can use up to
  // five concurrent fixed-profile probes without exceeding Workers' socket cap.
  for (const address of selectedAddresses) {
    const endpoint = await scanTlsEndpoint(hostname, address, connector, options.now ?? Date.now);
    endpoints.push(endpoint.observation);
    connectionCount += endpoint.connectionCount;
  }

  const ready = endpoints.filter((endpoint) => endpoint.status === "ready");
  const hasUnknownEvidence = endpoints.some((endpoint) =>
    endpoint.status !== "ready"
      || endpoint.protocols.some((protocol) => protocol.status === "unknown")
      || endpoint.weakCipher.status === "unknown",
  );
  const status: TlsAssessment["status"] = ready.length === 0
    ? "unavailable"
    : hasUnknownEvidence ? "partial" : "complete";
  const grade = gradeTlsEndpoints(ready);
  const endpointsTruncated = uniqueAddresses.length > selectedAddresses.length;

  return {
    assessment: {
      status,
      grade,
      summary: tlsSummary(status, grade, ready.length, endpoints.length),
      resolvedAddresses: uniqueAddresses.slice(0, MAX_REPORTED_ADDRESSES),
      endpoints,
      endpointsTruncated,
      reportUrl: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(hostname)}&hideResults=on`,
      limitations: [
        "This is a bounded TLS snapshot, not an SSL Labs-equivalent assessment or exhaustive cipher/client simulation.",
        "The scanner tests fixed TLS versions and one legacy CBC profile; it does not send exploit payloads for Heartbleed, ROBOT, DROWN, padding oracles, or similar vulnerabilities.",
        "Cloudflare blocks raw TCP/TLS sockets to Cloudflare address ranges and Worker self-loops. Those endpoints remain unavailable instead of being graded as failures.",
        ...(endpointsTruncated
          ? [`TLS handshakes were capped at ${MAX_TLS_ENDPOINTS} representative public endpoints; every resolved address was still safety-validated.`]
          : []),
        ...(uniqueAddresses.length > MAX_REPORTED_ADDRESSES
          ? [`The displayed address list was capped at ${MAX_REPORTED_ADDRESSES} entries.`]
          : []),
      ],
    },
    connectionCount,
  };
}

async function scanTlsEndpoint(
  hostname: string,
  address: string,
  connector: TlsConnector,
  now: () => number,
): Promise<{ observation: TlsEndpointObservation; connectionCount: number }> {
  let base: TlsConnectionEvidence;
  try {
    base = await runTlsConnector(connector, { hostname, address });
  } catch (error) {
    const failure = normalizeProbeError(error);
    return {
      observation: unavailableEndpoint(address, failure),
      connectionCount: 1,
    };
  }

  const probeResults = await Promise.all([
    ...TLS_PROTOCOLS.map(async (protocol) => probeProtocol(connector, hostname, address, protocol)),
    probeWeakCipher(connector, hostname, address),
  ]);
  const protocols = probeResults.slice(0, TLS_PROTOCOLS.length) as TlsProtocolObservation[];
  const weakCipher = probeResults.at(-1) as TlsEndpointObservation["weakCipher"];
  const certificate = base.certificate
    ? normalizeCertificateDates(base.certificate, now())
    : undefined;
  const certificateChain = base.certificateChain.map((entry) => normalizeCertificateDates(entry, now()));

  return {
    observation: {
      address,
      status: "ready",
      summary: endpointSummary(base, certificate),
      authorized: base.authorized,
      ...(base.authorizationError ? { authorizationError: base.authorizationError } : {}),
      hostnameValid: base.hostnameValid,
      ...(base.protocol ? { negotiatedProtocol: base.protocol } : {}),
      ...(base.cipher ? { cipher: base.cipher } : {}),
      ...(base.alpnProtocol ? { alpnProtocol: base.alpnProtocol } : {}),
      ...(base.ephemeralKey ? { ephemeralKey: base.ephemeralKey } : {}),
      ...(certificate ? { certificate } : {}),
      certificateChain,
      protocols,
      weakCipher,
    },
    connectionCount: 1 + TLS_PROTOCOLS.length + 1,
  };
}

async function probeProtocol(
  connector: TlsConnector,
  hostname: string,
  address: string,
  protocol: TlsProtocolVersion,
): Promise<TlsProtocolObservation> {
  try {
    const evidence = await runTlsConnector(connector, { hostname, address, protocol });
    return {
      version: protocol,
      status: "supported",
      ...(evidence.cipher ? { cipher: evidence.cipher } : {}),
    };
  } catch (error) {
    const failure = normalizeProbeError(error);
    return {
      version: protocol,
      status: failure.kind === "rejected" ? "not-supported" : "unknown",
      note: publicFailureMessage(failure),
    };
  }
}

async function probeWeakCipher(
  connector: TlsConnector,
  hostname: string,
  address: string,
): Promise<TlsEndpointObservation["weakCipher"]> {
  try {
    const evidence = await runTlsConnector(connector, { hostname, address, weakCipherOnly: true });
    return {
      status: "supported",
      ...(evidence.cipher ? { cipher: evidence.cipher } : {}),
      note: "The endpoint negotiated the fixed TLS 1.2 RSA/AES-CBC compatibility profile.",
    };
  } catch (error) {
    const failure = normalizeProbeError(error);
    return failure.kind === "rejected"
      ? { status: "not-supported", note: "The fixed TLS 1.2 RSA/AES-CBC profile was not negotiated." }
      : { status: "unknown", note: publicFailureMessage(failure) };
  }
}

export async function connectTls(input: TlsConnectorInput): Promise<TlsConnectionEvidence> {
  const options: ConnectionOptions = {
    host: input.address,
    port: 443,
    servername: input.hostname,
    rejectUnauthorized: false,
    ALPNProtocols: ["h2", "http/1.1"],
    ...(input.protocol ? { minVersion: input.protocol, maxVersion: input.protocol } : {}),
    ...(input.weakCipherOnly
      ? { minVersion: "TLSv1.2", maxVersion: "TLSv1.2", ciphers: "AES128-SHA" }
      : {}),
  };

  return new Promise<TlsConnectionEvidence>((resolve, reject) => {
    let socket: ReturnType<typeof connect>;
    let settled = false;
    let absoluteTimeout: ReturnType<typeof setTimeout> | undefined;

    const clearDeadline = () => {
      if (absoluteTimeout !== undefined) clearTimeout(absoluteTimeout);
      input.signal?.removeEventListener("abort", abort);
    };

    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      clearDeadline();
      socket?.destroy();
      reject(classifyTlsError(error));
    };

    const abort = () => fail(
      input.signal?.reason instanceof Error
        ? input.signal.reason
        : new TlsProbeError("timeout", "TLS handshake exceeded its absolute deadline."),
    );

    if (input.signal?.aborted) {
      abort();
      return;
    }
    input.signal?.addEventListener("abort", abort, { once: true });
    absoluteTimeout = setTimeout(
      () => fail(new TlsProbeError("timeout", "TLS handshake exceeded its absolute deadline.")),
      TLS_TIMEOUT_MS,
    );

    try {
      socket = connect(options);
    } catch (error) {
      fail(error);
      return;
    }

    socket.once("error", fail);
    socket.once("secureConnect", () => {
      if (settled) return;
      settled = true;
      clearDeadline();
      try {
        const detailed = socket.getPeerCertificate(true);
        const certificateChain = detailed && Object.keys(detailed).length > 0
          ? summarizeCertificateChain(detailed)
          : [];
        const certificate = certificateChain[0];
        const hostnameValid = detailed && Object.keys(detailed).length > 0
          ? checkServerIdentity(input.hostname, detailed as PeerCertificate) === undefined
          : false;
        const ephemeral = optionalSocketEvidence(() => socket.getEphemeralKeyInfo());
        const ephemeralKey = formatEphemeralKey(ephemeral);
        const cipher = sanitizeCipher(optionalSocketEvidence(() => socket.getCipher()));
        const protocol = optionalSocketEvidence(() => socket.getProtocol());
        const authorizationError = socket.authorizationError
          ? boundedText(String(socket.authorizationError), 256)
          : undefined;

        resolve({
          authorized: socket.authorized,
          ...(authorizationError ? { authorizationError } : {}),
          hostnameValid,
          ...(protocol ? { protocol: boundedText(protocol, 64) } : {}),
          ...(cipher ? { cipher } : {}),
          ...(socket.alpnProtocol ? { alpnProtocol: boundedText(socket.alpnProtocol, 64) } : {}),
          ...(ephemeralKey ? { ephemeralKey } : {}),
          ...(certificate ? { certificate } : {}),
          certificateChain,
        });
      } catch (error) {
        reject(classifyTlsError(error));
      } finally {
        socket.destroy();
      }
    });
  });
}

async function runTlsConnector(
  connector: TlsConnector,
  input: Omit<TlsConnectorInput, "signal">,
): Promise<TlsConnectionEvidence> {
  const controller = new AbortController();
  const deadlineError = new TlsProbeError("timeout", "TLS handshake exceeded its absolute deadline.");
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      connector({ ...input, signal: controller.signal }),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          controller.abort(deadlineError);
          reject(deadlineError);
        }, TLS_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

function unavailableEndpoint(address: string, failure: TlsProbeError): TlsEndpointObservation {
  const status: TlsEndpointObservation["status"] = failure.kind === "platform-blocked"
    ? "platform-blocked"
    : failure.kind === "unreachable" || failure.kind === "timeout"
      ? "unreachable"
      : "unavailable";
  return {
    address,
    status,
    summary: publicFailureMessage(failure),
    certificateChain: [],
    protocols: TLS_PROTOCOLS.map((version) => ({
      version,
      status: "unknown",
      note: publicFailureMessage(failure),
    })),
    weakCipher: { status: "unknown", note: publicFailureMessage(failure) },
  };
}

function selectTlsEndpoints(addresses: readonly string[]): string[] {
  const unique = [...new Set(addresses)];
  const selected: string[] = [];
  const firstIpv4 = unique.find((address) => !address.includes(":"));
  const firstIpv6 = unique.find((address) => address.includes(":"));
  if (firstIpv4) selected.push(firstIpv4);
  if (firstIpv6) selected.push(firstIpv6);
  for (const address of unique) {
    if (selected.length >= MAX_TLS_ENDPOINTS) break;
    if (!selected.includes(address)) selected.push(address);
  }
  return selected.slice(0, MAX_TLS_ENDPOINTS);
}

function gradeTlsEndpoints(endpoints: readonly TlsEndpointObservation[]): TlsAssessment["grade"] {
  if (endpoints.length === 0) return "N/A";
  const endpointGrades = endpoints.map(gradeTlsEndpoint).filter((grade) => grade !== "N/A");
  if (endpointGrades.length === 0) return "N/A";
  const order: Readonly<Record<Exclude<TlsAssessment["grade"], "N/A">, number>> = {
    F: 0,
    D: 1,
    C: 2,
    B: 3,
    A: 4,
  };
  return endpointGrades.reduce((worst, grade) => order[grade] < order[worst] ? grade : worst, "A");
}

function gradeTlsEndpoint(endpoint: TlsEndpointObservation): TlsAssessment["grade"] {
  if (
    endpoint.authorized === false
    || endpoint.hostnameValid === false
    || (endpoint.certificate?.daysRemaining !== undefined && endpoint.certificate.daysRemaining < 0)
  ) return "F";

  const negotiated = endpoint.negotiatedProtocol;
  const supportsModern = supports(endpoint, "TLSv1.2")
    || supports(endpoint, "TLSv1.3")
    || negotiated === "TLSv1.2"
    || negotiated === "TLSv1.3";
  const modernExplicitlyAbsent = protocolStatus(endpoint, "TLSv1.2") === "not-supported"
    && protocolStatus(endpoint, "TLSv1.3") === "not-supported";
  if (!supportsModern) {
    if (modernExplicitlyAbsent || negotiated === "TLSv1" || negotiated === "TLSv1.1") return "D";
    return "N/A";
  }
  if (supports(endpoint, "TLSv1")) return "C";
  if (
    supports(endpoint, "TLSv1.1")
    || endpoint.weakCipher.status === "supported"
    || (endpoint.certificate?.daysRemaining !== undefined && endpoint.certificate.daysRemaining < 30)
    || protocolStatus(endpoint, "TLSv1.3") === "not-supported"
  ) return "B";
  return "A";
}

function supports(endpoint: TlsEndpointObservation, version: TlsProtocolVersion): boolean {
  return protocolStatus(endpoint, version) === "supported";
}

function protocolStatus(
  endpoint: TlsEndpointObservation,
  version: TlsProtocolVersion,
): TlsProtocolObservation["status"] | undefined {
  return endpoint.protocols.find((protocol) => protocol.version === version)?.status;
}

function tlsSummary(
  status: TlsAssessment["status"],
  grade: TlsAssessment["grade"],
  ready: number,
  total: number,
): string {
  if (status === "unavailable") {
    return "HTTPS may still be reachable, but raw endpoint TLS evidence was unavailable from the Worker network. No TLS failure was inferred.";
  }
  const prefix = status === "complete" ? "Fixed TLS profiles completed" : "Partial TLS evidence was collected";
  return `${prefix} for ${ready} of ${total} representative endpoints. The bounded TLS posture grade is ${grade}.`;
}

function endpointSummary(base: TlsConnectionEvidence, certificate?: TlsCertificateSummary): string {
  if (!base.hostnameValid) return "The certificate did not match the requested hostname.";
  if (!base.authorized) return "The TLS handshake completed, but the certificate chain was not trusted by the runtime.";
  if (certificate?.daysRemaining !== undefined && certificate.daysRemaining < 0) return "The presented certificate is expired.";
  if (certificate?.daysRemaining !== undefined && certificate.daysRemaining < 30) {
    return `The certificate is trusted and hostname-valid but expires in ${certificate.daysRemaining} days.`;
  }
  return "The default TLS handshake completed with a trusted, hostname-valid certificate.";
}

function summarizeCertificateChain(leaf: DetailedPeerCertificate): TlsCertificateSummary[] {
  const chain: TlsCertificateSummary[] = [];
  const seen = new Set<string>();
  let current: DetailedPeerCertificate | undefined = leaf;

  while (current && chain.length < MAX_CERTIFICATE_CHAIN) {
    const key = String(current.fingerprint256 || current.serialNumber || `${formatDistinguishedName(current.subject)}-${chain.length}`);
    if (seen.has(key)) break;
    seen.add(key);
    chain.push(summarizeCertificate(current));
    const issuer: DetailedPeerCertificate | undefined = current.issuerCertificate;
    if (!issuer || issuer === current) break;
    current = issuer;
  }
  return chain;
}

function summarizeCertificate(certificate: DetailedPeerCertificate): TlsCertificateSummary {
  const validFrom = normalizeDate(certificate.valid_from);
  const validTo = normalizeDate(certificate.valid_to);
  const subjectAltNames = parseSubjectAltNames(certificate.subjectaltname);
  const bits = typeof certificate.bits === "number" && Number.isFinite(certificate.bits)
    ? certificate.bits
    : undefined;
  const signatureAlgorithm = boundedOptionalText((certificate as DetailedPeerCertificate & { sigalg?: unknown }).sigalg, 128);

  return {
    subject: formatDistinguishedName(certificate.subject),
    issuer: formatDistinguishedName(certificate.issuer),
    subjectAltNames,
    ...(validFrom ? { validFrom } : {}),
    ...(validTo ? { validTo } : {}),
    ...(certificate.serialNumber ? { serialNumber: boundedText(certificate.serialNumber, 128) } : {}),
    ...(certificate.fingerprint256 ? { fingerprint256: boundedText(certificate.fingerprint256, 256) } : {}),
    ...(bits ? { bits } : {}),
    ...(signatureAlgorithm ? { signatureAlgorithm } : {}),
    ...(typeof certificate.ca === "boolean" ? { ca: certificate.ca } : {}),
  };
}

function normalizeCertificateDates(certificate: TlsCertificateSummary, now: number): TlsCertificateSummary {
  if (!certificate.validTo) return certificate;
  const expiry = Date.parse(certificate.validTo);
  if (!Number.isFinite(expiry)) return certificate;
  return {
    ...certificate,
    daysRemaining: Math.floor((expiry - now) / 86_400_000),
  };
}

function formatDistinguishedName(value: PeerCertificate["subject"] | PeerCertificate["issuer"]): string {
  if (!value || typeof value !== "object") return "Unavailable";
  const parts: string[] = [];
  for (const [key, raw] of Object.entries(value)) {
    const values = Array.isArray(raw) ? raw : [raw];
    for (const entry of values) {
      if (typeof entry !== "string") continue;
      parts.push(`${boundedText(key, 32)}=${boundedText(entry, 160)}`);
      if (parts.length >= 16) break;
    }
    if (parts.length >= 16) break;
  }
  return boundedText(parts.join(", ") || "Unavailable", 512);
}

function parseSubjectAltNames(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(/,\s*(?=(?:DNS:|IP Address:|URI:|email:))/iu)
    .map((entry) => boundedText(entry, 253))
    .filter(Boolean)
    .slice(0, 64);
}

function normalizeDate(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : undefined;
}

function sanitizeCipher(
  value: ReturnType<ReturnType<typeof connect>["getCipher"]> | undefined,
): TlsCipherObservation | undefined {
  if (!value || typeof value.name !== "string") return undefined;
  const name = boundedText(value.name, 128);
  const standardName = typeof value.standardName === "string" ? boundedText(value.standardName, 128) : undefined;
  const version = typeof value.version === "string" ? boundedText(value.version, 64) : undefined;
  const bits = cipherBits(standardName || name);
  return {
    name,
    ...(standardName ? { standardName } : {}),
    ...(version ? { version } : {}),
    ...(bits ? { bits } : {}),
  };
}

function cipherBits(name: string): number | undefined {
  if (/AES[_-]?256|CHACHA20/iu.test(name)) return 256;
  if (/AES[_-]?128/iu.test(name)) return 128;
  if (/3DES|DES-CBC3/iu.test(name)) return 112;
  return undefined;
}

function formatEphemeralKey(
  value: ReturnType<ReturnType<typeof connect>["getEphemeralKeyInfo"]> | undefined,
): string | undefined {
  if (!value || typeof value !== "object" || Object.keys(value).length === 0) return undefined;
  const typed = value as { type?: unknown; name?: unknown; size?: unknown };
  const parts = [
    boundedOptionalText(typed.type, 32),
    boundedOptionalText(typed.name, 64),
    typeof typed.size === "number" && Number.isFinite(typed.size) ? `${typed.size} bits` : undefined,
  ].filter((entry): entry is string => Boolean(entry));
  return parts.length > 0 ? boundedText(parts.join(" · "), 160) : undefined;
}

function classifyTlsError(error: unknown): TlsProbeError {
  if (error instanceof TlsProbeError) return error;
  const record = typeof error === "object" && error !== null ? error as { code?: unknown; message?: unknown } : {};
  const code = typeof record.code === "string" ? record.code.toUpperCase() : "";
  const message = typeof record.message === "string" ? record.message.toLowerCase() : String(error).toLowerCase();

  if (/disallowed|cloudflare ip|tcp loop|proxy request failed|cannot connect to the specified address/u.test(message)) {
    return new TlsProbeError("platform-blocked", "Cloudflare blocked this raw TLS destination.");
  }
  if (code === "ETIMEDOUT" || /timed out|timeout/u.test(message)) {
    return new TlsProbeError("timeout", "TLS handshake timed out.");
  }
  if (["ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "ECONNRESET"].includes(code)) {
    return new TlsProbeError("unreachable", "The endpoint did not complete a TLS handshake.");
  }
  if (
    /alert protocol version|unsupported protocol|alert handshake failure|no shared cipher|wrong version number/u.test(message)
    && !/no protocols available|no ciphers available/u.test(message)
  ) {
    return new TlsProbeError("rejected", "The endpoint did not negotiate the fixed TLS profile.");
  }
  return new TlsProbeError("unavailable", "The TLS profile could not be determined.");
}

function normalizeProbeError(error: unknown): TlsProbeError {
  return error instanceof TlsProbeError ? error : classifyTlsError(error);
}

function publicFailureMessage(error: TlsProbeError): string {
  switch (error.kind) {
    case "platform-blocked":
      return "Raw TLS inspection is unavailable because Cloudflare blocks sockets to this endpoint range; HTTPS reachability is reported separately.";
    case "timeout":
      return "The bounded TLS handshake timed out; support remains unknown.";
    case "unreachable":
      return "The endpoint did not complete the bounded TLS handshake; support remains unknown.";
    case "rejected":
      return "The endpoint did not negotiate this fixed TLS profile.";
    default:
      return "The Worker runtime could not determine this TLS evidence.";
  }
}

function boundedOptionalText(value: unknown, maxLength: number): string | undefined {
  return typeof value === "string" && value ? boundedText(value, maxLength) : undefined;
}

function optionalSocketEvidence<T>(read: () => T): T | undefined {
  try {
    return read();
  } catch {
    return undefined;
  }
}

function boundedText(value: string, maxLength: number): string {
  return value.replace(/[\u0000-\u001f\u007f]/gu, " ").replace(/\s+/gu, " ").trim().slice(0, maxLength);
}
