import type { DnsRecordView } from "../shared/types";

export const DNS_TYPE_CODES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  LOC: 29,
  SRV: 33,
  CERT: 37,
  DS: 43,
  IPSECKEY: 45,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  NSEC3PARAM: 51,
  TLSA: 52,
  CAA: 257,
} as const;

export type DnsQueryType = keyof typeof DNS_TYPE_CODES;

const DNS_ENDPOINT = "https://dns.google/resolve";
const DNS_TIMEOUT_MS = 4_500;
const MAX_DNS_SUBREQUESTS = 48;
const MAX_ATTEMPTS = 2;
const MAX_CONCURRENT_DNS_QUERIES = 6;
const MAX_DNS_RESPONSE_BYTES = 262_144;
const MAX_DNS_ANSWERS = 256;

export interface DnsAnswer {
  name: string;
  type: DnsQueryType;
  ttl?: number;
  data: string;
}

export type DnsFetch = (url: string, init: RequestInit) => Promise<Response>;

export interface DnsTiming {
  now: () => number;
  setTimeout: (callback: () => void, delayMs: number) => unknown;
  clearTimeout: (handle: unknown) => void;
}

export interface DnsClientOptions {
  fetch?: DnsFetch;
  timing?: DnsTiming;
  timeoutMs?: number;
}

export class DnsQueryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DnsQueryError";
  }
}

class RetryableDnsQueryError extends DnsQueryError {}

const DEFAULT_TIMING: DnsTiming = {
  now: () => Date.now(),
  setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
  clearTimeout: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof globalThis.setTimeout>),
};

export class DnsClient {
  private readonly cache = new Map<string, Promise<DnsAnswer[]>>();
  private readonly fetchImpl: DnsFetch;
  private readonly timing: DnsTiming;
  private readonly timeoutMs: number;
  private subrequestCount = 0;
  private activeQueries = 0;
  private readonly queryWaiters: Array<() => void> = [];

  constructor(options: DnsClientOptions = {}) {
    this.fetchImpl = options.fetch ?? ((url, init) => globalThis.fetch(url, init));
    this.timing = options.timing ?? DEFAULT_TIMING;
    this.timeoutMs = normalizeTimeout(options.timeoutMs);
  }

  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    const safeName = normalizeDnsQueryName(name);
    const typeCode = getDnsTypeCode(type);
    const cacheKey = `${type}:${safeName}`;
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    const query = this.withQuerySlot(() => this.fetchQuery(safeName, type, typeCode));
    this.cache.set(cacheKey, query);
    return query;
  }

  private async withQuerySlot<T>(operation: () => Promise<T>): Promise<T> {
    await this.acquireQuerySlot();
    try {
      return await operation();
    } finally {
      this.releaseQuerySlot();
    }
  }

  private acquireQuerySlot(): Promise<void> {
    if (this.activeQueries < MAX_CONCURRENT_DNS_QUERIES) {
      this.activeQueries += 1;
      return Promise.resolve();
    }

    return new Promise((resolve) => {
      this.queryWaiters.push(() => {
        this.activeQueries += 1;
        resolve();
      });
    });
  }

  private releaseQuerySlot(): void {
    this.activeQueries -= 1;
    const next = this.queryWaiters.shift();
    if (next) next();
  }

  private async fetchQuery(name: string, type: DnsQueryType, typeCode: number): Promise<DnsAnswer[]> {
    const deadline = this.timing.now() + this.timeoutMs;
    let lastError: DnsQueryError | undefined;

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
      const remainingMs = deadline - this.timing.now();
      if (remainingMs <= 0) {
        throw new DnsQueryError("DNS resolver timed out.");
      }

      // Reserve time for the retry so one stalled request cannot consume the
      // entire query budget before a second attempt can begin.
      const attemptsRemaining = MAX_ATTEMPTS - attempt;
      const attemptBudgetMs = Math.max(1, Math.floor(remainingMs / attemptsRemaining));

      try {
        return await this.fetchAttempt(name, type, typeCode, attemptBudgetMs);
      } catch (error) {
        const dnsError = asDnsQueryError(error);
        lastError = dnsError;
        if (!(dnsError instanceof RetryableDnsQueryError) || attempt === MAX_ATTEMPTS - 1) {
          throw new DnsQueryError(dnsError.message);
        }
      }
    }

    throw lastError ?? new DnsQueryError("DNS resolver could not be reached.");
  }

  private async fetchAttempt(
    name: string,
    type: DnsQueryType,
    typeCode: number,
    timeoutMs: number,
  ): Promise<DnsAnswer[]> {
    if (this.subrequestCount >= MAX_DNS_SUBREQUESTS) {
      throw new DnsQueryError("The DNS lookup safety limit was reached.");
    }
    this.subrequestCount += 1;

    const url = new URL(DNS_ENDPOINT);
    url.searchParams.set("name", name);
    url.searchParams.set("type", String(typeCode));

    const controller = new AbortController();
    let timeoutHandle: unknown;
    const timeout = new Promise<never>((_, reject) => {
      timeoutHandle = this.timing.setTimeout(() => {
        controller.abort();
        reject(new RetryableDnsQueryError("DNS resolver timed out."));
      }, timeoutMs);
    });

    const request = this.performRequest(url.toString(), controller.signal, name, type, typeCode);

    try {
      return await Promise.race([request, timeout]);
    } catch (error) {
      if (error instanceof DnsQueryError) throw error;
      throw new RetryableDnsQueryError("DNS resolver could not be reached.");
    } finally {
      if (timeoutHandle !== undefined) this.timing.clearTimeout(timeoutHandle);
    }
  }

  private async performRequest(
    url: string,
    signal: AbortSignal,
    queryName: string,
    queryType: DnsQueryType,
    queryTypeCode: number,
  ): Promise<DnsAnswer[]> {
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: "GET",
        headers: { Accept: "application/dns-json" },
        redirect: "error",
        signal,
      });
    } catch {
      throw new RetryableDnsQueryError("DNS resolver could not be reached.");
    }

    if (!response.ok) {
      const ErrorType = isRetryableHttpStatus(response.status) ? RetryableDnsQueryError : DnsQueryError;
      throw new ErrorType(`DNS resolver returned HTTP ${response.status}.`);
    }

    const declaredLength = Number(response.headers.get("content-length") ?? "0");
    if (Number.isFinite(declaredLength) && declaredLength > MAX_DNS_RESPONSE_BYTES) {
      throw new DnsQueryError("DNS resolver response exceeded the safety limit.");
    }

    let payload: unknown;
    try {
      const body = await response.text();
      if (new TextEncoder().encode(body).byteLength > MAX_DNS_RESPONSE_BYTES) {
        throw new DnsQueryError("DNS resolver response exceeded the safety limit.");
      }
      payload = JSON.parse(body) as unknown;
    } catch (error) {
      if (error instanceof DnsQueryError) throw error;
      throw new RetryableDnsQueryError("DNS resolver returned a malformed response.");
    }

    return parseDnsResponse(payload, queryName, queryType, queryTypeCode);
  }
}

export function toRecordViews(answers: DnsAnswer[]): DnsRecordView[] {
  return answers.map((answer) => ({
    name: answer.name,
    type: answer.type,
    value: answer.data,
    ...(answer.ttl === undefined ? {} : { ttl: answer.ttl }),
  }));
}

/** Decode one TXT RR from the quoted presentation form returned by DNS JSON APIs. */
export function decodeDnsTxt(data: string): string {
  const value = data.trim();
  if (!value.startsWith('"')) return value;

  let result = "";
  let index = 0;
  let sawQuotedChunk = false;

  while (index < value.length) {
    while (index < value.length && /\s/u.test(value[index] ?? "")) index += 1;
    if (index >= value.length) break;
    if (value[index] !== '"') return value;

    sawQuotedChunk = true;
    index += 1;
    let closed = false;

    while (index < value.length) {
      const character = value[index] ?? "";
      if (character === '"') {
        index += 1;
        closed = true;
        break;
      }
      if (character !== "\\") {
        result += character;
        index += 1;
        continue;
      }

      index += 1;
      const escaped = value[index];
      if (escaped === undefined) return value;

      const decimalEscape = value.slice(index, index + 3);
      if (/^\d{3}$/u.test(decimalEscape)) {
        result += String.fromCharCode(Number(decimalEscape));
        index += 3;
      } else {
        result += escaped;
        index += 1;
      }
    }

    if (!closed) return value;
  }

  return sawQuotedChunk ? result : value;
}

function parseDnsResponse(
  payload: unknown,
  queryName: string,
  queryType: DnsQueryType,
  queryTypeCode: number,
): DnsAnswer[] {
  if (!isObject(payload) || !Number.isInteger(payload.Status)) {
    throw new RetryableDnsQueryError("DNS resolver returned a malformed response.");
  }

  const status = payload.Status as number;
  if (status === 3) return [];
  if (status === 2) throw new RetryableDnsQueryError("DNS resolver returned SERVFAIL.");
  if (status !== 0) {
    const label = status === 5 ? "REFUSED" : `DNS status ${status}`;
    throw new DnsQueryError(`DNS resolver returned ${label}.`);
  }

  if (payload.Answer === undefined || payload.Answer === null) return [];
  if (!Array.isArray(payload.Answer)) {
    throw new RetryableDnsQueryError("DNS resolver returned a malformed response.");
  }
  if (payload.Answer.length > MAX_DNS_ANSWERS) {
    throw new DnsQueryError("DNS resolver response exceeded the safety limit.");
  }

  const answers: DnsAnswer[] = [];
  for (const item of payload.Answer) {
    if (!isDnsJsonAnswer(item)) {
      throw new RetryableDnsQueryError("DNS resolver returned a malformed response.");
    }
    if (item.type !== queryTypeCode) continue;

    answers.push({
      name: formatOwnerName(item.name || queryName),
      type: queryType,
      ttl: item.TTL,
      data: formatDnsData(item.data, queryType),
    });
  }

  return answers;
}

function isDnsJsonAnswer(value: unknown): value is { name: string; type: number; TTL: number; data: string } {
  if (!isObject(value)) return false;
  return (
    typeof value.name === "string" &&
    Number.isInteger(value.type) &&
    Number.isInteger(value.TTL) &&
    (value.TTL as number) >= 0 &&
    typeof value.data === "string"
  );
}

function formatDnsData(data: string, type: DnsQueryType): string {
  const value = data.trim();
  switch (type) {
    case "TXT":
      return decodeDnsTxt(value);
    case "NS":
    case "CNAME":
    case "PTR":
      return formatDomainToken(value);
    case "MX":
      return formatTokenizedDomains(value, [1]);
    case "SOA":
      return formatTokenizedDomains(value, [0, 1]);
    case "SRV":
      return formatTokenizedDomains(value, [3]);
    case "RRSIG":
      return formatTokenizedDomains(value, [7]);
    case "NSEC":
      return formatTokenizedDomains(value, [0]);
    case "IPSECKEY":
      return formatTokenizedDomains(value, [3]);
    default:
      return value;
  }
}

function formatTokenizedDomains(value: string, domainIndexes: number[]): string {
  const tokens = value.split(/\s+/u);
  for (const index of domainIndexes) {
    if (index < tokens.length) tokens[index] = formatDomainToken(tokens[index] ?? "");
  }
  return tokens.join(" ");
}

function formatOwnerName(value: string): string {
  const normalized = value.trim().toLowerCase();
  return formatDomainToken(normalized);
}

function formatDomainToken(value: string): string {
  return value === "." ? value : value.replace(/\.$/u, "");
}

function normalizeDnsQueryName(name: string): string {
  const normalized = name.trim().replace(/\.$/u, "").toLowerCase();
  if (!normalized || normalized.length > 253 || !/^[a-z0-9._-]+$/u.test(normalized)) {
    throw new DnsQueryError("Refused an invalid DNS query name.");
  }

  const labels = normalized.split(".");
  if (
    labels.some(
      (label) =>
        !label ||
        label.length > 63 ||
        !/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/u.test(label),
    )
  ) {
    throw new DnsQueryError("Refused an invalid DNS query name.");
  }
  return normalized;
}

function getDnsTypeCode(type: DnsQueryType): number {
  const typeCode = (DNS_TYPE_CODES as Partial<Record<string, number>>)[type];
  if (typeCode === undefined) throw new DnsQueryError("Refused an invalid DNS query type.");
  return typeCode;
}

function normalizeTimeout(timeoutMs: number | undefined): number {
  if (timeoutMs === undefined) return DNS_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new DnsQueryError("Refused an invalid DNS timeout.");
  }
  return Math.floor(timeoutMs);
}

function isRetryableHttpStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

function asDnsQueryError(error: unknown): DnsQueryError {
  return error instanceof DnsQueryError ? error : new RetryableDnsQueryError("DNS resolver could not be reached.");
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
