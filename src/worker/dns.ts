import dns, {
  type CaaRecord,
  type MxRecord,
  type RecordWithTtl,
  type SoaRecord,
  type SrvRecord,
} from "node:dns";
import type { DnsRecordView } from "../shared/types";

/** RR types exposed by Workerd's specific node:dns resolver methods. */
export const DNS_TYPE_CODES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  CAA: 257,
} as const;

export type DnsQueryType = keyof typeof DNS_TYPE_CODES;

const DNS_TIMEOUT_MS = 4_500;
const MAX_DNS_SUBREQUESTS = 48;
const MAX_ATTEMPTS = 2;
const MAX_CONCURRENT_DNS_QUERIES = 6;
const MAX_DNS_ANSWERS = 256;
const MAX_DNS_RESULT_CHARACTERS = 262_144;
const MAX_CNAME_HOPS = 8;

export interface DnsAnswer {
  name: string;
  type: DnsQueryType;
  ttl?: number;
  data: string;
}

export interface DnsFollowingResult {
  answers: DnsAnswer[];
  canonicalName: string;
  aliases: DnsAnswer[];
}

/** Injectable subset of node:dns used by the Worker. */
export interface NativeDnsResolver {
  resolve4(name: string, options: { ttl: true }): Promise<RecordWithTtl[]>;
  resolve6(name: string, options: { ttl: true }): Promise<RecordWithTtl[]>;
  resolveCaa(name: string): Promise<CaaRecord[]>;
  resolveCname(name: string): Promise<string[]>;
  resolveMx(name: string): Promise<MxRecord[]>;
  resolveNs(name: string): Promise<string[]>;
  resolvePtr(name: string): Promise<string[]>;
  resolveSoa(name: string): Promise<SoaRecord>;
  resolveSrv(name: string): Promise<SrvRecord[]>;
  resolveTxt(name: string): Promise<string[][]>;
}

export interface DnsTiming {
  now: () => number;
  setTimeout: (callback: () => void, delayMs: number) => unknown;
  clearTimeout: (handle: unknown) => void;
}

export interface DnsClientOptions {
  resolver?: NativeDnsResolver;
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
  private readonly queryCache = new Map<string, Promise<DnsAnswer[]>>();
  private readonly directCache = new Map<string, Promise<DnsAnswer[]>>();
  private readonly canonicalCache = new Map<string, Promise<DnsFollowingResult>>();
  private readonly cnameChainCache = new Map<string, Promise<Omit<DnsFollowingResult, "answers">>>();
  private readonly resolver: NativeDnsResolver;
  private readonly timing: DnsTiming;
  private readonly timeoutMs: number;
  private subrequestCount = 0;
  private activeQueries = 0;
  private readonly queryWaiters: Array<() => void> = [];

  constructor(options: DnsClientOptions = {}) {
    this.resolver = options.resolver ?? dns.promises;
    this.timing = options.timing ?? DEFAULT_TIMING;
    this.timeoutMs = normalizeTimeout(options.timeoutMs);
  }

  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    if (type === "CNAME") return this.queryDirect(name, type);

    const safeName = normalizeDnsQueryName(name);
    validateDnsQueryType(type);
    const cacheKey = `FOLLOW:${type}:${safeName}`;
    const cached = this.queryCache.get(cacheKey);
    if (cached) return cached;

    const query = this.queryFollowingCname(safeName, type).then((result) => result.answers);
    this.queryCache.set(cacheKey, query);
    return query;
  }

  /** Run one native query without following aliases. Used internally for CNAME hops and terminal records. */
  queryDirect(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    const safeName = normalizeDnsQueryName(name);
    validateDnsQueryType(type);
    return this.queryDirectUntil(safeName, type, this.timing.now() + this.timeoutMs);
  }

  /** Follow CNAMEs before asking Workerd to normalize a terminal record type. */
  queryFollowingCname(
    name: string,
    type: Exclude<DnsQueryType, "CNAME">,
  ): Promise<DnsFollowingResult> {
    const safeName = normalizeDnsQueryName(name);
    validateDnsQueryType(type);
    const cacheKey = `FOLLOW:${type}:${safeName}`;
    const cached = this.canonicalCache.get(cacheKey);
    if (cached) return cached;

    const deadline = this.timing.now() + this.timeoutMs;
    const query = this.withLogicalQueryDeadline(deadline, async () => {
      const chain = await this.resolveCnameChain(safeName, deadline);
      const answers = await this.queryDirectUntil(chain.canonicalName, type, deadline);
      return { answers, canonicalName: chain.canonicalName, aliases: chain.aliases };
    });
    this.canonicalCache.set(cacheKey, query);
    return query;
  }

  /**
   * Workerd's node:dns adapter currently passes CNAME and terminal answers to
   * type-specific normalizers. Resolve the alias chain first so a CNAME cannot
   * be mislabeled as an address/TXT/NS value or break a structured parser.
   */
  private resolveCnameChain(
    name: string,
    deadline: number,
  ): Promise<Omit<DnsFollowingResult, "answers">> {
    const cached = this.cnameChainCache.get(name);
    if (cached) return this.withLogicalQueryDeadline(deadline, () => cached);

    const query = this.withLogicalQueryDeadline(deadline, () => this.resolveCnameChainUncached(name, deadline));
    this.cnameChainCache.set(name, query);
    return query;
  }

  private async resolveCnameChainUncached(
    name: string,
    deadline: number,
  ): Promise<Omit<DnsFollowingResult, "answers">> {
    let current = name;
    const visited = new Set([current]);
    const chain: DnsAnswer[] = [];

    for (let hop = 0; ; hop += 1) {
      const aliases = await this.queryDirectUntil(current, "CNAME", deadline);
      if (aliases.length === 0) {
        return { canonicalName: current, aliases: chain };
      }
      if (hop >= MAX_CNAME_HOPS) throw new DnsQueryError("DNS CNAME chain exceeded the safety limit.");

      const alias = aliases[0];
      const target = normalizeDnsQueryName(alias?.data ?? "");
      if (visited.has(target)) {
        throw new DnsQueryError("DNS returned a CNAME loop.");
      }
      if (alias) chain.push(alias);
      visited.add(target);
      current = target;
    }
  }

  private queryDirectUntil(name: string, type: DnsQueryType, deadline: number): Promise<DnsAnswer[]> {
    const cacheKey = `DIRECT:${type}:${name}`;
    const cached = this.directCache.get(cacheKey);
    if (cached) return this.withLogicalQueryDeadline(deadline, () => cached);

    const query = this.withQuerySlot(deadline, () => this.resolveQuery(name, type, deadline));
    this.directCache.set(cacheKey, query);
    return this.withLogicalQueryDeadline(deadline, () => query);
  }

  private withLogicalQueryDeadline<T>(deadline: number, operation: () => Promise<T>): Promise<T> {
    const remainingMs = deadline - this.timing.now();
    if (remainingMs <= 0) return Promise.reject(new DnsQueryError("DNS resolver timed out."));

    let timeoutHandle: unknown;
    const timeout = new Promise<never>((_, reject) => {
      timeoutHandle = this.timing.setTimeout(
        () => reject(new DnsQueryError("DNS resolver timed out.")),
        remainingMs,
      );
    });

    return Promise.race([operation(), timeout]).finally(() => {
      if (timeoutHandle !== undefined) this.timing.clearTimeout(timeoutHandle);
    });
  }

  private async withQuerySlot<T>(deadline: number, operation: () => Promise<T>): Promise<T> {
    await this.acquireQuerySlot(deadline);
    try {
      return await operation();
    } finally {
      this.releaseQuerySlot();
    }
  }

  private acquireQuerySlot(deadline: number): Promise<void> {
    if (this.activeQueries < MAX_CONCURRENT_DNS_QUERIES) {
      this.activeQueries += 1;
      return Promise.resolve();
    }

    const remainingMs = deadline - this.timing.now();
    if (remainingMs <= 0) return Promise.reject(new DnsQueryError("DNS resolver timed out."));

    return new Promise((resolve, reject) => {
      let settled = false;
      let timeoutHandle: unknown;
      const activate = () => {
        if (settled) return;
        settled = true;
        if (timeoutHandle !== undefined) this.timing.clearTimeout(timeoutHandle);
        this.activeQueries += 1;
        resolve();
      };

      timeoutHandle = this.timing.setTimeout(() => {
        if (settled) return;
        settled = true;
        const waiterIndex = this.queryWaiters.indexOf(activate);
        if (waiterIndex >= 0) this.queryWaiters.splice(waiterIndex, 1);
        reject(new DnsQueryError("DNS resolver timed out."));
      }, remainingMs);
      this.queryWaiters.push(activate);
    });
  }

  private releaseQuerySlot(): void {
    this.activeQueries -= 1;
    const next = this.queryWaiters.shift();
    if (next) next();
  }

  private async resolveQuery(name: string, type: DnsQueryType, deadline: number): Promise<DnsAnswer[]> {
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
      if (deadline - this.timing.now() <= 0) throw new DnsQueryError("DNS resolver timed out.");

      try {
        return await this.resolveAttempt(name, type);
      } catch (error) {
        if (isDnsAbsenceError(error)) return [];

        const dnsError = normalizeDnsError(error);
        if (!(dnsError instanceof RetryableDnsQueryError) || attempt === MAX_ATTEMPTS - 1) {
          throw new DnsQueryError(dnsError.message);
        }
      }
    }

    throw new DnsQueryError("DNS resolver could not be reached.");
  }

  private async resolveAttempt(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    if (this.subrequestCount >= MAX_DNS_SUBREQUESTS) {
      throw new DnsQueryError("The DNS lookup safety limit was reached.");
    }
    this.subrequestCount += 1;

    // node:dns promises are not abortable. The outer logical deadline can stop
    // waiting, but this native operation retains its concurrency slot until it
    // settles so timed-out work cannot exceed the six-query ceiling.
    const answers = await this.resolveNative(name, type);
    validateAnswerSet(answers);
    return answers;
  }

  private async resolveNative(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    switch (type) {
      case "A":
        return formatAddressAnswers(name, type, await this.resolver.resolve4(name, { ttl: true }));
      case "AAAA":
        return formatAddressAnswers(name, type, await this.resolver.resolve6(name, { ttl: true }));
      case "CAA":
        return formatCaaAnswers(name, await this.resolver.resolveCaa(name));
      case "CNAME":
        return formatNameAnswers(name, type, await this.resolver.resolveCname(name));
      case "MX":
        return formatMxAnswers(name, await this.resolver.resolveMx(name));
      case "NS":
        return formatNameAnswers(name, type, await this.resolver.resolveNs(name));
      case "PTR":
        return formatNameAnswers(name, type, await this.resolver.resolvePtr(name));
      case "SOA":
        return [formatSoaAnswer(name, await this.resolver.resolveSoa(name))];
      case "SRV":
        return formatSrvAnswers(name, await this.resolver.resolveSrv(name));
      case "TXT":
        return formatTxtAnswers(name, await this.resolver.resolveTxt(name));
    }
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

/**
 * Join the character-strings within one TXT RR. Workerd currently sometimes
 * returns Cloudflare JSON presentation boundaries (`" "`) inside a single
 * chunk. Repair only syntax that cannot be legitimate protocol content.
 */
export function joinDnsTxtChunks(chunks: readonly string[], ownerName?: string): string {
  if (!Array.isArray(chunks) || chunks.some((chunk) => typeof chunk !== "string")) {
    throw new DnsQueryError("DNS resolver returned malformed TXT data.");
  }

  const joined = chunks.join("");
  const isDkimOwner = ownerName?.toLowerCase().includes("._domainkey.") ?? false;
  if (isDkimOwner || isDkimTxt(joined)) return repairDkimPublicKeyBoundaries(joined);
  return isStructuredEmailTxt(joined) ? joined.replace(/"\s*"/gu, "") : joined;
}

/** Decode quoted DNS presentation data retained for parser and fixture compatibility. */
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

function formatAddressAnswers(name: string, type: "A" | "AAAA", records: RecordWithTtl[]): DnsAnswer[] {
  assertArray(records);
  return records.map((record) => {
    if (!isObject(record) || typeof record.address !== "string" || !isValidTtl(record.ttl)) {
      throw new DnsQueryError("DNS resolver returned malformed address data.");
    }
    return { name, type, ttl: record.ttl, data: record.address };
  });
}

function formatNameAnswers(name: string, type: "CNAME" | "NS" | "PTR", records: string[]): DnsAnswer[] {
  assertStringArray(records);
  return records.map((record) => ({ name, type, data: stripFinalDot(record) }));
}

function formatMxAnswers(name: string, records: MxRecord[]): DnsAnswer[] {
  assertArray(records);
  return records.map((record) => {
    if (!isObject(record) || !isUnsignedInteger(record.priority) || typeof record.exchange !== "string") {
      throw new DnsQueryError("DNS resolver returned malformed MX data.");
    }
    const exchange = stripFinalDot(record.exchange) || ".";
    return { name, type: "MX", data: `${record.priority} ${exchange}` };
  });
}

function formatCaaAnswers(name: string, records: CaaRecord[]): DnsAnswer[] {
  assertArray(records);
  return records.map((record) => {
    if (!isObject(record) || !isUnsignedInteger(record.critical) || record.critical > 255) {
      throw new DnsQueryError("DNS resolver returned malformed CAA data.");
    }

    const tag = ["issue", "issuewild", "iodef", "contactemail", "contactphone"].find(
      (candidate) => typeof record[candidate as keyof CaaRecord] === "string",
    ) as keyof CaaRecord | undefined;
    const value = tag === undefined ? undefined : record[tag];
    if (tag === undefined || typeof value !== "string") {
      throw new DnsQueryError("DNS resolver returned malformed CAA data.");
    }

    return {
      name,
      type: "CAA",
      data: `${record.critical} ${String(tag)} "${escapeQuotedValue(value)}"`,
    };
  });
}

function formatSoaAnswer(name: string, record: SoaRecord): DnsAnswer {
  if (
    !isObject(record) ||
    typeof record.nsname !== "string" ||
    typeof record.hostmaster !== "string" ||
    !isUnsignedInteger(record.serial) ||
    !isUnsignedInteger(record.refresh) ||
    !isUnsignedInteger(record.retry) ||
    !isUnsignedInteger(record.expire) ||
    !isUnsignedInteger(record.minttl)
  ) {
    throw new DnsQueryError("DNS resolver returned malformed SOA data.");
  }

  return {
    name,
    type: "SOA",
    data: [
      stripFinalDot(record.nsname),
      stripFinalDot(record.hostmaster),
      record.serial,
      record.refresh,
      record.retry,
      record.expire,
      record.minttl,
    ].join(" "),
  };
}

function formatSrvAnswers(name: string, records: SrvRecord[]): DnsAnswer[] {
  assertArray(records);
  return records.map((record) => {
    if (
      !isObject(record) ||
      !isUnsignedInteger(record.priority) ||
      !isUnsignedInteger(record.weight) ||
      !isUnsignedInteger(record.port) ||
      typeof record.name !== "string"
    ) {
      throw new DnsQueryError("DNS resolver returned malformed SRV data.");
    }
    return {
      name,
      type: "SRV",
      data: `${record.priority} ${record.weight} ${record.port} ${stripFinalDot(record.name)}`,
    };
  });
}

function formatTxtAnswers(name: string, records: string[][]): DnsAnswer[] {
  assertArray(records);
  return records.map((chunks) => ({ name, type: "TXT", data: joinDnsTxtChunks(chunks, name) }));
}

function validateAnswerSet(answers: DnsAnswer[]): void {
  if (!Array.isArray(answers) || answers.length > MAX_DNS_ANSWERS) {
    throw new DnsQueryError("DNS resolver response exceeded the safety limit.");
  }

  let characters = 0;
  for (const answer of answers) {
    characters += answer.name.length + answer.data.length;
    if (characters > MAX_DNS_RESULT_CHARACTERS) {
      throw new DnsQueryError("DNS resolver response exceeded the safety limit.");
    }
  }
}

function assertArray(value: unknown): asserts value is unknown[] {
  if (!Array.isArray(value) || value.length > MAX_DNS_ANSWERS) {
    throw new DnsQueryError("DNS resolver returned malformed response data.");
  }
}

function assertStringArray(value: unknown): asserts value is string[] {
  assertArray(value);
  if (value.some((item) => typeof item !== "string")) {
    throw new DnsQueryError("DNS resolver returned malformed response data.");
  }
}

function isStructuredEmailTxt(value: string): boolean {
  return /^v=(?:spf1|dmarc1|bimi1|tlsrptv1|stsv1)\b/iu.test(
    value.trimStart(),
  );
}

function isDkimTxt(value: string): boolean {
  return /^(?:v=dkim1\b|(?:h|k|n|p|s|t)\s*=)/iu.test(value.trimStart());
}

/**
 * Workerd can leak TXT presentation chunk markers into a DKIM public key.
 * Repair only an impossible marker inside p='s base64 instead of rewriting
 * the whole record, where quoted text can legitimately appear in n= notes.
 */
function repairDkimPublicKeyBoundaries(value: string): string {
  return value.replace(
    /((?:^|;)\s*p\s*=\s*)([^;]*)/iu,
    (_match, prefix: string, publicKey: string) =>
      `${prefix}${publicKey.replace(/([a-z0-9+/=])"\s*"(?=[a-z0-9+/=])/giu, "$1")}`,
  );
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

function validateDnsQueryType(type: DnsQueryType): void {
  if (!(type in DNS_TYPE_CODES)) throw new DnsQueryError("Refused an unsupported DNS query type.");
}

function normalizeTimeout(timeoutMs: number | undefined): number {
  if (timeoutMs === undefined) return DNS_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new DnsQueryError("Refused an invalid DNS timeout.");
  }
  return Math.floor(timeoutMs);
}

function isDnsAbsenceError(value: unknown): boolean {
  const code = dnsErrorCode(value);
  return code === "ENODATA" || code === "ENOTFOUND" || code === "NXDOMAIN";
}

function normalizeDnsError(value: unknown): DnsQueryError {
  if (value instanceof DnsQueryError) return value;

  const code = dnsErrorCode(value);
  if (code === "ESERVFAIL") return new RetryableDnsQueryError("DNS resolver returned SERVFAIL.");
  if (code === "EREFUSED") return new DnsQueryError("DNS resolver returned REFUSED.");
  if (
    code === "ETIMEOUT" ||
    code === "ECONNREFUSED" ||
    code === "EAI_AGAIN" ||
    code === "EBADQUERY" ||
    code === "EBADRESP"
  ) {
    return new RetryableDnsQueryError("DNS resolver could not be reached.");
  }
  return new DnsQueryError("DNS resolver could not complete the query.");
}

function dnsErrorCode(value: unknown): string | undefined {
  if (!isObject(value) || typeof value.code !== "string") return undefined;
  return value.code.toUpperCase();
}

function isValidTtl(value: unknown): value is number {
  return isUnsignedInteger(value) && value <= 2 ** 32 - 1;
}

function isUnsignedInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function escapeQuotedValue(value: string): string {
  return value.replace(/["\\]/gu, "\\$&");
}

function stripFinalDot(value: string): string {
  return value === "." ? value : value.replace(/\.$/u, "");
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
