import dns from "node:dns";
import type { DnsRecordView } from "../shared/types";

export type DnsQueryType = "TXT" | "MX" | "NS" | "CNAME";

const DNS_TIMEOUT_MS = 4_500;
const MAX_DNS_QUERIES = 48;

export interface DnsAnswer {
  name: string;
  type: DnsQueryType;
  ttl?: number;
  data: string;
}

export class DnsQueryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DnsQueryError";
  }
}

export class DnsClient {
  private readonly cache = new Map<string, Promise<DnsAnswer[]>>();
  private queryCount = 0;

  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    const safeName = normalizeDnsQueryName(name);
    const cacheKey = `${type}:${safeName}`;
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    if (this.queryCount >= MAX_DNS_QUERIES) {
      return Promise.reject(new DnsQueryError("The DNS lookup safety limit was reached."));
    }
    this.queryCount += 1;

    const query = this.fetchQuery(safeName, type);
    this.cache.set(cacheKey, query);
    return query;
  }

  private async fetchQuery(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    let timeout: ReturnType<typeof setTimeout> | undefined;

    try {
      const timeoutPromise = new Promise<never>((_, reject) => {
        timeout = setTimeout(() => reject(new DnsQueryError("DNS resolver timed out.")), DNS_TIMEOUT_MS);
      });
      return await Promise.race([this.resolveNodeDns(name, type), timeoutPromise]);
    } catch (error) {
      if (error instanceof DnsQueryError) throw error;
      if (isDnsAbsenceError(error)) return [];
      throw new DnsQueryError("DNS resolver could not be reached.");
    } finally {
      if (timeout !== undefined) clearTimeout(timeout);
    }
  }

  private async resolveNodeDns(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    switch (type) {
      case "TXT": {
        const records = await dns.promises.resolveTxt(name);
        return records.map((chunks) => ({ name, type, data: chunks.join("") }));
      }
      case "MX": {
        const records = await dns.promises.resolveMx(name);
        return records.map((record) => ({
          name,
          type,
          data: `${record.priority} ${stripFinalDot(record.exchange)}`,
        }));
      }
      case "NS": {
        const records = await dns.promises.resolveNs(name);
        return records.map((record) => ({ name, type, data: stripFinalDot(record) }));
      }
      case "CNAME": {
        const records = await dns.promises.resolveCname(name);
        return records.map((record) => ({ name, type, data: stripFinalDot(record) }));
      }
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

/** Decode the presentation form returned by Cloudflare's DNS JSON endpoint. */
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

function normalizeDnsQueryName(name: string): string {
  const normalized = name.trim().replace(/\.$/u, "").toLowerCase();
  if (!normalized || normalized.length > 253 || !/^[a-z0-9._-]+$/u.test(normalized)) {
    throw new DnsQueryError("Refused an invalid DNS query name.");
  }

  const labels = normalized.split(".");
  if (labels.some((label) => !label || label.length > 63 || !/^[a-z0-9_-]+$/u.test(label))) {
    throw new DnsQueryError("Refused an invalid DNS query name.");
  }
  return normalized;
}

function isDnsAbsenceError(value: unknown): boolean {
  if (!value || typeof value !== "object" || !("code" in value)) return false;
  const code = (value as { code?: unknown }).code;
  return code === "ENODATA" || code === "ENOTFOUND" || code === "ENONAME" || code === "NXDOMAIN";
}

function stripFinalDot(value: string): string {
  return value.endsWith(".") ? value.slice(0, -1) : value;
}
