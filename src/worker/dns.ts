import type { DnsRecordView } from "../shared/types";

export type DnsQueryType = "TXT" | "MX" | "NS" | "CNAME";

const DNS_TYPE_CODES: Record<DnsQueryType, number> = {
  CNAME: 5,
  MX: 15,
  TXT: 16,
  NS: 2,
};

const DNS_TIMEOUT_MS = 4_500;
const MAX_DNS_QUERIES = 48;

interface DnsJsonAnswer {
  name?: unknown;
  type?: unknown;
  TTL?: unknown;
  data?: unknown;
}

interface DnsJsonResponse {
  Status?: unknown;
  Answer?: unknown;
  Comment?: unknown;
}

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
    const endpoint = new URL("https://cloudflare-dns.com/dns-query");
    endpoint.searchParams.set("name", name);
    endpoint.searchParams.set("type", type);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), DNS_TIMEOUT_MS);

    try {
      const response = await fetch(endpoint.toString(), {
        method: "GET",
        headers: {
          Accept: "application/dns-json",
        },
        redirect: "error",
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new DnsQueryError(`DNS resolver returned HTTP ${response.status}.`);
      }

      const body = (await response.json()) as DnsJsonResponse;
      const status = typeof body.Status === "number" ? body.Status : -1;
      // Status 3 is NXDOMAIN. It is a valid, empty DNS result rather than an
      // upstream failure.
      if (status !== 0 && status !== 3) {
        throw new DnsQueryError(`DNS resolver returned status ${status}.`);
      }
      if (status === 3 || !Array.isArray(body.Answer)) return [];

      const expectedCode = DNS_TYPE_CODES[type];
      return body.Answer.flatMap((raw): DnsAnswer[] => {
        if (!isDnsJsonAnswer(raw) || raw.type !== expectedCode) return [];
        const recordName = stripFinalDot(raw.name);
        const ttl = typeof raw.TTL === "number" && Number.isFinite(raw.TTL) && raw.TTL >= 0 ? raw.TTL : undefined;
        const data = type === "TXT" ? decodeDnsTxt(raw.data) : stripFinalDot(raw.data.trim());
        return [{ name: recordName, type, ttl, data }];
      });
    } catch (error) {
      if (error instanceof DnsQueryError) throw error;
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new DnsQueryError("DNS resolver timed out.");
      }
      throw new DnsQueryError("DNS resolver could not be reached.");
    } finally {
      clearTimeout(timeout);
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

function isDnsJsonAnswer(value: unknown): value is {
  name: string;
  type: number;
  data: string;
  TTL?: unknown;
} {
  if (!value || typeof value !== "object") return false;
  const answer = value as DnsJsonAnswer;
  return typeof answer.name === "string" && typeof answer.type === "number" && typeof answer.data === "string";
}

function stripFinalDot(value: string): string {
  return value.endsWith(".") ? value.slice(0, -1) : value;
}
