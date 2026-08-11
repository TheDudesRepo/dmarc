import type { DnsLookupResult, DnsLookupType } from "../shared/types";
import { DnsClient, type DnsAnswer, type DnsQueryType, toRecordViews } from "./dns";

const MAX_INPUT_LENGTH = 512;
const MAX_DNS_NAME_LENGTH = 253;
const NON_PUBLIC_SUFFIXES = new Set([
  "home",
  "internal",
  "invalid",
  "lan",
  "local",
  "localdomain",
  "localhost",
  "onion",
  "test",
]);

export const DNS_LOOKUP_TYPES = [
  "A",
  "AAAA",
  "CAA",
  "CERT",
  "CNAME",
  "DNSKEY",
  "DS",
  "IPSECKEY",
  "LOC",
  "MX",
  "NS",
  "NSEC",
  "NSEC3PARAM",
  "PTR",
  "RRSIG",
  "SOA",
  "SRV",
  "TLSA",
  "TXT",
] as const satisfies readonly DnsLookupType[];

const DNS_LOOKUP_TYPE_SET = new Set<string>(DNS_LOOKUP_TYPES);

export interface LookupResolver {
  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]>;
}

export interface NormalizedLookupRequest {
  input: string;
  queryName: string;
  type: DnsLookupType;
}

export class LookupValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LookupValidationError";
  }
}

export class LookupUpstreamError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LookupUpstreamError";
  }
}

export function normalizeLookupRequest(name: unknown, type: unknown): NormalizedLookupRequest {
  const normalizedType = normalizeLookupType(type);
  if (normalizedType === "PTR") return normalizePtrRequest(name);

  const queryName = normalizePublicOwnerName(name);
  return { input: queryName, queryName, type: normalizedType };
}

export async function lookupDns(
  name: unknown,
  type: unknown,
  dns: LookupResolver = new DnsClient(),
): Promise<DnsLookupResult> {
  const request = normalizeLookupRequest(name, type);
  const scannedAt = new Date().toISOString();
  const startedAt = performance.now();

  let answers: DnsAnswer[];
  try {
    answers = await dns.query(request.queryName, request.type);
  } catch (error) {
    const detail = error instanceof Error ? error.message : "DNS resolver failed without a typed error.";
    throw new LookupUpstreamError(detail);
  }

  const records = toRecordViews(answers);
  const recordLabel = `${request.type} ${records.length === 1 ? "record" : "records"}`;
  const summary = records.length === 0
    ? `No ${request.type} records were returned for ${request.queryName}.`
    : `${records.length} ${recordLabel} returned for ${request.queryName}.`;

  return {
    input: request.input,
    queryName: request.queryName,
    type: request.type,
    scannedAt,
    durationMs: Math.max(1, Math.round(performance.now() - startedAt)),
    records,
    summary,
  };
}

function normalizeLookupType(type: unknown): DnsLookupType {
  if (typeof type !== "string" || !DNS_LOOKUP_TYPE_SET.has(type)) {
    throw new LookupValidationError(`Type must be one of: ${DNS_LOOKUP_TYPES.join(", ")}.`);
  }
  return type as DnsLookupType;
}

function normalizePublicOwnerName(input: unknown): string {
  const value = requireStringInput(input);
  if (value.includes(":")) {
    throw new LookupValidationError("IP addresses are only accepted for PTR lookups.");
  }
  if (/[\\/@:?#%*]/u.test(value)) {
    throw new LookupValidationError("Enter a DNS owner name only, without a URL, path, port, email address, or wildcard.");
  }
  if (!/^[\p{L}\p{N}\p{M}._-]+$/u.test(value)) {
    throw new LookupValidationError("DNS name contains unsupported characters.");
  }
  if (value.endsWith("..")) {
    throw new LookupValidationError("DNS name has an invalid trailing dot.");
  }

  const withoutTrailingDot = value.endsWith(".") ? value.slice(0, -1) : value;
  let ascii: string;
  try {
    ascii = new URL(`https://${withoutTrailingDot}`).hostname.toLowerCase();
  } catch {
    throw new LookupValidationError("Enter a valid DNS owner name.");
  }

  if (!ascii || ascii.length > MAX_DNS_NAME_LENGTH) {
    throw new LookupValidationError("DNS name must be 253 characters or fewer.");
  }

  const labels = ascii.split(".");
  if (labels.length < 2) {
    throw new LookupValidationError("Enter a public DNS name with at least two labels.");
  }
  for (const label of labels) {
    if (!label || label.length > 63) {
      throw new LookupValidationError("Each DNS label must be between 1 and 63 characters.");
    }
    if (!/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/u.test(label)) {
      throw new LookupValidationError("DNS labels cannot begin or end with a hyphen.");
    }
  }

  const suffix = labels.at(-1) ?? "";
  if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(suffix) || !/[a-z]/u.test(suffix)) {
    throw new LookupValidationError("The public DNS suffix must contain a letter and cannot contain underscores.");
  }
  if (NON_PUBLIC_SUFFIXES.has(suffix)) {
    throw new LookupValidationError("Enter a name published in the public DNS.");
  }
  if (parseIpv4(ascii) !== null) {
    throw new LookupValidationError("IP addresses are only accepted for PTR lookups.");
  }

  return ascii;
}

function normalizePtrRequest(input: unknown): NormalizedLookupRequest {
  const value = requireStringInput(input);
  const ipv4 = parseIpv4(value);
  if (ipv4 !== null) {
    return {
      input: ipv4,
      queryName: `${ipv4.split(".").reverse().join(".")}.in-addr.arpa`,
      type: "PTR",
    };
  }

  const ipv6 = parseIpv6(value);
  if (ipv6 !== null) {
    return {
      input: ipv6,
      queryName: ipv6ToReverseOwner(ipv6),
      type: "PTR",
    };
  }

  let owner: string;
  try {
    owner = normalizePublicOwnerName(value);
  } catch {
    throw new LookupValidationError("PTR name must be an IPv4 address, IPv6 address, or complete reverse-DNS owner name.");
  }

  if (!isCompleteReverseOwner(owner)) {
    throw new LookupValidationError("PTR name must be an IPv4 address, IPv6 address, or complete reverse-DNS owner name.");
  }
  return { input: owner, queryName: owner, type: "PTR" };
}

function requireStringInput(input: unknown): string {
  if (typeof input !== "string") {
    throw new LookupValidationError("Name must be a string.");
  }
  const value = input.trim();
  if (!value) throw new LookupValidationError("Enter a DNS name or IP address.");
  if (value.length > MAX_INPUT_LENGTH) throw new LookupValidationError("DNS input is too long.");
  if (/\s/u.test(value)) throw new LookupValidationError("DNS input cannot contain whitespace.");
  return value;
}

function parseIpv4(value: string): string | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  if (!parts.every((part) => /^(?:0|[1-9]\d{0,2})$/u.test(part) && Number(part) <= 255)) return null;
  return parts.map((part) => String(Number(part))).join(".");
}

function parseIpv6(value: string): string | null {
  if (!value.includes(":") || /[%\[\]]/u.test(value)) return null;
  try {
    const hostname = new URL(`http://[${value}]/`).hostname;
    if (!hostname.startsWith("[") || !hostname.endsWith("]")) return null;
    return hostname.slice(1, -1).toLowerCase();
  } catch {
    return null;
  }
}

function ipv6ToReverseOwner(address: string): string {
  const [leftPart, rightPart, ...extra] = address.split("::");
  if (extra.length > 0) {
    throw new LookupValidationError("Enter a valid IPv6 address.");
  }

  const left = leftPart ? leftPart.split(":") : [];
  const right = rightPart ? rightPart.split(":") : [];
  const compressed = address.includes("::");
  const missing = 8 - left.length - right.length;
  if ((!compressed && missing !== 0) || (compressed && missing < 1)) {
    throw new LookupValidationError("Enter a valid IPv6 address.");
  }

  const groups = compressed ? [...left, ...Array<string>(missing).fill("0"), ...right] : left;
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/u.test(group))) {
    throw new LookupValidationError("Enter a valid IPv6 address.");
  }

  return `${groups
    .map((group) => group.padStart(4, "0"))
    .join("")
    .split("")
    .reverse()
    .join(".")}.ip6.arpa`;
}

function isCompleteReverseOwner(owner: string): boolean {
  const labels = owner.split(".");
  if (labels.length === 6 && labels.slice(-2).join(".") === "in-addr.arpa") {
    return labels.slice(0, 4).every((label) => /^(?:0|[1-9]\d{0,2})$/u.test(label) && Number(label) <= 255);
  }
  if (labels.length === 34 && labels.slice(-2).join(".") === "ip6.arpa") {
    return labels.slice(0, 32).every((label) => /^[0-9a-f]$/u.test(label));
  }
  return false;
}
