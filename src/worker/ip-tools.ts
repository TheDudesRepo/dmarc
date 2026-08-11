import {
  DnsClient,
  type DnsAnswer,
  type DnsFollowingResult,
  type DnsQueryType,
} from "./dns";
import type {
  CymruAsNameEvidence,
  CymruOriginEvidence,
  CymruOriginRecord,
  IpClassification,
  IpClassificationKind,
  IpEnrichment,
  IpNetworkCalculation,
  IpToolsResult,
  IpUsableRange,
  IpVersion,
  PtrEvidence,
} from "../shared/types";

export type {
  CymruAsNameEvidence,
  CymruOriginEvidence,
  CymruOriginRecord,
  EnrichmentEvidenceStatus,
  EnrichmentStatus,
  IpClassification,
  IpClassificationKind,
  IpEnrichment,
  IpNetworkCalculation,
  IpToolsResult,
  IpUsableRange,
  IpVersion,
  Ipv4NetworkDetails,
  PtrEvidence,
} from "../shared/types";

const MAX_INPUT_LENGTH = 128;
const IPV4_BITS = 32;
const IPV6_BITS = 128;
const IPV4_MAX = (1n << 32n) - 1n;
const IPV6_MAX = (1n << 128n) - 1n;
const MAX_LOGICAL_ENRICHMENT_QUERIES = 4;
const MAX_PTR_NAMES = 8;
const MAX_DNS_EVIDENCE_CHARACTERS = 2_048;
const MAX_AS_NAME_EVIDENCE = 16;

export const TEAM_CYMRU_ATTRIBUTION = {
  name: "Team Cymru IP to ASN Mapping",
  url: "https://www.team-cymru.com/ip-asn-mapping",
} as const;

/** Injectable, deliberately small portion of DnsClient used by best-effort enrichment. */
export interface IpToolsDnsClient {
  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]>;
  queryFollowingCname?(
    name: string,
    type: Exclude<DnsQueryType, "CNAME">,
  ): Promise<DnsFollowingResult>;
}

export interface IpToolsOptions {
  enrich?: boolean;
  includeAsName?: boolean;
  dnsClient?: IpToolsDnsClient;
}

export class IpToolsValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IpToolsValidationError";
  }
}

interface ParsedAddress {
  version: IpVersion;
  value: bigint;
  formatted: string;
}

interface ParsedNetworkInput extends ParsedAddress {
  prefix: number;
}

interface QueryEvidence {
  status: "ok" | "indeterminate";
  answers: DnsAnswer[];
  answerOwner?: string;
}

/** Pure, deterministic IP/CIDR and dotted-netmask calculation. */
export function calculateIpNetwork(input: unknown): IpNetworkCalculation {
  const parsed = parseNetworkInput(input);
  const width = parsed.version === 4 ? IPV4_BITS : IPV6_BITS;
  const maximum = parsed.version === 4 ? IPV4_MAX : IPV6_MAX;
  const mask = prefixMask(width, parsed.prefix);
  const networkValue = parsed.value & mask;
  const lastValue = networkValue | (maximum ^ mask);
  const total = 1n << BigInt(width - parsed.prefix);
  const format = parsed.version === 4 ? formatIpv4 : formatIpv6;
  const network = format(networkValue);
  const lastAddress = format(lastValue);
  const classification = classifyAddress(parsed.version, parsed.value);

  const result: IpNetworkCalculation = {
    address: parsed.formatted,
    canonical: `${parsed.formatted}/${parsed.prefix}`,
    cidr: `${parsed.formatted}/${parsed.prefix}`,
    version: parsed.version,
    prefix: parsed.prefix,
    network,
    networkCidr: `${network}/${parsed.prefix}`,
    lastAddress,
    totalAddresses: total.toString(),
    isSingleAddress: total === 1n,
    classification,
    usable: buildUsableRange(parsed.version, parsed.prefix, networkValue, lastValue, total),
  };

  if (parsed.version === 4) {
    result.ipv4 = {
      netmask: formatIpv4(mask),
      wildcard: formatIpv4(IPV4_MAX ^ mask),
      broadcast: lastAddress,
    };
  }

  return result;
}

/**
 * Calculate first and optionally enrich one globally routable address. DNS is
 * evidence only: every upstream failure is returned as indeterminate and can
 * never turn a valid calculation into a failed request.
 */
export async function inspectIpNetwork(
  input: unknown,
  options: IpToolsOptions = {},
): Promise<IpToolsResult> {
  const calculation = calculateIpNetwork(input);
  const enrichment = await enrichAddress(calculation, options);
  return { ...calculation, enrichment };
}

export function buildPtrOwner(address: string): string {
  const parsed = parseBareAddress(address);
  return ptrOwner(parsed);
}

export function buildCymruOriginOwner(address: string): string {
  const parsed = parseBareAddress(address);
  return cymruOriginOwner(parsed);
}

export function parseCymruOriginTxt(value: string, version?: IpVersion): CymruOriginRecord {
  const fields = unwrapTxt(value).split("|").map((field) => field.trim());
  if (fields.length !== 5) throw new IpToolsValidationError("Team Cymru returned malformed origin data.");

  const [rawAsn = "", rawPrefix = "", rawCountry = "", rawRegistry = "", rawAllocated = ""] = fields;
  const asns = [...new Set(rawAsn.split(/[\t\n\f\r ]+/u).map((value) => parseCymruAsn(value, "origin")))]
    .sort(compareAsns);
  if (asns.length === 0 || asns.length > 16) {
    throw new IpToolsValidationError("Team Cymru returned malformed origin data.");
  }

  let parsedPrefix: ParsedNetworkInput;
  try {
    const prefixParts = rawPrefix.split("/");
    if (prefixParts.length !== 2 || !/^(?:0|[1-9]\d{0,2})$/u.test(prefixParts[1] ?? "")) {
      throw new IpToolsValidationError("Team Cymru returned malformed origin data.");
    }
    parsedPrefix = parseNetworkInput(rawPrefix);
    if (parsedPrefix.value !== networkValue(parsedPrefix)) {
      throw new IpToolsValidationError("Team Cymru returned malformed origin data.");
    }
  } catch {
    throw new IpToolsValidationError("Team Cymru returned malformed origin data.");
  }
  if (version !== undefined && parsedPrefix.version !== version) {
    throw new IpToolsValidationError("Team Cymru returned an origin prefix for the wrong IP version.");
  }
  if (!/^[A-Za-z]{2}$/u.test(rawCountry)) {
    throw new IpToolsValidationError("Team Cymru returned malformed origin data.");
  }
  if (!/^[A-Za-z][A-Za-z0-9-]{0,31}$/u.test(rawRegistry)) {
    throw new IpToolsValidationError("Team Cymru returned malformed origin data.");
  }
  if (!isIsoCalendarDate(rawAllocated)) {
    throw new IpToolsValidationError("Team Cymru returned malformed origin data.");
  }

  return {
    asn: asns[0] ?? "",
    asns,
    prefix: `${formatAddress(parsedPrefix.version, networkValue(parsedPrefix))}/${parsedPrefix.prefix}`,
    country: rawCountry.toUpperCase(),
    registry: rawRegistry.toLowerCase(),
    allocated: rawAllocated,
  };
}

export function parseCymruAsNameTxt(value: string, expectedAsn?: string): string {
  const fields = unwrapTxt(value).split("|").map((field) => field.trim());
  if (fields.length < 5) throw new IpToolsValidationError("Team Cymru returned malformed AS-name data.");
  const asn = parseCymruAsn(fields[0] ?? "", "AS-name");
  const country = fields[1] ?? "";
  const registry = fields[2] ?? "";
  const allocated = fields[3] ?? "";
  const name = fields.slice(4).join(" | ").trim();
  if ((expectedAsn !== undefined && asn !== expectedAsn)
    || !/^[A-Za-z]{2}$/u.test(country)
    || !/^[A-Za-z][A-Za-z0-9-]{0,31}$/u.test(registry)
    || !isIsoCalendarDate(allocated)
    || !name
    || name.length > 256) {
    throw new IpToolsValidationError("Team Cymru returned malformed AS-name data.");
  }
  return name;
}

async function enrichAddress(
  calculation: IpNetworkCalculation,
  options: IpToolsOptions,
): Promise<IpEnrichment> {
  const base = enrichmentBase();
  if (options.enrich !== true) return base;
  if (!calculation.isSingleAddress || !calculation.classification.global) {
    return {
      ...base,
      status: "not-applicable",
      reason: "DNS enrichment is limited to one globally routable IP address.",
    };
  }

  const parsed = parseBareAddress(calculation.address);
  const client = options.dnsClient ?? new DnsClient();
  let queryCount = 0;
  const query = async (name: string, type: DnsQueryType): Promise<QueryEvidence> => {
    if (queryCount >= MAX_LOGICAL_ENRICHMENT_QUERIES) {
      return { status: "indeterminate", answers: [] };
    }
    queryCount += 1;
    try {
      const answers = await client.query(name, type);
      if (!isBoundedEvidence(answers)) return { status: "indeterminate", answers: [] };
      return { status: "ok", answers };
    } catch {
      return { status: "indeterminate", answers: [] };
    }
  };
  const queryPtr = async (name: string): Promise<QueryEvidence> => {
    if (client.queryFollowingCname === undefined) return query(name, "PTR");
    if (queryCount >= MAX_LOGICAL_ENRICHMENT_QUERIES) {
      return { status: "indeterminate", answers: [] };
    }
    queryCount += 1;
    try {
      const result = await client.queryFollowingCname(name, "PTR");
      const answerOwner = normalizeDnsEvidenceOwner(result.canonicalName);
      if (answerOwner === undefined || !isBoundedEvidence(result.answers)) {
        return { status: "indeterminate", answers: [] };
      }
      return { status: "ok", answers: result.answers, answerOwner };
    } catch {
      return { status: "indeterminate", answers: [] };
    }
  };

  const ptrName = ptrOwner(parsed);
  const originName = cymruOriginOwner(parsed);
  const [ptrQuery, originQuery] = await Promise.all([
    queryPtr(ptrName),
    query(originName, "TXT"),
  ]);

  const ptr = parsePtrEvidence(ptrName, ptrQuery);
  const origin = parseOriginEvidence(originName, originQuery, parsed);
  let asName: CymruAsNameEvidence | undefined;
  let asNames: CymruAsNameEvidence[] | undefined;
  let asNamesTruncated = false;

  if (options.includeAsName === true) {
    if (origin.status === "found" && origin.records) {
      const uniqueAsns = [...new Set(origin.records.flatMap((record) => record.asns))];
      const reportedAsns = uniqueAsns.slice(0, MAX_AS_NAME_EVIDENCE);
      const availableQueries = Math.max(0, MAX_LOGICAL_ENRICHMENT_QUERIES - queryCount);
      const queriedAsns = reportedAsns.slice(0, availableQueries);
      const queriedNames = await Promise.all(queriedAsns.map(async (asn) => {
        // Team Cymru's ASN-description zone keys owners as AS<number>.
        const owner = `as${asn}.asn.cymru.com`;
        return parseAsNameEvidence(owner, await query(owner, "TXT"), asn);
      }));
      const skippedNames = reportedAsns.slice(availableQueries).map((asn): CymruAsNameEvidence => ({
        status: "not-requested",
        asn,
        owner: `as${asn}.asn.cymru.com`,
      }));
      asNames = [...queriedNames, ...skippedNames];
      asName = asNames[0];
      asNamesTruncated = uniqueAsns.length > queriedAsns.length;
    } else if (origin.status === "indeterminate") {
      asName = { status: "indeterminate" };
    }
  }

  const statuses = [
    ptr.status,
    origin.status,
    ...(asNames
      ? asNames.filter((entry) => entry.status !== "not-requested").map((entry) => entry.status)
      : asName ? [asName.status] : []),
  ];
  const hasIndeterminate = statuses.includes("indeterminate");
  const hasUsableEvidence = statuses.includes("found") || statuses.includes("not-found");

  return {
    ...base,
    status: hasIndeterminate ? (hasUsableEvidence ? "partial" : "indeterminate") : "complete",
    queryCount,
    ptr,
    origin,
    ...(asName ? { asName } : {}),
    ...(asNames ? { asNames } : {}),
    ...(asNamesTruncated ? { asNamesTruncated: true } : {}),
    ...(hasIndeterminate
      ? { reason: "One or more DNS enrichment queries failed or returned unrecognized data." }
      : asNamesTruncated
        ? { reason: "AS-name enrichment was capped at two origin ASNs." }
      : {}),
  };
}

function enrichmentBase(): IpEnrichment {
  return {
    status: "not-requested",
    queryCount: 0,
    ptr: { status: "not-requested", names: [] },
    origin: { status: "not-requested" },
    attribution: {
      ptr: "Native DNS PTR",
      asn: TEAM_CYMRU_ATTRIBUTION,
    },
  };
}

function parsePtrEvidence(owner: string, query: QueryEvidence): PtrEvidence {
  if (query.status === "indeterminate") return { status: "indeterminate", owner, names: [] };
  if (query.answers.length === 0) return { status: "not-found", owner, names: [] };
  if (query.answers.length > MAX_PTR_NAMES) return { status: "indeterminate", owner, names: [] };

  const answerOwner = query.answerOwner ?? owner;
  const names = query.answers.map((answer) => normalizePtrName(answer, answerOwner));
  if (names.some((name) => name === undefined)) {
    return { status: "indeterminate", owner, names: [] };
  }
  return {
    status: "found",
    owner,
    ...(answerOwner === owner ? {} : { canonicalOwner: answerOwner }),
    names: [...new Set(names as string[])],
  };
}

function normalizePtrName(answer: DnsAnswer, expectedOwner: string): string | undefined {
  if (answer.type !== "PTR" || normalizeDnsEvidenceOwner(answer.name) !== expectedOwner) return undefined;
  return normalizeDnsEvidenceOwner(answer.data);
}

function parseOriginEvidence(
  owner: string,
  query: QueryEvidence,
  address: ParsedAddress,
): CymruOriginEvidence {
  if (query.status === "indeterminate") return { status: "indeterminate", owner };
  if (query.answers.length === 0) return { status: "not-found", owner };
  try {
    const records: CymruOriginRecord[] = [];
    for (const answer of query.answers) {
      if (answer.type !== "TXT" || normalizeDnsEvidenceOwner(answer.name) !== owner) {
        return { status: "indeterminate", owner };
      }
      const record = parseCymruOriginTxt(answer.data, address.version);
      const originPrefix = parseNetworkInput(record.prefix);
      if (!inPrefix(address.value, originPrefix.value, originPrefix.prefix, address.version === 4 ? 32 : 128)) {
        return { status: "indeterminate", owner };
      }
      if (!records.some((existing) => sameOriginRecord(existing, record))) records.push(record);
    }
    records.sort(compareOriginRecords);
    if (records.length === 0) return { status: "not-found", owner };
    return { status: "found", owner, record: records[0], records };
  } catch {
    return { status: "indeterminate", owner };
  }
}

function parseAsNameEvidence(
  owner: string,
  query: QueryEvidence,
  expectedAsn: string,
): CymruAsNameEvidence {
  if (query.status === "indeterminate") return { status: "indeterminate", asn: expectedAsn, owner };
  if (query.answers.length === 0) return { status: "not-found", asn: expectedAsn, owner };
  if (query.answers.length !== 1
    || query.answers[0]?.type !== "TXT"
    || normalizeDnsEvidenceOwner(query.answers[0]?.name ?? "") !== owner) {
    return { status: "indeterminate", asn: expectedAsn, owner };
  }
  try {
    return {
      status: "found",
      asn: expectedAsn,
      owner,
      name: parseCymruAsNameTxt(query.answers[0].data, expectedAsn),
    };
  } catch {
    return { status: "indeterminate", asn: expectedAsn, owner };
  }
}

function isBoundedEvidence(answers: DnsAnswer[]): boolean {
  if (!Array.isArray(answers) || answers.length > MAX_PTR_NAMES) return false;
  let characters = 0;
  for (const answer of answers) {
    characters += answer.name.length + answer.data.length;
    if (characters > MAX_DNS_EVIDENCE_CHARACTERS) return false;
  }
  return true;
}

function parseNetworkInput(input: unknown): ParsedNetworkInput {
  const text = normalizeInput(input);
  const slashParts = text.split("/");
  if (slashParts.length > 2) throw new IpToolsValidationError("Enter one IP address or CIDR.");

  const addressText = slashParts[0] ?? "";
  const suffix = slashParts[1];
  const parsed = parseAddress(addressText);
  const width = parsed.version === 4 ? IPV4_BITS : IPV6_BITS;
  let prefix = width;

  if (suffix !== undefined) {
    if (!suffix) throw new IpToolsValidationError("CIDR prefix cannot be empty.");
    if (suffix.includes(".")) {
      if (parsed.version !== 4) {
        throw new IpToolsValidationError("A dotted netmask can only be used with IPv4.");
      }
      prefix = dottedNetmaskToPrefix(suffix);
    } else {
      prefix = parsePrefix(suffix, width);
    }
  }

  return { ...parsed, prefix };
}

function normalizeInput(input: unknown): string {
  if (typeof input !== "string") throw new IpToolsValidationError("IP input must be a string.");
  const text = input.trim();
  if (!text) throw new IpToolsValidationError("Enter an IP address or CIDR.");
  if (text.length > MAX_INPUT_LENGTH) throw new IpToolsValidationError("IP input is too long.");
  if (/\s/u.test(text)) throw new IpToolsValidationError("IP input cannot contain whitespace.");
  if (text.includes("%")) throw new IpToolsValidationError("Scoped IPv6 addresses are not accepted.");
  if (/[\[\],;?&#\\]/u.test(text) || text.includes("://")) {
    throw new IpToolsValidationError("Enter one IP address only, without URL, list, range, or zone syntax.");
  }
  if (text.includes("-")) {
    throw new IpToolsValidationError("IP ranges are not accepted; use one CIDR instead.");
  }
  return text;
}

function parseBareAddress(input: string): ParsedAddress {
  const text = normalizeInput(input);
  if (text.includes("/")) throw new IpToolsValidationError("Expected one IP address without a prefix.");
  return parseAddress(text);
}

function parseAddress(value: string): ParsedAddress {
  if (value.includes(":")) return parseIpv6(value);
  return parseIpv4(value);
}

function parseIpv4(value: string): ParsedAddress {
  const octets = value.split(".");
  if (octets.length !== 4) throw new IpToolsValidationError("Enter a valid IPv4 or IPv6 address.");

  let numeric = 0n;
  const canonical: string[] = [];
  for (const octet of octets) {
    if (!/^(?:0|[1-9]\d{0,2})$/u.test(octet)) {
      throw new IpToolsValidationError("IPv4 octets must be unambiguous decimal values.");
    }
    const number = Number(octet);
    if (number > 255) throw new IpToolsValidationError("IPv4 octets must be between 0 and 255.");
    numeric = (numeric << 8n) | BigInt(number);
    canonical.push(String(number));
  }
  return { version: 4, value: numeric, formatted: canonical.join(".") };
}

function parseIpv6(value: string): ParsedAddress {
  if (!value || value.includes(":::")) throw new IpToolsValidationError("Enter a valid IPv6 address.");
  const compressionParts = value.split("::");
  if (compressionParts.length > 2) throw new IpToolsValidationError("IPv6 can contain only one compressed run.");

  const hasCompression = compressionParts.length === 2;
  const left = parseIpv6Side(compressionParts[0] ?? "", !hasCompression);
  const right = parseIpv6Side(compressionParts[1] ?? "", true);
  const explicitCount = left.length + right.length;

  let groups: number[];
  if (hasCompression) {
    const missing = 8 - explicitCount;
    if (missing < 1) throw new IpToolsValidationError("Compressed IPv6 must omit at least one group.");
    groups = [...left, ...Array.from({ length: missing }, () => 0), ...right];
  } else {
    if (explicitCount !== 8) throw new IpToolsValidationError("IPv6 must contain eight groups or use :: compression.");
    groups = [...left, ...right];
  }

  let numeric = 0n;
  for (const group of groups) numeric = (numeric << 16n) | BigInt(group);
  return { version: 6, value: numeric, formatted: formatIpv6(numeric) };
}

function parseIpv6Side(value: string, mayContainIpv4: boolean): number[] {
  if (!value) return [];
  const tokens = value.split(":");
  if (tokens.some((token) => !token)) throw new IpToolsValidationError("IPv6 contains an empty uncompressed group.");

  const groups: number[] = [];
  for (const [index, token] of tokens.entries()) {
    if (token.includes(".")) {
      if (!mayContainIpv4 || index !== tokens.length - 1) {
        throw new IpToolsValidationError("Embedded IPv4 must be the final part of an IPv6 address.");
      }
      const ipv4 = parseIpv4(token);
      groups.push(Number((ipv4.value >> 16n) & 0xffffn), Number(ipv4.value & 0xffffn));
      continue;
    }
    if (!/^[0-9a-f]{1,4}$/iu.test(token)) throw new IpToolsValidationError("IPv6 contains an invalid group.");
    groups.push(Number.parseInt(token, 16));
  }
  return groups;
}

function parsePrefix(value: string, width: number): number {
  if (!/^(?:0|[1-9]\d{0,2})$/u.test(value)) throw new IpToolsValidationError("CIDR prefix is invalid.");
  const prefix = Number(value);
  if (prefix > width) throw new IpToolsValidationError(`CIDR prefix must be between 0 and ${width}.`);
  return prefix;
}

function dottedNetmaskToPrefix(value: string): number {
  const parsed = parseIpv4(value);
  const bits = parsed.value.toString(2).padStart(32, "0");
  if (!/^1*0*$/u.test(bits)) throw new IpToolsValidationError("IPv4 dotted netmask must be contiguous.");
  return bits.indexOf("0") === -1 ? 32 : bits.indexOf("0");
}

function prefixMask(width: number, prefix: number): bigint {
  if (prefix === 0) return 0n;
  const maximum = (1n << BigInt(width)) - 1n;
  return (maximum << BigInt(width - prefix)) & maximum;
}

function networkValue(parsed: ParsedNetworkInput): bigint {
  const width = parsed.version === 4 ? IPV4_BITS : IPV6_BITS;
  return parsed.value & prefixMask(width, parsed.prefix);
}

function formatAddress(version: IpVersion, value: bigint): string {
  return version === 4 ? formatIpv4(value) : formatIpv6(value);
}

function formatIpv4(value: bigint): string {
  return [24n, 16n, 8n, 0n].map((shift) => Number((value >> shift) & 255n)).join(".");
}

function formatIpv6(value: bigint): string {
  const groups = Array.from({ length: 8 }, (_unused, index) =>
    Number((value >> BigInt((7 - index) * 16)) & 0xffffn),
  );

  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < groups.length; ) {
    if (groups[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < groups.length && groups[end] === 0) end += 1;
    const length = end - index;
    if (length >= 2 && length > bestLength) {
      bestStart = index;
      bestLength = length;
    }
    index = end;
  }

  if (bestStart < 0) return groups.map((group) => group.toString(16)).join(":");
  const left = groups.slice(0, bestStart).map((group) => group.toString(16)).join(":");
  const right = groups.slice(bestStart + bestLength).map((group) => group.toString(16)).join(":");
  if (!left && !right) return "::";
  if (!left) return `::${right}`;
  if (!right) return `${left}::`;
  return `${left}::${right}`;
}

function buildUsableRange(
  version: IpVersion,
  prefix: number,
  network: bigint,
  last: bigint,
  total: bigint,
): IpUsableRange {
  if (version === 6) {
    return {
      first: formatIpv6(network),
      last: formatIpv6(last),
      count: total.toString(),
      convention: "ipv6-addresses",
    };
  }
  if (prefix <= 30) {
    return {
      first: formatIpv4(network + 1n),
      last: formatIpv4(last - 1n),
      count: (total - 2n).toString(),
      convention: "ipv4-traditional",
    };
  }
  if (prefix === 31) {
    return {
      first: formatIpv4(network),
      last: formatIpv4(last),
      count: "2",
      convention: "ipv4-point-to-point",
    };
  }
  return {
    first: formatIpv4(network),
    last: formatIpv4(last),
    count: "1",
    convention: "ipv4-host",
  };
}

function classifyAddress(version: IpVersion, value: bigint): IpClassification {
  const kind = version === 4 ? classifyIpv4(value) : classifyIpv6(value);
  return {
    kind,
    private: kind === "private",
    loopback: kind === "loopback",
    linkLocal: kind === "link-local",
    multicast: kind === "multicast",
    documentation: kind === "documentation",
    reserved: kind === "reserved",
    global: kind === "global",
  };
}

function classifyIpv4(value: bigint): IpClassificationKind {
  if (inPrefix(value, ipv4Number("10.0.0.0"), 8, 32)
    || inPrefix(value, ipv4Number("172.16.0.0"), 12, 32)
    || inPrefix(value, ipv4Number("192.168.0.0"), 16, 32)) return "private";
  if (inPrefix(value, ipv4Number("127.0.0.0"), 8, 32)) return "loopback";
  if (inPrefix(value, ipv4Number("169.254.0.0"), 16, 32)) return "link-local";
  if (inPrefix(value, ipv4Number("224.0.0.0"), 4, 32)) return "multicast";
  if (inPrefix(value, ipv4Number("192.0.2.0"), 24, 32)
    || inPrefix(value, ipv4Number("198.51.100.0"), 24, 32)
    || inPrefix(value, ipv4Number("203.0.113.0"), 24, 32)) return "documentation";
  // Globally reachable exceptions within IANA's 192.0.0.0/24 protocol block.
  if (value === ipv4Number("192.0.0.9") || value === ipv4Number("192.0.0.10")) return "global";
  if (inPrefix(value, 0n, 8, 32)
    || inPrefix(value, ipv4Number("100.64.0.0"), 10, 32)
    || inPrefix(value, ipv4Number("192.0.0.0"), 24, 32)
    || inPrefix(value, ipv4Number("192.88.99.0"), 24, 32)
    || inPrefix(value, ipv4Number("198.18.0.0"), 15, 32)
    || inPrefix(value, ipv4Number("240.0.0.0"), 4, 32)) return "reserved";
  return "global";
}

function classifyIpv6(value: bigint): IpClassificationKind {
  if (inPrefix(value, 0xfcn << 120n, 7, 128)) return "private";
  if (value === 1n) return "loopback";
  if (inPrefix(value, 0xfe80n << 112n, 10, 128)) return "link-local";
  if (inPrefix(value, 0xffn << 120n, 8, 128)) return "multicast";
  if (inPrefix(value, 0x20010db8n << 96n, 32, 128)
    || inPrefix(value, 0x3fff0n << 108n, 20, 128)) return "documentation";

  const globallyReachableSpecial = inPrefix(value, 0x0064ff9bn << 96n, 96, 128)
    || value === ((0x20010001n << 96n) | 1n)
    || value === ((0x20010001n << 96n) | 2n)
    || value === ((0x20010001n << 96n) | 3n)
    || inPrefix(value, 0x20010003n << 96n, 32, 128)
    || inPrefix(value, 0x200100040112n << 80n, 48, 128)
    || inPrefix(value, 0x20010020n << 96n, 28, 128)
    || inPrefix(value, 0x20010030n << 96n, 28, 128);
  if (globallyReachableSpecial) return "global";

  const globalUnicast = inPrefix(value, 0x2n << 124n, 3, 128);
  const protocolAssignments = inPrefix(value, 0x200100n << 104n, 23, 128);
  const deprecatedSixToFour = inPrefix(value, 0x2002n << 112n, 16, 128);
  return globalUnicast && !protocolAssignments && !deprecatedSixToFour ? "global" : "reserved";
}

function inPrefix(value: bigint, base: bigint, prefix: number, width: number): boolean {
  if (prefix === 0) return true;
  const shift = BigInt(width - prefix);
  return value >> shift === base >> shift;
}

function ipv4Number(value: string): bigint {
  return value.split(".").reduce((result, octet) => (result << 8n) | BigInt(octet), 0n);
}

function ptrOwner(address: ParsedAddress): string {
  if (address.version === 4) {
    return formatIpv4(address.value).split(".").reverse().join(".") + ".in-addr.arpa";
  }
  return expandedIpv6Hex(address.value).split("").reverse().join(".") + ".ip6.arpa";
}

function cymruOriginOwner(address: ParsedAddress): string {
  if (address.version === 4) {
    return formatIpv4(address.value).split(".").reverse().join(".") + ".origin.asn.cymru.com";
  }
  return expandedIpv6Hex(address.value).split("").reverse().join(".") + ".origin6.asn.cymru.com";
}

function expandedIpv6Hex(value: bigint): string {
  return value.toString(16).padStart(32, "0");
}

function unwrapTxt(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length > MAX_DNS_EVIDENCE_CHARACTERS) {
    throw new IpToolsValidationError("DNS enrichment response is too long.");
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}

function normalizeDnsEvidenceOwner(value: string): string | undefined {
  const normalized = value.trim().replace(/\.$/u, "").toLowerCase();
  if (!normalized || normalized.length > 253 || !/^[a-z0-9._-]+$/u.test(normalized)) return undefined;
  const labels = normalized.split(".");
  if (labels.some((label) => !label
    || label.length > 63
    || !/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/u.test(label))) return undefined;
  return normalized;
}

function parseCymruAsn(value: string, row: "origin" | "AS-name"): string {
  const match = /^(?:[Aa][Ss])?(\d{1,10})$/u.exec(value);
  if (!match) throw new IpToolsValidationError(`Team Cymru returned malformed ${row} data.`);
  const asn = BigInt(match[1] ?? "0");
  if (asn < 1n || asn > 4_294_967_295n) {
    throw new IpToolsValidationError(`Team Cymru returned malformed ${row} data.`);
  }
  return asn.toString();
}

function compareAsns(left: string, right: string): number {
  const leftValue = BigInt(left);
  const rightValue = BigInt(right);
  return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
}

function compareOriginRecords(left: CymruOriginRecord, right: CymruOriginRecord): number {
  const leftPrefix = parseNetworkInput(left.prefix);
  const rightPrefix = parseNetworkInput(right.prefix);
  if (leftPrefix.prefix !== rightPrefix.prefix) return rightPrefix.prefix - leftPrefix.prefix;
  const leftNetwork = networkValue(leftPrefix);
  const rightNetwork = networkValue(rightPrefix);
  if (leftNetwork !== rightNetwork) return leftNetwork < rightNetwork ? -1 : 1;
  for (let index = 0; index < Math.max(left.asns.length, right.asns.length); index += 1) {
    const leftAsn = left.asns[index];
    const rightAsn = right.asns[index];
    if (leftAsn === undefined) return -1;
    if (rightAsn === undefined) return 1;
    const comparison = compareAsns(leftAsn, rightAsn);
    if (comparison !== 0) return comparison;
  }
  return compareAscii(left.country, right.country)
    || compareAscii(left.registry, right.registry)
    || compareAscii(left.allocated, right.allocated);
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sameOriginRecord(left: CymruOriginRecord, right: CymruOriginRecord): boolean {
  return left.prefix === right.prefix
    && left.country === right.country
    && left.registry === right.registry
    && left.allocated === right.allocated
    && left.asns.length === right.asns.length
    && left.asns.every((asn, index) => asn === right.asns[index]);
}

function isIsoCalendarDate(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/u.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (year < 1 || month < 1 || month > 12 || day < 1) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= (days[month - 1] ?? 0);
}
