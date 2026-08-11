import type {
  DnsLookupResult,
  DnsLookupMode,
  SpfCorrectionGuidance,
  SpfLookupAnalysis,
} from "../shared/types";
import {
  DnsClient,
  type DnsAnswer,
  type DnsFollowingResult,
  type DnsQueryType,
  toRecordViews,
} from "./dns";
import { estimateSpfLookups, findSpfRecords, parseSpfRecord, type ParsedSpfRecord } from "./spf";

const MAX_INPUT_LENGTH = 512;
const MAX_DNS_NAME_LENGTH = 253;
const MAX_SPF_ANALYSIS_ITEMS = 256;
const MAX_SPF_OUTPUT_TEXT_LENGTH = 8_192;
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
  "CNAME",
  "MX",
  "NS",
  "PTR",
  "SPF",
  "SOA",
  "SRV",
  "TXT",
] as const satisfies readonly DnsLookupMode[];

export type SupportedDnsLookupType = (typeof DNS_LOOKUP_TYPES)[number];

const DNS_LOOKUP_TYPE_SET = new Set<string>(DNS_LOOKUP_TYPES);

export interface LookupResolver {
  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]>;
  queryFollowingCname?(
    name: string,
    type: Exclude<DnsQueryType, "CNAME">,
  ): Promise<DnsFollowingResult>;
}

export interface NormalizedLookupRequest {
  input: string;
  queryName: string;
  type: SupportedDnsLookupType;
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
  if (normalizedType === "SPF") return normalizeSpfRequest(name);

  const queryName = normalizePublicOwnerName(name);
  return { input: queryName, queryName, type: normalizedType };
}

export async function lookupDns(
  name: unknown,
  type: unknown,
  dns: LookupResolver = new DnsClient(),
): Promise<DnsLookupResult<DnsLookupMode>> {
  const request = normalizeLookupRequest(name, type);
  const scannedAt = new Date().toISOString();
  const startedAt = performance.now();

  if (request.type === "SPF") {
    return lookupSpf(request, dns, scannedAt, startedAt);
  }

  let answers: DnsAnswer[];
  let resolvedCanonicalName: string | undefined;
  try {
    if (request.type !== "CNAME" && dns.queryFollowingCname) {
      const result = await dns.queryFollowingCname(request.queryName, request.type);
      answers = result.answers;
      resolvedCanonicalName = result.canonicalName;
    } else {
      answers = await dns.query(request.queryName, request.type);
    }
  } catch {
    throw new LookupUpstreamError("The DNS lookup could not be completed.");
  }

  const records = toRecordViews(answers);
  const answerNames = [...new Set(records.map((record) => record.name.toLowerCase()))];
  const inferredCanonicalName = answerNames.length === 1 ? answerNames[0] : undefined;
  const canonicalName = (resolvedCanonicalName ?? inferredCanonicalName) !== request.queryName
    ? resolvedCanonicalName ?? inferredCanonicalName
    : undefined;
  const recordLabel = `${request.type} ${records.length === 1 ? "record" : "records"}`;
  const summary = records.length === 0
    ? canonicalName
      ? `No ${request.type} records were returned after following ${request.queryName} to ${canonicalName}.`
      : `No ${request.type} records were returned for ${request.queryName}.`
    : canonicalName
      ? `${records.length} ${recordLabel} returned from canonical target ${canonicalName}.`
      : `${records.length} ${recordLabel} returned for ${request.queryName}.`;

  return {
    input: request.input,
    queryName: request.queryName,
    ...(canonicalName ? { canonicalName } : {}),
    type: request.type,
    scannedAt,
    durationMs: Math.max(1, Math.round(performance.now() - startedAt)),
    records,
    summary,
  };
}

async function lookupSpf(
  request: NormalizedLookupRequest,
  dns: LookupResolver,
  scannedAt: string,
  startedAt: number,
): Promise<DnsLookupResult<"SPF">> {
  let answers: DnsAnswer[];
  let resolvedCanonicalName: string | undefined;
  try {
    if (dns.queryFollowingCname) {
      const result = await dns.queryFollowingCname(request.queryName, "TXT");
      answers = result.answers;
      resolvedCanonicalName = result.canonicalName;
    } else {
      answers = await dns.query(request.queryName, "TXT");
    }
  } catch {
    throw new LookupUpstreamError("The SPF DNS lookup could not be completed.");
  }

  const spfAnswers = answers.filter(
    (answer) => answer.type === "TXT" && findSpfRecords([answer.data]).length === 1,
  );
  const spfRecords = spfAnswers.map((answer) => answer.data);
  const spfAnalysis = await analyzeSpfLookup(request.queryName, spfRecords, dns);
  const records = toRecordViews(spfAnswers);
  const answerNames = [...new Set(records.map((record) => record.name.toLowerCase()))];
  const inferredCanonicalName = answerNames.length === 1 ? answerNames[0] : undefined;
  const resolvedName = resolvedCanonicalName ?? inferredCanonicalName;
  const canonicalName = resolvedName && resolvedName !== request.queryName ? resolvedName : undefined;

  return {
    input: request.input,
    queryName: request.queryName,
    ...(canonicalName ? { canonicalName } : {}),
    type: "SPF",
    scannedAt,
    durationMs: Math.max(1, Math.round(performance.now() - startedAt)),
    records,
    summary: summarizeSpfLookup(request.queryName, spfAnalysis),
    spfAnalysis,
  };
}

async function analyzeSpfLookup(
  domain: string,
  spfRecords: string[],
  dns: LookupResolver,
): Promise<SpfLookupAnalysis> {
  if (spfRecords.length === 0) {
    return {
      status: "missing",
      recordCount: 0,
      valid: false,
      syntaxValid: false,
      mechanisms: [],
      terminalPolicy: "none",
      warnings: [],
      errors: [],
      issues: ["No v=spf1 policy was found in the TXT records at this domain."],
      correctionGuidance: missingSpfGuidance(),
    };
  }

  if (spfRecords.length > 1) {
    return {
      status: "multiple",
      recordCount: spfRecords.length,
      valid: false,
      syntaxValid: false,
      mechanisms: [],
      terminalPolicy: "none",
      warnings: [],
      errors: ["A domain must publish exactly one SPF policy; multiple v=spf1 records cause permerror."],
      issues: [],
      correctionGuidance: multipleSpfGuidance(),
    };
  }

  const parsed = parseSpfRecord(spfRecords[0] ?? "");
  const terminalPolicy = formatTerminalPolicy(parsed);
  const mechanismOutputIssue = parsed.mechanisms.length > MAX_SPF_ANALYSIS_ITEMS
    ? `Mechanism output was limited to the first ${MAX_SPF_ANALYSIS_ITEMS} entries.`
    : undefined;
  const messageOutputIssue = parsed.errors.length > MAX_SPF_ANALYSIS_ITEMS
    || parsed.warnings.length > MAX_SPF_ANALYSIS_ITEMS
    || parsed.errors.some((message) => message.length > MAX_SPF_OUTPUT_TEXT_LENGTH)
    || parsed.warnings.some((message) => message.length > MAX_SPF_OUTPUT_TEXT_LENGTH)
    ? `Parser messages were limited to the first ${MAX_SPF_ANALYSIS_ITEMS} entries per category.`
    : undefined;
  const mechanisms = parsed.mechanisms.slice(0, MAX_SPF_ANALYSIS_ITEMS).map((mechanism) => ({ ...mechanism }));
  const warnings = parsed.warnings.slice(0, MAX_SPF_ANALYSIS_ITEMS).map(boundSpfOutputText);
  const errors = parsed.errors.slice(0, MAX_SPF_ANALYSIS_ITEMS).map(boundSpfOutputText);
  if (!parsed.valid) {
    return {
      status: "invalid",
      recordCount: 1,
      valid: false,
      syntaxValid: false,
      mechanisms,
      terminalPolicy,
      warnings,
      errors,
      issues: [mechanismOutputIssue, messageOutputIssue].filter((issue): issue is string => Boolean(issue)),
      correctionGuidance: invalidSpfGuidance(errors),
    };
  }

  const lookupEstimate = await estimateSpfLookups(domain, parsed, async (target) => {
    const includedAnswers = await dns.query(target, "TXT");
    return includedAnswers
      .filter((answer) => answer.type === "TXT")
      .map((answer) => answer.data);
  });
  const issues = [
    ...lookupEstimate.issues,
    ...[mechanismOutputIssue, messageOutputIssue].filter((issue): issue is string => Boolean(issue)),
  ];
  if (lookupEstimate.exceedsLimit) {
    issues.unshift(
      `The estimated SPF evaluation path uses ${lookupEstimate.count} DNS lookups, above the RFC limit of 10.`,
    );
  }
  const hasCaveat = warnings.length > 0 || lookupEstimate.truncated || issues.length > 0;
  const status: SpfLookupAnalysis["status"] = lookupEstimate.exceedsLimit
    ? "invalid"
    : hasCaveat
      ? "warning"
      : "valid";

  return {
    status,
    recordCount: 1,
    valid: !lookupEstimate.exceedsLimit,
    syntaxValid: true,
    mechanisms,
    terminalPolicy,
    lookupEstimate: {
      count: lookupEstimate.count,
      exceedsLimit: lookupEstimate.exceedsLimit,
      truncated: lookupEstimate.truncated,
      expandedDomains: [...lookupEstimate.expandedDomains],
      issues: [...lookupEstimate.issues],
    },
    warnings,
    errors: [],
    issues,
    correctionGuidance: analyzedSpfGuidance(parsed, lookupEstimate.exceedsLimit, lookupEstimate.truncated || lookupEstimate.issues.length > 0),
  };
}

function summarizeSpfLookup(domain: string, analysis: SpfLookupAnalysis): string {
  switch (analysis.status) {
    case "missing":
      return `No SPF policy was found in the TXT records for ${domain}.`;
    case "multiple":
      return `${analysis.recordCount} SPF policies were found for ${domain}; SPF permits exactly one.`;
    case "invalid":
      return analysis.syntaxValid
        ? `The SPF policy for ${domain} is syntactically valid but exceeds the ten-lookup limit.`
        : `The SPF policy for ${domain} has syntax errors.`;
    case "warning":
      return `One SPF policy was found for ${domain}, with warnings or incomplete recursive analysis.`;
    case "valid":
      return `One valid SPF policy was found for ${domain}; the recursive lookup estimate is ${analysis.lookupEstimate?.count ?? 0}.`;
  }
}

function formatTerminalPolicy(parsed: ParsedSpfRecord): SpfLookupAnalysis["terminalPolicy"] {
  return parsed.terminalAll ? `${parsed.terminalAll}all` : "none";
}

function missingSpfGuidance(): SpfCorrectionGuidance {
  return {
    summary: "Inventory outbound senders before publishing one SPF TXT policy.",
    steps: [
      "List every mailbox, marketing, ticketing, billing, and application service that uses this domain in its envelope-from address.",
      "Use only provider-documented include mechanisms or verified sending IP ranges and combine them into one v=spf1 TXT value.",
      "Begin with ~all while validating controlled mail flows, then consider -all after the sender inventory is complete.",
    ],
    caution: "Do not publish a generic SPF value or guess provider includes; an incomplete policy can block legitimate mail.",
  };
}

function multipleSpfGuidance(): SpfCorrectionGuidance {
  return {
    summary: "Consolidate the active sender authorization into exactly one SPF policy.",
    steps: [
      "Inventory the mechanisms in every current SPF record and confirm which services still send mail.",
      "Build one reviewed v=spf1 value; merge required mechanisms rather than concatenating complete records or repeated all terms.",
      "Keep the recursive evaluation path at ten DNS lookups or fewer, replace the conflicting records, and rescan after the TTL expires.",
    ],
    caution: "Removing a still-active sender or briefly publishing no policy during the change can affect authentication results.",
  };
}

function invalidSpfGuidance(errors: string[]): SpfCorrectionGuidance {
  const displayedErrors = errors.slice(0, 8);
  const omitted = errors.length - displayedErrors.length;
  return {
    summary: "Repair the existing SPF TXT value without adding a second policy.",
    steps: [
      boundSpfOutputText(`Correct the reported syntax ${errors.length === 1 ? "error" : "errors"}: ${displayedErrors.join(" ")}${omitted > 0 ? ` (${omitted} more omitted from this instruction.)` : ""}`),
      "Keep one v=spf1 prefix, validate every IP/CIDR and include target, and retain no more than one terminal all mechanism.",
      "Rescan, then send controlled tests through every legitimate provider before tightening the terminal policy.",
    ],
    caution: "The analyzer cannot invent a replacement record because public DNS does not reveal the complete legitimate sender inventory.",
  };
}

function analyzedSpfGuidance(
  parsed: ParsedSpfRecord,
  exceedsLimit: boolean,
  incompleteEstimate: boolean,
): SpfCorrectionGuidance {
  if (exceedsLimit) {
    return {
      summary: "Reduce the worst-case SPF evaluation path to ten DNS lookups or fewer.",
      steps: [
        "Remove obsolete and duplicate provider includes before changing active authorization.",
        "Move independent senders to aligned return-path subdomains where appropriate, or ask providers for a lower-lookup include.",
        "Rescan the bounded recursive path and test each legitimate sender after the DNS change.",
      ],
      caution: "Avoid one-time SPF flattening unless provider IP changes are monitored continuously; stale addresses can break delivery.",
    };
  }

  if (parsed.terminalAll === "+") {
    return {
      summary: "Replace universal +all authorization with an inventoried sender policy.",
      steps: [
        "Identify every legitimate envelope-from sender and retain only its documented include or verified IP mechanism.",
        "Use ~all during validation, then consider -all after controlled messages from every sender pass SPF or aligned DKIM.",
        "Confirm the updated policy remains within the ten-lookup limit.",
      ],
      caution: "+all allows every source to pass SPF, but changing it before sender discovery can block legitimate mail.",
    };
  }

  if (incompleteEstimate) {
    return {
      summary: "Resolve the incomplete SPF branches before relying on the lookup estimate.",
      steps: [
        "Review each unresolved include, redirect, cycle, or macro reported by the analyzer.",
        "Confirm the current provider record directly and remove only senders known to be obsolete.",
        "Use receiver authentication results and controlled mail-flow tests to validate the real evaluation path.",
      ],
      caution: "A lower-bound static estimate is not proof that the runtime path stays within ten lookups.",
    };
  }

  if (parsed.warnings.length > 0) {
    const displayedWarnings = parsed.warnings.slice(0, 8).map(boundSpfOutputText);
    const omitted = parsed.warnings.length - displayedWarnings.length;
    return {
      summary: "Review each SPF warning before relying on this policy.",
      steps: [
        boundSpfOutputText(`Address the reported ${parsed.warnings.length === 1 ? "warning" : "warnings"}: ${displayedWarnings.join(" ")}${omitted > 0 ? ` (${omitted} more omitted from this instruction.)` : ""}`),
        "Confirm every remaining mechanism is reachable, intentional, and tied to an active sender.",
        "Rescan and validate controlled messages before tightening or removing authorization.",
      ],
      caution: "Syntax warnings can reflect deprecated, unreachable, or overly permissive behavior even when the record parses successfully.",
    };
  }

  return {
    summary: "Keep the single SPF policy current and revalidate it whenever a sender changes.",
    steps: [
      "Confirm every mechanism maps to a currently authorized outbound service.",
      "Remove retired senders through change control and preserve a single terminal all policy.",
      "Rescan after provider or DNS changes and verify real messages pass SPF or aligned DKIM.",
    ],
  };
}

function boundSpfOutputText(value: string): string {
  if (value.length <= MAX_SPF_OUTPUT_TEXT_LENGTH) return value;
  return `${value.slice(0, MAX_SPF_OUTPUT_TEXT_LENGTH - 1)}…`;
}

function normalizeLookupType(type: unknown): SupportedDnsLookupType {
  if (typeof type !== "string" || !DNS_LOOKUP_TYPE_SET.has(type)) {
    throw new LookupValidationError(`Type must be one of: ${DNS_LOOKUP_TYPES.join(", ")}.`);
  }
  return type as SupportedDnsLookupType;
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

function normalizeSpfRequest(input: unknown): NormalizedLookupRequest {
  const owner = normalizePublicOwnerName(input);
  return { input: owner, queryName: owner, type: "SPF" };
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
