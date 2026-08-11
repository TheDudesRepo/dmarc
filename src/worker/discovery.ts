import type {
  DiscoveryFinding,
  DiscoveredDnsHost,
  DnsSnapshotGroup,
  DnsSnapshotResult,
  HostDiscoveryProfile,
  HostDiscoveryResult,
  SecurityDnsRecord,
  SnapshotRecordType,
} from "../shared/types";
import {
  DnsClient,
  type DnsAnswer,
  type DnsQueryType,
  toRecordViews,
} from "./dns";
import { findSpfRecords, parseSpfRecord } from "./spf";

export const SNAPSHOT_RECORD_TYPES = [
  "A",
  "AAAA",
  "CAA",
  "CNAME",
  "MX",
  "NS",
  "SOA",
  "TXT",
] as const satisfies readonly DnsQueryType[];

export const HOST_DISCOVERY_LABELS: Readonly<Record<HostDiscoveryProfile, readonly string[]>> = {
  core: ["www", "mail", "autodiscover", "api", "vpn", "portal", "remote"],
  extended: ["smtp", "webmail", "admin", "dev", "staging", "status", "ftp"],
};

const SECURITY_OWNER_NAMES = [
  { key: "dmarc", label: "DMARC", prefix: "_dmarc" },
  { key: "mta-sts", label: "MTA-STS", prefix: "_mta-sts" },
  { key: "tls-rpt", label: "TLS-RPT", prefix: "_smtp._tls" },
  { key: "bimi", label: "BIMI", prefix: "default._bimi" },
] as const;

const MAX_INFRASTRUCTURE_HOSTS = 2;

export interface DiscoveryResolver {
  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]>;
  queryDirect(name: string, type: DnsQueryType): Promise<DnsAnswer[]>;
}

export class DiscoveryUpstreamError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DiscoveryUpstreamError";
  }
}

export async function createDnsSnapshot(
  domain: string,
  dns: DiscoveryResolver = new DnsClient(),
): Promise<DnsSnapshotResult> {
  const scannedAt = new Date().toISOString();
  const startedAt = performance.now();

  const [groups, securityRecords] = await Promise.all([
    Promise.all(SNAPSHOT_RECORD_TYPES.map((type) => querySnapshotGroup(domain, type, dns))),
    Promise.all(SECURITY_OWNER_NAMES.map((owner) => querySecurityOwner(domain, owner, dns))),
  ]);

  if (groups.every((group) => group.status === "unavailable")) {
    throw new DiscoveryUpstreamError("The DNS snapshot could not reach the resolver.");
  }

  const infrastructureHosts = await resolveInfrastructureHosts(groups, dns);
  const findings = buildSnapshotFindings(domain, groups, securityRecords, infrastructureHosts);
  const recordCount = groups.reduce((total, group) => total + group.records.length, 0)
    + securityRecords.reduce((total, record) => total + record.records.length, 0);
  const unavailableCount = groups.filter((group) => group.status === "unavailable").length
    + securityRecords.filter((record) => record.status === "unavailable").length
    + infrastructureHosts.reduce((total, host) => total + (host.unavailableAddressTypes?.length ?? 0), 0);
  const summary = unavailableCount > 0
    ? `${recordCount} public DNS records were returned; ${unavailableCount} record ${unavailableCount === 1 ? "query was" : "queries were"} temporarily unavailable.`
    : `${recordCount} public DNS records were returned across the apex and email-security owner names.`;

  return {
    domain,
    scannedAt,
    durationMs: Math.max(1, Math.round(performance.now() - startedAt)),
    groups,
    securityRecords,
    infrastructureHosts,
    findings,
    recordCount,
    unavailableCount,
    summary,
    disclaimer: "This is an explicit live RRset sweep, not an ANY query or a complete zone listing. Public DNS cannot enumerate every owner name unless the zone is transferred or historical datasets are consulted.",
  };
}

export async function discoverCommonHosts(
  domain: string,
  profile: HostDiscoveryProfile,
  dns: DiscoveryResolver = new DnsClient(),
): Promise<HostDiscoveryResult> {
  const labels = HOST_DISCOVERY_LABELS[profile];
  const scannedAt = new Date().toISOString();
  const startedAt = performance.now();
  const wildcardHostname = `${createWildcardProbeLabel()}.${domain}`;
  const [wildcardResult, ...results] = await Promise.all([
    discoverOneHost(wildcardHostname, profile, dns),
    ...labels.map((label) => discoverOneHost(`${label}.${domain}`, profile, dns)),
  ]);
  const wildcardFingerprint = wildcardResult.host ? hostAnswerFingerprint(wildcardResult.host) : undefined;
  const hosts = results.flatMap((result) => {
    if (!result.host) return [];
    const wildcardMatch = Boolean(wildcardFingerprint && hostAnswerFingerprint(result.host) === wildcardFingerprint);
    return [{ ...result.host, ...(wildcardMatch ? { wildcardMatch: true } : {}) }];
  });
  const unavailableNames = results.filter((result) => result.unavailable).map((result) => result.hostname);

  const resolvedLabel = hosts.length === 1 ? "name" : "names";
  const unavailableSuffix = unavailableNames.length > 0
    ? ` ${unavailableNames.length} ${unavailableNames.length === 1 ? "name was" : "names were"} temporarily unavailable and were not treated as absent.`
    : "";
  const wildcardSuffix = wildcardResult.host
    ? " A random-label wildcard response was detected; matching host answers are tagged for review."
    : "";

  return {
    domain,
    profile,
    scannedAt,
    durationMs: Math.max(1, Math.round(performance.now() - startedAt)),
    testedNames: labels.map((label) => `${label}.${domain}`),
    hosts,
    unavailableNames,
    wildcardProbe: {
      hostname: wildcardHostname,
      detected: Boolean(wildcardResult.host),
      ...(wildcardResult.host?.alias ? { alias: wildcardResult.host.alias } : {}),
      addresses: wildcardResult.host?.addresses ?? [],
      unavailable: wildcardResult.unavailable,
    },
    summary: `${hosts.length} of ${labels.length} common public host ${resolvedLabel} resolved.${wildcardSuffix}${unavailableSuffix}`,
    disclaimer: "Common-name discovery checks a documented bounded label set plus one random-label wildcard probe. It does not brute-force the namespace and cannot prove that undiscovered hosts do not exist.",
  };
}

export function normalizeHostDiscoveryProfile(value: unknown): HostDiscoveryProfile {
  if (value === "core" || value === "extended") return value;
  throw new TypeError("Profile must be core or extended.");
}

async function querySnapshotGroup(
  domain: string,
  type: SnapshotRecordType,
  dns: DiscoveryResolver,
): Promise<DnsSnapshotGroup> {
  try {
    const answers = await dns.query(domain, type);
    const records = toRecordViews(answers);
    const canonicalName = inferCanonicalName(domain, answers);
    return {
      type,
      status: records.length > 0 ? "found" : "empty",
      records,
      ...(canonicalName ? { canonicalName } : {}),
    };
  } catch {
    return { type, status: "unavailable", records: [] };
  }
}

async function querySecurityOwner(
  domain: string,
  owner: (typeof SECURITY_OWNER_NAMES)[number],
  dns: DiscoveryResolver,
): Promise<SecurityDnsRecord> {
  const ownerName = `${owner.prefix}.${domain}`;
  try {
    const answers = await dns.query(ownerName, "TXT");
    const records = toRecordViews(answers);
    const canonicalName = inferCanonicalName(ownerName, answers);
    return {
      key: owner.key,
      label: owner.label,
      ownerName,
      status: records.length > 0 ? "found" : "empty",
      records,
      ...(canonicalName ? { canonicalName } : {}),
    };
  } catch {
    return {
      key: owner.key,
      label: owner.label,
      ownerName,
      status: "unavailable",
      records: [],
    };
  }
}

async function resolveInfrastructureHosts(
  groups: DnsSnapshotGroup[],
  dns: DiscoveryResolver,
): Promise<DiscoveredDnsHost[]> {
  const candidates = new Map<string, "mail" | "nameserver">();
  for (const group of groups) {
    if (group.type !== "MX" && group.type !== "NS") continue;
    for (const record of group.records) {
      const hostname = group.type === "MX" ? parseMxHostname(record.value) : normalizeAnswerName(record.value);
      if (hostname && hostname !== "." && !candidates.has(hostname)) {
        candidates.set(hostname, group.type === "MX" ? "mail" : "nameserver");
      }
    }
  }

  const selected = [...candidates.entries()].slice(0, MAX_INFRASTRUCTURE_HOSTS);
  const hosts = await Promise.all(selected.map(async ([hostname, source]) => {
    const [ipv4, ipv6] = await Promise.all([
      safeDirectQuery(hostname, "A", dns),
      safeDirectQuery(hostname, "AAAA", dns),
    ]);
    const unavailableAddressTypes = [
      ...(ipv4.unavailable ? ["A" as const] : []),
      ...(ipv6.unavailable ? ["AAAA" as const] : []),
    ];
    return {
      hostname,
      source,
      addresses: [...ipv4.answers, ...ipv6.answers].map((answer) => answer.data),
      ...(unavailableAddressTypes.length > 0 ? { unavailableAddressTypes } : {}),
      reverseNames: [],
    } satisfies DiscoveredDnsHost;
  }));
  return hosts;
}

async function discoverOneHost(
  hostname: string,
  profile: HostDiscoveryProfile,
  dns: DiscoveryResolver,
): Promise<{ hostname: string; host?: DiscoveredDnsHost; unavailable: boolean }> {
  const aliasResult = await safeDirectQuery(hostname, "CNAME", dns);
  const alias = aliasResult.answers[0]?.data ? normalizeAnswerName(aliasResult.answers[0].data) : undefined;
  const addressOwner = alias ?? hostname;
  const [ipv4, ipv6] = await Promise.all([
    safeDirectQuery(addressOwner, "A", dns),
    safeDirectQuery(addressOwner, "AAAA", dns),
  ]);
  const unavailable = aliasResult.unavailable || ipv4.unavailable || ipv6.unavailable;
  const addresses = [...ipv4.answers, ...ipv6.answers].map((answer) => answer.data);

  if (!alias && addresses.length === 0) return { hostname, unavailable };
  return {
    hostname,
    unavailable,
    host: {
      hostname,
      source: "common-name",
      profile,
      ...(alias ? { alias } : {}),
      addresses,
      reverseNames: [],
    },
  };
}

async function safeDirectQuery(
  name: string,
  type: DnsQueryType,
  dns: DiscoveryResolver,
): Promise<{ answers: DnsAnswer[]; unavailable: boolean }> {
  try {
    return { answers: await dns.queryDirect(name, type), unavailable: false };
  } catch {
    return { answers: [], unavailable: true };
  }
}

function buildSnapshotFindings(
  domain: string,
  groups: DnsSnapshotGroup[],
  securityRecords: SecurityDnsRecord[],
  infrastructureHosts: DiscoveredDnsHost[],
): DiscoveryFinding[] {
  const findings: DiscoveryFinding[] = [];
  const group = (type: SnapshotRecordType) => groups.find((candidate) => candidate.type === type);
  const security = (key: SecurityDnsRecord["key"]) => securityRecords.find((candidate) => candidate.key === key);
  const txtGroup = group("TXT");
  const txtRecords = txtGroup?.records.map((record) => record.value) ?? [];
  const spfRecords = findSpfRecords(txtRecords);
  const activeMx = (group("MX")?.records ?? []).filter((record) => record.value !== "0 .");

  if (group("NS")?.status === "empty" || group("SOA")?.status === "empty") {
    findings.push({
      id: "authority-records-missing",
      severity: "warning",
      title: "No direct zone authority was found at this owner name",
      detail: `The response for ${domain} did not include both a direct NS and SOA RRset. This is normal for a hostname, but needs review if ${domain} is intended to be a zone apex.`,
      steps: [
        "First confirm whether this exact owner name is a zone apex or only a host inside a parent zone.",
        "For a zone apex, compare the registrar delegation with the authoritative DNS provider.",
        "Restore provider-generated SOA/NS data only when the owner is meant to be independently delegated.",
      ],
    });
  }

  if (spfRecords.length > 1) {
    findings.push({
      id: "multiple-spf-records",
      severity: "critical",
      title: "Multiple SPF policies are published",
      detail: `${domain} publishes ${spfRecords.length} separate v=spf1 TXT records. Receivers evaluate this as an SPF permanent error.`,
      steps: [
        "Inventory every legitimate sending service represented by the existing records.",
        "Merge the required mechanisms into one v=spf1 policy.",
        "Keep the final policy within SPF's ten DNS-lookup limit, then remove the duplicate records.",
      ],
    });
  } else if (spfRecords.length === 1) {
    const parsed = parseSpfRecord(spfRecords[0] ?? "");
    if (!parsed.valid || parsed.terminalAll === "+") {
      findings.push({
        id: "invalid-or-open-spf",
        severity: "critical",
        title: parsed.terminalAll === "+" ? "SPF authorizes every sender" : "SPF syntax needs correction",
        detail: parsed.terminalAll === "+"
          ? "The +all mechanism allows any source to pass SPF for this domain."
          : parsed.errors.join(" ") || "The SPF record could not be parsed reliably.",
        steps: [
          "Use the SPF analyzer to review mechanisms and recursive lookups.",
          "Confirm every authorized sender before changing the policy.",
          "Publish one corrected TXT record and re-scan before tightening DMARC.",
        ],
      });
    }
  } else if (activeMx.length > 0 && txtGroup?.status !== "unavailable") {
    findings.push({
      id: "spf-missing",
      severity: "warning",
      title: "No SPF policy was found at the apex",
      detail: "The domain has active mail exchangers but no v=spf1 TXT record was returned.",
      steps: [
        "Inventory every service that sends mail using this domain in the visible From or envelope-from address.",
        "Build one SPF record from provider-documented mechanisms; do not guess IP ranges.",
        "Test the record and its recursive lookup count before publishing it.",
      ],
    });
  }

  if (security("dmarc")?.status === "empty") {
    findings.push({
      id: "dmarc-missing",
      severity: "warning",
      title: "No DMARC record was found",
      detail: `No TXT answer was returned at _dmarc.${domain}.`,
      steps: [
        "Create a monitored DMARC policy with an aggregate-report destination you control.",
        "Identify and align legitimate senders from aggregate reports.",
        "Move toward quarantine only after the evidence shows legitimate mail will continue to pass.",
      ],
    });
  }

  if (security("tls-rpt")?.status === "empty") {
    findings.push({
      id: "tls-rpt-missing",
      severity: "info",
      title: "SMTP TLS reporting is not published",
      detail: `No TXT answer was returned at _smtp._tls.${domain}. TLS-RPT is optional but helps reveal transport failures.`,
      steps: [
        "Choose a TLS report mailbox or approved reporting service.",
        `Publish a provider-reviewed v=TLSRPTv1 TXT record at _smtp._tls.${domain}.`,
      ],
    });
  }

  if (findings.length === 0) {
    const unavailableEvidenceCount = groups.filter((candidate) => candidate.status === "unavailable").length
      + securityRecords.filter((candidate) => candidate.status === "unavailable").length
      + infrastructureHosts.reduce((total, host) => total + (host.unavailableAddressTypes?.length ?? 0), 0);
    findings.push(unavailableEvidenceCount > 0
      ? {
          id: "review-incomplete",
          severity: "info",
          title: "DNS review is incomplete",
          detail: `${unavailableEvidenceCount} DNS ${unavailableEvidenceCount === 1 ? "query was" : "queries were"} unavailable, so this scan cannot make a complete conflict assessment.`,
          steps: [
            "Retry the scan before treating unavailable RRsets or address families as absent.",
            "Compare the returned evidence with the current asset and sender inventory.",
            "Make DNS changes only after the missing evidence can be reviewed.",
          ],
        }
      : {
          id: "review-inventory",
          severity: "success",
          title: "No obvious apex DNS conflict was detected",
          detail: "The returned RRsets are internally plausible, but public DNS alone cannot confirm that every host and sender is authorized.",
          steps: [
            "Compare all returned hosts and provider records with the current asset inventory.",
            "Remove stale records only after confirming they are no longer referenced.",
            "Use DMARC aggregate reports before changing enforcement policy.",
          ],
        });
  }

  return findings;
}

function inferCanonicalName(queryName: string, answers: DnsAnswer[]): string | undefined {
  const names = [...new Set(answers.map((answer) => normalizeAnswerName(answer.name)).filter(Boolean))];
  return names.length === 1 && names[0] !== queryName ? names[0] : undefined;
}

function parseMxHostname(value: string): string | undefined {
  const match = /^\d+\s+(.+)$/u.exec(value.trim());
  return match?.[1] ? normalizeAnswerName(match[1]) : undefined;
}

function normalizeAnswerName(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/u, "");
}

function createWildcardProbeLabel(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return `dmarc-ready-probe-${[...bytes].map((value) => value.toString(16).padStart(2, "0")).join("")}`;
}

function hostAnswerFingerprint(host: DiscoveredDnsHost): string {
  return JSON.stringify({
    alias: host.alias ?? null,
    addresses: [...host.addresses].sort(),
  });
}
