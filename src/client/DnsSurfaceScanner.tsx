import {
  AlertCircle,
  AlertTriangle,
  BadgeCheck,
  Check,
  CircleHelp,
  Code2,
  Copy,
  Globe2,
  Info,
  LoaderCircle,
  Network,
  Radar,
  ServerCog,
  Waypoints,
} from "lucide-react";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import type {
  DiscoveredDnsHost,
  DnsRecordView,
  DnsSnapshotGroup,
  DnsSnapshotResult,
  FindingSeverity,
  HostDiscoveryResult,
  ScanError,
  SecurityDnsRecord,
  SnapshotRecordType,
} from "../shared/types";

const SNAPSHOT_TYPE_SET = new Set<SnapshotRecordType>(["A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "TXT"]);
const RECORD_STATUS_SET = new Set(["found", "empty", "unavailable"]);
const FINDING_SEVERITY_SET = new Set<FindingSeverity>(["critical", "warning", "success", "info"]);
const SECURITY_KEY_SET = new Set(["dmarc", "mta-sts", "tls-rpt", "bimi"]);
const HOST_SOURCE_SET = new Set(["common-name", "mail", "nameserver"]);
const HOST_PROFILE_SET = new Set(["core", "extended"]);
const SCAN_ERROR_CODE_SET = new Set(["INVALID_DOMAIN", "METHOD_NOT_ALLOWED", "BAD_REQUEST", "UPSTREAM_ERROR", "NOT_FOUND"]);

const findingIcons: Record<FindingSeverity, React.ReactNode> = {
  critical: <AlertCircle aria-hidden="true" />,
  warning: <AlertTriangle aria-hidden="true" />,
  success: <BadgeCheck aria-hidden="true" />,
  info: <Info aria-hidden="true" />,
};

interface DnsSurfaceScannerProps {
  suggestedDomain: string;
}

interface EndpointResult<T> {
  value?: T;
  error?: string;
}

export function DnsSurfaceScanner({ suggestedDomain }: DnsSurfaceScannerProps) {
  const [domain, setDomain] = useState("");
  const [hasEditedDomain, setHasEditedDomain] = useState(false);
  const [snapshot, setSnapshot] = useState<DnsSnapshotResult | null>(null);
  const [hostResults, setHostResults] = useState<HostDiscoveryResult[]>([]);
  const [errors, setErrors] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const controllerRef = useRef<AbortController | null>(null);
  const requestVersionRef = useRef(0);
  const cleanSuggestedDomain = suggestedDomain.trim();

  useEffect(() => {
    requestVersionRef.current += 1;
    controllerRef.current?.abort();
    controllerRef.current = null;
    setLoading(false);
    setSnapshot(null);
    setHostResults([]);
    setErrors([]);
    setCopyState("idle");
    if (!hasEditedDomain && cleanSuggestedDomain) setDomain(cleanSuggestedDomain);
  }, [cleanSuggestedDomain]);

  useEffect(() => () => {
    requestVersionRef.current += 1;
    controllerRef.current?.abort();
  }, []);

  const discoveredHosts = useMemo(
    () => mergeDiscoveredHosts(snapshot?.infrastructureHosts ?? [], hostResults.flatMap((result) => result.hosts)),
    [snapshot, hostResults],
  );
  const unavailableHostNames = useMemo(
    () => [...new Set(hostResults.flatMap((result) => result.unavailableNames))].sort(),
    [hostResults],
  );
  const wildcardProbes = useMemo(
    () => hostResults
      .filter((result) => result.wildcardProbe.detected && !result.wildcardProbe.unavailable)
      .map((result) => result.wildcardProbe),
    [hostResults],
  );
  const unavailableWildcardProbes = useMemo(
    () => hostResults.filter((result) => result.wildcardProbe.unavailable).map((result) => result.wildcardProbe),
    [hostResults],
  );

  async function runSurfaceScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = domain.trim();
    if (!target) return;

    requestVersionRef.current += 1;
    const requestVersion = requestVersionRef.current;
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 25_000);
    setLoading(true);
    setSnapshot(null);
    setHostResults([]);
    setErrors([]);
    setCopyState("idle");

    try {
      const [snapshotResult, coreResult, extendedResult] = await Promise.all([
        postTool<DnsSnapshotResult>("/api/dns-snapshot", { domain: target }, isDnsSnapshotResult, controller.signal, "DNS record sweep"),
        postTool<HostDiscoveryResult>("/api/host-discovery", { domain: target, profile: "core" }, isHostDiscoveryResult, controller.signal, "Core host discovery"),
        postTool<HostDiscoveryResult>("/api/host-discovery", { domain: target, profile: "extended" }, isHostDiscoveryResult, controller.signal, "Extended host discovery"),
      ]);

      if (requestVersionRef.current !== requestVersion || controllerRef.current !== controller) return;
      const nextSnapshot = snapshotResult.value ?? null;
      const nextHosts = [coreResult.value, extendedResult.value].filter((value): value is HostDiscoveryResult => Boolean(value));
      const nextErrors = [snapshotResult.error, coreResult.error, extendedResult.error].filter((error): error is string => Boolean(error));
      setSnapshot(nextSnapshot);
      setHostResults(nextHosts);
      setErrors(nextErrors);

      if (!nextSnapshot && nextHosts.length === 0 && nextErrors.length === 0) {
        setErrors(["The DNS surface scan returned no usable response. Please try again."]);
      }
    } catch (error) {
      if (requestVersionRef.current !== requestVersion || controllerRef.current !== controller) return;
      setErrors([
        error instanceof DOMException && error.name === "AbortError"
          ? "The DNS surface scan timed out. Unfinished queries were not treated as absent."
          : error instanceof Error
            ? error.message
            : "The DNS surface scan could not be completed.",
      ]);
    } finally {
      window.clearTimeout(timeout);
      if (requestVersionRef.current === requestVersion && controllerRef.current === controller) {
        controllerRef.current = null;
        setLoading(false);
      }
    }
  }

  async function copyJson() {
    if (!snapshot && hostResults.length === 0) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify({ snapshot, hostDiscovery: hostResults }, null, 2));
      setCopyState("copied");
      window.setTimeout(() => setCopyState("idle"), 1800);
    } catch {
      setCopyState("failed");
      window.setTimeout(() => setCopyState("idle"), 2600);
    }
  }

  const hasResults = Boolean(snapshot || hostResults.length > 0);
  const unavailableCount = (snapshot?.unavailableCount ?? 0) + unavailableHostNames.length + unavailableWildcardProbes.length;

  return (
    <section className="dns-surface-section" id="dns-surface" aria-labelledby="dns-surface-title">
      <div className="container">
        <div className="dns-surface-heading">
          <div>
            <div className="eyebrow"><span /> DNS &amp; OSINT · bounded discovery</div>
            <h2 id="dns-surface-title">Map the public DNS surface in one scan.</h2>
          </div>
          <p>
            Sweep the useful apex RRsets, email-security owner names, mail and nameserver hosts,
            plus fourteen bounded common hostnames. Every value remains tied to live DNS evidence.
          </p>
        </div>

        <div className="dns-surface-card">
          <form className="dns-surface-form" onSubmit={(event) => void runSurfaceScan(event)}>
            <div className="dns-surface-input">
              <label htmlFor="dns-surface-domain">Domain to discover</label>
              <div>
                <Radar aria-hidden="true" />
                <input
                  id="dns-surface-domain"
                  type="text"
                  value={domain}
                  onChange={(event) => {
                    requestVersionRef.current += 1;
                    controllerRef.current?.abort();
                    controllerRef.current = null;
                    setDomain(event.target.value);
                    setHasEditedDomain(true);
                    setLoading(false);
                    setSnapshot(null);
                    setHostResults([]);
                    setErrors([]);
                    setCopyState("idle");
                  }}
                  placeholder="example.com"
                  autoCapitalize="none"
                  autoCorrect="off"
                  autoComplete="off"
                  spellCheck="false"
                  required
                />
              </div>
            </div>
            <button className="button button-primary" type="submit" disabled={loading || !domain.trim()}>
              {loading ? <LoaderCircle className="spin" aria-hidden="true" /> : <Network aria-hidden="true" />}
              {loading ? "Mapping DNS" : "Scan DNS surface"}
            </button>
          </form>

          <div className="dns-surface-scope" aria-label="Discovery scope">
            <span><Code2 aria-hidden="true" /> 8 explicit apex RRsets</span>
            <span><Waypoints aria-hidden="true" /> 14 bounded host labels</span>
            <span><Info aria-hidden="true" /> No ANY, AXFR, ports, or service probes</span>
          </div>

          {loading && (
            <div className="dns-surface-loading" role="status" aria-live="polite">
              <LoaderCircle className="spin" aria-hidden="true" />
              <div>
                <strong>Mapping {domain}</strong>
                <span>Running three separately budgeted DNS passes so resolver retries cannot exhaust one request.</span>
              </div>
            </div>
          )}

          {errors.length > 0 && (
            <div className={hasResults ? "dns-surface-partial" : "dns-surface-error"} role="alert">
              <AlertTriangle aria-hidden="true" />
              <div>
                <strong>{hasResults ? "Partial result" : "Scan could not complete"}</strong>
                <ul>{errors.map((error, index) => <li key={`${error}-${index}`}>{error}</li>)}</ul>
              </div>
            </div>
          )}

          {hasResults && !loading && (
            <div className="dns-surface-results" aria-live="polite">
              <div className="dns-surface-result-bar">
                <div>
                  <span>Observed public DNS</span>
                  <h3>{snapshot?.domain ?? hostResults[0]?.domain}</h3>
                </div>
                <button type="button" onClick={() => void copyJson()}>
                  {copyState === "copied" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                  {copyState === "copied" ? "Copied JSON" : copyState === "failed" ? "Copy failed" : "Copy JSON"}
                </button>
              </div>

              <div className="dns-surface-metrics">
                <div><span>DNS records</span><strong>{snapshot?.recordCount ?? "—"}</strong></div>
                <div><span>Observed hosts</span><strong>{discoveredHosts.length}</strong></div>
                <div><span>Indeterminate queries</span><strong>{unavailableCount}</strong></div>
              </div>

              {snapshot && <SnapshotFindings snapshot={snapshot} />}
              {snapshot && <RecordGroupGrid groups={snapshot.groups} />}
              {snapshot && <SecurityRecordGrid records={snapshot.securityRecords} />}
              <ObservedHosts
                hosts={discoveredHosts}
                unavailableNames={unavailableHostNames}
                wildcardProbes={wildcardProbes}
                unavailableWildcardProbes={unavailableWildcardProbes}
              />

              <div className="dns-surface-disclaimer">
                <CircleHelp aria-hidden="true" />
                <div>
                  <strong>Why this says “discovered,” not “every record”</strong>
                  <p>{snapshot?.disclaimer ?? "Public DNS does not provide a complete zone-listing operation."}</p>
                  {hostResults.map((result) => <p key={result.profile}>{result.disclaimer}</p>)}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function SnapshotFindings({ snapshot }: { snapshot: DnsSnapshotResult }) {
  return (
    <div className="dns-surface-block">
      <div className="dns-surface-block-heading">
        <div><ServerCog aria-hidden="true" /><span><small>Correction plan</small><strong>What needs review</strong></span></div>
        <p>{snapshot.summary}</p>
      </div>
      <div className="dns-surface-findings">
        {snapshot.findings.map((finding) => (
          <article className={`dns-surface-finding dns-surface-finding-${finding.severity}`} key={finding.id}>
            <span>{findingIcons[finding.severity]}</span>
            <div>
              <h4>{finding.title}</h4>
              <p>{finding.detail}</p>
              <ol>{finding.steps.map((step, index) => <li key={`${step}-${index}`}>{step}</li>)}</ol>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}

function RecordGroupGrid({ groups }: { groups: DnsSnapshotGroup[] }) {
  return (
    <div className="dns-surface-block">
      <div className="dns-surface-block-heading">
        <div><Globe2 aria-hidden="true" /><span><small>Exact owner</small><strong>Apex RRset sweep</strong></span></div>
        <p>Empty and unavailable are kept separate; a resolver error never becomes a false “missing” result.</p>
      </div>
      <div className="dns-rrset-grid">
        {groups.map((group) => <RecordGroupCard group={group} key={group.type} />)}
      </div>
    </div>
  );
}

function RecordGroupCard({ group }: { group: DnsSnapshotGroup }) {
  return (
    <article className={`dns-rrset-card dns-rrset-${group.status}`}>
      <header>
        <strong>{group.type}</strong>
        <span>{group.status === "found" ? `${group.records.length} found` : group.status}</span>
      </header>
      {group.canonicalName && <p className="dns-rrset-canonical">Canonical target: <code>{group.canonicalName}</code></p>}
      {group.records.length > 0 ? (
        <ul>
          {group.records.map((record, index) => (
            <li key={`${record.name}-${record.value}-${index}`}>
              <code>{record.value}</code>
              <small>{record.name}{record.ttl === undefined ? "" : ` · TTL ${record.ttl}s`}</small>
            </li>
          ))}
        </ul>
      ) : (
        <p>{group.status === "unavailable" ? "Resolver data was unavailable; no absence was inferred." : "No answer was returned for this RRset."}</p>
      )}
    </article>
  );
}

function SecurityRecordGrid({ records }: { records: SecurityDnsRecord[] }) {
  return (
    <div className="dns-surface-block">
      <div className="dns-surface-block-heading">
        <div><BadgeCheck aria-hidden="true" /><span><small>Email security</small><strong>Policy owner names</strong></span></div>
        <p>DMARC, MTA-STS, SMTP TLS reporting, and BIMI are queried at their required owner names.</p>
      </div>
      <div className="dns-security-records">
        {records.map((record) => (
          <article key={record.key}>
            <header><strong>{record.label}</strong><span className={`dns-record-status dns-record-${record.status}`}>{record.status}</span></header>
            <code className="dns-security-owner">{record.ownerName}</code>
            {record.canonicalName && <small>Canonical target: {record.canonicalName}</small>}
            {record.records.map((answer, index) => <code className="dns-security-value" key={`${answer.value}-${index}`}>{answer.value}</code>)}
            {record.records.length === 0 && <p>{record.status === "unavailable" ? "Resolver unavailable" : "No TXT answer returned"}</p>}
          </article>
        ))}
      </div>
    </div>
  );
}

function ObservedHosts({
  hosts,
  unavailableNames,
  wildcardProbes,
  unavailableWildcardProbes,
}: {
  hosts: DiscoveredDnsHost[];
  unavailableNames: string[];
  wildcardProbes: HostDiscoveryResult["wildcardProbe"][];
  unavailableWildcardProbes: HostDiscoveryResult["wildcardProbe"][];
}) {
  const partialWildcardProbes = unavailableWildcardProbes.filter((probe) => probe.detected);
  const unknownWildcardProbes = unavailableWildcardProbes.filter((probe) => !probe.detected);
  const hostsWithUnavailableAddresses = hosts.filter((host) => (host.unavailableAddressTypes?.length ?? 0) > 0);
  return (
    <div className="dns-surface-block">
      <div className="dns-surface-block-heading">
        <div><Waypoints aria-hidden="true" /><span><small>Bounded discovery</small><strong>Observed hosts and relationships</strong></span></div>
        <p>CNAME, MX, and NS targets can be third-party dependencies; discovery does not prove organizational ownership.</p>
      </div>
      {wildcardProbes.length > 0 && (
        <div className="dns-host-wildcard" role="status">
          <AlertTriangle aria-hidden="true" />
          <div>
            <strong>Wildcard DNS response detected</strong>
            <p>
              Random probe{wildcardProbes.length === 1 ? "" : "s"} {wildcardProbes.map((probe) => probe.hostname).join(", ")} resolved.
              Common-name answers with the same alias/address fingerprint are labeled as wildcard matches, not confirmed host records.
            </p>
          </div>
        </div>
      )}
      {partialWildcardProbes.length > 0 && (
        <div className="dns-host-wildcard dns-host-wildcard-unknown" role="status">
          <AlertTriangle aria-hidden="true" />
          <div>
            <strong>Wildcard control partially available</strong>
            <p>
              Random probe{partialWildcardProbes.length === 1 ? "" : "s"} {partialWildcardProbes.map((probe) => probe.hostname).join(", ")} returned positive wildcard evidence, but at least one address query was unavailable.
              The displayed fingerprint is partial; retry before using it to classify every common-name answer.
            </p>
          </div>
        </div>
      )}
      {unknownWildcardProbes.length > 0 && (
        <div className="dns-host-wildcard dns-host-wildcard-unknown" role="status">
          <AlertTriangle aria-hidden="true" />
          <div>
            <strong>Wildcard control unavailable</strong>
            <p>
              Random probe{unknownWildcardProbes.length === 1 ? "" : "s"} {unknownWildcardProbes.map((probe) => probe.hostname).join(", ")} could not be resolved reliably.
              Wildcard behavior is unknown, so matching common-name answers may still be catch-all responses. Retry before treating them as confirmed hosts.
            </p>
          </div>
        </div>
      )}
      {hosts.length > 0 ? (
        <div className="dns-host-table-wrap">
          <table className="dns-host-table">
            <thead><tr><th>Hostname</th><th>Source</th><th>Alias</th><th>Addresses</th><th>Reverse DNS</th></tr></thead>
            <tbody>
              {hosts.map((host) => (
                <tr key={host.hostname}>
                  <td><code>{host.hostname}</code></td>
                  <td>{formatHostSource(host)}</td>
                  <td>{host.alias ? <code>{host.alias}</code> : "—"}</td>
                  <td>{host.addresses.length > 0 ? host.addresses.map((address) => <code key={address}>{address}</code>) : "—"}</td>
                  <td>{host.reverseNames.length > 0 ? host.reverseNames.map((name) => <code key={name}>{name}</code>) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="dns-no-hosts"><CircleHelp aria-hidden="true" /> No bounded common hostname resolved in the completed passes.</div>
      )}
      {unavailableNames.length > 0 && (
        <p className="dns-host-unavailable">Indeterminate host queries: {unavailableNames.join(", ")}. Retry before treating these names as absent.</p>
      )}
      {hostsWithUnavailableAddresses.length > 0 && (
        <p className="dns-host-unavailable">
          Indeterminate address queries: {hostsWithUnavailableAddresses.map((host) => `${host.hostname} (${host.unavailableAddressTypes?.join(", ")})`).join("; ")}.
          Returned addresses remain evidence, but unavailable address families must not be treated as empty.
        </p>
      )}
    </div>
  );
}

async function postTool<T>(
  path: string,
  body: Record<string, string>,
  validate: (value: unknown) => value is T,
  signal: AbortSignal,
  label: string,
): Promise<EndpointResult<T>> {
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
      signal,
    });
    if (!(response.headers.get("content-type")?.toLowerCase() ?? "").includes("application/json")) {
      return { error: `${label}: the API returned a non-JSON response.` };
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      return { error: `${label}: the API returned malformed JSON.` };
    }
    if (!response.ok || isScanError(payload)) {
      return { error: `${label}: ${isScanError(payload) ? payload.error : "request failed"}` };
    }
    if (!validate(payload)) return { error: `${label}: the API returned an incomplete response.` };
    return { value: payload };
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    return { error: `${label}: ${error instanceof Error ? error.message : "request failed"}` };
  }
}

function mergeDiscoveredHosts(...collections: DiscoveredDnsHost[][]): DiscoveredDnsHost[] {
  const merged = new Map<string, DiscoveredDnsHost>();
  for (const host of collections.flat()) {
    const key = host.hostname.toLowerCase();
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, {
        ...host,
        addresses: [...new Set(host.addresses)].sort(),
        ...(host.unavailableAddressTypes
          ? { unavailableAddressTypes: [...new Set(host.unavailableAddressTypes)].sort() as Array<"A" | "AAAA"> }
          : {}),
        reverseNames: [...new Set(host.reverseNames)].sort(),
      });
      continue;
    }
    merged.set(key, {
      ...existing,
      ...(existing.alias ? {} : host.alias ? { alias: host.alias } : {}),
      addresses: [...new Set([...existing.addresses, ...host.addresses])].sort(),
      ...((existing.unavailableAddressTypes || host.unavailableAddressTypes)
        ? {
            unavailableAddressTypes: [...new Set([
              ...(existing.unavailableAddressTypes ?? []),
              ...(host.unavailableAddressTypes ?? []),
            ])].sort() as Array<"A" | "AAAA">,
          }
        : {}),
      reverseNames: [...new Set([...existing.reverseNames, ...host.reverseNames])].sort(),
      ...((existing.wildcardMatch || host.wildcardMatch) ? { wildcardMatch: true } : {}),
    });
  }
  return [...merged.values()].sort((a, b) => a.hostname.localeCompare(b.hostname));
}

function formatHostSource(host: DiscoveredDnsHost): string {
  if (host.wildcardMatch) return "Wildcard match";
  if (host.source === "mail") return "MX target";
  if (host.source === "nameserver") return "NS target";
  return host.profile === "extended" ? "Extended label" : "Core label";
}

export function isDnsSnapshotResult(value: unknown): value is DnsSnapshotResult {
  if (!isObject(value)) return false;
  return (
    isDomain(value.domain) &&
    isIsoDate(value.scannedAt) &&
    isFiniteNonnegative(value.durationMs) &&
    Array.isArray(value.groups) &&
    value.groups.length === SNAPSHOT_TYPE_SET.size &&
    value.groups.every(isSnapshotGroup) &&
    new Set(value.groups.map((group) => group.type)).size === value.groups.length &&
    Array.isArray(value.securityRecords) &&
    value.securityRecords.length === SECURITY_KEY_SET.size &&
    value.securityRecords.every(isSecurityRecord) &&
    Array.isArray(value.infrastructureHosts) &&
    value.infrastructureHosts.length <= 16 &&
    value.infrastructureHosts.every(isDiscoveredHost) &&
    Array.isArray(value.findings) &&
    value.findings.length <= 64 &&
    value.findings.every((finding) => (
      isObject(finding) &&
      isText(finding.id, 256) &&
      typeof finding.severity === "string" &&
      FINDING_SEVERITY_SET.has(finding.severity as FindingSeverity) &&
      isText(finding.title, 1_024) &&
      isText(finding.detail, 8_192) &&
      isTextArray(finding.steps, 32, 8_192)
    )) &&
    typeof value.recordCount === "number" &&
    Number.isInteger(value.recordCount) &&
    value.recordCount >= 0 &&
    value.recordCount <= 4_096 &&
    typeof value.unavailableCount === "number" &&
    Number.isInteger(value.unavailableCount) &&
    value.unavailableCount >= 0 &&
    value.unavailableCount <= 64 &&
    isText(value.summary, 4_096) &&
    isText(value.disclaimer, 8_192)
  );
}

export function isHostDiscoveryResult(value: unknown): value is HostDiscoveryResult {
  if (!isObject(value)) return false;
  return (
    isDomain(value.domain) &&
    (value.profile === "core" || value.profile === "extended") &&
    isIsoDate(value.scannedAt) &&
    isFiniteNonnegative(value.durationMs) &&
    isTextArray(value.testedNames, 32, 253) &&
    value.testedNames.length === 7 &&
    Array.isArray(value.hosts) &&
    value.hosts.length <= 32 &&
    value.hosts.every(isDiscoveredHost) &&
    isTextArray(value.unavailableNames, 32, 253) &&
    isWildcardProbe(value.wildcardProbe) &&
    isText(value.summary, 4_096) &&
    isText(value.disclaimer, 8_192)
  );
}

function isSnapshotGroup(value: unknown): value is DnsSnapshotGroup {
  if (!isObject(value)) return false;
  const type = value.type;
  return (
    typeof type === "string" &&
    SNAPSHOT_TYPE_SET.has(type as SnapshotRecordType) &&
    typeof value.status === "string" &&
    RECORD_STATUS_SET.has(value.status) &&
    Array.isArray(value.records) &&
    value.records.length <= 256 &&
    value.records.every((record) => isDnsRecord(record, type)) &&
    (value.canonicalName === undefined || isDomain(value.canonicalName))
  );
}

function isSecurityRecord(value: unknown): value is SecurityDnsRecord {
  if (!isObject(value)) return false;
  return (
    typeof value.key === "string" &&
    SECURITY_KEY_SET.has(value.key) &&
    isText(value.label, 64) &&
    isDnsOwner(value.ownerName) &&
    typeof value.status === "string" &&
    RECORD_STATUS_SET.has(value.status) &&
    Array.isArray(value.records) &&
    value.records.length <= 256 &&
    value.records.every((record) => isDnsRecord(record, "TXT")) &&
    (value.canonicalName === undefined || isDnsOwner(value.canonicalName))
  );
}

function isDiscoveredHost(value: unknown): value is DiscoveredDnsHost {
  if (!isObject(value)) return false;
  return (
    isDomain(value.hostname) &&
    typeof value.source === "string" &&
    HOST_SOURCE_SET.has(value.source) &&
    (value.profile === undefined || (typeof value.profile === "string" && HOST_PROFILE_SET.has(value.profile))) &&
    (value.alias === undefined || isDomain(value.alias)) &&
    isTextArray(value.addresses, 512, 64) &&
    (
      value.unavailableAddressTypes === undefined ||
      (
        Array.isArray(value.unavailableAddressTypes) &&
        value.unavailableAddressTypes.length <= 2 &&
        new Set(value.unavailableAddressTypes).size === value.unavailableAddressTypes.length &&
        value.unavailableAddressTypes.every((type) => type === "A" || type === "AAAA")
      )
    ) &&
    isTextArray(value.reverseNames, 256, 253) &&
    (value.wildcardMatch === undefined || typeof value.wildcardMatch === "boolean")
  );
}

function isWildcardProbe(value: unknown): value is HostDiscoveryResult["wildcardProbe"] {
  if (!isObject(value)) return false;
  return (
    isDomain(value.hostname) &&
    typeof value.detected === "boolean" &&
    (value.alias === undefined || isDomain(value.alias)) &&
    isTextArray(value.addresses, 512, 64) &&
    typeof value.unavailable === "boolean"
  );
}

function isDnsRecord(value: unknown, expectedType: string): value is DnsRecordView {
  if (!isObject(value)) return false;
  return (
    isDnsOwner(value.name) &&
    value.type === expectedType &&
    typeof value.value === "string" &&
    value.value.length <= 262_144 &&
    (value.ttl === undefined || (Number.isInteger(value.ttl) && Number(value.ttl) >= 0 && Number(value.ttl) <= 2 ** 32 - 1))
  );
}

function isScanError(value: unknown): value is ScanError {
  return isObject(value) &&
    isText(value.error, 8_192) &&
    typeof value.code === "string" &&
    SCAN_ERROR_CODE_SET.has(value.code);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isText(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

function isTextArray(value: unknown, maxItems: number, maxLength: number): value is string[] {
  return Array.isArray(value) && value.length <= maxItems && value.every((item) => isText(item, maxLength));
}

function isDomain(value: unknown): value is string {
  return isText(value, 253) && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u.test(value) && value.includes(".");
}

function isDnsOwner(value: unknown): value is string {
  return isText(value, 253) && /^[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?$/u.test(value) && value.includes(".");
}

function isIsoDate(value: unknown): value is string {
  return typeof value === "string" && value.length <= 64 && !Number.isNaN(Date.parse(value));
}

function isFiniteNonnegative(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}
