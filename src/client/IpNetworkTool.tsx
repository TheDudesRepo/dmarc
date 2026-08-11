import {
  AlertCircle,
  Binary,
  Calculator,
  Check,
  CircleHelp,
  Copy,
  ExternalLink,
  Globe2,
  Info,
  LoaderCircle,
  Network,
  ServerCog,
  ShieldCheck,
} from "lucide-react";
import { FormEvent, useEffect, useRef, useState } from "react";
import type {
  CymruAsNameEvidence,
  CymruOriginEvidence,
  CymruOriginRecord,
  EnrichmentEvidenceStatus,
  IpClassification,
  IpEnrichment,
  IpToolsResult,
  PtrEvidence,
  ScanError,
} from "../shared/types";

const EXAMPLES = ["192.168.10.42/24", "8.8.8.8", "2001:4860:4860::8888/128"] as const;
const CLASSIFICATION_KINDS = new Set([
  "private",
  "loopback",
  "link-local",
  "multicast",
  "documentation",
  "reserved",
  "global",
]);
const EVIDENCE_STATUSES = new Set<EnrichmentEvidenceStatus>([
  "found",
  "not-found",
  "indeterminate",
  "not-requested",
]);
const ENRICHMENT_STATUSES = new Set([
  "not-requested",
  "not-applicable",
  "complete",
  "partial",
  "indeterminate",
]);
const USABLE_CONVENTIONS = new Set([
  "ipv4-traditional",
  "ipv4-point-to-point",
  "ipv4-host",
  "ipv6-addresses",
]);
const SCAN_ERROR_CODE_SET = new Set(["INVALID_DOMAIN", "METHOD_NOT_ALLOWED", "BAD_REQUEST", "UPSTREAM_ERROR", "NOT_FOUND"]);

export function IpNetworkTool() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<IpToolsResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const controllerRef = useRef<AbortController | null>(null);
  const requestVersionRef = useRef(0);

  useEffect(() => () => {
    requestVersionRef.current += 1;
    controllerRef.current?.abort();
  }, []);

  function resetForInput(value: string) {
    requestVersionRef.current += 1;
    controllerRef.current?.abort();
    controllerRef.current = null;
    setInput(value);
    setResult(null);
    setError(null);
    setLoading(false);
    setCopyState("idle");
  }

  async function runTool(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = input.trim();
    if (!target) return;

    requestVersionRef.current += 1;
    const requestVersion = requestVersionRef.current;
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 15_000);
    setLoading(true);
    setResult(null);
    setError(null);
    setCopyState("idle");

    try {
      const response = await fetch("/api/ip-network", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ input: target }),
        signal: controller.signal,
      });
      const body: unknown = await response.json().catch(() => null);
      if (requestVersionRef.current !== requestVersion || controllerRef.current !== controller) return;

      if (!response.ok) {
        throw new Error(isScanError(body) ? body.error : "The IP tools API is temporarily unavailable.");
      }
      if (!isIpToolsResult(body)) {
        throw new Error("The IP tools API returned an invalid response. Please try again.");
      }
      setResult(body);
    } catch (caught) {
      if (requestVersionRef.current !== requestVersion || controllerRef.current !== controller) return;
      setError(
        caught instanceof DOMException && caught.name === "AbortError"
          ? "The IP lookup timed out. No missing evidence was inferred from the timeout."
          : caught instanceof Error
            ? caught.message
            : "The IP or subnet calculation could not be completed.",
      );
    } finally {
      window.clearTimeout(timeout);
      if (requestVersionRef.current === requestVersion && controllerRef.current === controller) {
        controllerRef.current = null;
        setLoading(false);
      }
    }
  }

  async function copyJson() {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(result, null, 2));
      setCopyState("copied");
      window.setTimeout(() => setCopyState("idle"), 1_800);
    } catch {
      setCopyState("failed");
      window.setTimeout(() => setCopyState("idle"), 2_400);
    }
  }

  return (
    <section className="ip-tool-section" id="ip-tools" aria-labelledby="ip-tool-title">
      <div className="container">
        <div className="ip-tool-heading">
          <div>
            <div className="eyebrow"><span /> IP and subnet tools</div>
            <h2 id="ip-tool-title">Calculate the network. Inspect the DNS evidence.</h2>
          </div>
          <p>
            Parse IPv4, IPv6, CIDR, or an IPv4 netmask. A single public address also gets
            best-effort reverse DNS and origin-AS evidence through a tightly bounded DNS path.
          </p>
        </div>

        <div className="ip-tool-card">
          <form className="ip-tool-form" onSubmit={(event) => void runTool(event)}>
            <div className="ip-tool-input">
              <label htmlFor="ip-tool-input">IP address or CIDR</label>
              <div>
                <Binary aria-hidden="true" />
                <input
                  id="ip-tool-input"
                  type="text"
                  inputMode="text"
                  value={input}
                  onChange={(event) => resetForInput(event.target.value)}
                  placeholder="192.168.10.42/24"
                  autoCapitalize="none"
                  autoCorrect="off"
                  autoComplete="off"
                  spellCheck="false"
                  aria-describedby="ip-tool-help ip-tool-scope"
                  required
                />
              </div>
            </div>
            <button className="button button-primary" type="submit" disabled={loading || !input.trim()}>
              {loading ? <LoaderCircle className="spin" aria-hidden="true" /> : <Calculator aria-hidden="true" />}
              {loading ? "Calculating" : "Inspect IP / subnet"}
            </button>
          </form>

          <div className="ip-tool-help" id="ip-tool-help">
            <span>Try an example</span>
            {EXAMPLES.map((example) => (
              <button type="button" key={example} onClick={() => resetForInput(example)} disabled={loading}>
                <code>{example}</code>
              </button>
            ))}
          </div>

          {loading && (
            <div className="ip-tool-loading" role="status" aria-live="polite">
              <LoaderCircle className="spin" aria-hidden="true" />
              <div>
                <strong>Calculating {input}</strong>
                <span>Network arithmetic runs first; eligible host addresses then use at most four logical DNS queries.</span>
              </div>
            </div>
          )}

          {error && (
            <div className="ip-tool-error" role="alert">
              <AlertCircle aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

          {result && !loading && (
            <div className="ip-tool-results" aria-live="polite">
              <div className="ip-tool-result-bar">
                <div>
                  <span>Canonical input</span>
                  <h3>{result.canonical}</h3>
                </div>
                <button type="button" onClick={() => void copyJson()}>
                  {copyState === "copied" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                  {copyState === "copied" ? "Copied JSON" : copyState === "failed" ? "Copy failed" : "Copy JSON"}
                </button>
              </div>

              <div className="ip-tool-metrics">
                <Metric label="Version" value={`IPv${result.version}`} />
                <Metric label="Address class" value={formatClassification(result.classification.kind)} />
                <Metric label="Prefix" value={`/${result.prefix}`} />
                <Metric label="Total addresses" value={formatInteger(result.totalAddresses)} />
              </div>

              <dl className="ip-tool-detail-grid">
                <Detail label="Network" value={result.networkCidr} />
                <Detail label="Last address" value={result.lastAddress} />
                <Detail label="Usable first" value={result.usable.first} />
                <Detail label="Usable last" value={result.usable.last} />
                <Detail label="Usable count" value={formatInteger(result.usable.count)} />
                {result.ipv4 && <Detail label="Netmask" value={result.ipv4.netmask} />}
                {result.ipv4 && <Detail label="Wildcard mask" value={result.ipv4.wildcard} />}
                {result.ipv4 && <Detail label="Broadcast / last" value={result.ipv4.broadcast} />}
              </dl>

              <EnrichmentPanel enrichment={result.enrichment} />
            </div>
          )}
        </div>

        <div className="ip-tool-scope" id="ip-tool-scope">
          <ShieldCheck aria-hidden="true" />
          <p>
            This tool performs deterministic network arithmetic plus bounded DNS-only evidence. It does not ping,
            trace, connect to ports, fetch arbitrary URLs, identify services, or prove that an address is reachable.
          </p>
        </div>
      </div>
    </section>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div><span>{label}</span><strong>{value}</strong></div>;
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd><code>{value}</code></dd></div>;
}

function EnrichmentPanel({ enrichment }: { enrichment: IpEnrichment }) {
  const originRecords = enrichment.origin.records ?? (enrichment.origin.record ? [enrichment.origin.record] : []);
  const names = enrichment.asNames ?? (enrichment.asName ? [enrichment.asName] : []);

  return (
    <div className={`ip-enrichment ip-enrichment-${enrichment.status}`}>
      <div className="ip-enrichment-heading">
        <div><Globe2 aria-hidden="true" /><span><small>DNS enrichment</small><strong>Reverse name and network origin</strong></span></div>
        <span>{formatClassification(enrichment.status)}</span>
      </div>

      {enrichment.status === "not-applicable" ? (
        <div className="ip-enrichment-note">
          <CircleHelp aria-hidden="true" />
          <p>{enrichment.reason ?? "DNS enrichment is limited to one globally routable IP address."}</p>
        </div>
      ) : (
        <div className="ip-evidence-grid">
          <EvidenceCard title="Reverse DNS (PTR)" icon={<Network aria-hidden="true" />} status={enrichment.ptr.status}>
            {enrichment.ptr.names.length > 0
              ? enrichment.ptr.names.map((name) => <code key={name}>{name}</code>)
              : <EvidenceStatus status={enrichment.ptr.status} />}
          </EvidenceCard>
          <EvidenceCard title="Origin ASN" icon={<ServerCog aria-hidden="true" />} status={enrichment.origin.status}>
            {originRecords.length > 0
              ? originRecords.map((record) => <OriginRecord key={`${record.prefix}-${record.asns.join("-")}`} record={record} names={names} />)
              : <EvidenceStatus status={enrichment.origin.status} />}
          </EvidenceCard>
        </div>
      )}

      {((enrichment.reason && enrichment.status !== "not-applicable") || enrichment.status === "partial" || enrichment.status === "indeterminate") && (
        <div className="ip-enrichment-caution">
          <Info aria-hidden="true" />
          <span>{enrichment.reason ?? "One or more DNS queries were indeterminate; absence was not inferred."}</span>
        </div>
      )}

      <div className="ip-attribution">
        <span>{enrichment.queryCount} of 4 logical DNS queries used</span>
        <a href={enrichment.attribution.asn.url} target="_blank" rel="noreferrer">
          ASN data: {enrichment.attribution.asn.name} <ExternalLink aria-hidden="true" />
        </a>
      </div>
    </div>
  );
}

function EvidenceCard({
  title,
  icon,
  status,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  status: EnrichmentEvidenceStatus;
  children: React.ReactNode;
}) {
  return (
    <article className={`ip-evidence-card ip-evidence-${status}`}>
      <header><span>{icon}{title}</span><small>{formatClassification(status)}</small></header>
      <div>{children}</div>
    </article>
  );
}

function EvidenceStatus({ status }: { status: EnrichmentEvidenceStatus }) {
  const messages: Record<EnrichmentEvidenceStatus, string> = {
    found: "Evidence returned.",
    "not-found": "No record was returned.",
    indeterminate: "The DNS result was unavailable or unrecognized.",
    "not-requested": "This evidence was not requested.",
  };
  return <p>{messages[status]}</p>;
}

function OriginRecord({ record, names }: { record: CymruOriginRecord; names: CymruAsNameEvidence[] }) {
  const matchingNames = names.filter((entry) => entry.asn && record.asns.includes(entry.asn) && entry.name);
  return (
    <div className="ip-origin-record">
      <strong>{record.asns.map((asn) => `AS${asn}`).join(" · ")}</strong>
      {matchingNames.map((entry) => <span key={entry.asn}>{entry.name}</span>)}
      <code>{record.prefix}</code>
      <small>{record.country} · {record.registry.toUpperCase()} · allocated {record.allocated}</small>
    </div>
  );
}

function formatInteger(value: string): string {
  try {
    return BigInt(value).toLocaleString("en-US");
  } catch {
    return value;
  }
}

function formatClassification(value: string): string {
  return value.split("-").map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}

export function isIpToolsResult(value: unknown): value is IpToolsResult {
  if (!isObject(value)) return false;
  const version = value.version;
  const prefix = value.prefix;
  const maximumPrefix = version === 4 ? 32 : version === 6 ? 128 : -1;

  return (
    (version === 4 || version === 6) &&
    typeof prefix === "number" && Number.isInteger(prefix) && prefix >= 0 && prefix <= maximumPrefix &&
    isBoundedString(value.address, 128) &&
    isBoundedString(value.canonical, 132) &&
    isBoundedString(value.cidr, 132) &&
    isBoundedString(value.network, 128) &&
    isBoundedString(value.networkCidr, 132) &&
    isBoundedString(value.lastAddress, 128) &&
    isDecimalCount(value.totalAddresses) &&
    typeof value.isSingleAddress === "boolean" &&
    isClassification(value.classification) &&
    isObject(value.usable) &&
    isBoundedString(value.usable.first, 128) &&
    isBoundedString(value.usable.last, 128) &&
    isDecimalCount(value.usable.count) &&
    typeof value.usable.convention === "string" && USABLE_CONVENTIONS.has(value.usable.convention) &&
    (version === 4 ? isIpv4Details(value.ipv4) : value.ipv4 === undefined) &&
    isEnrichment(value.enrichment)
  );
}

function isClassification(value: unknown): value is IpClassification {
  if (!isObject(value) || typeof value.kind !== "string" || !CLASSIFICATION_KINDS.has(value.kind)) return false;
  const flags = ["private", "loopback", "linkLocal", "multicast", "documentation", "reserved", "global"] as const;
  if (!flags.every((flag) => typeof value[flag] === "boolean")) return false;
  const expectedFlag = value.kind === "link-local" ? "linkLocal" : value.kind;
  return flags.filter((flag) => value[flag] === true).length === 1 && value[expectedFlag] === true;
}

function isIpv4Details(value: unknown): boolean {
  return isObject(value) &&
    isBoundedString(value.netmask, 15) &&
    isBoundedString(value.wildcard, 15) &&
    isBoundedString(value.broadcast, 15);
}

function isEnrichment(value: unknown): value is IpEnrichment {
  if (!isObject(value) || typeof value.status !== "string" || !ENRICHMENT_STATUSES.has(value.status)) return false;
  return (
    typeof value.queryCount === "number" && Number.isInteger(value.queryCount) && value.queryCount >= 0 && value.queryCount <= 4 &&
    isPtrEvidence(value.ptr) &&
    isOriginEvidence(value.origin) &&
    (value.asName === undefined || isAsNameEvidence(value.asName)) &&
    (value.asNames === undefined || (Array.isArray(value.asNames) && value.asNames.length <= 16 && value.asNames.every(isAsNameEvidence))) &&
    (value.asNamesTruncated === undefined || typeof value.asNamesTruncated === "boolean") &&
    (value.reason === undefined || isBoundedString(value.reason, 1_024)) &&
    isObject(value.attribution) &&
    value.attribution.ptr === "Native DNS PTR" &&
    isObject(value.attribution.asn) &&
    isBoundedString(value.attribution.asn.name, 128) &&
    value.attribution.asn.url === "https://www.team-cymru.com/ip-asn-mapping"
  );
}

function isPtrEvidence(value: unknown): value is PtrEvidence {
  return isObject(value) &&
    isEvidenceStatus(value.status) &&
    (value.owner === undefined || isBoundedString(value.owner, 512)) &&
    (value.canonicalOwner === undefined || isBoundedString(value.canonicalOwner, 512)) &&
    Array.isArray(value.names) && value.names.length <= 8 && value.names.every((name) => isBoundedString(name, 253));
}

function isOriginEvidence(value: unknown): value is CymruOriginEvidence {
  return isObject(value) &&
    isEvidenceStatus(value.status) &&
    (value.owner === undefined || isBoundedString(value.owner, 512)) &&
    (value.record === undefined || isOriginRecord(value.record)) &&
    (value.records === undefined || (Array.isArray(value.records) && value.records.length <= 8 && value.records.every(isOriginRecord)));
}

function isOriginRecord(value: unknown): value is CymruOriginRecord {
  return isObject(value) &&
    isBoundedString(value.asn, 10) && /^\d{1,10}$/u.test(value.asn) &&
    Array.isArray(value.asns) && value.asns.length > 0 && value.asns.length <= 16 &&
    value.asns.every((asn) => isBoundedString(asn, 10) && /^\d{1,10}$/u.test(asn)) &&
    isBoundedString(value.prefix, 132) &&
    isBoundedString(value.country, 2) && /^[A-Z]{2}$/u.test(value.country) &&
    isBoundedString(value.registry, 32) &&
    isBoundedString(value.allocated, 10) && /^\d{4}-\d{2}-\d{2}$/u.test(value.allocated);
}

function isAsNameEvidence(value: unknown): value is CymruAsNameEvidence {
  return isObject(value) &&
    isEvidenceStatus(value.status) &&
    (value.asn === undefined || (isBoundedString(value.asn, 10) && /^\d{1,10}$/u.test(value.asn))) &&
    (value.owner === undefined || isBoundedString(value.owner, 512)) &&
    (value.name === undefined || isBoundedString(value.name, 256));
}

function isEvidenceStatus(value: unknown): value is EnrichmentEvidenceStatus {
  return typeof value === "string" && EVIDENCE_STATUSES.has(value as EnrichmentEvidenceStatus);
}

function isDecimalCount(value: unknown): value is string {
  return typeof value === "string" && /^(?:0|[1-9]\d{0,38})$/u.test(value);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isBoundedString(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

function isScanError(value: unknown): value is ScanError {
  return isObject(value) &&
    isBoundedString(value.error, 8_192) &&
    typeof value.code === "string" &&
    SCAN_ERROR_CODE_SET.has(value.code);
}
