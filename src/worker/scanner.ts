import type {
  CheckResult,
  DkimSelectorResult,
  Finding,
  FindingSeverity,
  ScanResult,
} from "../shared/types";
import { type DmarcPolicy, type ParsedDmarcRecord, findDmarcRecords, parseDmarcRecord } from "./dmarc";
import { DnsClient, DnsQueryError, type DnsAnswer, type DnsQueryType, toRecordViews } from "./dns";
import { estimateSpfLookups, findSpfRecords, parseSpfRecord, type SpfLookupEstimate } from "./spf";

const COMMON_DKIM_SELECTORS = ["selector1", "selector2", "google", "default", "k1", "k2", "s1", "s2", "dkim", "mail"] as const;

const DISCLAIMER =
  "This is a point-in-time DNS configuration snapshot, not proof of deliverability or enforcement readiness. DNS alone cannot inventory legitimate senders, observe real SPF/DKIM alignment, verify every DKIM selector, validate external DMARC reporting authorization, or reliably calculate organizational-domain inheritance for every public suffix. Review DMARC aggregate reports and test mail flows before changing policy.";

export interface DnsResolver {
  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]>;
}

interface OptionalDnsResult {
  answers: DnsAnswer[];
  failed: boolean;
}

interface DmarcAnalysis {
  check: CheckResult;
  policy?: DmarcPolicy;
  scope?: DmarcScopeAnalysis;
  testing: boolean;
  posture: ScanResult["posture"];
  points: number;
  findings: Finding[];
}

interface DmarcScopeAnalysis {
  organizationalPolicy: DmarcPolicy;
  subdomainPolicy: DmarcPolicy;
  nonexistentSubdomainPolicy: DmarcPolicy;
  effectiveOrganizationalPolicy: DmarcPolicy;
  effectiveSubdomainPolicy: DmarcPolicy;
  effectiveNonexistentSubdomainPolicy: DmarcPolicy;
  subdomainSource: "p" | "sp";
  nonexistentSubdomainSource: "p" | "sp" | "np";
  weakerSubdomainPolicy: boolean;
  weakerNonexistentSubdomainPolicy: boolean;
}

interface SpfAnalysis {
  check: CheckResult;
  points: number;
  findings: Finding[];
}

interface DkimDiscoveryResult {
  selectors: DkimSelectorResult[];
  failedQueries: number;
}

interface DnsHealthAnalysis {
  check: CheckResult;
  findings: Finding[];
}

export class ScanUpstreamError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanUpstreamError";
  }
}

export async function scanDomain(domain: string, dns: DnsResolver = new DnsClient()): Promise<ScanResult> {
  const startedAt = performance.now();
  const scannedAt = new Date().toISOString();
  const dmarcQuery = dns.query(`_dmarc.${domain}`, "TXT");
  const rootTxtQuery = optionalDns(dns.query(domain, "TXT"));
  const aQuery = optionalDns(dns.query(domain, "A"));
  const aaaaQuery = optionalDns(dns.query(domain, "AAAA"));
  const mxQuery = optionalDns(dns.query(domain, "MX"));
  const nsQuery = optionalDns(dns.query(domain, "NS"));
  const cnameQuery = optionalDns(dns.query(domain, "CNAME"));
  const soaQuery = optionalDns(dns.query(domain, "SOA"));
  const caaQuery = optionalDns(dns.query(domain, "CAA"));
  const mtaStsQuery = optionalDns(dns.query(`_mta-sts.${domain}`, "TXT"));
  const tlsRptQuery = optionalDns(dns.query(`_smtp._tls.${domain}`, "TXT"));
  const bimiQuery = optionalDns(dns.query(`default._bimi.${domain}`, "TXT"));
  const dkimQuery = discoverDkim(domain, dns);

  let dmarcAnswers: DnsAnswer[];
  try {
    dmarcAnswers = await dmarcQuery;
  } catch (error) {
    if (error instanceof DnsQueryError) {
      throw new ScanUpstreamError("The DMARC DNS query could not be completed.");
    }
    throw error;
  }

  const [rootTxt, a, aaaa, mx, ns, cname, soa, caa, mtaSts, tlsRpt, bimi, dkimDiscovery] = await Promise.all([
    rootTxtQuery,
    aQuery,
    aaaaQuery,
    mxQuery,
    nsQuery,
    cnameQuery,
    soaQuery,
    caaQuery,
    mtaStsQuery,
    tlsRptQuery,
    bimiQuery,
    dkimQuery,
  ]);

  const dmarc = analyzeDmarc(domain, dmarcAnswers);

  let spfEstimate: SpfLookupEstimate | undefined;
  if (!rootTxt.failed) {
    const rootSpfRecords = findSpfRecords(rootTxt.answers.map((answer) => answer.data));
    if (rootSpfRecords.length === 1) {
      const parsed = parseSpfRecord(rootSpfRecords[0] ?? "");
      if (parsed.valid) {
        spfEstimate = await estimateSpfLookups(domain, parsed, async (target) => {
          const answers = await dns.query(target, "TXT");
          return answers.map((answer) => answer.data);
        });
      }
    }
  }

  const spf = analyzeSpf(rootTxt, spfEstimate);
  const dkim = analyzeDkim(dkimDiscovery);
  const transport = analyzeTransport(domain, mx, mtaSts, tlsRpt);
  const dnsHealth = analyzeDnsHealth({ rootTxt, a, aaaa, mx, ns, cname, soa, caa });
  const mxProviders = unique(
    mx.answers
      .map((answer) => parseMxHostname(answer.data))
      .filter((provider): provider is string => Boolean(provider)),
  );
  const nameservers = unique(ns.answers.map((answer) => answer.data.toLowerCase()));
  const hasMtaSts = hasVersionRecord(mtaSts.answers, "STSv1");
  const hasTlsRpt = hasVersionRecord(tlsRpt.answers, "TLSRPTv1");
  const hasBimi = hasVersionRecord(bimi.answers, "BIMI1");

  const findings: Finding[] = [
    ...dmarc.findings,
    ...spf.findings,
    ...dkim.findings,
    ...transport.findings,
    ...dnsHealth.findings,
  ];
  if (hasBimi) {
    findings.push({
      id: "bimi-published",
      severity: "info",
      title: "BIMI record discovered",
      detail: "A default-selector BIMI TXT record is published. This scan does not validate its logo, certificate, or mailbox-provider eligibility.",
    });
  }

  const partialFailures =
    [rootTxt, a, aaaa, mx, ns, cname, soa, caa, mtaSts, tlsRpt, bimi].filter((result) => result.failed).length +
    dkimDiscovery.failedQueries;
  if (partialFailures > 0) {
    findings.push({
      id: "partial-dns-results",
      severity: "info",
      title: "Some optional DNS checks were unavailable",
      detail: `${partialFailures} optional DNS ${partialFailures === 1 ? "query" : "queries"} failed, so affected checks are shown as unknown rather than absent.`,
      action: "Run the scan again before making a configuration decision.",
    });
  }

  const score = clampScore(
    dmarc.points +
      spf.points +
      dkim.points +
      transport.points +
      (hasBimi ? 3 : 0) +
      (mx.answers.length > 0 ? 5 : 0) +
      (ns.answers.length > 0 ? 2 : 0),
  );
  const grade = gradeForScore(score);
  const presentation = posturePresentation(dmarc.posture, dmarc.policy, dmarc.testing, dmarc.scope);

  return {
    domain,
    scannedAt,
    durationMs: Math.max(1, Math.round(performance.now() - startedAt)),
    score,
    grade,
    posture: dmarc.posture,
    postureLabel: presentation.label,
    headline: presentation.headline,
    summary: presentation.summary,
    checks: {
      dmarc: dmarc.check,
      spf: spf.check,
      dkim: dkim.check,
      transport: transport.check,
      dns: dnsHealth.check,
    },
    dkimSelectors: dkimDiscovery.selectors,
    findings: sortFindings(findings),
    metadata: {
      mxProviders,
      nameservers,
      hasBimi,
      hasMtaSts,
      hasTlsRpt,
    },
    disclaimer: DISCLAIMER,
  };
}

function analyzeDnsHealth({
  rootTxt,
  a,
  aaaa,
  mx,
  ns,
  cname,
  soa,
  caa,
}: {
  rootTxt: OptionalDnsResult;
  a: OptionalDnsResult;
  aaaa: OptionalDnsResult;
  mx: OptionalDnsResult;
  ns: OptionalDnsResult;
  cname: OptionalDnsResult;
  soa: OptionalDnsResult;
  caa: OptionalDnsResult;
}): DnsHealthAnalysis {
  const findings: Finding[] = [];
  const unavailable = [rootTxt, a, aaaa, mx, ns, cname, soa, caa].filter((result) => result.failed).length;
  const aliasOwners = new Set(cname.answers.map((answer) => answer.name.toLowerCase().replace(/\.$/u, "")));
  const hasConflictingAlias = aliasOwners.size > 0 && [...rootTxt.answers, ...mx.answers].some((answer) =>
    aliasOwners.has(answer.name.toLowerCase().replace(/\.$/u, "")),
  );

  if (!ns.failed && ns.answers.length === 0) {
    findings.push({
      id: "dns-nameservers-not-found",
      severity: "critical",
      title: "No authoritative nameservers were returned",
      detail: "The NS lookup completed without returning a nameserver. A public delegated zone normally requires authoritative NS records.",
      action: "Confirm registrar delegation and restore the DNS provider's authoritative nameservers.",
      remediation: {
        summary: "Restore a valid delegation between the registrar and authoritative DNS provider.",
        steps: [
          "Open the registrar's nameserver settings and compare them with the active DNS provider's assigned NS hostnames.",
          "Replace stale or missing delegation values and confirm the zone exists at the provider.",
          "Wait for parent-zone TTLs to expire, then verify NS and SOA responses from multiple networks.",
        ],
        caution: "Changing delegation can take the entire domain offline. Copy the exact nameservers assigned by the active provider.",
      },
    });
  } else if (!ns.failed && ns.answers.length === 1) {
    findings.push({
      id: "dns-single-nameserver",
      severity: "warning",
      title: "Only one authoritative nameserver was returned",
      detail: "A single authoritative server creates an avoidable availability dependency for the domain.",
      action: "Use at least two authoritative nameservers on resilient infrastructure.",
      remediation: {
        summary: "Add the additional authoritative nameservers assigned by the DNS provider.",
        steps: [
          "Confirm the provider has provisioned the zone on at least two authoritative servers.",
          "Add every assigned NS hostname at the registrar; do not invent nameserver addresses.",
          "Verify all servers return the same current SOA serial and record set.",
        ],
      },
    });
  }

  if (!soa.failed && soa.answers.length === 0) {
    findings.push({
      id: "dns-soa-not-found",
      severity: "warning",
      title: "No SOA record was returned",
      detail: "The SOA lookup completed without the zone authority metadata expected for a delegated DNS zone.",
      action: "Confirm the zone exists and is authoritative at the delegated DNS provider.",
      remediation: {
        summary: "Restore the zone's Start of Authority through the authoritative DNS provider.",
        steps: [
          "Confirm the domain is delegated to the intended provider and the DNS zone is active there.",
          "Check that the provider publishes a valid SOA with a current serial and responsible mailbox.",
          "Correct delegation or zone provisioning, then compare SOA answers across every authoritative server.",
        ],
        caution: "Most managed DNS services create SOA automatically; do not hand-edit it unless the platform explicitly requires that workflow.",
      },
    });
  }

  if (hasConflictingAlias) {
    findings.push({
      id: "dns-cname-data-conflict",
      severity: "critical",
      title: "CNAME conflicts with other records at the same name",
      detail: "A CNAME answer was returned while TXT or MX data also exists at the scanned name. Standard DNS does not allow a CNAME to coexist with other record data at one owner name.",
      action: "Remove the alias or replace it with a provider-supported apex ALIAS/ANAME/flattening record.",
      remediation: {
        summary: "Choose one owner-name model: an alias, or independent records—not both.",
        steps: [
          "Identify which service added the CNAME and which existing TXT/MX records must remain.",
          "For an apex domain, use the DNS provider's supported ALIAS, ANAME, or CNAME-flattening feature instead of a literal CNAME.",
          "Remove the conflicting value, wait for its TTL, and verify CNAME, MX, and TXT again.",
        ],
        caution: "Removing MX or verification TXT records can interrupt mail or vendor ownership checks. Preserve required data during the change.",
      },
    });
  }

  const hasCritical = findings.some((finding) => finding.severity === "critical");
  const hasWarning = findings.some((finding) => finding.severity === "warning");
  const status: CheckResult["status"] = hasCritical
    ? "fail"
    : hasWarning
      ? "warning"
      : unavailable > 0
        ? "unknown"
        : "pass";

  return {
    findings,
    check: {
      status,
      title: "DNS record health",
      summary: unavailable > 0
        ? `${unavailable} core DNS ${unavailable === 1 ? "lookup was" : "lookups were"} unavailable; completed answers are still shown.`
        : `Resolved ${a.answers.length} A, ${aaaa.answers.length} AAAA, ${mx.answers.length} MX, ${ns.answers.length} NS, ${rootTxt.answers.length} TXT, ${soa.answers.length} SOA, and ${caa.answers.length} CAA records.`,
      details: [
        { label: "IPv4 (A)", value: dnsResultLabel(a) },
        { label: "IPv6 (AAAA)", value: dnsResultLabel(aaaa) },
        { label: "Canonical alias (CNAME)", value: dnsResultLabel(cname) },
        { label: "Mail exchange (MX)", value: dnsResultLabel(mx) },
        { label: "Nameservers (NS)", value: dnsResultLabel(ns) },
        { label: "Text (TXT)", value: dnsResultLabel(rootTxt) },
        { label: "Zone authority (SOA)", value: dnsResultLabel(soa) },
        { label: "Certificate authorities (CAA)", value: caa.failed ? "Unknown" : caa.answers.length > 0 ? `${caa.answers.length} record(s)` : "Not restricted (optional)" },
      ],
      records: toRecordViews([
        ...a.answers,
        ...aaaa.answers,
        ...cname.answers,
        ...ns.answers,
        ...rootTxt.answers,
        ...soa.answers,
        ...caa.answers,
      ]),
    },
  };
}

function dnsResultLabel(result: OptionalDnsResult): string {
  if (result.failed) return "Unknown";
  return result.answers.length > 0 ? `${result.answers.length} record(s)` : "Not found";
}

function setDmarcTag(record: string, tag: string, value: string): string {
  const normalizedTag = tag.toLowerCase();
  const segments = record
    .split(";")
    .map((segment) => segment.trim())
    .filter(Boolean)
    .filter((segment) => segment.slice(0, segment.indexOf("=")).trim().toLowerCase() !== normalizedTag);
  const nextTag = `${normalizedTag}=${value}`;
  if (normalizedTag === "p" && /^v\s*=\s*DMARC1$/iu.test(segments[0] ?? "")) {
    segments.splice(1, 0, nextTag);
  } else {
    segments.push(nextTag);
  }
  return segments.join("; ");
}

function removeDmarcTag(record: string, tag: string): string {
  const normalizedTag = tag.toLowerCase();
  return record
    .split(";")
    .map((segment) => segment.trim())
    .filter(Boolean)
    .filter((segment) => segment.slice(0, segment.indexOf("=")).trim().toLowerCase() !== normalizedTag)
    .join("; ");
}

function analyzeDmarc(domain: string, answers: DnsAnswer[]): DmarcAnalysis {
  const records = findDmarcRecords(answers.map((answer) => answer.data));
  const recordViews = toRecordViews(answers.filter((answer) => records.includes(answer.data)));

  if (records.length === 0) {
    return {
      testing: false,
      posture: "missing",
      points: 0,
      check: {
        status: "fail",
        title: "DMARC",
        summary: "No direct DMARC TXT record was returned for this exact hostname.",
        details: [
          { label: "Lookup", value: answers[0]?.name ?? "_dmarc domain" },
          { label: "Important", value: "A parent organizational-domain policy can apply to some subdomains." },
        ],
        records: [],
      },
      findings: [
        {
          id: "dmarc-not-found",
          severity: "warning",
          title: "No direct DMARC record found",
          detail: "The exact _dmarc hostname returned no v=DMARC1 record. For a subdomain, a parent organizational-domain policy may still apply; this scanner does not use a full public-suffix calculation.",
          action: "Confirm whether this is an apex domain, then publish or review DMARC at the applicable organizational domain.",
          remediation: {
            summary: "Start with monitoring at the applicable organizational domain.",
            steps: [
              "Confirm this is the organizational domain and inventory every service that sends mail using it.",
              `Create or choose an aggregate-report destination such as dmarc-reports@${domain}.`,
              "Publish one TXT record at the host shown below, then verify reports before increasing enforcement.",
            ],
            record: {
              name: `_dmarc.${domain}`,
              type: "TXT",
              value: `v=DMARC1; p=none; rua=mailto:dmarc-reports@${domain}`,
            },
            caution: "Do not use a reporting address until the mailbox or reporting service exists. Subdomains may inherit policy from a parent domain.",
          },
        },
      ],
    };
  }

  if (records.length > 1) {
    return {
      testing: false,
      posture: "invalid",
      points: 0,
      check: {
        status: "fail",
        title: "DMARC",
        summary: "Multiple DMARC policy records were returned; receivers may treat DMARC as invalid.",
        details: [{ label: "Policy records", value: String(records.length) }],
        records: recordViews,
      },
      findings: [
        {
          id: "multiple-dmarc-records",
          severity: "critical",
          title: "Multiple DMARC records published",
          detail: "DMARC expects one policy record at the applicable _dmarc hostname. Multiple records can cause receivers to ignore the policy.",
          action: "Consolidate the policy and reporting destinations into one DMARC TXT record.",
          remediation: {
            summary: "Replace the competing TXT records with one reviewed DMARC policy.",
            steps: [
              `Export every TXT value currently published at _dmarc.${domain}.`,
              "Choose one policy and combine only the reporting destinations you still control.",
              "Delete the old DMARC values, publish the single replacement, and rescan after the TTL expires.",
            ],
            caution: "Do not concatenate complete DMARC records; the result would still contain duplicate v and p tags.",
          },
        },
      ],
    };
  }

  const parsed = parseDmarcRecord(records[0] ?? "");
  if (!parsed.valid || !parsed.policy) {
    return {
      testing: false,
      posture: "invalid",
      points: 0,
      check: {
        status: "fail",
        title: "DMARC",
        summary: "A DMARC-like record was found but did not pass syntax checks.",
        details: parsed.errors.map((error, index) => ({ label: `Issue ${index + 1}`, value: error })),
        records: recordViews,
      },
      findings: [
        {
          id: "invalid-dmarc-record",
          severity: "critical",
          title: "DMARC record has syntax problems",
          detail: parsed.errors.join(" "),
          action: "Correct the record and confirm that only one v=DMARC1 TXT record is published.",
          remediation: {
            summary: "Repair the existing policy in place so receivers see one valid record.",
            steps: [
              "Keep v=DMARC1 as the first tag and publish exactly one p tag.",
              "Correct the syntax issues listed above without creating a second TXT policy.",
              "Rescan the domain and inspect aggregate reports before changing enforcement.",
            ],
            caution: "An automatic rewrite is unsafe when the intended reporting addresses and policy are unknown.",
          },
        },
      ],
    };
  }

  const policy = parsed.policy;
  const scope = analyzeDmarcScope(parsed);
  const effectivePolicy = scope.effectiveOrganizationalPolicy;
  const points = Math.min(
    dmarcPolicyPoints(scope.effectiveOrganizationalPolicy),
    dmarcPolicyPoints(scope.effectiveSubdomainPolicy),
    dmarcPolicyPoints(scope.effectiveNonexistentSubdomainPolicy),
  );
  const hasWeakerScopedPolicy = scope.weakerSubdomainPolicy || scope.weakerNonexistentSubdomainPolicy;
  const status = effectivePolicy === "none" || parsed.testing || hasWeakerScopedPolicy ? "warning" : "pass";
  const policyFindingSeverity = effectivePolicy === "none" || parsed.testing ? "warning" : "success";
  const findings: Finding[] = [
    {
      id: `dmarc-policy-${policy}`,
      severity: policyFindingSeverity,
      title: `DMARC policy is p=${policy}${parsed.testing ? "; t=y" : ""}`,
      detail:
        policy === "none"
          ? "The record requests aggregate monitoring but does not request quarantine or rejection of messages that fail DMARC."
          : parsed.testing
            ? `The record declares p=${policy}, while t=y requests testing behavior one policy level lower (${effectivePolicy}). Receiver behavior can still vary.`
            : `The record requests ${policy} treatment for DMARC-failing messages. Receiver behavior can still vary.`,
      ...(policy === "none"
        ? {
            action: "Use aggregate reports to inventory and remediate legitimate senders before moving gradually toward enforcement.",
            remediation: {
              summary: "Move from monitoring to enforcement only after legitimate mail is aligned.",
              steps: [
                "Collect aggregate reports long enough to cover normal and infrequent sending services.",
                "For each legitimate source, align either DKIM d= or the SPF-authenticated return-path with the visible From domain.",
                "Run controlled mail-flow tests, then change p to quarantine; monitor again before moving to reject.",
              ],
              caution: "A DNS scan cannot see every sender. Raising policy without report evidence can quarantine legitimate mail.",
            },
          }
        : parsed.testing
          ? {
              action: "Validate the expected lower enforcement level, then remove t=y when the declared policy is ready to apply normally.",
              remediation: {
                summary: "Finish the test-mode validation before applying the declared policy normally.",
                steps: [
                  "Confirm aggregate reports show all legitimate senders aligned at the declared policy scope.",
                  "Test business-critical and low-frequency mail flows, including forwarding and third-party services.",
                  "Remove t=y from the existing DMARC record and monitor receiver behavior after propagation.",
                ],
                caution: "Receiver support for t=y can vary; use observed mail and aggregate evidence rather than assuming uniform behavior.",
              },
            }
        : {}),
    },
    ...weakerScopedPolicyFindings(scope, parsed.testing),
  ];

  if (!parsed.tags.rua) {
    findings.push({
      id: "dmarc-no-rua",
      severity: "warning",
      title: "Aggregate reporting is not configured",
      detail: "No rua destination is present, limiting visibility into observed authentication and alignment results.",
      action: "Add an authorized aggregate-report mailbox or DMARC analysis service.",
      remediation: {
        summary: "Add aggregate reporting to the existing valid policy.",
        steps: [
          `Create dmarc-reports@${domain} or select a reporting provider and complete any external-destination authorization it requires.`,
          "Add one rua tag to the existing DMARC TXT record.",
          "Verify XML reports are arriving before relying on the data for enforcement changes.",
        ],
        record: {
          name: `_dmarc.${domain}`,
          type: "TXT",
          value: setDmarcTag(records[0] ?? "v=DMARC1; p=none", "rua", `mailto:dmarc-reports@${domain}`),
        },
        caution: "Use the reporting address or service you actually operate; the example mailbox is not created automatically.",
      },
    });
  }
  if (parsed.tags.pct !== undefined) {
    findings.push({
      id: "dmarc-legacy-pct",
      severity: "warning",
      title: `Historic pct=${parsed.tags.pct} tag is published`,
      detail: "RFC 9989 removed pct because percentage sampling was not applied consistently. Current DMARC processing ignores this tag.",
      action: "Use RFC 9989 t=y when test-mode signaling is appropriate, and use aggregate evidence plus controlled rollout procedures before changing policy.",
      remediation: {
        summary: "Remove the obsolete pct tag without changing the active policy.",
        steps: [
          "Edit the existing TXT value rather than publishing a second record.",
          "Remove only the pct tag and leave the reviewed policy and report destinations intact.",
          "Rescan after DNS propagation and confirm that receivers still send aggregate reports.",
        ],
        record: {
          name: `_dmarc.${domain}`,
          type: "TXT",
          value: removeDmarcTag(records[0] ?? "", "pct"),
        },
      },
    });
  }

  if (!parsed.tags.p) {
    findings.push({
      id: "dmarc-default-policy",
      severity: "warning",
      title: "No explicit p tag is published",
      detail: "RFC 9989 can use p=none as a default for an otherwise applicable record. Explicit policy is clearer, and records without a valid p or rua may result in no DMARC processing during discovery.",
      action: "Publish an explicit reviewed p value appropriate for the domain's current configuration stage.",
      remediation: {
        summary: "Make the current monitoring policy explicit.",
        steps: [
          "Confirm p=none matches the intended rollout stage.",
          "Add p=none immediately after v=DMARC1 in the existing record.",
          "Use aggregate evidence to plan a later move to quarantine and reject.",
        ],
        record: {
          name: `_dmarc.${domain}`,
          type: "TXT",
          value: setDmarcTag(records[0] ?? "v=DMARC1", "p", "none"),
        },
      },
    });
  }

  return {
    policy,
    scope,
    testing: parsed.testing,
    posture: effectivePolicy === "none" ? "monitoring" : effectivePolicy,
    points,
    check: {
      status,
      title: "DMARC",
      summary: dmarcCheckSummary(scope, parsed.testing),
      details: [
        {
          label: "Organizational-domain policy (p)",
          value: formatScopedPolicy(
            scope.organizationalPolicy,
            scope.effectiveOrganizationalPolicy,
            parsed.tags.p ? "explicit p tag" : "RFC 9989 p=none default",
            parsed.testing,
          ),
        },
        {
          label: "Existing-subdomain policy (sp)",
          value: formatScopedPolicy(
            scope.subdomainPolicy,
            scope.effectiveSubdomainPolicy,
            scope.subdomainSource === "sp" ? "explicit sp tag" : `inherits p=${scope.organizationalPolicy}`,
            parsed.testing,
          ),
        },
        {
          label: "Nonexistent-subdomain policy (np)",
          value: formatScopedPolicy(
            scope.nonexistentSubdomainPolicy,
            scope.effectiveNonexistentSubdomainPolicy,
            scope.nonexistentSubdomainSource === "np"
              ? "explicit np tag"
              : scope.nonexistentSubdomainSource === "sp"
                ? `inherits sp=${scope.subdomainPolicy}`
                : `inherits p=${scope.organizationalPolicy}`,
            parsed.testing,
          ),
        },
        { label: "Test mode", value: parsed.testing ? `Yes; expected one-level reduction to ${effectivePolicy}` : "No" },
        ...(parsed.tags.pct ? [{ label: "Historic pct tag", value: `${parsed.tags.pct} (ignored by RFC 9989)` }] : []),
        { label: "Aggregate reports", value: parsed.tags.rua ?? "Not configured" },
        { label: "DKIM alignment", value: parsed.tags.adkim?.toLowerCase() === "s" ? "Strict" : "Relaxed (default)" },
        { label: "SPF alignment", value: parsed.tags.aspf?.toLowerCase() === "s" ? "Strict" : "Relaxed (default)" },
      ],
      records: recordViews,
    },
    findings,
  };
}

function analyzeSpf(rootTxt: OptionalDnsResult, estimate: SpfLookupEstimate | undefined): SpfAnalysis {
  if (rootTxt.failed) {
    return {
      points: 0,
      check: {
        status: "unknown",
        title: "SPF",
        summary: "The SPF DNS query was unavailable; absence was not inferred.",
        details: [],
        records: [],
      },
      findings: [],
    };
  }

  const spfRecords = findSpfRecords(rootTxt.answers.map((answer) => answer.data));
  const recordViews = toRecordViews(rootTxt.answers.filter((answer) => spfRecords.includes(answer.data)));
  if (spfRecords.length === 0) {
    return {
      points: 0,
      check: {
        status: "warning",
        title: "SPF",
        summary: "No v=spf1 TXT record was found at the scanned hostname.",
        details: [],
        records: [],
      },
      findings: [
        {
          id: "spf-not-found",
          severity: "warning",
          title: "No SPF record found",
          detail: "The scanned hostname does not directly publish a v=spf1 TXT record. Whether SPF is needed depends on how the domain is used in envelope-from identities.",
          action: "Inventory outbound services before publishing SPF; do not guess include mechanisms.",
          remediation: {
            summary: "Publish one SPF policy only after identifying every envelope-from sender.",
            steps: [
              "List the mailbox provider, marketing platforms, ticketing systems, and other services that send with this domain in the return-path.",
              "Use each provider's documented include mechanism or approved IP ranges and combine them into one TXT record at the root.",
              "End with ~all during validation, then consider -all after mail-flow evidence confirms the inventory.",
            ],
            caution: "Do not publish a generic fallback policy. An active sending domain needs a policy built from its verified sender inventory; a non-sending domain requires an explicit business decision.",
          },
        },
      ],
    };
  }

  if (spfRecords.length > 1) {
    return {
      points: 0,
      check: {
        status: "fail",
        title: "SPF",
        summary: "Multiple SPF records were found, which produces an SPF permanent error.",
        details: [{ label: "SPF records", value: String(spfRecords.length) }],
        records: recordViews,
      },
      findings: [
        {
          id: "multiple-spf-records",
          severity: "critical",
          title: "Multiple SPF records published",
          detail: "A hostname must not publish more than one SPF policy record.",
          action: "Merge authorized mechanisms into one reviewed SPF record.",
          remediation: {
            summary: "Consolidate all authorized senders into one SPF TXT value.",
            steps: [
              "Inventory the mechanisms from every current SPF record and remove services that are no longer used.",
              "Build one v=spf1 record with each required mechanism once and a single terminal all mechanism.",
              "Replace the old SPF TXT values with the one reviewed record and verify the recursive lookup count is 10 or fewer.",
            ],
            caution: "Do not simply concatenate whole records; duplicate v=spf1 and all terms create invalid or unreachable policy.",
          },
        },
      ],
    };
  }

  const parsed = parseSpfRecord(spfRecords[0] ?? "");
  if (!parsed.valid) {
    return {
      points: 0,
      check: {
        status: "fail",
        title: "SPF",
        summary: "The SPF record did not pass syntax checks.",
        details: parsed.errors.map((error, index) => ({ label: `Issue ${index + 1}`, value: error })),
        records: recordViews,
      },
      findings: [
        {
          id: "invalid-spf-record",
          severity: "critical",
          title: "SPF record has syntax problems",
          detail: parsed.errors.join(" "),
          action: "Correct and test the SPF record before relying on it for DMARC alignment.",
          remediation: {
            summary: "Repair the existing SPF TXT record without adding a second policy.",
            steps: [
              "Correct each syntax issue listed above in the existing root TXT value.",
              "Keep one v=spf1 prefix, validate every IP/CIDR and include target, and leave one terminal all mechanism.",
              "Rescan and send controlled test messages through every legitimate provider.",
            ],
            caution: "The scanner cannot safely invent a replacement because it does not know the domain's full sender inventory.",
          },
        },
      ],
    };
  }

  const lookupLabel = estimate
    ? `${estimate.truncated ? "At least " : ""}${estimate.count}${estimate.exceedsLimit ? " (over the RFC limit of 10)" : ""}`
    : "Not calculated";
  const dangerousAll = parsed.terminalAll === "+";
  const lookupWarning = Boolean(estimate?.exceedsLimit || estimate?.truncated || estimate?.issues.length);
  const status = dangerousAll ? "fail" : lookupWarning ? "warning" : "pass";
  const points = dangerousAll ? 3 : estimate?.exceedsLimit ? 9 : parsed.terminalAll === "-" ? 20 : parsed.terminalAll === "~" ? 18 : 13;
  const findings: Finding[] = [];

  if (dangerousAll) {
    findings.push({
      id: "spf-plus-all",
      severity: "critical",
      title: "SPF authorizes every sender",
      detail: "+all matches every source as an SPF pass and removes useful sender restriction.",
      action: "Replace +all only after identifying the systems that legitimately use this envelope-from domain.",
      remediation: {
        summary: "Replace universal authorization with an inventoried sender policy.",
        steps: [
          "Inventory every legitimate envelope-from sender and add only its approved include or IP mechanism.",
          "Use ~all while validating the inventory, then move to -all when legitimate mail is consistently passing.",
          "Confirm the complete policy stays within the ten-lookup SPF limit.",
        ],
        caution: "Changing +all before sender discovery can block legitimate mail; leaving it in place allows any source to pass SPF.",
      },
    });
  } else {
    findings.push({
      id: "spf-valid",
      severity: status === "pass" ? "success" : "info",
      title: "One syntactically valid SPF record found",
      detail: `The record ends with ${parsed.terminalAll ?? "no all mechanism"}. Static recursive analysis estimated ${lookupLabel.toLowerCase()} lookup-causing terms.`,
    });
  }

  if (estimate?.exceedsLimit) {
    findings.push({
      id: "spf-lookup-limit",
      severity: "critical",
      title: "SPF lookup estimate exceeds 10",
      detail: `Static recursive expansion found ${estimate.count} lookup-causing terms. Runtime macro expansion and short-circuit evaluation can change the path, but exceeding 10 can produce permerror.`,
      action: "Review nested include and redirect chains; remove obsolete services instead of flattening blindly.",
      remediation: {
        summary: "Reduce the worst-case SPF evaluation path to ten DNS lookups or fewer.",
        steps: [
          "Remove unused provider includes and duplicate mechanisms first.",
          "Move senders that can use a dedicated return-path onto an authenticated subdomain with its own SPF policy.",
          "Ask active providers for a lower-lookup include; avoid static flattening unless changes are monitored continuously.",
        ],
        caution: "Provider IP ranges change. A one-time flattened record can silently become stale and break delivery.",
      },
    });
  }
  if (estimate?.truncated || estimate?.issues.length) {
    findings.push({
      id: "spf-estimate-caveat",
      severity: "info",
      title: "SPF estimate has unresolved branches",
      detail: [...(estimate.issues.slice(0, 3)), ...(estimate.truncated ? ["Expansion was truncated by a scanner safety limit."] : [])].join(" "),
      action: "Use a controlled mail-flow test and receiver results to confirm the actual evaluation path.",
    });
  }

  return {
    points,
    check: {
      status,
      title: "SPF",
      summary: dangerousAll
        ? "The SPF record is syntactically valid but ends in unsafe +all."
        : `One SPF record was found; recursive static analysis estimated ${lookupLabel.toLowerCase()} lookup-causing terms.`,
      details: [
        { label: "Terminal mechanism", value: parsed.terminalAll ? `${parsed.terminalAll}all` : "None" },
        { label: "Lookup estimate", value: lookupLabel },
        { label: "Expanded domains", value: estimate?.expandedDomains.join(", ") || "None" },
      ],
      records: recordViews,
    },
    findings,
  };
}

function analyzeDkim(discovery: DkimDiscoveryResult): { check: CheckResult; points: number; findings: Finding[] } {
  const { selectors, failedQueries } = discovery;
  const found = selectors.filter((selector) => selector.found);
  if (found.length === 0) {
    return {
      points: 0,
      check: {
        status: "unknown",
        title: "DKIM discovery",
        summary:
          failedQueries > 0
            ? "Some common-selector queries were unavailable and no key was discovered in the completed checks. DKIM status remains unknown."
            : "No key was found at the limited set of common selectors. DKIM selectors are not enumerable, so this does not establish that DKIM is absent.",
        details: [
          { label: "Selectors tested", value: String(selectors.length) },
          { label: "Unavailable DNS queries", value: String(failedQueries) },
        ],
        records: [],
      },
      findings: [
        {
          id: "dkim-not-observed",
          severity: "info",
          title: "No common DKIM selector discovered",
          detail: `The scanner tested a short list of common selectors only${failedQueries > 0 ? `, with ${failedQueries} DNS queries unavailable` : ""}. A domain may use any selector, and a published key does not prove that current messages are correctly signed or aligned.`,
          action: "Inspect DKIM-Signature headers and DMARC aggregate data to identify selectors actually in use.",
          remediation: {
            summary: "Find the real selector before adding or changing DKIM DNS.",
            steps: [
              "Send a test through each legitimate platform and inspect the DKIM-Signature header for s= (selector) and d= (signing domain).",
              "Query selector._domainkey.signing-domain and compare the result with the platform's current setup instructions.",
              "Enable signing or repair the provider-supplied TXT/CNAME, then verify that d= aligns with the visible From domain.",
            ],
            caution: "Selectors are not enumerable. Do not assume DKIM is missing merely because common names were not found.",
          },
        },
      ],
    };
  }

  return {
    points: 12,
    check: {
      status: "pass",
      title: "DKIM discovery",
      summary: `${found.length} common ${found.length === 1 ? "selector was" : "selectors were"} discovered; message signing and alignment remain unverified.`,
      details: [
        { label: "Discovered", value: found.map((selector) => selector.selector).join(", ") },
        { label: "Scope", value: "Common-selector DNS discovery only" },
        ...(failedQueries > 0 ? [{ label: "Unavailable DNS queries", value: String(failedQueries) }] : []),
      ],
      records: found.flatMap((selector) =>
        selector.value
          ? [{ name: `${selector.selector}._domainkey`, type: selector.kind ?? "TXT", value: selector.value }]
          : [],
      ),
    },
    findings: [
      {
        id: "dkim-selector-found",
        severity: "success",
        title: "Common DKIM selector discovered",
        detail: `${found.map((selector) => selector.selector).join(", ")} returned DKIM-like DNS data. This does not verify live signing, cryptographic validity, or From-domain alignment.`,
      },
    ],
  };
}

function analyzeTransport(
  domain: string,
  mx: OptionalDnsResult,
  mtaSts: OptionalDnsResult,
  tlsRpt: OptionalDnsResult,
): { check: CheckResult; points: number; findings: Finding[] } {
  const hasMx = mx.answers.length > 0;
  const hasNullMx = mx.answers.some((answer) => /^\s*0\s+\.\s*$/u.test(answer.data));
  const receivesMail = hasMx && !hasNullMx;
  const hasMtaSts = hasVersionRecord(mtaSts.answers, "STSv1");
  const hasTlsRpt = hasVersionRecord(tlsRpt.answers, "TLSRPTv1");
  const points = (hasMtaSts ? 8 : 0) + (hasTlsRpt ? 5 : 0);
  const findings: Finding[] = [];

  if (!mx.failed && !hasMx) {
    findings.push({
      id: "mx-not-found",
      severity: "info",
      title: "No MX record found",
      detail: "The domain may not receive email. This is informational and is not treated as an authentication failure.",
      action: "Confirm whether the domain should receive mail and publish either provider MX records or an explicit null MX.",
      remediation: {
        summary: "Make the domain's inbound-mail intent explicit.",
        steps: [
          "If the domain receives mail, copy the exact MX priorities and hostnames supplied by the mailbox provider.",
          "If it must never receive mail, publish the null MX value shown below.",
          "Remove obsolete MX values and rescan after the DNS TTL expires.",
        ],
        record: {
          name: domain,
          type: "MX",
          value: "0 .",
        },
        caution: "A null MX deliberately prevents inbound delivery. Do not publish it on a domain that should receive email.",
      },
    });
  }
  if (hasMtaSts) {
    findings.push({
      id: "mta-sts-dns-found",
      severity: "success",
      title: "MTA-STS DNS marker found",
      detail: "A v=STSv1 TXT record is present. This DNS-only scan does not fetch or validate the HTTPS policy file.",
    });
  }
  if (hasTlsRpt) {
    findings.push({
      id: "tls-rpt-found",
      severity: "success",
      title: "TLS reporting record found",
      detail: "A v=TLSRPTv1 TXT record is present. Destination authorization and report delivery were not tested.",
    });
  }

  if (receivesMail && !mtaSts.failed && !hasMtaSts) {
    findings.push({
      id: "mta-sts-not-found",
      severity: "info",
      title: "MTA-STS is not published",
      detail: "The domain accepts mail but no v=STSv1 DNS marker was found. MTA-STS is optional hardening against transport downgrade and MX impersonation.",
      action: "Host and test an MTA-STS HTTPS policy before publishing its DNS marker.",
      remediation: {
        summary: "Deploy the HTTPS policy first, then publish a versioned DNS marker.",
        steps: [
          `Serve a valid policy at https://mta-sts.${domain}/.well-known/mta-sts.txt using mode: testing and the real MX patterns.`,
          "Confirm the certificate, content type, policy syntax, and every MX pattern.",
          "Publish the TXT marker below, monitor TLS reports, then move the HTTPS policy to mode: enforce when ready.",
        ],
        record: {
          name: `_mta-sts.${domain}`,
          type: "TXT",
          value: `v=STSv1; id=${new Date().toISOString().slice(0, 10).replaceAll("-", "")}`,
        },
        caution: "The DNS marker alone does not enable MTA-STS. A valid HTTPS policy and accurate MX patterns are required.",
      },
    });
  }

  if (receivesMail && !tlsRpt.failed && !hasTlsRpt) {
    findings.push({
      id: "tls-rpt-not-found",
      severity: "info",
      title: "SMTP TLS reporting is not published",
      detail: "No v=TLSRPTv1 record was found. TLS-RPT is optional, but it provides visibility into transport failures and downgrade attempts.",
      action: "Create a report destination, then publish one TLS-RPT TXT record.",
      remediation: {
        summary: "Create a TLS report mailbox or service and publish its destination.",
        steps: [
          `Create tls-reports@${domain} or choose a TLS reporting service.`,
          "Publish the TXT value below at the exact _smtp._tls host.",
          "Verify JSON reports arrive and investigate sustained policy or certificate failures.",
        ],
        record: {
          name: `_smtp._tls.${domain}`,
          type: "TXT",
          value: `v=TLSRPTv1; rua=mailto:tls-reports@${domain}`,
        },
        caution: "The destination must exist and accept reports; external services can require additional authorization.",
      },
    });
  }

  const unavailable = mx.failed || mtaSts.failed || tlsRpt.failed;
  return {
    points,
    check: {
      status: unavailable ? "unknown" : hasMtaSts && hasTlsRpt ? "pass" : "info",
      title: "Mail transport",
      summary: unavailable
        ? "One or more transport DNS queries were unavailable."
        : `MX ${hasNullMx ? "explicitly disabled (null MX)" : hasMx ? "found" : "not found"}; MTA-STS marker ${hasMtaSts ? "found" : "not found"}; TLS-RPT ${hasTlsRpt ? "found" : "not found"}.`,
      details: [
        { label: "MX", value: hasNullMx ? "Null MX (inbound mail disabled)" : hasMx ? `${mx.answers.length} record(s)` : mx.failed ? "Unknown" : "Not found" },
        { label: "MTA-STS", value: hasMtaSts ? "DNS marker found; HTTPS policy not tested" : mtaSts.failed ? "Unknown" : "Not found" },
        { label: "TLS-RPT", value: hasTlsRpt ? "Record found" : tlsRpt.failed ? "Unknown" : "Not found" },
      ],
      records: toRecordViews([...mx.answers, ...mtaSts.answers, ...tlsRpt.answers]),
    },
    findings,
  };
}

async function discoverDkim(domain: string, dns: DnsResolver): Promise<DkimDiscoveryResult> {
  let failedQueries = 0;
  const selectors = await Promise.all(
    COMMON_DKIM_SELECTORS.map(async (selector): Promise<DkimSelectorResult> => {
      const name = `${selector}._domainkey.${domain}`;
      const [txtResult, cnameResult] = await Promise.all([
        optionalDns(dns.query(name, "TXT")),
        optionalDns(dns.query(name, "CNAME")),
      ]);
      const dkimTxt = txtResult.answers.find((answer) => looksLikeDkimKey(answer.data));
      const cname = cnameResult.answers[0];
      if (txtResult.failed) failedQueries += 1;
      if (cnameResult.failed) failedQueries += 1;
      if (dkimTxt) return { selector, found: true, kind: "TXT", value: dkimTxt.data };
      if (cname) return { selector, found: true, kind: "CNAME", value: cname.data };
      return { selector, found: false };
    }),
  );
  return { selectors, failedQueries };
}

function looksLikeDkimKey(value: string): boolean {
  const tags = new Map<string, string>();
  for (const segment of value.split(";")) {
    const separator = segment.indexOf("=");
    if (separator < 1) continue;
    tags.set(segment.slice(0, separator).trim().toLowerCase(), segment.slice(separator + 1).trim());
  }
  const version = tags.get("v");
  return tags.has("p") && (!version || version.toUpperCase() === "DKIM1");
}

function hasVersionRecord(result: DnsAnswer[], version: string): boolean {
  return result.some((answer) => new RegExp(`^\\s*v\\s*=\\s*${version}(?:\\s*;|\\s*$)`, "iu").test(answer.data));
}

function parseMxHostname(value: string): string | undefined {
  const match = /^\s*\d+\s+([^\s]+)\s*$/u.exec(value);
  if (!match?.[1] || match[1] === ".") return undefined;
  return match[1].replace(/\.$/u, "").toLowerCase();
}

async function optionalDns(promise: Promise<DnsAnswer[]>): Promise<OptionalDnsResult> {
  try {
    return { answers: await promise, failed: false };
  } catch {
    return { answers: [], failed: true };
  }
}

function analyzeDmarcScope(parsed: ParsedDmarcRecord): DmarcScopeAnalysis {
  const organizationalPolicy = parsed.policy ?? "none";
  const subdomainPolicy = parsed.subdomainPolicy ?? organizationalPolicy;
  const nonexistentSubdomainPolicy = parsed.nonexistentSubdomainPolicy ?? parsed.subdomainPolicy ?? organizationalPolicy;
  const effective = (policy: DmarcPolicy): DmarcPolicy => parsed.testing ? downgradePolicy(policy) : policy;
  const strongestBroaderPolicy = policyRank(subdomainPolicy) > policyRank(organizationalPolicy)
    ? subdomainPolicy
    : organizationalPolicy;

  return {
    organizationalPolicy,
    subdomainPolicy,
    nonexistentSubdomainPolicy,
    effectiveOrganizationalPolicy: effective(organizationalPolicy),
    effectiveSubdomainPolicy: effective(subdomainPolicy),
    effectiveNonexistentSubdomainPolicy: effective(nonexistentSubdomainPolicy),
    subdomainSource: parsed.subdomainPolicy ? "sp" : "p",
    nonexistentSubdomainSource: parsed.nonexistentSubdomainPolicy ? "np" : parsed.subdomainPolicy ? "sp" : "p",
    weakerSubdomainPolicy: Boolean(
      parsed.subdomainPolicy && policyRank(subdomainPolicy) < policyRank(organizationalPolicy),
    ),
    weakerNonexistentSubdomainPolicy: Boolean(
      parsed.nonexistentSubdomainPolicy && policyRank(nonexistentSubdomainPolicy) < policyRank(strongestBroaderPolicy),
    ),
  };
}

function weakerScopedPolicyFindings(scope: DmarcScopeAnalysis, testing: boolean): Finding[] {
  const findings: Finding[] = [];

  if (scope.weakerSubdomainPolicy) {
    const inheritedNonexistentPolicy = scope.nonexistentSubdomainSource === "sp"
      ? ` Because np is absent, nonexistent subdomains also inherit sp=${scope.subdomainPolicy}.`
      : " The np tag separately controls nonexistent subdomains.";
    findings.push({
      id: "dmarc-weaker-sp-policy",
      severity: "warning",
      title: "Existing subdomains have a weaker DMARC policy",
      detail: `The record declares p=${scope.organizationalPolicy}, but explicit sp=${scope.subdomainPolicy} requests weaker handling for existing subdomains.${inheritedNonexistentPolicy}${testing ? ` With t=y, their expected handling is ${scope.effectiveSubdomainPolicy}.` : ""}`,
      action: "Confirm that the weaker subdomain policy is intentional and review aggregate evidence before strengthening it.",
      remediation: {
        summary: "Remove or strengthen sp only after subdomain senders are verified.",
        steps: [
          "Use aggregate reports to identify every legitimate From-domain below the organizational domain.",
          "Fix SPF or DKIM alignment for those sources and confirm parked subdomains do not send mail.",
          `When ready, set sp=${scope.organizationalPolicy} or remove sp so it inherits p=${scope.organizationalPolicy}.`,
        ],
        caution: "An inherited stronger policy can affect every existing subdomain, including rarely used business systems.",
      },
    });
  }

  if (scope.weakerNonexistentSubdomainPolicy) {
    const broaderPolicies = [
      ...(policyRank(scope.nonexistentSubdomainPolicy) < policyRank(scope.organizationalPolicy)
        ? [`p=${scope.organizationalPolicy}`]
        : []),
      ...(policyRank(scope.nonexistentSubdomainPolicy) < policyRank(scope.subdomainPolicy)
        ? [`${scope.subdomainSource}=${scope.subdomainPolicy}`]
        : []),
    ];
    findings.push({
      id: "dmarc-weaker-np-policy",
      severity: "warning",
      title: "Nonexistent subdomains have a weaker DMARC policy",
      detail: `Explicit np=${scope.nonexistentSubdomainPolicy} requests weaker handling for nonexistent subdomains than ${broaderPolicies.join(" and ")}.${testing ? ` With t=y, their expected handling is ${scope.effectiveNonexistentSubdomainPolicy}.` : ""}`,
      action: "Confirm that the weaker nonexistent-subdomain policy is intentional; random subdomain spoofing can otherwise receive less restrictive treatment.",
      remediation: {
        summary: "Align the nonexistent-subdomain policy with the intended broader policy.",
        steps: [
          "Confirm no provisioning workflow depends on mail from names that do not yet exist in DNS.",
          "Review aggregate evidence for random-subdomain abuse and legitimate subdomain senders.",
          `When ready, set np=${scope.organizationalPolicy} or remove np to inherit the broader policy.`,
        ],
        caution: "The np tag is defined by current DMARC but receiver deployment may vary; keep the broader p/sp policy sound as well.",
      },
    });
  }

  return findings;
}

function dmarcCheckSummary(scope: DmarcScopeAnalysis, testing: boolean): string {
  const declaredScope = [
    `p=${scope.organizationalPolicy}`,
    scope.subdomainSource === "sp" ? `sp=${scope.subdomainPolicy}` : `sp inherits p=${scope.subdomainPolicy}`,
    scope.nonexistentSubdomainSource === "np"
      ? `np=${scope.nonexistentSubdomainPolicy}`
      : `np inherits ${scope.nonexistentSubdomainSource}=${scope.nonexistentSubdomainPolicy}`,
  ].join("; ");
  const expectedHandling = testing
    ? ` With t=y, expected handling is ${scope.effectiveOrganizationalPolicy} for the domain, ${scope.effectiveSubdomainPolicy} for existing subdomains, and ${scope.effectiveNonexistentSubdomainPolicy} for nonexistent subdomains.`
    : "";
  return `One syntactically valid DMARC record was found. Declared scope: ${declaredScope}.${expectedHandling}`;
}

function formatScopedPolicy(
  declaredPolicy: DmarcPolicy,
  effectivePolicy: DmarcPolicy,
  source: string,
  testing: boolean,
): string {
  const testMode = testing && declaredPolicy !== "none"
    ? `; t=y expects ${effectivePolicy} handling`
    : testing
      ? "; t=y does not reduce none handling"
      : "";
  return `${declaredPolicy} (${source})${testMode}`;
}

function dmarcPolicyPoints(policy: DmarcPolicy): number {
  if (policy === "reject") return 45;
  if (policy === "quarantine") return 40;
  return 16;
}

function policyRank(policy: DmarcPolicy): number {
  if (policy === "reject") return 2;
  if (policy === "quarantine") return 1;
  return 0;
}

function posturePresentation(
  posture: ScanResult["posture"],
  declaredPolicy: DmarcPolicy | undefined,
  testing: boolean,
  scope: DmarcScopeAnalysis | undefined,
): { label: string; headline: string; summary: string } {
  switch (posture) {
    case "reject":
      return qualifyPostureForScope({
        label: "Reject policy published",
        headline: "DMARC requests rejection of failing mail",
        summary: "The DNS policy is at reject, but only aggregate data and mail-flow validation can show whether legitimate senders are aligned.",
      }, scope);
    case "quarantine":
      return qualifyPostureForScope({
        label: testing && declaredPolicy === "reject" ? "Reject policy in test mode" : "Quarantine policy published",
        headline: testing && declaredPolicy === "reject" ? "p=reject with t=y signals quarantine-level testing" : "DMARC requests quarantine of failing mail",
        summary: "The DNS configuration indicates quarantine-level handling. This snapshot does not establish safe readiness for a stronger policy.",
      }, scope);
    case "monitoring":
      return qualifyPostureForScope({
        label: testing && declaredPolicy === "quarantine" ? "Quarantine policy in test mode" : "Monitoring policy",
        headline: testing && declaredPolicy === "quarantine" ? "p=quarantine with t=y signals monitoring-level testing" : "DMARC is published in monitoring mode",
        summary: "Monitoring-level DMARC can collect visibility through aggregate reports, but it does not request quarantine or rejection of failing messages.",
      }, scope);
    case "invalid":
      return {
        label: "Invalid policy",
        headline: "The published DMARC configuration needs attention",
        summary: "A DMARC-like record was found, but deterministic syntax checks found a conflict or error that may cause receivers to ignore it.",
      };
    case "missing":
      return {
        label: "No direct policy found",
        headline: "No DMARC record was found at this exact hostname",
        summary: "If this is a subdomain, an organizational-domain policy may still apply. Confirm inheritance before publishing a new record.",
      };
  }
}

function qualifyPostureForScope(
  presentation: { label: string; headline: string; summary: string },
  scope: DmarcScopeAnalysis | undefined,
): { label: string; headline: string; summary: string } {
  if (!scope) return presentation;

  const weakerScopes: Array<{ name: string; policy: DmarcPolicy }> = [];
  if (policyRank(scope.subdomainPolicy) < policyRank(scope.organizationalPolicy)) {
    weakerScopes.push({ name: "existing subdomains", policy: scope.subdomainPolicy });
  }
  if (policyRank(scope.nonexistentSubdomainPolicy) < policyRank(scope.organizationalPolicy)) {
    weakerScopes.push({ name: "nonexistent subdomains", policy: scope.nonexistentSubdomainPolicy });
  }
  if (weakerScopes.length === 0) return presentation;

  const scopeNames = weakerScopes.length === 2
    ? "existing and nonexistent subdomains"
    : weakerScopes[0]?.name ?? "scoped domains";
  const scopePolicies = weakerScopes
    .map((item) => `${item.name} declare ${item.policy}`)
    .join(", while ");
  return {
    label: `${presentation.label}; scoped exceptions`,
    headline: `${presentation.headline}; the record declares weaker policies for ${scopeNames}`,
    summary: `${presentation.summary} ${scopePolicies[0]?.toUpperCase() ?? ""}${scopePolicies.slice(1)}, below p=${scope.organizationalPolicy}.`,
  };
}

function downgradePolicy(policy: DmarcPolicy): DmarcPolicy {
  if (policy === "reject") return "quarantine";
  return "none";
}

function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function gradeForScore(score: number): ScanResult["grade"] {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

function sortFindings(findings: Finding[]): Finding[] {
  const rank: Record<FindingSeverity, number> = { critical: 0, warning: 1, success: 2, info: 3 };
  return findings.sort((left, right) => rank[left.severity] - rank[right.severity] || left.id.localeCompare(right.id));
}

function unique(values: string[]): string[] {
  return [...new Set(values)].sort();
}
