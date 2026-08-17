import { X509Certificate } from "node:crypto";
import {
  CONTRACT_VERSION,
  GRADE_METHODOLOGY,
  LIMITS,
  SECTION_NAMES,
  TESTSSL,
} from "./constants.mjs";

const TESTSSL_SEVERITY = Object.freeze({
  OK: { severity: "none", status: "pass" },
  INFO: { severity: "info", status: "info" },
  DEBUG: { severity: "info", status: "info" },
  LOW: { severity: "low", status: "warning" },
  WARN: { severity: "medium", status: "warning" },
  MEDIUM: { severity: "medium", status: "warning" },
  HIGH: { severity: "high", status: "fail" },
  CRITICAL: { severity: "critical", status: "fail" },
  FATAL: { severity: "critical", status: "fail" },
});

const SECTION_PHASES = Object.freeze({
  certificate: ["identity"],
  protocols: ["identity"],
  ciphers: ["cryptography"],
  keyExchange: ["cryptography"],
  features: ["identity", "cryptography"],
  clientSimulations: ["compatibility"],
  knownIssues: ["compatibility"],
});

const GRADE_WEIGHTS = Object.freeze({
  certificate: Object.freeze({
    cert_chain_of_trust: 5,
    cert_trust: 3,
    cert_expirationStatus: 3,
    cert_signatureAlgorithm: 2,
    cert_keySize: 2,
    cert_subjectAltName: 2,
    certs_list_ordering_problem: 1,
    OCSP_stapling: 1,
    cert_numbers: 1,
  }),
  protocols: Object.freeze({ SSLv2: 2, SSLv3: 3, TLS1: 3, TLS1_1: 3, TLS1_2: 5, TLS1_3: 4 }),
  ciphers: Object.freeze({
    cipherlist_NULL: 4,
    cipherlist_aNULL: 4,
    cipherlist_EXPORT: 4,
    cipherlist_LOW: 3,
    cipherlist_3DES_IDEA: 3,
    cipherlist_OBSOLETED: 2,
    cipherlist_STRONG_NOFS: 2,
    cipherlist_STRONG_FS: 3,
  }),
  keyExchange: Object.freeze({ FS: 6, FS_ECDHE_curves: 3, DH_groups: 3, FS_TLS12_sig_algs: 2, FS_TLS13_sig_algs: 1 }),
  features: Object.freeze({
    TLS_extensions: 2,
    TLS_session_ticket: 2,
    SSL_sessionID_support: 2,
    sessionresumption_ticket: 2,
    sessionresumption_ID: 2,
  }),
  clientSimulations: Object.freeze({}),
  knownIssues: Object.freeze({
    secure_renego: 2,
    secure_client_renego: 2,
    heartbleed: 2,
    CCS: 2,
    ticketbleed: 2,
    ROBOT: 2,
    CRIME_TLS: 2,
    POODLE_SSL: 2,
    fallback_SCSV: 2,
    SWEET32: 2,
    FREAK: 1,
    DROWN: 1,
    LOGJAM: 2,
    BEAST: 1,
    LUCKY13: 1,
    RC4: 2,
  }),
});

const PROTOCOL_INVENTORY = Object.freeze(["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"]);
const SAFE_ISSUE_INVENTORY = Object.freeze([
  ["secure_renego", "Secure renegotiation"],
  ["secure_client_renego", "Client-initiated renegotiation"],
  ["heartbleed", "Heartbleed"],
  ["CCS", "CCS injection"],
  ["ticketbleed", "Ticketbleed"],
  ["ROBOT", "ROBOT"],
  ["CRIME_TLS", "CRIME TLS compression"],
  ["POODLE_SSL", "POODLE"],
  ["fallback_SCSV", "TLS fallback SCSV"],
  ["SWEET32", "SWEET32"],
  ["FREAK", "FREAK"],
  ["DROWN", "DROWN on this endpoint"],
  ["LOGJAM", "LOGJAM"],
  ["BEAST", "BEAST"],
  ["LUCKY13", "LUCKY13 exposure"],
  ["RC4", "RC4"],
]);
const SAFETY_EXCLUSIONS = Object.freeze([
  ["breach", "BREACH HTTP response-compression probe", ["CVE-2013-3587"]],
  ["live-revocation", "Live OCSP/CRL responder query", []],
  ["cross-service-drown", "Cross-service DROWN certificate reuse search", ["CVE-2016-0800", "CVE-2016-0703"]],
]);

export function normalizeDeepTlsResult({ request, phaseResults, connectionBudget, startedAt, durationMs }) {
  const sections = createEmptySections();
  const usablePhases = [];
  for (const phase of phaseResults) {
    const scan = extractScan(phase.report, request);
    if (!scan) continue;
    usablePhases.push(phase.id);
    importScanRecord(sections, scan);
  }
  ensureInventories(sections, usablePhases);
  deduplicateAndBound(sections);

  for (const name of SECTION_NAMES) {
    sections[name].status = sectionStatus(name, phaseResults, usablePhases);
    sections[name].grade = gradeSection(name, sections[name].observations);
  }
  const grade = gradeAll(sections);
  const issues = buildIssues(sections);
  const processesCompleted = phaseResults.filter((phase) => phase.status === "complete").length;
  const outputBytes = phaseResults.reduce((sum, phase) => sum + finiteNonnegative(phase.outputBytes), 0);
  const status = processesCompleted === phaseResults.length
      && usablePhases.length === phaseResults.length
      && phaseResults.length > 0
    ? "complete"
    : usablePhases.length > 0 ? "partial" : "unavailable";

  const result = {
    schemaVersion: CONTRACT_VERSION,
    scanner: { ...TESTSSL },
    target: {
      hostname: request.hostname,
      address: request.address,
      addressFamily: request.addressFamily,
      port: 443,
      sni: request.hostname,
      profile: request.profile,
    },
    status,
    startedAt,
    durationMs: finiteNonnegative(durationMs),
    grade,
    budget: {
      deadlineMs: request.deadlineMs,
      maxProcesses: LIMITS.maximumProcesses,
      processesStarted: phaseResults.length,
      processesCompleted,
      maxConcurrentConnections: LIMITS.maximumConcurrentConnections,
      maxConnections: LIMITS.maximumConnections,
      connectionsOpened: finiteNonnegative(connectionBudget?.opened),
      maxPhaseOutputBytes: LIMITS.maximumPhaseOutputBytes,
      outputBytes,
      maxResponseBytes: LIMITS.maximumResponseBytes,
    },
    phases: phaseResults.map((phase) => ({
      id: phase.id,
      status: phase.report && !usablePhases.includes(phase.id) ? "failed" : phase.status,
      exitCode: Number.isInteger(phase.exitCode) ? phase.exitCode : null,
      durationMs: finiteNonnegative(phase.durationMs),
      outputBytes: finiteNonnegative(phase.outputBytes),
    })),
    sections,
    issues,
    limitations: [
      "This bounded Cresswell grade uses the cresswell-tls-v1 methodology; it is not an SSL Labs grade or a substitute for an exhaustive assessment.",
      "The safe profile is limited to the validated endpoint on TCP port 443 and never follows certificate, OCSP, CRL, AIA, or report links.",
      "BREACH, live revocation lookups, and cross-service certificate searches are explicitly not tested; active Heartbleed, CCS injection, Ticketbleed, and ROBOT probes remain bounded by the same deadline and connection budget.",
      "Results are point-in-time observations. Load balancers and address-specific configurations can differ between endpoints and over time.",
    ],
  };
  return enforceResponseLimit(result);
}

function createEmptySections() {
  return Object.fromEntries(SECTION_NAMES.map((name) => [name, {
    status: "unavailable",
    grade: emptyGrade(),
    observations: [],
  }]));
}

function extractScan(report, request) {
  const scan = report?.scanResult?.[0];
  if (!scan || typeof scan !== "object") return undefined;
  const targetHost = String(scan.targetHost ?? "").toLowerCase();
  const address = String(scan.ip ?? "").replace(/^\[|\]$/gu, "").toLowerCase();
  if (targetHost !== request.hostname || address !== request.address.toLowerCase() || String(scan.port) !== "443") {
    return undefined;
  }
  return scan;
}

function importScanRecord(sections, scan) {
  importRecords(sections.protocols, scan.protocols, "protocols");
  importRecords(sections.ciphers, scan.ciphers, "ciphers");
  importRecords(sections.ciphers, scan.serverPreferences, "ciphers");
  importRecords(sections.ciphers, scan.cipherTests, "ciphers");
  importRecords(sections.keyExchange, scan.fs, "keyExchange");
  importRecords(sections.features, scan.pretest, "features");
  importRecords(sections.features, scan.grease, "features");
  importRecords(sections.clientSimulations, scan.browserSimulations, "clientSimulations");
  importRecords(sections.knownIssues, scan.vulnerabilities, "knownIssues");
  for (const record of boundedRecords(scan.serverDefaults)) {
    const sectionName = isCertificateRecord(record?.id) ? "certificate" : "features";
    const observation = normalizeRecord(record, sectionName);
    if (observation) sections[sectionName].observations.push(observation);
  }
}

function importRecords(section, records, sectionName) {
  for (const record of boundedRecords(records)) {
    const observation = normalizeRecord(record, sectionName);
    if (observation) section.observations.push(observation);
  }
}

function boundedRecords(records) {
  return Array.isArray(records) ? records.slice(0, LIMITS.maximumObservationsPerSection * 2) : [];
}

function normalizeRecord(record, sectionName) {
  if (!record || typeof record !== "object") return undefined;
  const sourceId = sanitizeId(record.id);
  if (!sourceId) return undefined;
  const finding = sanitizeText(record.finding) || "No bounded finding was returned.";
  const mapped = TESTSSL_SEVERITY[String(record.severity ?? "INFO").toUpperCase()] ?? TESTSSL_SEVERITY.INFO;
  const status = semanticStatus(sectionName, sourceId, finding, mapped.status);
  const severity = status === "pass" ? "none" : mapped.severity;
  const details = recordDetails(sectionName, sourceId, finding, record);
  return {
    id: `${sectionName}:testssl:${sourceId}`,
    sourceId,
    status,
    evidenceKind: "tested",
    severity,
    summary: sourceId === "cert"
      ? "Leaf certificate material was captured for analysis and omitted from the API response."
      : finding,
    ...(Object.keys(details).length > 0 ? { details } : {}),
  };
}

function semanticStatus(section, sourceId, finding, fallback) {
  const lower = finding.toLowerCase();
  if (section === "protocols") {
    const offered = /\boffered\b/u.test(lower) && !/not offered/u.test(lower);
    if (["SSLv2", "SSLv3"].includes(sourceId)) return offered ? "fail" : "pass";
    if (["TLS1", "TLS1_1"].includes(sourceId)) return offered ? "warning" : "pass";
    if (["TLS1_2", "TLS1_3"].includes(sourceId)) return offered ? "pass" : "warning";
  }
  if (section === "ciphers" && sourceId.startsWith("cipherlist_")) {
    const offered = /\boffered\b/u.test(lower) && !/not offered/u.test(lower);
    if (["cipherlist_NULL", "cipherlist_aNULL", "cipherlist_EXPORT", "cipherlist_LOW"].includes(sourceId)) {
      return offered ? "fail" : "pass";
    }
    if (["cipherlist_3DES_IDEA", "cipherlist_OBSOLETED"].includes(sourceId)) return offered ? "warning" : "pass";
    if (["cipherlist_STRONG_NOFS", "cipherlist_STRONG_FS"].includes(sourceId)) return offered ? "pass" : "warning";
  }
  if (section === "knownIssues" && /\bnot vulnerable\b/u.test(lower)) return "pass";
  if (section === "knownIssues"
    && ["heartbleed", "CCS", "ticketbleed", "ROBOT"].includes(sourceId)
    && /\bvulnerable\b/u.test(lower)) return "fail";
  if (section === "knownIssues" && sourceId === "secure_renego" && /\bsupported\b/u.test(lower)) return "pass";
  if (section === "knownIssues" && sourceId === "fallback_SCSV" && /no protocol below/u.test(lower)) return "pass";
  return fallback;
}

function recordDetails(section, sourceId, finding, record) {
  const details = {};
  const cves = tokens(record.cve, /^CVE-\d{4}-\d+$/u);
  const cwes = tokens(record.cwe, /^CWE-\d+$/u);
  if (cves.length) details.cve = cves;
  if (cwes.length) details.cwe = cwes;

  if (section === "ciphers" && /^cipher-(?:tls1_2|tls1_3)_/u.test(sourceId)) {
    Object.assign(details, parseCipherFinding(finding));
  } else if (sourceId.startsWith("supportedciphers_")) {
    details.ciphers = tokens(finding).slice(0, 96);
  } else if (["FS_ECDHE_curves", "DH_groups", "FS_KEMs"].includes(sourceId)) {
    details.groups = tokens(finding).slice(0, 64);
  } else if (sourceId.includes("sig_algs")) {
    details.algorithms = tokens(finding).slice(0, 64);
  } else if (section === "clientSimulations") {
    const [protocol, cipher] = finding.split(/\s+/u);
    details.profile = sourceId.replace(/^clientsimulation-/u, "");
    details.connected = !/no connection/iu.test(finding);
    if (details.connected && protocol) details.protocol = sanitizeText(protocol);
    if (details.connected && cipher) details.cipher = sanitizeText(cipher);
  } else if (sourceId === "cert") {
    details.materialOmitted = true;
    try {
      const certificate = new X509Certificate(String(record.finding));
      details.subject = sanitizeText(certificate.subject);
      details.issuer = sanitizeText(certificate.issuer);
      details.selfSigned = certificate.checkIssued(certificate);
    } catch {
      // Other certificate observations retain the structured metadata.
    }
  } else if (sourceId === "cert_commonName" || sourceId === "cert_commonName_wo_SNI") {
    details.commonName = finding;
  } else if (sourceId === "cert_subjectAltName") {
    details.names = finding === "--" ? [] : finding.split(/[ ,]+/u).filter(Boolean).slice(0, 128);
  } else if (/fingerprint/iu.test(sourceId)) {
    details.fingerprint = finding.replace(/[^0-9A-F:]/giu, "").toUpperCase();
  } else if (sourceId === "cert_keySize") {
    const match = /\b([A-Za-z0-9-]+)\s+(\d{2,5})\s+bits\b/u.exec(finding);
    if (match) {
      details.keyType = match[1];
      details.bits = Number(match[2]);
    }
  } else if (sourceId === "cert_signatureAlgorithm") {
    details.algorithm = finding;
  } else if (["cert_numbers", "certs_countServer"].includes(sourceId)) {
    const count = Number.parseInt(finding, 10);
    if (Number.isFinite(count)) details.count = count;
  } else if (["cert_notBefore", "cert_notAfter"].includes(sourceId)) {
    details.date = finding;
  } else if (sourceId === "TLS_extensions") {
    details.extensions = [...finding.matchAll(/'([^']+)'/gu)].map((match) => match[1]).slice(0, 64);
  } else if (/session|ALPN|NPN/iu.test(sourceId)) {
    details.supported = /\b(?:yes|supported|offered)\b/iu.test(finding) && !/\bnot\b/iu.test(finding);
    details.values = tokens(finding).slice(0, 32);
  }
  return boundDetails(details);
}

function parseCipherFinding(finding) {
  const values = finding.split(/\s+/u).filter(Boolean);
  if (values.length < 4) return {};
  const ianaName = values.at(-1) ?? "";
  const bitsValue = Number(values.at(-2));
  const keyExchange = ianaName.startsWith("TLS_")
    ? ianaName.includes("_WITH_")
      ? ianaName.slice(4, ianaName.indexOf("_WITH_"))
      : "TLS1.3"
    : "unknown";
  return boundDetails({
    protocol: values[0],
    code: values[1],
    opensslName: values[2],
    ianaName,
    keyExchange,
    bits: Number.isFinite(bitsValue) ? bitsValue : null,
    aead: /(?:GCM|CCM|CHACHA20|POLY1305)/u.test(ianaName),
    cbc: /_CBC_/u.test(ianaName),
    forwardSecrecy: keyExchange === "TLS1.3" || /^(?:EC)?DHE/u.test(keyExchange),
  });
}

function ensureInventories(sections, usablePhases) {
  const identityAvailable = usablePhases.includes("identity");
  for (const sourceId of PROTOCOL_INVENTORY) {
    addMissing(sections.protocols, "protocols", sourceId, {
      status: "unknown",
      evidenceKind: "tested",
      severity: "info",
      summary: identityAvailable
        ? "The fixed protocol phase returned no result for this protocol."
        : "The fixed protocol phase did not complete.",
    });
  }

  const compatibilityAvailable = usablePhases.includes("compatibility");
  for (const [sourceId, title] of SAFE_ISSUE_INVENTORY) {
    addMissing(sections.knownIssues, "knownIssues", sourceId, {
      status: "unknown",
      evidenceKind: "tested",
      severity: "info",
      summary: compatibilityAvailable
        ? `${title} returned no bounded result.`
        : `${title} was scheduled, but the compatibility phase did not complete.`,
    });
  }
  for (const [sourceId, title, cve] of SAFETY_EXCLUSIONS) {
    sections.knownIssues.observations.push({
      id: `knownIssues:scanner:not-tested:${sourceId}`,
      sourceId,
      status: "not-tested",
      evidenceKind: "not-testable",
      severity: "info",
      summary: `${title} is intentionally excluded from the bounded safe profile.`,
      ...(cve.length ? { details: { cve } } : {}),
    });
  }
}

function addMissing(section, sectionName, sourceId, value) {
  if (section.observations.some((observation) => observation.sourceId === sourceId)) return;
  section.observations.push({ id: `${sectionName}:scanner:${sourceId}`, sourceId, ...value });
}

function deduplicateAndBound(sections) {
  for (const name of SECTION_NAMES) {
    const byId = new Map();
    for (const observation of sections[name].observations) {
      const existing = byId.get(observation.id);
      if (!existing || severityRank(observation.severity) > severityRank(existing.severity)) {
        byId.set(observation.id, observation);
      }
    }
    sections[name].observations = selectObservations(
      name,
      [...byId.values()],
      LIMITS.maximumObservationsPerSection,
    );
  }
}

function sectionStatus(name, phaseResults, usablePhases) {
  const expected = SECTION_PHASES[name];
  const relevant = phaseResults.filter((phase) => expected.includes(phase.id));
  if (relevant.length === 0) return "unavailable";
  if (relevant.every((phase) => phase.status === "complete" && usablePhases.includes(phase.id))) return "complete";
  return relevant.some((phase) => usablePhases.includes(phase.id)) ? "partial" : "unavailable";
}

function gradeSection(name, observations) {
  const weights = GRADE_WEIGHTS[name];
  const caps = gradeCaps(name, observations);
  let totalWeight = 0;
  let evaluatedWeight = 0;
  let earnedWeight = 0;
  for (const [sourceId, weight] of Object.entries(weights)) {
    totalWeight += weight;
    const observation = observations.find((entry) => entry.sourceId === sourceId);
    if (!observation || ["unknown", "not-tested"].includes(observation.status)) continue;
    evaluatedWeight += weight;
    earnedWeight += weight * statusCredit(observation.status);
  }
  return finishGrade({ totalWeight, evaluatedWeight, earnedWeight, caps });
}

function gradeAll(sections) {
  const parts = SECTION_NAMES.map((name) => sections[name].grade);
  const totalWeight = parts.reduce((sum, grade) => sum + grade.coverage.totalWeight, 0);
  const evaluatedWeight = parts.reduce((sum, grade) => sum + grade.coverage.evaluatedWeight, 0);
  let earnedWeight = 0;
  for (const name of SECTION_NAMES) {
    const weights = GRADE_WEIGHTS[name];
    for (const [sourceId, weight] of Object.entries(weights)) {
      const observation = sections[name].observations.find((entry) => entry.sourceId === sourceId);
      if (observation && !["unknown", "not-tested"].includes(observation.status)) {
        earnedWeight += weight * statusCredit(observation.status);
      }
    }
  }
  const caps = parts.flatMap((grade) => grade.caps).filter((cap, index, values) =>
    values.findIndex((candidate) => candidate.id === cap.id) === index);
  return finishGrade({ totalWeight, evaluatedWeight, earnedWeight, caps });
}

function finishGrade({ totalWeight, evaluatedWeight, earnedWeight, caps }) {
  const coverage = { evaluatedWeight, totalWeight };
  if (totalWeight === 0 || evaluatedWeight / totalWeight < 0.7) return { ...emptyGrade(), coverage, caps };
  const score = Math.round((earnedWeight / evaluatedWeight) * 100);
  let value = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  for (const cap of caps) value = lowerGrade(value, cap.maxGrade);
  return { value, score, coverage, methodology: GRADE_METHODOLOGY, caps };
}

function gradeCaps(sectionName, observations) {
  const caps = [];
  const bySource = (sourceId) => observations.find((entry) => entry.sourceId === sourceId);
  if (sectionName === "certificate" && bySource("cert_chain_of_trust")?.status === "fail") {
    caps.push({ id: "untrusted-chain", maxGrade: "F", reason: "The observed certificate chain was not trusted." });
  }
  if (sectionName === "protocols") {
    if (["SSLv2", "SSLv3"].some((id) => bySource(id)?.status === "fail")) {
      caps.push({ id: "ssl-enabled", maxGrade: "F", reason: "SSLv2 or SSLv3 was offered." });
    }
    if (["TLS1", "TLS1_1"].some((id) => bySource(id)?.status === "warning")) {
      caps.push({ id: "legacy-tls", maxGrade: "B", reason: "TLS 1.0 or TLS 1.1 was offered." });
    }
  }
  if (sectionName === "ciphers") {
    if (["cipherlist_NULL", "cipherlist_aNULL", "cipherlist_EXPORT", "cipherlist_LOW"]
      .some((id) => bySource(id)?.status === "fail")) {
      caps.push({ id: "critically-weak-cipher", maxGrade: "F", reason: "A null, anonymous, export, or low-strength cipher category was offered." });
    }
    if (bySource("cipherlist_3DES_IDEA")?.status === "warning") {
      caps.push({ id: "64-bit-block-cipher", maxGrade: "C", reason: "A 3DES or IDEA cipher was offered." });
    }
  }
  if (sectionName === "knownIssues") {
    for (const sourceId of ["heartbleed", "CCS", "ticketbleed"]) {
      if (bySource(sourceId)?.status === "fail") {
        caps.push({ id: `confirmed-${sourceId.toLowerCase()}`, maxGrade: "F", reason: `${sourceId} was reported as vulnerable by the active bounded probe.` });
      }
    }
    if (bySource("ROBOT")?.status === "fail") {
      caps.push({ id: "confirmed-robot", maxGrade: "F", reason: "The active bounded ROBOT probe reported an RSA oracle." });
    }
  }
  return caps;
}

function enforceResponseLimit(result) {
  const sectionCaps = {
    certificate: 48,
    protocols: 16,
    ciphers: 96,
    keyExchange: 40,
    features: 48,
    clientSimulations: 40,
    knownIssues: 48,
  };
  let truncated = false;
  // Issues and grades are derived again after compaction, so references can
  // never point at removed observations.
  result.issues = [];
  for (const [name, maximum] of Object.entries(sectionCaps)) {
    if (result.sections[name].observations.length > maximum) {
      result.sections[name].observations = selectObservations(name, result.sections[name].observations, maximum);
      truncated = true;
    }
  }
  const byteLength = () => Buffer.byteLength(JSON.stringify(result));
  const compactTargetBytes = LIMITS.maximumResponseBytes - 43_840;
  while (byteLength() > compactTargetBytes) {
    const candidates = Object.entries(result.sections)
      .filter(([, section]) => section.observations.length > 8)
      .sort(([, first], [, second]) => second.observations.length - first.observations.length);
    let candidate;
    let removable = -1;
    for (const entry of candidates) {
      const [name, section] = entry;
      removable = section.observations.findLastIndex((observation) =>
        GRADE_WEIGHTS[name][observation.sourceId] === undefined
        && !["warning", "fail"].includes(observation.status));
      if (removable >= 0) {
        candidate = entry;
        break;
      }
    }
    if (!candidate) {
      for (const entry of candidates) {
        const [name, section] = entry;
        removable = section.observations.findLastIndex((observation) =>
          GRADE_WEIGHTS[name][observation.sourceId] === undefined);
        if (removable >= 0) {
          candidate = entry;
          break;
        }
      }
    }
    if (!candidate) break;
    const [, section] = candidate;
    section.observations.splice(removable, 1);
    truncated = true;
  }
  if (truncated) {
    result.status = result.status === "unavailable" ? "unavailable" : "partial";
    result.limitations.push("Normalized endpoint evidence was truncated to keep the serialized response within 160 KiB; section counts and grades use the bounded observations retained by the scanner.");
  }
  refreshDerivedEvidence(result);
  if (byteLength() > LIMITS.maximumResponseBytes) {
    throw new Error("normalized TLS response exceeded its hard serialized size limit");
  }
  return result;
}

function selectObservations(sectionName, observations, maximum) {
  const sorted = [...observations].sort((a, b) => {
    const aWeighted = GRADE_WEIGHTS[sectionName][a.sourceId] !== undefined;
    const bWeighted = GRADE_WEIGHTS[sectionName][b.sourceId] !== undefined;
    if (aWeighted !== bWeighted) return aWeighted ? -1 : 1;
    const aIssue = ["warning", "fail"].includes(a.status);
    const bIssue = ["warning", "fail"].includes(b.status);
    if (aIssue !== bIssue) return aIssue ? -1 : 1;
    return severityRank(b.severity) - severityRank(a.severity) || a.id.localeCompare(b.id);
  });
  return sorted.slice(0, maximum).sort((a, b) => a.id.localeCompare(b.id));
}

function refreshDerivedEvidence(result) {
  for (const name of SECTION_NAMES) {
    result.sections[name].grade = gradeSection(name, result.sections[name].observations);
  }
  result.grade = gradeAll(result.sections);
  result.issues = buildIssues(result.sections);
}

function buildIssues(sections) {
  const issues = [];
  for (const section of SECTION_NAMES) {
    for (const observation of sections[section].observations) {
      if (!["critical", "high", "medium", "low"].includes(observation.severity)
        || !["warning", "fail"].includes(observation.status)) continue;
      issues.push({
        id: `issue:${observation.id}`,
        section,
        observationId: observation.id,
        severity: observation.severity,
        evidenceKind: observation.evidenceKind,
        summary: observation.summary,
      });
    }
  }
  return issues.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.id.localeCompare(b.id))
    .slice(0, LIMITS.maximumIssues);
}

function isCertificateRecord(id) {
  const value = String(id ?? "");
  return /^(?:cert|OCSP|DNS_CAA|certificate_transparency|intermediate_cert)/u.test(value);
}

function emptyGrade() {
  return {
    value: "N/A",
    score: null,
    coverage: { evaluatedWeight: 0, totalWeight: 0 },
    methodology: GRADE_METHODOLOGY,
    caps: [],
  };
}

function statusCredit(status) {
  if (status === "pass" || status === "info") return 1;
  if (status === "warning") return 0.5;
  return 0;
}

function lowerGrade(first, second) {
  const order = ["A", "B", "C", "D", "F"];
  return order.indexOf(first) >= order.indexOf(second) ? first : second;
}

function sanitizeId(input) {
  const value = String(input ?? "").replace(/[^A-Za-z0-9_.:-]/gu, "-").slice(0, 96);
  return value || undefined;
}

function sanitizeText(input) {
  const value = String(input ?? "")
    .replace(/https?:\/\/\S+/giu, "[external reference omitted]")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  return value.length > LIMITS.maximumSummaryCharacters
    ? `${value.slice(0, LIMITS.maximumSummaryCharacters - 1)}…`
    : value;
}

function boundDetails(details) {
  const result = {};
  for (const [key, value] of Object.entries(details).slice(0, 16)) {
    if (Array.isArray(value)) {
      result[key] = value.slice(0, 128).map((entry) => sanitizeDetail(entry));
    } else if (["string", "number", "boolean"].includes(typeof value) || value === null) {
      result[key] = typeof value === "string" ? sanitizeDetail(value) : value;
    }
  }
  return result;
}

function sanitizeDetail(value) {
  const text = String(value).replace(/[\u0000-\u001F\u007F]/gu, " ").trim();
  return text.slice(0, LIMITS.maximumDetailCharacters);
}

function tokens(value, filter = () => true) {
  const accept = filter instanceof RegExp ? (entry) => filter.test(entry) : filter;
  return String(value ?? "").split(/[\s,]+/u).map((entry) => entry.trim()).filter((entry) => entry && accept(entry));
}

function finiteNonnegative(value) {
  return Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0;
}

function severityRank(severity) {
  return ({ none: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 })[severity] ?? 0;
}
