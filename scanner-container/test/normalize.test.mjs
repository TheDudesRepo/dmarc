import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { LIMITS } from "../src/constants.mjs";
import { normalizeDeepTlsResult } from "../src/normalize.mjs";

const fixture = JSON.parse(await readFile(new URL("./fixtures/testssl-safe.json", import.meta.url), "utf8"));
const request = {
  hostname: "example.com",
  address: "93.184.216.34",
  addressFamily: 4,
  profile: "safe",
  deadlineMs: 180_000,
};

function phases(report = fixture) {
  return ["identity", "cryptography", "compatibility"].map((id) => ({
    id,
    status: "complete",
    exitCode: 0,
    durationMs: 100,
    outputBytes: 1_000,
    report,
  }));
}

test("normalizes structured evidence, active issues, grading, and exclusions", () => {
  const result = normalizeDeepTlsResult({
    request,
    phaseResults: phases(),
    connectionBudget: { opened: 42 },
    startedAt: "2026-08-16T00:00:00.000Z",
    durationMs: 1_000,
  });
  assert.equal(result.status, "complete");
  assert.equal(result.target.port, 443);
  assert.equal(result.budget.connectionsOpened, 42);
  assert.equal(result.grade.value, "F", "confirmed Heartbleed must cap the grade");
  assert.ok(result.grade.caps.some((cap) => cap.id === "confirmed-heartbleed"));

  const cipher = result.sections.ciphers.observations.find((entry) => entry.sourceId === "cipher-tls1_2_xc02f");
  assert.deepEqual(cipher.details, {
    protocol: "TLSv1.2",
    code: "xc02f",
    opensslName: "ECDHE-RSA-AES128-GCM-SHA256",
    ianaName: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    keyExchange: "ECDHE_RSA",
    bits: 128,
    aead: true,
    cbc: false,
    forwardSecrecy: true,
  });
  const curves = result.sections.keyExchange.observations.find((entry) => entry.sourceId === "FS_ECDHE_curves");
  assert.deepEqual(curves.details.groups, ["prime256v1", "secp384r1", "X25519"]);
  const client = result.sections.clientSimulations.observations.find((entry) => entry.sourceId === "clientsimulation-chrome_current");
  assert.deepEqual(client.details, {
    profile: "chrome_current",
    connected: true,
    protocol: "TLSv1.3",
    cipher: "TLS_AES_128_GCM_SHA256",
  });
  assert.ok(result.sections.knownIssues.observations.some((entry) =>
    entry.sourceId === "breach" && entry.status === "not-tested" && entry.evidenceKind === "not-testable"));
  assert.equal(JSON.stringify(result).includes("BEGIN CERTIFICATE"), false);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) <= LIMITS.maximumResponseBytes);
});

test("never reports complete when completed child output targets the wrong endpoint", () => {
  const wrong = structuredClone(fixture);
  wrong.scanResult[0].ip = "93.184.216.35";
  const result = normalizeDeepTlsResult({
    request,
    phaseResults: phases(wrong),
    connectionBudget: { opened: 3 },
    startedAt: "2026-08-16T00:00:00.000Z",
    durationMs: 1_000,
  });
  assert.equal(result.status, "unavailable");
  assert.ok(result.phases.every((phase) => phase.status === "failed"));
  assert.ok(Object.values(result.sections).every((section) => section.status === "unavailable"));
  assert.equal(result.grade.value, "N/A");
});

test("caps a confirmed ROBOT result even if every other weighted check passes", () => {
  const robot = structuredClone(fixture);
  const vulnerabilities = robot.scanResult[0].vulnerabilities;
  vulnerabilities.find((entry) => entry.id === "heartbleed").severity = "OK";
  vulnerabilities.find((entry) => entry.id === "heartbleed").finding = "not vulnerable";
  vulnerabilities.find((entry) => entry.id === "ROBOT").severity = "CRITICAL";
  vulnerabilities.find((entry) => entry.id === "ROBOT").finding = "vulnerable, strong oracle";
  const result = normalizeDeepTlsResult({
    request,
    phaseResults: phases(robot),
    connectionBudget: { opened: 42 },
    startedAt: "2026-08-16T00:00:00.000Z",
    durationMs: 1_000,
  });
  assert.equal(result.grade.value, "F");
  assert.ok(result.grade.caps.some((cap) => cap.id === "confirmed-robot"));
});

test("compacts oversized evidence and leaves grades and issue references internally consistent", () => {
  const oversized = structuredClone(fixture);
  const scan = oversized.scanResult[0];
  for (let index = 0; index < 300; index += 1) {
    scan.serverPreferences.push({
      id: `cipher-tls1_2_x${index.toString(16).padStart(4, "0")}`,
      severity: index % 3 === 0 ? "LOW" : "INFO",
      finding: `TLSv1.2 xffff GENERATED-CIPHER ECDH 253 AESGCM 128 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ${"bounded ".repeat(80)}`,
    });
    scan.browserSimulations.push({
      id: `clientsimulation-generated_${index}`,
      severity: "INFO",
      finding: `TLSv1.3 TLS_AES_128_GCM_SHA256 ${"bounded ".repeat(80)}`,
    });
  }
  const result = normalizeDeepTlsResult({
    request,
    phaseResults: phases(oversized),
    connectionBudget: { opened: 128 },
    startedAt: "2026-08-16T00:00:00.000Z",
    durationMs: 1_000,
  });
  assert.ok(Buffer.byteLength(JSON.stringify(result)) <= LIMITS.maximumResponseBytes);
  assert.equal(result.status, "partial");
  assert.ok(result.limitations.some((entry) => /truncated/u.test(entry)));
  const observations = new Set(Object.values(result.sections).flatMap((section) =>
    section.observations.map((observation) => observation.id)));
  assert.ok(result.issues.every((issue) => observations.has(issue.observationId)));
  for (const sourceId of ["cipherlist_NULL", "cipherlist_aNULL", "cipherlist_EXPORT", "cipherlist_LOW"]) {
    assert.ok(result.sections.ciphers.observations.some((entry) => entry.sourceId === sourceId));
  }
});
