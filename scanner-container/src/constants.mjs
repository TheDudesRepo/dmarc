export const CONTRACT_VERSION = "tls-deep-v1";
export const PROFILE = "safe";
export const PROFILE_REVISION = "safe-v1";
export const GRADE_METHODOLOGY = "cresswell-tls-v1";

export const TESTSSL = Object.freeze({
  engine: "testssl.sh",
  version: "3.2.4",
  commit: "97763a411c525720a5f9bd9d2cded416b10f210a",
  sourceUrl: "https://github.com/testssl/testssl.sh",
  license: "GPL-2.0-only",
  profileRevision: PROFILE_REVISION,
});

export const LIMITS = Object.freeze({
  requestBodyBytes: 2_048,
  minimumDeadlineMs: 120_000,
  maximumDeadlineMs: 180_000,
  processKillGraceMs: 250,
  maximumProcesses: 3,
  maximumConcurrentConnections: 5,
  maximumConnections: 128,
  connectHeaderBytes: 1_024,
  connectHeaderTimeoutMs: 1_500,
  connectionLifetimeMs: 15_000,
  maximumPhaseOutputBytes: 393_216,
  maximumLogBytes: 131_072,
  maximumResponseBytes: 163_840,
  maximumObservationsPerSection: 128,
  maximumIssues: 64,
  maximumSummaryCharacters: 384,
  maximumDetailCharacters: 512,
});

export const SECTION_NAMES = Object.freeze([
  "certificate",
  "protocols",
  "ciphers",
  "keyExchange",
  "features",
  "clientSimulations",
  "knownIssues",
]);

export const PHASES = Object.freeze([
  Object.freeze({
    id: "identity",
    options: Object.freeze(["--protocols", "--server-defaults"]),
  }),
  Object.freeze({
    id: "cryptography",
    options: Object.freeze([
      "--standard",
      "--server-preference",
      "--forward-secrecy",
    ]),
  }),
  Object.freeze({
    id: "compatibility",
    options: Object.freeze([
      "--client-simulation",
      "--heartbleed",
      "--ccs-injection",
      "--ticketbleed",
      "--robot",
      "--renegotiation",
      "--compression",
      "--poodle",
      "--tls-fallback",
      "--sweet32",
      "--beast",
      "--lucky13",
      "--freak",
      "--logjam",
      "--drown",
      "--rc4",
    ]),
  }),
]);
