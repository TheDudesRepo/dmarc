import { Container } from "@cloudflare/containers";
import type { DeepTlsResponseV1 } from "../shared/types";
import { canonicalPublicScanAddress } from "./target-safety";

const DISPOSE_RETRY_FAST_MS = 30_000;
const DISPOSE_RETRY_SLOW_MS = 60 * 60 * 1_000;
const DISPOSE_RETRY_FAST_ATTEMPTS = 3;
const DISPOSE_RETRY_KEY = "cresswell:deep-tls:dispose-retry:v1";
const SCAN_ONCE_RESULT_KEY = "cresswell:deep-tls:scan-once-result:v1";
const SCAN_ONCE_MAX_JSON_BYTES = 160 * 1024;
const SCAN_ONCE_DEADLINE_MS = 180_000;

export interface DeepTlsScanIdentity {
  hostname: string;
  address: string;
  deadlineMs: number;
}

type StoredScanRecord =
  | { identity: DeepTlsScanIdentity; phase: "running"; ownerToken: string }
  | { identity: DeepTlsScanIdentity; phase: "complete"; resultJson: string };

export type DeepTlsScanClaim =
  | { status: "claimed"; ownerToken: string }
  | { status: "in-progress" }
  | { status: "complete"; result: DeepTlsResponseV1 };

interface DisposeMarker {
  phase: "stop-required" | "stopped";
  attempt: number;
}

interface BeginDisposeOperations {
  stop(): Promise<void>;
  mark(marker: DisposeMarker, delayMs: number): Promise<void>;
}

interface DisposeAlarmOperations extends BeginDisposeOperations {
  clear(): Promise<void>;
  fallback(): Promise<void>;
}

/**
 * Phase one durably records recovery before asking the platform to stop the
 * paid instance. A confirmed stop schedules a separate native alarm for the
 * final wipe, allowing any already-running base Container alarm to unwind.
 */
export async function beginTwoPhaseDispose(operations: BeginDisposeOperations): Promise<void> {
  const stopping: DisposeMarker = { phase: "stop-required", attempt: 1 };
  await operations.mark(stopping, DISPOSE_RETRY_FAST_MS);
  try {
    await operations.stop();
  } catch (error) {
    // The original marker/alarm remains. Refresh it when storage is healthy,
    // but never erase state when the stop outcome is uncertain.
    await operations.mark(stopping, DISPOSE_RETRY_FAST_MS).catch(() => undefined);
    throw error;
  }
  await operations.mark({ phase: "stopped", attempt: 1 }, 1);
}

/**
 * Route the subclass-owned alarm state machine. The final-delete branch never
 * invokes Container.alarm because its SQL tables have just been removed.
 */
export async function runDisposeAlarm(
  marker: unknown,
  operations: DisposeAlarmOperations,
): Promise<void> {
  if (!isDisposeMarker(marker)) {
    await operations.fallback();
    return;
  }

  if (marker.phase === "stop-required") {
    try {
      await operations.stop();
    } catch {
      const attempt = nextDisposeAttempt(marker.attempt);
      await operations.mark(
        { phase: "stop-required", attempt },
        disposeRetryDelayMs(attempt),
      );
      return;
    }
    // A second alarm performs deletion after this alarm invocation returns.
    await operations.mark({ phase: "stopped", attempt: 1 }, 1);
    return;
  }

  try {
    await operations.clear();
  } catch {
    const attempt = nextDisposeAttempt(marker.attempt);
    await operations.mark(
      { phase: "stopped", attempt },
      disposeRetryDelayMs(attempt),
    );
  }
}

/** Paid Container wrapper. The image service enforces the request schema too. */
export class DeepTlsScanner extends Container {
  defaultPort = 8080;
  requiredPorts = [8080];
  pingEndpoint = "localhost/healthz";
  sleepAfter = "30s";
  // testssl.sh reaches the fixed-target CONNECT proxy through raw TCP; Containers
  // require internet capability for that socket path. The image, not allowedHosts,
  // enforces the exact validated IP:443 destination for opaque TCP traffic.
  enableInternet = true;
  interceptHttps = false;
  allowedHosts: string[] = [];

  /**
   * Atomically claim this job/endpoint before any active probe. A replay that
   * finds an unfinished claim returns indeterminate rather than probing twice.
   */
  async claimScan(identity: DeepTlsScanIdentity): Promise<DeepTlsScanClaim> {
    assertScanIdentity(identity);
    const record = await this.ctx.storage.get<StoredScanRecord>(SCAN_ONCE_RESULT_KEY);
    if (record === undefined) {
      const ownerToken = generateOwnerToken();
      await this.ctx.storage.put(SCAN_ONCE_RESULT_KEY, {
        identity: { ...identity },
        phase: "running",
        ownerToken,
      } satisfies StoredScanRecord);
      return { status: "claimed", ownerToken };
    }
    if (!isStoredScanRecord(record, identity)) {
      throw new Error("The stored deep TLS replay record was invalid.");
    }
    if (record.phase === "running") return { status: "in-progress" };
    const result: unknown = JSON.parse(record.resultJson);
    if (!matchesStoredReportIdentity(result, identity)) {
      throw new Error("The stored deep TLS replay result targeted a different endpoint.");
    }
    return { status: "complete", result: result as DeepTlsResponseV1 };
  }

  /**
   * First valid result wins. The Workflow keeps this record until step.do has
   * durably returned, so an incomplete-step replay cannot launch a new profile.
   */
  async storeScanResult(
    identity: DeepTlsScanIdentity,
    ownerToken: string,
    result: DeepTlsResponseV1,
  ): Promise<void> {
    assertScanIdentity(identity);
    if (!matchesStoredReportIdentity(result, identity)) {
      throw new Error("The deep TLS replay result targeted a different endpoint.");
    }
    const resultJson = JSON.stringify(result);
    if (new TextEncoder().encode(resultJson).byteLength > SCAN_ONCE_MAX_JSON_BYTES) {
      throw new Error("The deep TLS replay result exceeded its storage bound.");
    }
    const existing = await this.ctx.storage.get<StoredScanRecord>(SCAN_ONCE_RESULT_KEY);
    if (!isStoredScanRecord(existing, identity)) {
      throw new Error("The deep TLS scan was not durably claimed before execution.");
    }
    if (existing.phase === "complete") {
      return;
    }
    if (existing.ownerToken !== ownerToken) {
      throw new Error("The deep TLS scan claim owner did not match.");
    }
    await this.ctx.storage.put(SCAN_ONCE_RESULT_KEY, {
      identity: { ...identity },
      phase: "complete",
      resultJson,
    } satisfies StoredScanRecord);
  }

  /** Stop the one-shot container, then queue a race-safe persistent-state wipe. */
  async dispose(): Promise<void> {
    await beginTwoPhaseDispose({
      stop: () => this.destroy(),
      mark: (marker, delayMs) => this.markDisposeRetry(marker, delayMs),
    });
  }

  /**
   * Cleanup uses a subclass-owned marker and native alarm. Calling the base
   * Container alarm after deleteAll would access its deleted SQL tables.
   */
  override async alarm(alarmProps?: AlarmInvocationInfo): Promise<void> {
    const marker = await this.ctx.storage.get(DISPOSE_RETRY_KEY);
    await runDisposeAlarm(marker, {
      stop: () => this.destroy(),
      clear: () => this.ctx.storage.deleteAll(),
      mark: (nextMarker, delayMs) => this.markDisposeRetry(nextMarker, delayMs),
      fallback: () => super.alarm(alarmProps),
    });
  }

  private async markDisposeRetry(marker: DisposeMarker, delayMs: number): Promise<void> {
    await this.ctx.storage.put(DISPOSE_RETRY_KEY, marker);
    await this.ctx.storage.setAlarm(Date.now() + Math.max(1, Math.floor(delayMs)));
  }
}

function nextDisposeAttempt(attempt: number): number {
  return Math.min(DISPOSE_RETRY_FAST_ATTEMPTS, attempt + 1);
}

function disposeRetryDelayMs(attempt: number): number {
  return attempt < DISPOSE_RETRY_FAST_ATTEMPTS
    ? DISPOSE_RETRY_FAST_MS * (2 ** (attempt - 1))
    : DISPOSE_RETRY_SLOW_MS;
}

function isDisposeMarker(value: unknown): value is DisposeMarker {
  if (typeof value !== "object" || value === null || !("attempt" in value) || !("phase" in value)) return false;
  const { attempt, phase } = value;
  return (phase === "stop-required" || phase === "stopped")
    && typeof attempt === "number"
    && Number.isInteger(attempt)
    && attempt >= 1
    && attempt <= DISPOSE_RETRY_FAST_ATTEMPTS;
}

function assertScanIdentity(value: DeepTlsScanIdentity): void {
  if (
    typeof value !== "object"
    || value === null
    || typeof value.hostname !== "string"
    || value.hostname.length < 1
    || value.hostname.length > 253
    || value.hostname !== value.hostname.toLowerCase()
    || canonicalPublicScanAddress(value.address) === null
    || value.deadlineMs !== SCAN_ONCE_DEADLINE_MS
  ) {
    throw new Error("The deep TLS replay identity was invalid.");
  }
}

function isStoredScanRecord(value: unknown, expected: DeepTlsScanIdentity): value is StoredScanRecord {
  return typeof value === "object"
    && value !== null
    && "identity" in value
    && "phase" in value
    && (value.phase === "running" || value.phase === "complete")
    && (value.phase === "running"
      ? "ownerToken" in value
        && typeof value.ownerToken === "string"
        && /^[a-f0-9]{32}$/u.test(value.ownerToken)
        && (!("resultJson" in value) || value.resultJson === undefined)
      : "resultJson" in value
        && typeof value.resultJson === "string"
        && value.resultJson.length <= SCAN_ONCE_MAX_JSON_BYTES)
    && sameScanIdentity(value.identity, expected);
}

function generateOwnerToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function sameScanIdentity(value: unknown, expected: DeepTlsScanIdentity): boolean {
  return typeof value === "object"
    && value !== null
    && "hostname" in value
    && "address" in value
    && "deadlineMs" in value
    && value.hostname === expected.hostname
    && value.address === expected.address
    && value.deadlineMs === expected.deadlineMs;
}

function matchesStoredReportIdentity(value: unknown, expected: DeepTlsScanIdentity): boolean {
  if (typeof value !== "object" || value === null || !("schemaVersion" in value) || !("target" in value)) return false;
  const target = value.target;
  return value.schemaVersion === "tls-deep-v1"
    && typeof target === "object"
    && target !== null
    && "hostname" in target
    && "address" in target
    && target.hostname === expected.hostname
    && target.address === expected.address;
}
