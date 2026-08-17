import { getContainer } from "@cloudflare/containers";
import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import { NonRetryableError } from "cloudflare:workflows";
import {
  SECURITY_ASSESSMENT_DISCLAIMER,
  WEB_SECURITY_DISCLAIMER,
  type DeepTlsAssessmentResult,
  type DeepTlsGrade,
  type DeepTlsGradeCap,
  type DeepTlsGradeValue,
  type DeepTlsIssue,
  type DeepTlsObservation,
  type DeepTlsReportStatus,
  type DeepTlsResponseV1,
  type DeepTlsSection,
  type DeepTlsSectionName,
  type SecurityAssessmentCancelResponse,
  type SecurityAssessmentJobError,
  type SecurityAssessmentJobResource,
  type SecurityAssessmentJobStatus,
  type SecurityAssessmentProgress,
  type SecurityAssessmentProgressPhase,
  type SecurityAssessmentResult,
} from "../shared/types";
import { DeepTlsScanner } from "./deep-tls-scanner";
import { createPinnedHttpFetcher, type PinnedHttpTelemetry } from "./pinned-http";
import {
  MAX_DEEP_TLS_ENDPOINTS,
  canonicalPublicScanAddress,
  resolvePublicHost,
  ScanTargetResolutionError,
  selectDeepTlsEndpoints,
  UnsafeScanTargetError,
} from "./target-safety";
import { scanWebSecurity } from "./web-security";

export const SECURITY_ASSESSMENT_JOB_ID_PATTERN = /^sa_[a-f0-9]{48}$/u;
export const SECURITY_ASSESSMENT_CANCEL_TOKEN_PATTERN = /^sc_[a-f0-9]{64}$/u;
export const SECURITY_ASSESSMENT_CACHE_MS = 6 * 60 * 60 * 1_000;
export const SECURITY_ASSESSMENT_JOB_RETENTION_MS = 24 * 60 * 60 * 1_000;
export const SECURITY_ASSESSMENT_STALE_RUNNING_MS = 25 * 60 * 1_000;
export const SECURITY_ASSESSMENT_GLOBAL_CONCURRENCY = 2;
export const SECURITY_ASSESSMENT_MAX_QUEUED = 8;
export const SECURITY_ASSESSMENT_MAX_RETAINED_JOBS = 256;
export const SECURITY_ASSESSMENT_POLL_SECONDS = 2;
export const DEEP_TLS_ENDPOINT_DEADLINE_MS = 180_000;
export const MAX_DEEP_TLS_RESPONSE_BYTES = 163_840;
export const MAX_NORMALIZED_DEEP_TLS_ENDPOINT_BYTES = 128 * 1024;
export const MAX_COMBINED_ASSESSMENT_BYTES = 700 * 1024;

const MAX_INTERNAL_CREATE_BYTES = 8_192;
const MAX_INTERNAL_PROGRESS_BYTES = 4_096;
const MAX_INTERNAL_RESULT_BYTES = MAX_COMBINED_ASSESSMENT_BYTES + 32_768;
const MAX_RESULT_TEXT = 2_048;
const MAX_RESULT_SHORT_TEXT = 512;
const MAX_RESULT_IDENTIFIER = 180;
const MAX_OBSERVATIONS_PER_SECTION = 128;
const MAX_ISSUES = 64;
const MAX_LIMITATIONS = 8;
const MAX_DETAIL_KEYS = 16;
const MAX_DETAIL_ARRAY = 128;
const SECTION_NAMES = [
  "certificate",
  "protocols",
  "ciphers",
  "keyExchange",
  "features",
  "clientSimulations",
  "knownIssues",
] as const satisfies readonly DeepTlsSectionName[];
const WEB_CHECK_IDS = [
  "https-enforcement",
  "hsts",
  "content-security-policy",
  "frame-protection",
  "mime-sniffing",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-isolation",
  "cors-policy",
  "http-methods",
  "cookie-secure",
  "cookie-httponly",
  "cookie-samesite",
  "cookie-scope-prefix",
  "cache-control",
  "technology-disclosure",
  "error-handling",
  "mixed-content",
  "form-transport",
  "subresource-integrity",
] as const;

export interface SecurityAssessmentWorkflowParams {
  jobId: string;
  hostname: string;
  addresses: string[];
  startedAt: string;
}

export interface SecurityAssessmentBindings {
  SECURITY_ASSESSMENT_COORDINATOR: DurableObjectNamespace;
  SECURITY_ASSESSMENT_WORKFLOW: Workflow<SecurityAssessmentWorkflowParams>;
  DEEP_TLS_SCANNER: DurableObjectNamespace<DeepTlsScanner>;
}

export interface CreateSecurityAssessmentInput {
  jobId: string;
  hostname: string;
  addresses: string[];
  createdAt: string;
  cancelTokenHash: string;
}

export interface CoordinatorCreateResult {
  job: SecurityAssessmentJobResource;
  reuse: "new" | "cache-hit" | "single-flight";
  pollAfterSeconds: number;
}

export class SecurityAssessmentConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecurityAssessmentConfigurationError";
  }
}

export class SecurityAssessmentNotFoundError extends Error {
  constructor(message = "The assessment job was not found or has expired.") {
    super(message);
    this.name = "SecurityAssessmentNotFoundError";
  }
}

export function generateSecurityAssessmentJobId(
  randomValues: (array: Uint8Array) => Uint8Array = (array) => crypto.getRandomValues(array as Uint8Array<ArrayBuffer>),
): string {
  const bytes = randomValues(new Uint8Array(24));
  const hex = [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
  return `sa_${hex}`;
}

export function generateSecurityAssessmentCancelToken(
  randomValues: (array: Uint8Array) => Uint8Array = (array) => crypto.getRandomValues(array as Uint8Array<ArrayBuffer>),
): string {
  const bytes = randomValues(new Uint8Array(32));
  return `sc_${[...bytes].map((value) => value.toString(16).padStart(2, "0")).join("")}`;
}

export async function digestSecurityAssessmentCancelToken(token: string): Promise<string> {
  if (!SECURITY_ASSESSMENT_CANCEL_TOKEN_PATTERN.test(token)) throw new SecurityAssessmentNotFoundError();
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`cresswell-security-lab:assessment-cancel:v1:${token}`),
  );
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

export async function createSecurityAssessmentJob(
  env: SecurityAssessmentBindings,
  input: CreateSecurityAssessmentInput,
): Promise<CoordinatorCreateResult> {
  return coordinatorJsonRequest(env, "/jobs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  }, isCoordinatorCreateResult);
}

export async function getSecurityAssessmentJob(
  env: SecurityAssessmentBindings,
  jobId: string,
): Promise<SecurityAssessmentJobResource> {
  validateJobId(jobId);
  return coordinatorJsonRequest(env, `/jobs/${jobId}`, { method: "GET" }, isSecurityAssessmentJobResource);
}

export async function cancelSecurityAssessmentJob(
  env: SecurityAssessmentBindings,
  jobId: string,
  cancelTokenHash: string,
): Promise<SecurityAssessmentCancelResponse> {
  validateJobId(jobId);
  return coordinatorJsonRequest(
    env,
    `/jobs/${jobId}`,
    { method: "DELETE", headers: { "X-Assessment-Cancel-Hash": cancelTokenHash } },
    isSecurityAssessmentCancelResponse,
  );
}

/** Global, SQLite-backed job/cache/single-flight scheduler. */
export class SecurityAssessmentCoordinator {
  private readonly storage: DurableObjectStorage;
  private readonly sql: SqlStorage;
  private mutationTail: Promise<void> = Promise.resolve();

  constructor(state: DurableObjectState, private readonly env: SecurityAssessmentBindings) {
    this.storage = state.storage;
    this.sql = state.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS security_assessment_jobs (
        job_id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL,
        target_key TEXT NOT NULL,
        addresses_json TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        completed_at INTEGER,
        progress_json TEXT NOT NULL,
        result_json TEXT,
        error_json TEXT,
        source_job_id TEXT,
        cancel_token_hash TEXT
      )
    `);
    this.sql.exec("CREATE INDEX IF NOT EXISTS idx_security_jobs_target ON security_assessment_jobs(target_key, status, completed_at)");
    this.sql.exec("CREATE INDEX IF NOT EXISTS idx_security_jobs_queue ON security_assessment_jobs(status, created_at)");
    if (typeof state.blockConcurrencyWhile === "function") {
      state.blockConcurrencyWhile(() => this.scheduleCoordinatorAlarm());
    }
  }

  fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const segments = url.pathname.split("/").filter(Boolean);
    if (segments[0] !== "jobs") return Promise.resolve(internalError("Not found.", 404));

    if (segments.length === 1 && request.method === "POST") {
      return this.serialize(() => this.handleCreate(request));
    }
    const jobId = segments[1] ?? "";
    if (!SECURITY_ASSESSMENT_JOB_ID_PATTERN.test(jobId)) {
      return Promise.resolve(internalError("Not found.", 404));
    }
    if (segments.length === 2 && request.method === "GET") {
      return this.serialize(() => this.handleGet(jobId));
    }
    if (segments.length === 2 && request.method === "DELETE") {
      return this.serialize(() => this.handleCancel(jobId, request));
    }
    if (segments.length === 3 && request.method === "POST") {
      if (segments[2] === "progress") return this.serialize(() => this.handleProgress(jobId, request));
      if (segments[2] === "complete") return this.serialize(() => this.handleComplete(jobId, request));
      if (segments[2] === "fail") return this.serialize(() => this.handleFailure(jobId, request));
    }
    return Promise.resolve(internalError("Not found.", 404));
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const guarded = async () => {
      try {
        return await operation();
      } finally {
        await this.scheduleCoordinatorAlarm();
      }
    };
    const result = this.mutationTail.then(guarded, guarded);
    this.mutationTail = result.then(() => undefined, () => undefined);
    return result;
  }

  async alarm(): Promise<void> {
    await this.serialize(async () => {
      const now = Date.now();
      await this.reapStaleRunningJobs(now);
      this.sql.exec(
        "DELETE FROM security_assessment_jobs WHERE expires_at <= ? AND status != 'running'",
        now,
      );
      await this.promoteQueuedJobs(false);
    });
  }

  private async scheduleCoordinatorAlarm(): Promise<void> {
    if (
      typeof this.storage.getAlarm !== "function"
      || typeof this.storage.setAlarm !== "function"
      || typeof this.storage.deleteAlarm !== "function"
    ) {
      return;
    }
    const expiry = this.firstRow<{ earliest: number | null }>(
      "SELECT MIN(expires_at) AS earliest FROM security_assessment_jobs",
    )?.earliest;
    const runningUpdated = this.firstRow<{ earliest: number | null }>(
      "SELECT MIN(updated_at) AS earliest FROM security_assessment_jobs WHERE status = 'running'",
    )?.earliest;
    const candidates = [
      typeof expiry === "number" && Number.isSafeInteger(expiry) ? expiry : null,
      typeof runningUpdated === "number" && Number.isSafeInteger(runningUpdated)
        ? runningUpdated + SECURITY_ASSESSMENT_STALE_RUNNING_MS + 1
        : null,
    ].filter((value): value is number => value !== null);
    if (candidates.length === 0) {
      await this.storage.deleteAlarm();
      return;
    }
    const now = Date.now();
    const nextAlarm = Math.max(now + 1, Math.min(...candidates));
    const existing = await this.storage.getAlarm();
    if (existing === null || existing <= now || nextAlarm < existing) {
      await this.storage.setAlarm(nextAlarm);
    }
  }

  private async handleCreate(request: Request): Promise<Response> {
    const payload = await readBoundedJson(request, MAX_INTERNAL_CREATE_BYTES);
    if (!isCreateInput(payload)) return internalError("Invalid job request.", 400);
    const createdAtMs = Date.parse(payload.createdAt);
    if (!Number.isFinite(createdAtMs) || Math.abs(Date.now() - createdAtMs) > 60_000) {
      return internalError("Invalid job request.", 400);
    }
    const addresses = validateStoredAddressList(payload.addresses);
    if (!addresses) return internalError("Invalid job request.", 400);

    const now = Date.now();
    await this.reapStaleRunningJobs(now);
    this.sql.exec(
      "DELETE FROM security_assessment_jobs WHERE expires_at <= ? AND status != 'running'",
      now,
    );
    await this.promoteQueuedJobs(false);
    const targetKey = `${payload.hostname}\n${JSON.stringify(addresses)}`;
    const running = this.firstRow<JobRow>(
      "SELECT * FROM security_assessment_jobs WHERE target_key = ? AND status IN ('queued', 'running') ORDER BY created_at ASC LIMIT 1",
      targetKey,
    );
    if (running) {
      if (running.cancel_token_hash !== null) {
        this.sql.exec(
          "UPDATE security_assessment_jobs SET cancel_token_hash = NULL WHERE job_id = ? AND status IN ('queued', 'running')",
          running.job_id,
        );
        running.cancel_token_hash = null;
      }
      return internalJson({
        job: rowToJob(running),
        reuse: "single-flight",
        pollAfterSeconds: SECURITY_ASSESSMENT_POLL_SECONDS,
      } satisfies CoordinatorCreateResult);
    }

    const cached = this.firstRow<JobRow>(
      "SELECT * FROM security_assessment_jobs WHERE target_key = ? AND status = 'complete' AND completed_at > ? AND result_json IS NOT NULL ORDER BY completed_at DESC LIMIT 1",
      targetKey,
      now - SECURITY_ASSESSMENT_CACHE_MS,
    );
    if (cached?.result_json) {
      return internalJson({
        job: rowToJob(cached),
        reuse: "cache-hit",
        pollAfterSeconds: 0,
      } satisfies CoordinatorCreateResult);
    }

    const retainedCount = Number(this.firstRow<{ count: number }>(
      "SELECT COUNT(*) AS count FROM security_assessment_jobs",
    )?.count ?? 0);
    if (retainedCount >= SECURITY_ASSESSMENT_MAX_RETAINED_JOBS) {
      return internalError("The retained assessment capacity is temporarily full.", 503);
    }

    const queuedCount = Number(this.firstRow<{ count: number }>(
      "SELECT COUNT(*) AS count FROM security_assessment_jobs WHERE status = 'queued' AND expires_at > ?",
      now,
    )?.count ?? 0);
    if (queuedCount >= SECURITY_ASSESSMENT_MAX_QUEUED) {
      return internalError("The global assessment queue is at capacity.", 503);
    }

    const progress = queuedProgress(addresses.length, now);
    this.sql.exec(
      `INSERT INTO security_assessment_jobs
        (job_id, hostname, target_key, addresses_json, status, created_at, updated_at, expires_at,
         completed_at, progress_json, result_json, error_json, source_job_id, cancel_token_hash)
       VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, NULL, ?, NULL, NULL, NULL, ?)`,
      payload.jobId,
      payload.hostname,
      targetKey,
      JSON.stringify(addresses),
      now,
      now,
      now + SECURITY_ASSESSMENT_JOB_RETENTION_MS,
      JSON.stringify(progress),
      payload.cancelTokenHash,
    );

    await this.promoteQueuedJobs();
    const job = rowToJob(this.requireRow(payload.jobId));
    return internalJson({
      job,
      reuse: "new",
      pollAfterSeconds: terminalStatus(job.status) ? 0 : SECURITY_ASSESSMENT_POLL_SECONDS,
    } satisfies CoordinatorCreateResult);
  }

  private async handleGet(jobId: string): Promise<Response> {
    const initial = this.firstRow<JobRow>(
      "SELECT * FROM security_assessment_jobs WHERE job_id = ? LIMIT 1",
      jobId,
    );
    if (!initial || initial.expires_at <= Date.now()) return internalError("Not found.", 404);
    // A queued/running caller can repair a persisted promotion gap or reap a
    // stale lease. Random capabilities and terminal-result reads stay on the
    // single indexed lookup path instead of invoking global scheduler work.
    if (initial.status === "queued" || initial.status === "running") {
      await this.promoteQueuedJobs();
    }
    const row = initial.status === "queued" || initial.status === "running"
      ? this.firstRow<JobRow>("SELECT * FROM security_assessment_jobs WHERE job_id = ? LIMIT 1", jobId)
      : initial;
    if (!row || row.expires_at <= Date.now()) return internalError("Not found.", 404);
    try {
      return internalJson(rowToJob(row));
    } catch {
      return internalError("Stored job data is invalid.", 500);
    }
  }

  private async handleCancel(jobId: string, request: Request): Promise<Response> {
    const row = this.firstRow<JobRow>("SELECT * FROM security_assessment_jobs WHERE job_id = ? LIMIT 1", jobId);
    if (!row || row.expires_at <= Date.now()) return internalError("Not found.", 404);
    if (terminalStatus(row.status)) {
      return internalJson({ cancelled: false, job: rowToJob(row) } satisfies SecurityAssessmentCancelResponse);
    }
    const presentedHash = request.headers.get("x-assessment-cancel-hash") ?? "";
    if (
      !/^[a-f0-9]{64}$/u.test(presentedHash)
      || typeof row.cancel_token_hash !== "string"
      || !constantTimeTextEqual(presentedHash, row.cancel_token_hash)
    ) {
      return internalError("Not found.", 404);
    }

    const now = Date.now();
    const progress: SecurityAssessmentProgress = {
      phase: "cancelled",
      message: "The assessment was cancelled.",
      completedEndpoints: parseProgress(row.progress_json).completedEndpoints,
      totalEndpoints: parseProgress(row.progress_json).totalEndpoints,
      percent: 100,
      updatedAt: new Date(now).toISOString(),
    };
    this.sql.exec(
      "UPDATE security_assessment_jobs SET status = 'cancelled', updated_at = ?, completed_at = ?, progress_json = ?, error_json = NULL WHERE job_id = ?",
      now,
      now,
      JSON.stringify(progress),
      jobId,
    );

    if (row.status === "running") {
      await this.terminateWorkflowThenDisposeEndpoints(jobId);
    }
    await this.promoteQueuedJobs();
    return internalJson({
      cancelled: true,
      job: rowToJob(this.requireRow(jobId)),
    } satisfies SecurityAssessmentCancelResponse);
  }

  private async handleProgress(jobId: string, request: Request): Promise<Response> {
    const payload = await readBoundedJson(request, MAX_INTERNAL_PROGRESS_BYTES);
    if (!isSecurityAssessmentProgress(payload)) return internalError("Invalid progress update.", 400);
    const row = this.firstRow<JobRow>("SELECT * FROM security_assessment_jobs WHERE job_id = ? LIMIT 1", jobId);
    if (!row) return internalError("Not found.", 404);
    // A non-success response is a durable stop signal to a Workflow whose
    // termination raced or failed. It must not advance to another paid scan.
    if (row.status !== "running") return internalError("The job is no longer running.", 409);
    this.sql.exec(
      "UPDATE security_assessment_jobs SET updated_at = ?, progress_json = ? WHERE job_id = ?",
      Date.parse(payload.updatedAt),
      JSON.stringify(payload),
      jobId,
    );
    return internalJson(rowToJob(this.requireRow(jobId)));
  }

  private async handleComplete(jobId: string, request: Request): Promise<Response> {
    const payload = await readBoundedJson(request, MAX_INTERNAL_RESULT_BYTES);
    if (!isPlainObject(payload)) {
      return internalError("Invalid assessment result.", 400);
    }
    const result = repairLegacyBlankObservationSummaries(payload.result);
    if (!isSecurityAssessmentResult(result)) {
      return internalError("Invalid assessment result.", 400);
    }
    const row = this.firstRow<JobRow>("SELECT * FROM security_assessment_jobs WHERE job_id = ? LIMIT 1", jobId);
    if (!row) return internalError("Not found.", 404);
    if (row.status !== "running") {
      await this.disposeEndpointContainersBestEffort(jobId);
      return internalJson(rowToJob(row));
    }
    if (result.hostname !== row.hostname) return internalError("Invalid assessment result.", 400);

    const now = Date.now();
    this.sql.exec(
      `UPDATE security_assessment_jobs
       SET status = 'complete', updated_at = ?, completed_at = ?, progress_json = ?, result_json = ?, error_json = NULL
       WHERE job_id = ?`,
      now,
      now,
      JSON.stringify(completeProgress(
        result.tls.endpoints.length,
        parseProgress(row.progress_json).totalEndpoints,
        now,
      )),
      JSON.stringify(result),
      jobId,
    );
    // The per-endpoint release step is retried by Workflow, and terminal
    // publication adds an independent all-ID sweep. A retried publication
    // repeats the idempotent sweep if the first RPC attempt was unavailable.
    await this.disposeEndpointContainersBestEffort(jobId);
    await this.promoteQueuedJobs();
    return internalJson(rowToJob(this.requireRow(jobId)));
  }

  private async handleFailure(jobId: string, request: Request): Promise<Response> {
    const payload = await readBoundedJson(request, MAX_INTERNAL_PROGRESS_BYTES);
    if (!isPlainObject(payload) || !isJobError(payload.error)) return internalError("Invalid failure update.", 400);
    const row = this.firstRow<JobRow>("SELECT * FROM security_assessment_jobs WHERE job_id = ? LIMIT 1", jobId);
    if (!row) return internalError("Not found.", 404);
    if (row.status !== "running") {
      await this.disposeEndpointContainersBestEffort(jobId);
      return internalJson(rowToJob(row));
    }

    const now = Date.now();
    const prior = parseProgress(row.progress_json);
    const progress: SecurityAssessmentProgress = {
      phase: "failed",
      message: "The assessment could not be completed.",
      completedEndpoints: prior.completedEndpoints,
      totalEndpoints: prior.totalEndpoints,
      percent: 100,
      updatedAt: new Date(now).toISOString(),
    };
    this.sql.exec(
      `UPDATE security_assessment_jobs
       SET status = 'failed', updated_at = ?, completed_at = ?, progress_json = ?, error_json = ?
       WHERE job_id = ?`,
      now,
      now,
      JSON.stringify(progress),
      JSON.stringify(payload.error),
      jobId,
    );
    await this.disposeEndpointContainersBestEffort(jobId);
    await this.promoteQueuedJobs();
    return internalJson(rowToJob(this.requireRow(jobId)));
  }

  private async promoteQueuedJobs(reapStale = true): Promise<void> {
    if (reapStale) await this.reapStaleRunningJobs(Date.now());
    this.sql.exec(
      "DELETE FROM security_assessment_jobs WHERE expires_at <= ? AND status != 'running'",
      Date.now(),
    );
    const runningCount = this.firstRow<{ count: number }>(
      "SELECT COUNT(*) AS count FROM security_assessment_jobs WHERE status = 'running'",
    )?.count ?? 0;
    let capacity = Math.max(0, SECURITY_ASSESSMENT_GLOBAL_CONCURRENCY - Number(runningCount));
    while (capacity > 0) {
      const row = this.firstRow<JobRow>(
        "SELECT * FROM security_assessment_jobs WHERE status = 'queued' AND expires_at > ? ORDER BY created_at ASC LIMIT 1",
        Date.now(),
      );
      if (!row) return;
      const addresses = parseAddressList(row.addresses_json);
      const now = Date.now();
      const progress: SecurityAssessmentProgress = {
        phase: "web-security",
        message: "Running the bounded web-control observations.",
        completedEndpoints: 0,
        totalEndpoints: selectDeepTlsEndpoints(addresses).length,
        percent: 5,
        updatedAt: new Date(now).toISOString(),
      };
      this.sql.exec(
        "UPDATE security_assessment_jobs SET status = 'running', updated_at = ?, progress_json = ? WHERE job_id = ? AND status = 'queued'",
        now,
        JSON.stringify(progress),
        row.job_id,
      );
      try {
        await this.env.SECURITY_ASSESSMENT_WORKFLOW.create({
          id: row.job_id,
          params: {
            jobId: row.job_id,
            hostname: row.hostname,
            addresses,
            startedAt: new Date(now).toISOString(),
          },
          retention: { successRetention: "1 day", errorRetention: "1 day" },
        });
        capacity -= 1;
      } catch {
        const failure: SecurityAssessmentJobError = {
          code: "ORCHESTRATION_FAILED",
          message: "The isolated assessment worker could not be started.",
        };
        const failedProgress: SecurityAssessmentProgress = {
          ...progress,
          phase: "failed",
          message: "The assessment worker could not be started.",
          percent: 100,
          updatedAt: new Date(Date.now()).toISOString(),
        };
        this.sql.exec(
          `UPDATE security_assessment_jobs
           SET status = 'failed', updated_at = ?, completed_at = ?, progress_json = ?, error_json = ?
           WHERE job_id = ?`,
          Date.now(),
          Date.now(),
          JSON.stringify(failedProgress),
          JSON.stringify(failure),
          row.job_id,
        );
        // Publish the terminal lease state before cleanup. An ambiguously
        // accepted Workflow then receives 409 on progress while termination
        // and the final all-endpoint sweep settle.
        await this.terminateWorkflowThenDisposeEndpoints(row.job_id);
      }
    }
  }

  private async reapStaleRunningJobs(now: number): Promise<number> {
    const stale = [...this.sql.exec<JobRow>(
      "SELECT * FROM security_assessment_jobs WHERE status = 'running' AND updated_at <= ? ORDER BY updated_at ASC",
      now - SECURITY_ASSESSMENT_STALE_RUNNING_MS,
    )];
    for (const row of stale) {
      const prior = parseProgress(row.progress_json);
      const failure: SecurityAssessmentJobError = {
        code: "ORCHESTRATION_FAILED",
        message: "The assessment stopped reporting progress and was safely recovered.",
      };
      const failedProgress: SecurityAssessmentProgress = {
        ...prior,
        phase: "failed",
        message: "The assessment stopped reporting progress.",
        percent: 100,
        updatedAt: new Date(now).toISOString(),
      };
      this.sql.exec(
        `UPDATE security_assessment_jobs
         SET status = 'failed', updated_at = ?, completed_at = ?, progress_json = ?, error_json = ?
         WHERE job_id = ? AND status = 'running'`,
        now,
        now,
        JSON.stringify(failedProgress),
        JSON.stringify(failure),
        row.job_id,
      );
      await this.terminateWorkflowThenDisposeEndpoints(row.job_id);
    }
    return stale.length;
  }

  private destroyEndpointContainers(jobId: string): Promise<void>[] {
    return Array.from({ length: MAX_DEEP_TLS_ENDPOINTS }, async (_, endpointIndex) => {
      const container = getContainer(this.env.DEEP_TLS_SCANNER, `${jobId}-e${endpointIndex}`);
      await container.dispose();
    });
  }

  /**
   * Termination is awaited before the final all-ID sweep so a Workflow cannot
   * advance into a new endpoint after that endpoint was already disposed.
   * A rejected termination still receives the final sweep; terminal progress
   * updates then stop any surviving Workflow before its next endpoint.
   */
  private async terminateWorkflowThenDisposeEndpoints(jobId: string): Promise<void> {
    await Promise.allSettled([
      this.env.SECURITY_ASSESSMENT_WORKFLOW.get(jobId).then((instance) => instance.terminate()),
    ]);
    await this.disposeEndpointContainersBestEffort(jobId);
  }

  private async disposeEndpointContainersBestEffort(jobId: string): Promise<void> {
    await Promise.allSettled(this.destroyEndpointContainers(jobId));
  }

  private requireRow(jobId: string): JobRow {
    const row = this.firstRow<JobRow>("SELECT * FROM security_assessment_jobs WHERE job_id = ? LIMIT 1", jobId);
    if (!row) throw new Error("The job row disappeared.");
    return row;
  }

  private firstRow<T extends Record<string, SqlStorageValue>>(query: string, ...bindings: SqlStorageValue[]): T | undefined {
    return [...this.sql.exec<T>(query, ...bindings)][0];
  }
}

interface JobRow {
  [key: string]: SqlStorageValue;
  job_id: string;
  hostname: string;
  target_key: string;
  addresses_json: string;
  status: string;
  created_at: number;
  updated_at: number;
  expires_at: number;
  completed_at: number | null;
  progress_json: string;
  result_json: string | null;
  error_json: string | null;
  source_job_id: string | null;
  cancel_token_hash: string | null;
}

/** Durable Workflow: one combined web + deep TLS result, with no automatic active-test retries. */
export class SecurityAssessmentWorkflow extends WorkflowEntrypoint<
  SecurityAssessmentBindings,
  SecurityAssessmentWorkflowParams
> {
  async run(event: Readonly<WorkflowEvent<SecurityAssessmentWorkflowParams>>, step: WorkflowStep): Promise<unknown> {
    const params = event.payload;
    if (!isWorkflowParams(params)) throw new NonRetryableError("Invalid assessment workflow parameters.");
    const selected = selectDeepTlsEndpoints(params.addresses);
    const reports: DeepTlsResponseV1[] = [];
    const limitations: string[] = [];

    try {
      const webBundle = await step.do(
        "bounded web-control assessment",
        { retries: { limit: 0, delay: "1 second" }, timeout: "1 minute" },
        async () => {
          const telemetry: PinnedHttpTelemetry = { pinnedSocketAttempts: 0, platformFetchFallbacks: 0 };
          const execution = await scanWebSecurity(params.hostname, {
            fetcher: createPinnedHttpFetcher({ platformFallback: fetch, telemetry }),
          });
          return { execution, telemetry };
        },
      );
      const { tls: _unsupportedNativeTls, ...webWithoutTls } = webBundle.execution;
      const web = webBundle.telemetry.platformFetchFallbacks > 0
        ? {
          ...webWithoutTls,
          summary: `${webWithoutTls.summary} ${webBundle.telemetry.platformFetchFallbacks} bounded request(s) used the Cloudflare HTTP fetch path after raw socket pinning was unavailable; fresh DNS was validated before and after each request, but those requests were not IP-pinned.`,
        }
        : webWithoutTls;

      await postProgress(this.env, params.jobId, progress(
        "tls-validation",
        "Validating every public TLS endpoint before active testing.",
        0,
        selected.length,
        20,
      ));

      for (const [index, address] of selected.entries()) {
        await postProgress(this.env, params.jobId, progress(
          "tls-scanning",
          `Running the bounded deep TLS profile for endpoint ${index + 1} of ${selected.length}.`,
          index,
          selected.length,
          selected.length === 0 ? 75 : 20 + Math.floor((index / selected.length) * 70),
        ));

        try {
          const outcome = await step.do(
            `fresh validation and deep TLS endpoint ${index + 1}`,
            { retries: { limit: 0, delay: "1 second" }, timeout: "4 minutes" },
            () => scanFreshDeepTlsEndpoint(
              this.env,
              params.jobId,
              index,
              params.hostname,
              address,
            ),
          );
          if (outcome.kind === "complete") {
            reports.push(outcome.report);
          } else {
            limitations.push(outcome.limitation);
            if (outcome.kind === "validation-unavailable") break;
          }
        } catch {
          limitations.push(`Endpoint ${address} did not return a valid bounded deep TLS report.`);
        } finally {
          // step.do resolves only after its result is durably recorded. Keep the
          // Container DO's scan-once record until then, and only now stop/wipe it.
          await step.do(
            `release deep TLS endpoint ${index + 1}`,
            { retries: { limit: 3, delay: "2 seconds", backoff: "exponential" }, timeout: "30 seconds" },
            () => disposeDeepTlsEndpoint(this.env, params.jobId, index),
          ).catch(() => {
            limitations.push(`Endpoint ${address} cleanup was deferred to the Container recovery alarm.`);
          });
        }
      }

      await postProgress(this.env, params.jobId, progress(
        "finalizing",
        "Validating and combining the web and TLS evidence.",
        reports.length,
        selected.length,
        95,
      ));
      const completedAt = new Date().toISOString();
      const result: SecurityAssessmentResult = {
        schemaVersion: "security-assessment-v1",
        hostname: params.hostname,
        startedAt: params.startedAt,
        completedAt,
        durationMs: Math.max(1, Date.parse(completedAt) - Date.parse(params.startedAt)),
        web,
        tls: aggregateDeepTlsReports(params.addresses, selected, reports, limitations),
        disclaimer: SECURITY_ASSESSMENT_DISCLAIMER,
      };
      if (!isSecurityAssessmentResult(result)) throw new Error("The combined result failed validation.");
      if (jsonByteLength(result) > MAX_COMBINED_ASSESSMENT_BYTES) {
        throw new Error("The combined assessment exceeded its normalized result limit.");
      }

      await step.do(
        "publish combined result",
        { retries: { limit: 3, delay: "2 seconds", backoff: "exponential" }, timeout: "30 seconds" },
        () => postCoordinator(this.env, `/jobs/${params.jobId}/complete`, { result }),
      );
      return { jobId: params.jobId, status: "complete" };
    } catch (error) {
      const failure = workflowFailure(error);
      await publishWorkflowFailure(step, () => (
        postCoordinator(this.env, `/jobs/${params.jobId}/fail`, { error: failure })
      ));
      throw new NonRetryableError("The bounded security assessment failed.");
    }
  }
}

/** Failure publication gets the same durable, bounded delivery semantics as success. */
export async function publishWorkflowFailure(
  step: WorkflowStep,
  publish: () => Promise<void>,
): Promise<void> {
  await step.do(
    "publish assessment failure",
    { retries: { limit: 3, delay: "2 seconds", backoff: "exponential" }, timeout: "30 seconds" },
    publish,
  );
}

export type FreshDeepTlsEndpointOutcome =
  | { kind: "complete"; report: DeepTlsResponseV1 }
  | { kind: "target-changed" | "validation-unavailable" | "scan-unavailable"; limitation: string };

/**
 * Fresh DNS authorization and the active container call deliberately share
 * one Workflow step. A resumed Workflow therefore cannot reuse a completed
 * DNS-only step and scan later against stale membership evidence.
 */
export async function scanFreshDeepTlsEndpoint(
  env: SecurityAssessmentBindings,
  jobId: string,
  endpointIndex: number,
  hostname: string,
  address: string,
  dependencies: {
    resolve?: typeof resolvePublicHost;
    scan?: typeof scanDeepTlsEndpoint;
  } = {},
): Promise<FreshDeepTlsEndpointOutcome> {
  const resolver = dependencies.resolve ?? resolvePublicHost;
  const scanner = dependencies.scan ?? scanDeepTlsEndpoint;
  let currentAddresses: string[];
  try {
    currentAddresses = await resolver(hostname);
  } catch (error) {
    return { kind: "validation-unavailable", limitation: publicEndpointFailure(address, error) };
  }
  if (!isFreshEndpointAuthorized(address, currentAddresses)) {
    return {
      kind: "target-changed",
      limitation: `Endpoint ${address} was not scanned because it was no longer in the hostname's fresh public DNS answer.`,
    };
  }
  try {
    return {
      kind: "complete",
      report: await scanner(env, jobId, endpointIndex, hostname, address),
    };
  } catch {
    return {
      kind: "scan-unavailable",
      limitation: `Endpoint ${address} did not return a valid bounded deep TLS report.`,
    };
  }
}

export async function scanDeepTlsEndpoint(
  env: SecurityAssessmentBindings,
  jobId: string,
  endpointIndex: number,
  hostname: string,
  address: string,
): Promise<DeepTlsResponseV1> {
  const instanceName = `${jobId}-e${endpointIndex}`;
  const container = getContainer(env.DEEP_TLS_SCANNER, instanceName);
  const identity = { hostname, address, deadlineMs: DEEP_TLS_ENDPOINT_DEADLINE_MS } as const;
  const claim = await container.claimScan(identity);
  if (claim.status === "complete") {
    return compactDeepTlsResponse(validateDeepTlsResponse(claim.result, identity));
  }
  if (claim.status === "in-progress") {
    throw new Error("The deep TLS endpoint already has an unfinished scan-once claim.");
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEEP_TLS_ENDPOINT_DEADLINE_MS + 15_000);
  try {
    await container.setAllowedHosts([address]);
    const response = await container.fetch("http://container/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ hostname, address, profile: "safe", deadlineMs: DEEP_TLS_ENDPOINT_DEADLINE_MS }),
      signal: controller.signal,
    });
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new Error("The deep TLS container rejected the bounded request.");
    }
    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.includes("application/json")) {
      await response.body?.cancel().catch(() => undefined);
      throw new Error("The deep TLS container returned an unsupported content type.");
    }
    const declaredLength = Number(response.headers.get("content-length") ?? "0");
    if (Number.isFinite(declaredLength) && declaredLength > MAX_DEEP_TLS_RESPONSE_BYTES) {
      await response.body?.cancel().catch(() => undefined);
      throw new Error("The deep TLS report exceeded the response limit.");
    }
    const payload = await readBoundedJson(response, MAX_DEEP_TLS_RESPONSE_BYTES);
    const validated = validateDeepTlsResponse(payload, { hostname, address, deadlineMs: DEEP_TLS_ENDPOINT_DEADLINE_MS });
    const compact = compactDeepTlsResponse(validated);
    await container.storeScanResult(identity, claim.ownerToken, compact);
    return compact;
  } finally {
    clearTimeout(timeout);
  }
}

export async function disposeDeepTlsEndpoint(
  env: SecurityAssessmentBindings,
  jobId: string,
  endpointIndex: number,
): Promise<void> {
  const container = getContainer(env.DEEP_TLS_SCANNER, `${jobId}-e${endpointIndex}`);
  await container.dispose();
}

export function validateDeepTlsResponse(
  value: unknown,
  expected: { hostname: string; address: string; deadlineMs: number },
): DeepTlsResponseV1 {
  if (!isDeepTlsResponse(value, expected)) {
    throw new Error("The deep TLS container returned an invalid report.");
  }
  return value;
}

export function compactDeepTlsResponse(
  report: DeepTlsResponseV1,
  maximumBytes = MAX_NORMALIZED_DEEP_TLS_ENDPOINT_BYTES,
): DeepTlsResponseV1 {
  if (jsonByteLength(report) <= maximumBytes) return report;
  const compact = JSON.parse(JSON.stringify(report)) as DeepTlsResponseV1;
  const truncationNotice =
    "Displayed endpoint evidence was truncated to the combined-result size limit; the grade was computed from the full bounded scanner output.";
  compact.limitations = uniqueBoundedStrings([...compact.limitations, truncationNotice], MAX_LIMITATIONS, MAX_RESULT_TEXT);
  compact.grade = compactGrade(compact.grade);

  for (const sectionName of SECTION_NAMES) {
    const section = compact.sections[sectionName];
    section.grade = compactGrade(section.grade);
    section.observations = section.observations.map((observation) => ({
      ...observation,
      summary: observation.summary.slice(0, MAX_RESULT_SHORT_TEXT),
      ...(observation.details === undefined ? {} : { details: compactDetails(observation.details) }),
    })).sort((left, right) => observationPriority(left) - observationPriority(right));
  }
  compact.issues = compact.issues.map((issue) => ({
    ...issue,
    summary: issue.summary.slice(0, MAX_RESULT_SHORT_TEXT),
  }));
  compact.limitations = compact.limitations.map((limitation) => limitation.slice(0, MAX_RESULT_SHORT_TEXT));

  while (jsonByteLength(compact) > maximumBytes) {
    const largest = SECTION_NAMES
      .map((name) => compact.sections[name])
      .sort((left, right) => right.observations.length - left.observations.length)[0];
    if (!largest || largest.observations.length === 0) break;
    largest.observations.pop();
    compact.issues = compact.issues.filter((issue) =>
      compact.sections[issue.section].observations.some((observation) => observation.id === issue.observationId));
  }
  while (jsonByteLength(compact) > maximumBytes && compact.issues.length > 0) compact.issues.pop();
  while (jsonByteLength(compact) > maximumBytes && compact.limitations.length > 1) compact.limitations.shift();
  if (jsonByteLength(compact) > maximumBytes) {
    throw new Error("The normalized endpoint report could not fit the result limit.");
  }
  return compact;
}

export function aggregateDeepTlsReports(
  allAddresses: readonly string[],
  selectedAddresses: readonly string[],
  endpoints: DeepTlsResponseV1[],
  extraLimitations: readonly string[],
): DeepTlsAssessmentResult {
  const endpointsTruncated = allAddresses.length > selectedAddresses.length;
  const status: DeepTlsReportStatus = endpoints.length === 0
    ? "unavailable"
    : endpoints.length === selectedAddresses.length
      && endpoints.every((endpoint) => endpoint.status === "complete")
      && extraLimitations.length === 0
      ? "complete"
      : "partial";
  const grade = aggregateGrade(selectedAddresses.length, endpoints);
  const limitations = uniqueBoundedStrings([
    ...endpoints.flatMap((endpoint) => endpoint.limitations),
    ...extraLimitations,
    ...(endpointsTruncated
      ? [`Deep TLS work was capped at ${MAX_DEEP_TLS_ENDPOINTS} representative public endpoints; all resolved addresses were safety-validated.`]
      : []),
    "The Cresswell TLS grade is independent methodology and is not an SSL Labs grade or compliance certification.",
  ], MAX_LIMITATIONS, MAX_RESULT_TEXT);
  const summary = status === "unavailable"
    ? "No endpoint returned enough tested deep TLS evidence for a grade."
    : status === "partial"
      ? `${endpoints.length} of ${selectedAddresses.length} selected endpoints returned at least partial deep TLS evidence.`
      : `All ${endpoints.length} selected endpoints completed the bounded deep TLS profile.`;
  return {
    status,
    grade,
    summary,
    resolvedAddresses: [...allAddresses],
    endpoints,
    endpointsTruncated,
    limitations,
  };
}

export function isFreshEndpointAuthorized(address: string, freshPublicAddresses: readonly string[]): boolean {
  return freshPublicAddresses.includes(address);
}

function aggregateGrade(expectedEndpointCount: number, endpoints: readonly DeepTlsResponseV1[]): DeepTlsGrade {
  const representativeTotal = endpoints[0]?.grade.coverage.totalWeight ?? 0;
  const totalWeight = representativeTotal * expectedEndpointCount;
  const evaluatedWeight = endpoints.reduce((sum, endpoint) => sum + endpoint.grade.coverage.evaluatedWeight, 0);
  const graded = endpoints.map((endpoint) => endpoint.grade).filter((grade) => grade.value !== "N/A");
  const enoughCoverage = totalWeight > 0 && evaluatedWeight / totalWeight >= 0.7;
  const worst = graded.sort((left, right) => gradeRank(left.value) - gradeRank(right.value))[0];
  const caps = endpoints.flatMap((endpoint) => endpoint.grade.caps.map((cap) => ({
    ...cap,
    id: `${endpoint.target.address}:${cap.id}`,
  }))).sort((left, right) =>
    gradeRank(left.maxGrade) - gradeRank(right.maxGrade) || left.id.localeCompare(right.id)).slice(0, 16);
  const baseValue = enoughCoverage && worst ? worst.value : "N/A";
  const worstCap = caps[0];
  const value = baseValue !== "N/A" && worstCap && gradeRank(worstCap.maxGrade) < gradeRank(baseValue)
    ? worstCap.maxGrade
    : baseValue;
  return {
    value,
    score: enoughCoverage && worst
      ? Math.min(...graded.map((grade) => grade.score ?? 100))
      : null,
    coverage: { evaluatedWeight, totalWeight },
    methodology: "cresswell-tls-v1",
    caps,
  };
}

function gradeRank(value: DeepTlsGradeValue): number {
  return ({ F: 0, D: 1, C: 2, B: 3, A: 4, "N/A": 5 } as const)[value];
}

function workflowFailure(error: unknown): SecurityAssessmentJobError {
  if (error instanceof UnsafeScanTargetError) {
    return { code: "TARGET_CHANGED", message: "The target no longer resolved exclusively to approved public addresses." };
  }
  if (error instanceof ScanTargetResolutionError) {
    return { code: "TARGET_UNAVAILABLE", message: "The target could not be resolved safely during the assessment." };
  }
  return { code: "ORCHESTRATION_FAILED", message: "The isolated assessment could not be completed." };
}

function publicEndpointFailure(address: string, error: unknown): string {
  return error instanceof UnsafeScanTargetError
    ? `Scanning stopped before endpoint ${address} because fresh DNS was no longer exclusively public.`
    : `Scanning stopped before endpoint ${address} because fresh DNS validation was unavailable.`;
}

async function postProgress(
  env: SecurityAssessmentBindings,
  jobId: string,
  value: SecurityAssessmentProgress,
): Promise<void> {
  await postCoordinator(env, `/jobs/${jobId}/progress`, value);
}

async function postCoordinator(env: SecurityAssessmentBindings, path: string, body: unknown): Promise<void> {
  const response = await coordinatorStub(env).fetch(`https://security-assessment.internal${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new SecurityAssessmentConfigurationError("The assessment coordinator rejected an internal update.");
  }
  await response.body?.cancel().catch(() => undefined);
}

async function coordinatorJsonRequest<T>(
  env: SecurityAssessmentBindings,
  path: string,
  init: RequestInit,
  validator: (value: unknown) => value is T,
): Promise<T> {
  const response = await coordinatorStub(env).fetch(`https://security-assessment.internal${path}`, init);
  if (response.status === 404) {
    await response.body?.cancel().catch(() => undefined);
    throw new SecurityAssessmentNotFoundError();
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new SecurityAssessmentConfigurationError("The assessment coordinator is unavailable.");
  }
  const payload = await readBoundedJson(response, MAX_INTERNAL_RESULT_BYTES);
  if (!validator(payload)) {
    throw new SecurityAssessmentConfigurationError("The assessment coordinator returned an invalid response.");
  }
  return payload;
}

function coordinatorStub(env: SecurityAssessmentBindings): DurableObjectStub {
  const namespace = env.SECURITY_ASSESSMENT_COORDINATOR;
  if (!namespace || typeof namespace.idFromName !== "function" || typeof namespace.get !== "function") {
    throw new SecurityAssessmentConfigurationError("The assessment coordinator is not configured.");
  }
  return namespace.get(namespace.idFromName("global-v1"));
}

function validateJobId(jobId: string): void {
  if (!SECURITY_ASSESSMENT_JOB_ID_PATTERN.test(jobId)) throw new SecurityAssessmentNotFoundError();
}

function rowToJob(row: JobRow): SecurityAssessmentJobResource {
  if (!isJobStatus(row.status)) throw new Error("Invalid stored job status.");
  const progressValue = parseProgress(row.progress_json);
  const resultValue = row.result_json
    ? repairLegacyBlankObservationSummaries(JSON.parse(row.result_json) as unknown)
    : undefined;
  const errorValue = row.error_json ? JSON.parse(row.error_json) as unknown : undefined;
  if (resultValue !== undefined && !isSecurityAssessmentResult(resultValue)) throw new Error("Invalid stored job result.");
  if (errorValue !== undefined && !isJobError(errorValue)) throw new Error("Invalid stored job error.");
  if (row.status === "complete" && resultValue === undefined) throw new Error("A completed job has no result.");
  if (row.status === "failed" && errorValue === undefined) throw new Error("A failed job has no error.");
  if (row.status !== "complete" && resultValue !== undefined) throw new Error("A non-complete job has a result.");
  if (row.status !== "failed" && errorValue !== undefined) throw new Error("A non-failed job has an error.");
  return {
    jobId: row.job_id,
    hostname: row.hostname,
    status: row.status,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    expiresAt: new Date(row.expires_at).toISOString(),
    progress: progressValue,
    ...(resultValue ? { result: resultValue } : {}),
    ...(errorValue ? { error: errorValue } : {}),
  };
}

/**
 * Reports created by the initial deep-scanner release could contain an empty
 * informational finding when testssl.sh returned an explicit empty string.
 * Repair only that legacy omission at ingress/read time so retained cache hits
 * remain usable while every other report field still passes the strict schema.
 */
function repairLegacyBlankObservationSummaries(value: unknown): unknown {
  if (!isPlainObject(value) || !isPlainObject(value.tls) || !Array.isArray(value.tls.endpoints)) return value;
  for (const endpoint of value.tls.endpoints) {
    if (!isPlainObject(endpoint) || !isPlainObject(endpoint.sections)) continue;
    for (const section of Object.values(endpoint.sections)) {
      if (!isPlainObject(section) || !Array.isArray(section.observations)) continue;
      for (const observation of section.observations) {
        if (
          isPlainObject(observation)
          && typeof observation.summary === "string"
          && observation.summary.trim().length === 0
          && observation.status === "info"
          && observation.evidenceKind === "tested"
          && observation.severity === "info"
          && typeof observation.sourceId === "string"
          && observation.sourceId.length > 0
        ) {
          observation.summary = "No bounded finding was returned.";
        }
      }
    }
  }
  return value;
}

function queuedProgress(totalEndpoints: number, now: number): SecurityAssessmentProgress {
  return {
    phase: "queued",
    message: "Waiting for one of the two isolated assessment slots.",
    completedEndpoints: 0,
    totalEndpoints: Math.min(totalEndpoints, MAX_DEEP_TLS_ENDPOINTS),
    percent: 0,
    updatedAt: new Date(now).toISOString(),
  };
}

function completeProgress(completedEndpoints: number, totalEndpoints: number, now: number): SecurityAssessmentProgress {
  return {
    phase: "complete",
    message: "The combined assessment is complete.",
    completedEndpoints,
    totalEndpoints,
    percent: 100,
    updatedAt: new Date(now).toISOString(),
  };
}

function progress(
  phase: SecurityAssessmentProgressPhase,
  message: string,
  completedEndpoints: number,
  totalEndpoints: number,
  percent: number,
): SecurityAssessmentProgress {
  return {
    phase,
    message,
    completedEndpoints,
    totalEndpoints,
    percent,
    updatedAt: new Date().toISOString(),
  };
}

function parseProgress(value: string): SecurityAssessmentProgress {
  const parsed = JSON.parse(value) as unknown;
  if (!isSecurityAssessmentProgress(parsed)) throw new Error("Invalid stored progress.");
  return parsed;
}

function parseAddressList(value: string): string[] {
  const parsed = JSON.parse(value) as unknown;
  const addresses = validateStoredAddressList(parsed);
  if (!addresses) throw new Error("Invalid stored address list.");
  return addresses;
}

function validateStoredAddressList(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16 || value.some((entry) => typeof entry !== "string")) {
    return undefined;
  }
  const addresses = [...new Set(value as string[])].sort();
  if (addresses.length !== value.length) return undefined;
  try {
    return resolveValidatedAddressLiterals(addresses);
  } catch {
    return undefined;
  }
}

function resolveValidatedAddressLiterals(addresses: string[]): string[] {
  return addresses.map(canonicalPublicScanAddress);
}

function terminalStatus(status: SecurityAssessmentJobStatus | string): boolean {
  return status === "complete" || status === "cancelled" || status === "failed";
}

function isCreateInput(value: unknown): value is CreateSecurityAssessmentInput {
  return isPlainObject(value)
    && hasExactKeys(value, ["jobId", "hostname", "addresses", "createdAt", "cancelTokenHash"])
    && typeof value.jobId === "string"
    && SECURITY_ASSESSMENT_JOB_ID_PATTERN.test(value.jobId)
    && isHostname(value.hostname)
    && Array.isArray(value.addresses)
    && typeof value.createdAt === "string"
    && typeof value.cancelTokenHash === "string"
    && /^[a-f0-9]{64}$/u.test(value.cancelTokenHash);
}

function isWorkflowParams(value: unknown): value is SecurityAssessmentWorkflowParams {
  return isPlainObject(value)
    && hasExactKeys(value, ["jobId", "hostname", "addresses", "startedAt"])
    && typeof value.jobId === "string"
    && SECURITY_ASSESSMENT_JOB_ID_PATTERN.test(value.jobId)
    && isHostname(value.hostname)
    && validateStoredAddressList(value.addresses) !== undefined
    && isTimestamp(value.startedAt);
}

function isCoordinatorCreateResult(value: unknown): value is CoordinatorCreateResult {
  return isPlainObject(value)
    && hasExactKeys(value, ["job", "reuse", "pollAfterSeconds"])
    && isSecurityAssessmentJobResource(value.job)
    && (value.reuse === "new" || value.reuse === "cache-hit" || value.reuse === "single-flight")
    && typeof value.pollAfterSeconds === "number"
    && Number.isInteger(value.pollAfterSeconds)
    && value.pollAfterSeconds >= 0
    && value.pollAfterSeconds <= 30;
}

export function isSecurityAssessmentJobResource(value: unknown): value is SecurityAssessmentJobResource {
  if (!isPlainObject(value)) return false;
  const allowed = ["jobId", "hostname", "status", "createdAt", "updatedAt", "expiresAt", "progress", "result", "error"];
  if (!hasOnlyKeys(value, allowed)
    || typeof value.jobId !== "string"
    || !SECURITY_ASSESSMENT_JOB_ID_PATTERN.test(value.jobId)
    || !isHostname(value.hostname)
    || !isJobStatus(value.status)
    || !isTimestamp(value.createdAt)
    || !isTimestamp(value.updatedAt)
    || !isTimestamp(value.expiresAt)
    || Date.parse(value.createdAt) > Date.parse(value.updatedAt)
    || Date.parse(value.updatedAt) > Date.parse(value.expiresAt)
    || !isSecurityAssessmentProgress(value.progress)) return false;
  if (value.status === "complete") return isSecurityAssessmentResult(value.result) && value.error === undefined;
  if (value.status === "failed") return isJobError(value.error) && value.result === undefined;
  return value.result === undefined && value.error === undefined;
}

function isSecurityAssessmentCancelResponse(value: unknown): value is SecurityAssessmentCancelResponse {
  return isPlainObject(value)
    && hasExactKeys(value, ["cancelled", "job"])
    && typeof value.cancelled === "boolean"
    && isSecurityAssessmentJobResource(value.job);
}

function isSecurityAssessmentProgress(value: unknown): value is SecurityAssessmentProgress {
  if (!isPlainObject(value) || !hasOnlyKeys(value, [
    "phase", "message", "completedEndpoints", "totalEndpoints", "percent", "updatedAt",
  ])) return false;
  const phases: readonly SecurityAssessmentProgressPhase[] = [
    "queued", "web-security", "tls-validation", "tls-scanning", "finalizing", "complete", "cancelled", "failed",
  ];
  return phases.includes(value.phase as SecurityAssessmentProgressPhase)
    && isBoundedString(value.message, MAX_RESULT_SHORT_TEXT)
    && typeof value.completedEndpoints === "number"
    && Number.isInteger(value.completedEndpoints)
    && value.completedEndpoints >= 0
    && value.completedEndpoints <= MAX_DEEP_TLS_ENDPOINTS
    && typeof value.totalEndpoints === "number"
    && Number.isInteger(value.totalEndpoints)
    && value.totalEndpoints >= 0
    && value.totalEndpoints <= MAX_DEEP_TLS_ENDPOINTS
    && value.completedEndpoints <= value.totalEndpoints
    && (value.percent === undefined
      || (typeof value.percent === "number" && Number.isInteger(value.percent) && value.percent >= 0 && value.percent <= 100))
    && isTimestamp(value.updatedAt);
}

function isJobStatus(value: unknown): value is SecurityAssessmentJobStatus {
  return value === "queued" || value === "running" || value === "complete" || value === "cancelled" || value === "failed";
}

function isJobError(value: unknown): value is SecurityAssessmentJobError {
  if (!isPlainObject(value) || !hasExactKeys(value, ["code", "message"]) || !isBoundedString(value.message, MAX_RESULT_SHORT_TEXT)) {
    return false;
  }
  return ["TARGET_CHANGED", "TARGET_UNAVAILABLE", "WEB_SCAN_FAILED", "TLS_SCAN_FAILED", "ORCHESTRATION_FAILED"]
    .includes(String(value.code));
}

function isSecurityAssessmentResult(value: unknown): value is SecurityAssessmentResult {
  if (!isPlainObject(value)
    || !hasExactKeys(value, ["schemaVersion", "hostname", "startedAt", "completedAt", "durationMs", "web", "tls", "disclaimer"])
    || value.schemaVersion !== "security-assessment-v1"
    || !isHostname(value.hostname)
    || !isTimestamp(value.startedAt)
    || !isTimestamp(value.completedAt)
    || Date.parse(value.startedAt) > Date.parse(value.completedAt)
    || !isNonNegativeInteger(value.durationMs, SECURITY_ASSESSMENT_JOB_RETENTION_MS)
    || value.disclaimer !== SECURITY_ASSESSMENT_DISCLAIMER
    || !isWebSecurityResult(value.web, value.hostname)
    || !isDeepTlsAssessment(value.tls, value.hostname)) return false;
  return jsonByteLength(value) <= MAX_COMBINED_ASSESSMENT_BYTES;
}

function isWebSecurityResult(value: unknown, hostname: string): boolean {
  if (!isPlainObject(value) || !hasExactKeys(value, [
    "hostname", "effectiveUrl", "scannedAt", "durationMs", "score", "grade", "headline", "summary", "checks",
    "coverage", "requestBudget", "disclaimer",
  ])) return false;
  if (value.hostname !== hostname
    || !isBoundedString(value.effectiveUrl, 4_096)
    || !isSafeObservedUrl(value.effectiveUrl, hostname)
    || !isTimestamp(value.scannedAt)
    || !isNonNegativeInteger(value.durationMs, 60_000)
    || !isNonNegativeInteger(value.score, 100)
    || !(["A", "B", "C", "D", "F", "N/A"] as const).includes(value.grade as never)
    || !isBoundedString(value.headline, MAX_RESULT_SHORT_TEXT)
    || !isBoundedString(value.summary, 4_096)
    || value.disclaimer !== WEB_SECURITY_DISCLAIMER
    || !Array.isArray(value.checks)
    || value.checks.length !== 20) return false;
  const ids = new Set<string>();
  for (const check of value.checks) {
    if (!isWebSecurityCheck(check)) return false;
    ids.add(String(check.id));
  }
  if (ids.size !== 20 || WEB_CHECK_IDS.some((id) => !ids.has(id))) return false;
  if (!isPlainObject(value.coverage) || !hasExactKeys(value.coverage, ["evaluated", "total", "unknown", "notApplicable"])) {
    return false;
  }
  if (value.coverage.total !== 20
    || !isNonNegativeInteger(value.coverage.evaluated, 20)
    || !isNonNegativeInteger(value.coverage.unknown, 20)
    || !isNonNegativeInteger(value.coverage.notApplicable, 20)
    || value.coverage.evaluated + value.coverage.unknown + value.coverage.notApplicable !== 20) return false;
  if (!isPlainObject(value.requestBudget) || !hasExactKeys(value.requestBudget, [
    "httpRequests", "tlsConnections", "maxResponseBytes", "redirectHopsFollowed",
  ])) return false;
  return isNonNegativeInteger(value.requestBudget.httpRequests, 6)
    && value.requestBudget.tlsConnections === 0
    && value.requestBudget.maxResponseBytes === 131_072
    && isNonNegativeInteger(value.requestBudget.redirectHopsFollowed, 2);
}

function isWebSecurityCheck(value: unknown): boolean {
  if (!isPlainObject(value) || !hasExactKeys(value, [
    "id", "status", "title", "summary", "evidence", "remediation", "owasp",
  ])) return false;
  if (!WEB_CHECK_IDS.includes(value.id as never)
    || !(["pass", "warning", "fail", "not-applicable", "unknown"] as const).includes(value.status as never)
    || !isBoundedString(value.title, 256)
    || !isBoundedString(value.summary, 2_048)
    || !isStringArray(value.evidence, 12, 512)
    || !isBoundedString(value.remediation, 2_048)
    || !isPlainObject(value.owasp)
    || !hasExactKeys(value.owasp, ["top10", "wstg"])) return false;
  return isStringArray(value.owasp.top10, 8, 128) && isStringArray(value.owasp.wstg, 8, 128);
}

function isSafeObservedUrl(value: string, hostname: string): boolean {
  try {
    const url = new URL(value);
    const candidate = url.hostname.toLowerCase();
    const normalized = hostname.toLowerCase();
    const allowedHost = candidate === normalized || (normalized.startsWith("www.")
      ? candidate === normalized.slice(4)
      : candidate === `www.${normalized}`);
    return (url.protocol === "http:" || url.protocol === "https:")
      && allowedHost
      && !url.username
      && !url.password
      && !url.port;
  } catch {
    return false;
  }
}

function isDeepTlsAssessment(value: unknown, hostname: string): value is DeepTlsAssessmentResult {
  if (!isPlainObject(value)
    || !hasExactKeys(value, ["status", "grade", "summary", "resolvedAddresses", "endpoints", "endpointsTruncated", "limitations"])
    || !isReportStatus(value.status)
    || !isDeepTlsGrade(value.grade)
    || !isBoundedString(value.summary, MAX_RESULT_TEXT)
    || validateStoredAddressList(value.resolvedAddresses) === undefined
    || !Array.isArray(value.endpoints)
    || value.endpoints.length > MAX_DEEP_TLS_ENDPOINTS
    || typeof value.endpointsTruncated !== "boolean"
    || !isNonEmptyStringArray(value.limitations, MAX_LIMITATIONS, MAX_RESULT_SHORT_TEXT)) return false;
  return value.endpoints.every((endpoint) => {
    if (!isPlainObject(endpoint) || !isPlainObject(endpoint.target) || typeof endpoint.target.address !== "string") return false;
    return isDeepTlsResponse(endpoint, {
      hostname,
      address: endpoint.target.address,
      deadlineMs: DEEP_TLS_ENDPOINT_DEADLINE_MS,
    });
  });
}

function isDeepTlsResponse(
  value: unknown,
  expected: { hostname: string; address: string; deadlineMs: number },
): value is DeepTlsResponseV1 {
  if (!isPlainObject(value) || !hasExactKeys(value, [
    "schemaVersion", "scanner", "target", "status", "startedAt", "durationMs", "grade", "budget", "phases",
    "sections", "issues", "limitations",
  ])) return false;
  if (value.schemaVersion !== "tls-deep-v1" || !isPlainObject(value.scanner) || !hasExactKeys(value.scanner, [
    "engine", "version", "commit", "sourceUrl", "license", "profileRevision",
  ])) return false;
  if (value.scanner.engine !== "testssl.sh"
    || value.scanner.version !== "3.2.4"
    || value.scanner.commit !== "97763a411c525720a5f9bd9d2cded416b10f210a"
    || value.scanner.sourceUrl !== "https://github.com/testssl/testssl.sh"
    || value.scanner.license !== "GPL-2.0-only"
    || value.scanner.profileRevision !== "safe-v1") return false;
  if (!isPlainObject(value.target) || !hasExactKeys(value.target, [
    "hostname", "address", "addressFamily", "port", "sni", "profile",
  ])) return false;
  if (value.target.hostname !== expected.hostname
    || value.target.address !== expected.address
    || value.target.addressFamily !== (expected.address.includes(":") ? 6 : 4)
    || value.target.port !== 443
    || value.target.sni !== expected.hostname
    || value.target.profile !== "safe") return false;
  if (!isReportStatus(value.status)
    || !isTimestamp(value.startedAt)
    || !isNonNegativeInteger(value.durationMs, expected.deadlineMs)
    || !isDeepTlsGrade(value.grade)
    || !isDeepTlsBudget(value.budget, expected.deadlineMs)
    || !isDeepTlsPhases(value.phases)
    || !isDeepTlsSections(value.sections)
    || !isDeepTlsIssues(value.issues, value.sections)
    || !isNonEmptyStringArray(value.limitations, MAX_LIMITATIONS, MAX_RESULT_SHORT_TEXT)) return false;
  return true;
}

function isDeepTlsBudget(value: unknown, deadlineMs: number): boolean {
  if (!isPlainObject(value) || !hasExactKeys(value, [
    "deadlineMs", "maxProcesses", "processesStarted", "processesCompleted", "maxConcurrentConnections",
    "maxConnections", "connectionsOpened", "maxPhaseOutputBytes", "outputBytes", "maxResponseBytes",
  ])) return false;
  return value.deadlineMs === deadlineMs
    && value.maxProcesses === 3
    && isNonNegativeInteger(value.processesStarted, 3)
    && isNonNegativeInteger(value.processesCompleted, value.processesStarted as number)
    && value.maxConcurrentConnections === 5
    && value.maxConnections === 128
    && isNonNegativeInteger(value.connectionsOpened, 128)
    && value.maxPhaseOutputBytes === 393_216
    && isNonNegativeInteger(value.outputBytes, 3 * 393_216)
    && value.maxResponseBytes === 163_840;
}

function isDeepTlsPhases(value: unknown): boolean {
  if (!Array.isArray(value) || value.length > 3) return false;
  const ids = new Set<string>();
  for (const phase of value) {
    if (!isPlainObject(phase) || !hasExactKeys(phase, ["id", "status", "exitCode", "durationMs", "outputBytes"])) return false;
    if (!(["identity", "cryptography", "compatibility"] as const).includes(phase.id as never)
      || !(["complete", "timed-out", "failed", "output-limit", "unavailable"] as const).includes(phase.status as never)
      || !(phase.exitCode === null || (typeof phase.exitCode === "number" && Number.isInteger(phase.exitCode) && phase.exitCode >= 0 && phase.exitCode <= 255))
      || !isNonNegativeInteger(phase.durationMs, DEEP_TLS_ENDPOINT_DEADLINE_MS)
      || !isNonNegativeInteger(phase.outputBytes, 393_216)) return false;
    ids.add(String(phase.id));
  }
  return ids.size === value.length;
}

function isDeepTlsSections(value: unknown): value is Record<DeepTlsSectionName, DeepTlsSection> {
  if (!isPlainObject(value) || !hasExactKeys(value, SECTION_NAMES)) return false;
  return SECTION_NAMES.every((name) => isDeepTlsSection(value[name]));
}

function isDeepTlsSection(value: unknown): value is DeepTlsSection {
  return isPlainObject(value)
    && hasExactKeys(value, ["status", "grade", "observations"])
    && isReportStatus(value.status)
    && isDeepTlsGrade(value.grade)
    && Array.isArray(value.observations)
    && value.observations.length <= MAX_OBSERVATIONS_PER_SECTION
    && value.observations.every(isDeepTlsObservation);
}

function isDeepTlsObservation(value: unknown): value is DeepTlsObservation {
  if (!isPlainObject(value) || !hasOnlyKeys(value, [
    "id", "sourceId", "status", "evidenceKind", "severity", "summary", "details",
  ])) return false;
  if (!isBoundedString(value.id, 160)
    || value.id.length === 0
    || (value.sourceId !== undefined && (!isBoundedString(value.sourceId, 96) || value.sourceId.length === 0))
    || !(["pass", "warning", "fail", "info", "unknown", "not-tested"] as const).includes(value.status as never)
    || !(["tested", "inferred", "not-testable"] as const).includes(value.evidenceKind as never)
    || !(["critical", "high", "medium", "low", "info", "none"] as const).includes(value.severity as never)
    || !isBoundedString(value.summary, 384)
    || value.summary.trim().length === 0) return false;
  return value.details === undefined || isDeepTlsDetails(value.details);
}

function isDeepTlsDetails(value: unknown): boolean {
  if (!isPlainObject(value) || Object.keys(value).length > MAX_DETAIL_KEYS) return false;
  return Object.entries(value).every(([key, detail]) => {
    if (!isIdentifier(key)) return false;
    if (detail === null || typeof detail === "boolean") return true;
    if (typeof detail === "number") return Number.isSafeInteger(detail);
    if (typeof detail === "string") return isBoundedString(detail, 512);
    return isStringArray(detail, MAX_DETAIL_ARRAY, 512);
  });
}

function isDeepTlsIssues(
  value: unknown,
  sections: Record<DeepTlsSectionName, DeepTlsSection>,
): value is DeepTlsIssue[] {
  if (!Array.isArray(value) || value.length > MAX_ISSUES) return false;
  return value.every((issue) => {
    if (!isPlainObject(issue) || !hasExactKeys(issue, [
      "id", "section", "observationId", "severity", "evidenceKind", "summary",
    ])) return false;
    if (!isBoundedString(issue.id, 180)
      || issue.id.length === 0
      || !SECTION_NAMES.includes(issue.section as DeepTlsSectionName)
      || !isBoundedString(issue.observationId, 160)
      || issue.observationId.length === 0
      || !(["critical", "high", "medium", "low"] as const).includes(issue.severity as never)
      || !(["tested", "inferred", "not-testable"] as const).includes(issue.evidenceKind as never)
      || !isBoundedString(issue.summary, 384)) return false;
    const section = sections[issue.section as DeepTlsSectionName];
    return section.observations.some((observation) => observation.id === issue.observationId);
  });
}

function isDeepTlsGrade(value: unknown): value is DeepTlsGrade {
  if (!isPlainObject(value) || !hasExactKeys(value, ["value", "score", "coverage", "methodology", "caps"])) return false;
  if (!(["A", "B", "C", "D", "F", "N/A"] as const).includes(value.value as never)
    || value.methodology !== "cresswell-tls-v1"
    || !isPlainObject(value.coverage)
    || !hasExactKeys(value.coverage, ["evaluatedWeight", "totalWeight"])
    || !isNonNegativeInteger(value.coverage.totalWeight, 100_000)
    || !isNonNegativeInteger(value.coverage.evaluatedWeight, value.coverage.totalWeight as number)
    || !Array.isArray(value.caps)
    || value.caps.length > 16
    || !value.caps.every(isGradeCap)) return false;
  return value.value === "N/A"
    ? value.score === null
    : typeof value.score === "number" && Number.isInteger(value.score) && value.score >= 0 && value.score <= 100;
}

function isGradeCap(value: unknown): value is DeepTlsGradeCap {
  return isPlainObject(value)
    && hasExactKeys(value, ["id", "maxGrade", "reason"])
    && isBoundedString(value.id, 96)
    && value.id.length > 0
    && (["B", "C", "D", "F"] as const).includes(value.maxGrade as never)
    && isBoundedString(value.reason, 384);
}

function isReportStatus(value: unknown): value is DeepTlsReportStatus {
  return value === "complete" || value === "partial" || value === "unavailable";
}

async function readBoundedJson(request: Request | Response, maxBytes: number): Promise<unknown> {
  const body = request.body;
  if (!body) throw new Error("A JSON body is required.");
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error("The JSON body exceeded its safety limit.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
}

function internalJson(value: unknown, status = 200): Response {
  return Response.json(value, { status, headers: { "Cache-Control": "no-store" } });
}

function internalError(error: string, status: number): Response {
  return internalJson({ error }, status);
}

function isHostname(value: unknown): value is string {
  return typeof value === "string"
    && value.length >= 1
    && value.length <= 253
    && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u.test(value)
    && !value.includes("..");
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string"
    && value.length >= 1
    && value.length <= MAX_RESULT_IDENTIFIER
    && /^[A-Za-z0-9._:-]+$/u.test(value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string"
    && value.length <= 40
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value)
    && Number.isFinite(Date.parse(value));
}

function isNonNegativeInteger(value: unknown, maximum: number): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= maximum;
}

function isBoundedString(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length <= maximum && !/[\0]/u.test(value);
}

function isStringArray(value: unknown, maximumItems: number, maximumString: number): value is string[] {
  return Array.isArray(value)
    && value.length <= maximumItems
    && value.every((entry) => isBoundedString(entry, maximumString));
}

function isNonEmptyStringArray(value: unknown, maximumItems: number, maximumString: number): value is string[] {
  return isStringArray(value, maximumItems, maximumString)
    && value.length > 0
    && value.every((entry) => entry.length > 0);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => key in value);
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function uniqueBoundedStrings(values: readonly string[], maximumItems: number, maximumLength: number): string[] {
  return [...new Set(values.map((value) => value.slice(0, maximumLength)))].slice(0, maximumItems);
}

function compactGrade(grade: DeepTlsGrade): DeepTlsGrade {
  return {
    ...grade,
    caps: grade.caps.slice(0, 16).map((cap) => ({ ...cap, reason: cap.reason.slice(0, 384) })),
  };
}

function compactDetails(details: NonNullable<DeepTlsObservation["details"]>): NonNullable<DeepTlsObservation["details"]> {
  return Object.fromEntries(Object.entries(details).slice(0, MAX_DETAIL_KEYS).map(([key, value]) => [
    key,
    typeof value === "string"
      ? value.slice(0, 256)
      : Array.isArray(value)
        ? value.slice(0, 16).map((entry) => entry.slice(0, 256))
        : value,
  ]));
}

function observationPriority(observation: DeepTlsObservation): number {
  return ({ fail: 0, warning: 1, unknown: 2, "not-tested": 3, pass: 4, info: 5 } as const)[observation.status];
}

function jsonByteLength(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function constantTimeTextEqual(left: string, right: string): boolean {
  const length = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}
