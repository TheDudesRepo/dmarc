import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import {
  SECURITY_ASSESSMENT_DISCLAIMER,
  WEB_SECURITY_DISCLAIMER,
  type DeepTlsGrade,
  type DeepTlsResponseV1,
  type DeepTlsSection,
  type SecurityAssessmentJobResource,
  type SecurityAssessmentResult,
  type WebSecurityCheckId,
} from "../shared/types";
import {
  aggregateDeepTlsReports,
  compactDeepTlsResponse,
  digestSecurityAssessmentCancelToken,
  disposeDeepTlsEndpoint,
  generateSecurityAssessmentCancelToken,
  generateSecurityAssessmentJobId,
  isSecurityAssessmentJobResource,
  isFreshEndpointAuthorized,
  MAX_COMBINED_ASSESSMENT_BYTES,
  MAX_NORMALIZED_DEEP_TLS_ENDPOINT_BYTES,
  publishWorkflowFailure,
  SECURITY_ASSESSMENT_MAX_QUEUED,
  SECURITY_ASSESSMENT_MAX_RETAINED_JOBS,
  SECURITY_ASSESSMENT_STALE_RUNNING_MS,
  SecurityAssessmentCoordinator,
  scanDeepTlsEndpoint,
  scanFreshDeepTlsEndpoint,
  type SecurityAssessmentBindings,
  validateDeepTlsResponse,
} from "./security-assessment";

const checkIds: WebSecurityCheckId[] = [
  "https-enforcement", "hsts", "content-security-policy", "frame-protection", "mime-sniffing",
  "referrer-policy", "permissions-policy", "cross-origin-isolation", "cors-policy", "http-methods",
  "cookie-secure", "cookie-httponly", "cookie-samesite", "cookie-scope-prefix", "cache-control",
  "technology-disclosure", "error-handling", "mixed-content", "form-transport", "subresource-integrity",
];

describe("deep TLS response boundary", () => {
  it("accepts only the versioned scanner constants and exact requested target", () => {
    const report = deepReport("example.com", "8.8.8.8");
    expect(validateDeepTlsResponse(report, {
      hostname: "example.com",
      address: "8.8.8.8",
      deadlineMs: 180_000,
    })).toBe(report);

    expect(() => validateDeepTlsResponse({
      ...report,
      target: { ...report.target, address: "127.0.0.1" },
    }, {
      hostname: "example.com",
      address: "8.8.8.8",
      deadlineMs: 180_000,
    })).toThrow(/invalid report/u);
    expect(() => validateDeepTlsResponse({
      ...report,
      budget: { ...report.budget, maxConnections: 999 },
    }, {
      hostname: "example.com",
      address: "8.8.8.8",
      deadlineMs: 180_000,
    })).toThrow(/invalid report/u);
  });

  it("normalizes oversized displayed evidence below the endpoint and combined Workflow caps", () => {
    const report = deepReport("example.com", "8.8.8.8");
    for (const [sectionName, section] of Object.entries(report.sections)) {
      section.observations = Array.from({ length: 128 }, (_, index) => ({
        id: `${sectionName}-${index}`,
        status: index % 11 === 0 ? "fail" : "pass",
        evidenceKind: "tested",
        severity: index % 11 === 0 ? "high" : "none",
        summary: "s".repeat(384),
        details: { evidence: Array.from({ length: 16 }, () => "e".repeat(512)) },
      }));
    }

    const compact = compactDeepTlsResponse(report);
    expect(byteLength(compact)).toBeLessThanOrEqual(MAX_NORMALIZED_DEEP_TLS_ENDPOINT_BYTES);
    expect(compact.limitations.join(" ")).toContain("truncated");
    expect(validateDeepTlsResponse(compact, {
      hostname: "example.com",
      address: "8.8.8.8",
      deadlineMs: 180_000,
    })).toBe(compact);

    const fourEndpoints = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]
      .map((address) => compactDeepTlsResponse(deepReport("example.com", address)));
    const job = completedJob(fourEndpoints);
    expect(byteLength(job.result)).toBeLessThan(MAX_COMBINED_ASSESSMENT_BYTES);
    expect(isSecurityAssessmentJobResource(job)).toBe(true);
  });

  it("rejects an off-target or private effective web URL in a stored combined result", () => {
    const job = completedJob([deepReport("example.com", "8.8.8.8")]);
    const offTarget = structuredClone(job);
    if (offTarget.result) offTarget.result.web.effectiveUrl = "https://attacker.example/";
    expect(isSecurityAssessmentJobResource(offTarget)).toBe(false);

    const privateTarget = structuredClone(job);
    if (privateTarget.result) privateTarget.result.web.effectiveUrl = "http://127.0.0.1/";
    expect(isSecurityAssessmentJobResource(privateTarget)).toBe(false);
  });

  it("keeps a partial multi-endpoint grade N/A below 70% weight coverage", () => {
    const selected = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"];
    const partial = aggregateDeepTlsReports(
      selected,
      selected,
      [deepReport("example.com", selected[0] ?? "")],
      ["Three endpoints changed or were unavailable."],
    );
    expect(partial.status).toBe("partial");
    expect(partial.grade.value).toBe("N/A");
    expect(partial.grade.coverage).toEqual({ evaluatedWeight: 100, totalWeight: 400 });

    const complete = aggregateDeepTlsReports(
      selected,
      selected,
      selected.map((address) => deepReport("example.com", address)),
      [],
    );
    expect(complete.status).toBe("complete");
    expect(complete.grade.value).toBe("A");
  });

  it("applies confirmed endpoint caps even when that endpoint itself has insufficient grade coverage", () => {
    const selected = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"];
    const reports = selected.map((address) => deepReport("example.com", address));
    const ungradedCritical = reports[3];
    if (!ungradedCritical) throw new Error("Missing endpoint fixture.");
    ungradedCritical.grade = {
      value: "N/A",
      score: null,
      coverage: { evaluatedWeight: 0, totalWeight: 100 },
      methodology: "cresswell-tls-v1",
      caps: [{
        id: "confirmed-heartbleed",
        maxGrade: "F",
        reason: "A bounded active probe confirmed Heartbleed behavior.",
      }],
    };

    const tls = aggregateDeepTlsReports(selected, selected, reports, ["One endpoint returned incomplete coverage."]);

    expect(tls.grade.coverage).toEqual({ evaluatedWeight: 300, totalWeight: 400 });
    expect(tls.grade.value).toBe("F");
    expect(tls.grade.caps).toContainEqual(expect.objectContaining({
      id: "208.67.222.222:confirmed-heartbleed",
      maxGrade: "F",
    }));
  });

  it("bounds multi-endpoint grade caps while retaining later critical caps", () => {
    const selected = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"];
    const reports = selected.map((address, endpointIndex) => {
      const report = deepReport("example.com", address);
      report.grade.caps = Array.from({ length: 9 }, (_, capIndex) => ({
        id: `cap-${capIndex}`,
        maxGrade: endpointIndex === 3 && capIndex === 8 ? "F" as const : "B" as const,
        reason: `Endpoint cap ${capIndex}.`,
      }));
      if (endpointIndex === 3) report.grade = { ...report.grade, value: "F", score: 0 };
      return report;
    });
    const tls = aggregateDeepTlsReports(selected, selected, reports, []);
    expect(tls.grade.caps).toHaveLength(16);
    expect(tls.grade.caps[0]).toEqual(expect.objectContaining({
      id: "208.67.222.222:cap-8",
      maxGrade: "F",
    }));

    const job = completedJob(reports);
    if (job.result) job.result.tls = tls;
    expect(isSecurityAssessmentJobResource(job)).toBe(true);
  });

  it("requires the exact pre-job endpoint to remain in every fresh public DNS view", () => {
    expect(isFreshEndpointAuthorized("8.8.8.8", ["8.8.8.8", "1.1.1.1"])).toBe(true);
    expect(isFreshEndpointAuthorized("8.8.8.8", ["1.1.1.1"])).toBe(false);
  });

  it("revalidates fresh DNS membership inside the same operation before starting active TLS", async () => {
    const events: string[] = [];
    const scan = vi.fn(async () => {
      events.push("scan");
      return deepReport("example.com", "8.8.8.8");
    });
    const env = {} as SecurityAssessmentBindings;
    const completed = await scanFreshDeepTlsEndpoint(
      env,
      jobId(8),
      0,
      "example.com",
      "8.8.8.8",
      {
        resolve: async () => {
          events.push("resolve");
          return ["8.8.8.8"];
        },
        scan,
      },
    );
    expect(events).toEqual(["resolve", "scan"]);
    expect(completed.kind).toBe("complete");

    scan.mockClear();
    const changed = await scanFreshDeepTlsEndpoint(
      env,
      jobId(8),
      0,
      "example.com",
      "8.8.8.8",
      { resolve: async () => ["1.1.1.1"], scan },
    );
    expect(changed.kind).toBe("target-changed");
    expect(scan).not.toHaveBeenCalled();
  });

  it("persists one validated endpoint result for Workflow replay until durable-step cleanup", async () => {
    const allowed = vi.fn(async () => undefined);
    const destroy = vi.fn(async () => undefined);
    const good = deepReport("example.com", "8.8.8.8");
    let stored: DeepTlsResponseV1 | null = null;
    let claimed = false;
    const container = {
      setAllowedHosts: allowed,
      fetch: vi.fn(async () => Response.json(good)),
      claimScan: vi.fn(async () => {
        if (stored) return { status: "complete" as const, result: stored };
        if (claimed) return { status: "in-progress" as const };
        claimed = true;
        return { status: "claimed" as const, ownerToken: "ab".repeat(16) };
      }),
      storeScanResult: vi.fn(async (_identity: unknown, _ownerToken: string, result: DeepTlsResponseV1) => {
        stored = result;
      }),
      dispose: destroy,
    };
    const env = containerEnv(container);
    await expect(scanDeepTlsEndpoint(env, jobId(7), 0, "example.com", "8.8.8.8"))
      .resolves.toEqual(good);
    expect(allowed).toHaveBeenCalledWith(["8.8.8.8"]);
    expect(container.storeScanResult).toHaveBeenCalledOnce();
    expect(container.storeScanResult).toHaveBeenCalledWith(
      expect.objectContaining({ hostname: "example.com", address: "8.8.8.8" }),
      "ab".repeat(16),
      good,
    );
    expect(destroy).not.toHaveBeenCalled();

    await expect(scanDeepTlsEndpoint(env, jobId(7), 0, "example.com", "8.8.8.8"))
      .resolves.toEqual(good);
    expect(container.fetch).toHaveBeenCalledOnce();
    expect(container.storeScanResult).toHaveBeenCalledOnce();

    await disposeDeepTlsEndpoint(env, jobId(7), 0);
    expect(destroy).toHaveBeenCalledOnce();

    stored = null;
    claimed = false;
    container.fetch.mockResolvedValueOnce(Response.json({ schemaVersion: "wrong" }));
    await expect(scanDeepTlsEndpoint(env, jobId(7), 1, "example.com", "8.8.8.8"))
      .rejects.toThrow(/invalid report/u);
    expect(container.storeScanResult).toHaveBeenCalledOnce();

    claimed = false;
    allowed.mockRejectedValueOnce(new Error("container allocation failed"));
    await expect(scanDeepTlsEndpoint(env, jobId(7), 2, "example.com", "8.8.8.8"))
      .rejects.toThrow(/allocation failed/u);
    expect(destroy).toHaveBeenCalledOnce();

    claimed = true;
    const fetchCalls = container.fetch.mock.calls.length;
    await expect(scanDeepTlsEndpoint(env, jobId(7), 3, "example.com", "8.8.8.8"))
      .rejects.toThrow(/unfinished scan-once claim/u);
    expect(container.fetch).toHaveBeenCalledTimes(fetchCalls);
  });
});

describe("assessment capabilities and paid runtime configuration", () => {
  it("generates fixed-length independent job and creator-only cancellation capabilities", async () => {
    const jobId = generateSecurityAssessmentJobId((array) => array.fill(0xab));
    const cancelToken = generateSecurityAssessmentCancelToken((array) => array.fill(0xcd));

    expect(jobId).toMatch(/^sa_[a-f0-9]{48}$/u);
    expect(cancelToken).toMatch(/^sc_[a-f0-9]{64}$/u);
    expect(await digestSecurityAssessmentCancelToken(cancelToken)).toMatch(/^[a-f0-9]{64}$/u);
    expect(await digestSecurityAssessmentCancelToken(cancelToken)).not.toContain(cancelToken.slice(3));
  });

  it("pins Container, Workflow, coordinator proxy export, and global capacity two", () => {
    const config = JSON.parse(readFileSync(new URL("../../wrangler.jsonc", import.meta.url), "utf8")) as {
      compatibility_flags: string[];
      containers: Array<Record<string, unknown>>;
      workflows: Array<Record<string, unknown>>;
      durable_objects: { bindings: Array<Record<string, unknown>> };
    };
    const entrySource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
    const containerSource = readFileSync(new URL("./deep-tls-scanner.ts", import.meta.url), "utf8");
    const container = config.containers.find((item) => item.class_name === "DeepTlsScanner");

    expect(container).toEqual(expect.objectContaining({
      image: "./scanner-container/Dockerfile",
      image_build_context: "./scanner-container",
      max_instances: 2,
      instance_type: "basic",
    }));
    expect(config.workflows).toContainEqual(expect.objectContaining({
      binding: "SECURITY_ASSESSMENT_WORKFLOW",
      class_name: "SecurityAssessmentWorkflow",
    }));
    expect(config.durable_objects.bindings).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "SECURITY_ASSESSMENT_COORDINATOR" }),
      expect.objectContaining({ name: "DEEP_TLS_SCANNER" }),
    ]));
    expect(config.compatibility_flags).toEqual(expect.arrayContaining([
      "nodejs_compat",
      "global_fetch_strictly_public",
    ]));
    expect(entrySource).toContain('export { ContainerProxy } from "@cloudflare/containers"');
    expect(containerSource).toContain("enableInternet = true");
    expect(containerSource).toContain("async dispose()");
    expect(containerSource).not.toContain("this.ctx.storage.deleteAlarm()");
    expect(containerSource).toContain("this.ctx.storage.deleteAll()");
  });
});

describe("global assessment coordinator", () => {
  it("atomically single-flights, caches six hours, holds two slots, and requires creator cancellation authority", async () => {
    const sql = new FakeAssessmentSql();
    const workflowCreate = vi.fn(async () => ({ id: "workflow" }));
    const workflowTerminate = vi.fn(async () => undefined);
    const containerDestroy = vi.fn(async () => undefined);
    const env = {
      SECURITY_ASSESSMENT_WORKFLOW: {
        create: workflowCreate,
        get: async () => ({ terminate: workflowTerminate }),
      },
      DEEP_TLS_SCANNER: {
        idFromName: (name: string) => name,
        get: () => ({ dispose: containerDestroy }),
      },
      SECURITY_ASSESSMENT_COORDINATOR: {},
    } as unknown as SecurityAssessmentBindings;
    const coordinator = new SecurityAssessmentCoordinator({
      storage: { sql: sql as unknown as SqlStorage },
    } as DurableObjectState, env);
    const firstId = jobId(1);
    const first = await coordinatorCreate(coordinator, firstId, "example.com", ["8.8.8.8"], "aa".repeat(32));
    expect(first.reuse).toBe("new");
    expect(first.job.status).toBe("running");

    const joined = await coordinatorCreate(coordinator, jobId(2), "example.com", ["8.8.8.8"], "bb".repeat(32));
    expect(joined.reuse).toBe("single-flight");
    expect(joined.job.jobId).toBe(firstId);
    expect(workflowCreate).toHaveBeenCalledTimes(1);

    const revokedCreatorCancel = await coordinator.fetch(new Request(
      `https://security-assessment.internal/jobs/${firstId}`,
      { method: "DELETE", headers: { "X-Assessment-Cancel-Hash": "aa".repeat(32) } },
    ));
    expect(revokedCreatorCancel.status).toBe(404);
    expect(workflowTerminate).not.toHaveBeenCalled();

    const result = completedJob([deepReport("example.com", "8.8.8.8")]).result;
    const completion = await coordinator.fetch(jsonInternalRequest(`/jobs/${firstId}/complete`, { result }));
    expect(completion.status).toBe(200);
    expect(containerDestroy).toHaveBeenCalledTimes(4);
    containerDestroy.mockClear();
    const cached = await coordinatorCreate(coordinator, jobId(3), "example.com", ["8.8.8.8"], "cc".repeat(32));
    expect(cached.reuse).toBe("cache-hit");
    expect(cached.job.jobId).toBe(firstId);
    expect(cached.job.status).toBe("complete");
    expect(sql.rows.size).toBe(1);
    expect(workflowCreate).toHaveBeenCalledTimes(1);

    const alpha = await coordinatorCreate(coordinator, jobId(4), "alpha.example", ["1.1.1.1"], "dd".repeat(32));
    const beta = await coordinatorCreate(coordinator, jobId(5), "beta.example", ["9.9.9.9"], "ee".repeat(32));
    const gamma = await coordinatorCreate(coordinator, jobId(6), "gamma.example", ["208.67.222.222"], "ff".repeat(32));
    expect([alpha.job.status, beta.job.status, gamma.job.status]).toEqual(["running", "running", "queued"]);
    expect(workflowCreate).toHaveBeenCalledTimes(3);

    const unauthorized = await coordinator.fetch(new Request(`https://security-assessment.internal/jobs/${alpha.job.jobId}`, {
      method: "DELETE",
      headers: { "X-Assessment-Cancel-Hash": "00".repeat(32) },
    }));
    expect(unauthorized.status).toBe(404);
    expect(workflowTerminate).not.toHaveBeenCalled();

    const authorized = await coordinator.fetch(new Request(`https://security-assessment.internal/jobs/${alpha.job.jobId}`, {
      method: "DELETE",
      headers: { "X-Assessment-Cancel-Hash": "dd".repeat(32) },
    }));
    expect(authorized.status).toBe(200);
    expect(workflowTerminate).toHaveBeenCalledOnce();
    expect(containerDestroy).toHaveBeenCalledTimes(4);
    expect(workflowCreate).toHaveBeenCalledTimes(4);
    const promoted = await coordinator.fetch(new Request(`https://security-assessment.internal/jobs/${gamma.job.jobId}`));
    await expect(promoted.json()).resolves.toEqual(expect.objectContaining({ status: "running" }));
  });

  it("rejects private or transition addresses even on its internal create boundary", async () => {
    const sql = new FakeAssessmentSql();
    const coordinator = new SecurityAssessmentCoordinator({
      storage: { sql: sql as unknown as SqlStorage },
    } as DurableObjectState, {
      SECURITY_ASSESSMENT_WORKFLOW: {},
      DEEP_TLS_SCANNER: {},
      SECURITY_ASSESSMENT_COORDINATOR: {},
    } as SecurityAssessmentBindings);

    for (const address of ["127.0.0.1", "::1", "64:ff9b::808:808"]) {
      const response = await coordinator.fetch(jsonInternalRequest("/jobs", {
        jobId: jobId(address.length),
        hostname: "example.com",
        addresses: [address],
        createdAt: new Date().toISOString(),
        cancelTokenHash: "aa".repeat(32),
      }));
      expect(response.status).toBe(400);
    }
    expect(sql.rows.size).toBe(0);
  });

  it("reaps a silent running job after 25 minutes without touching a legitimate long scan", async () => {
    const sql = new FakeAssessmentSql();
    const workflowCreate = vi.fn(async () => ({ id: "workflow" }));
    const workflowTerminate = vi.fn(async () => undefined);
    const containerDestroy = vi.fn(async () => undefined);
    const coordinator = new SecurityAssessmentCoordinator({
      storage: { sql: sql as unknown as SqlStorage },
    } as DurableObjectState, {
      SECURITY_ASSESSMENT_WORKFLOW: {
        create: workflowCreate,
        get: async () => ({ terminate: workflowTerminate }),
      },
      DEEP_TLS_SCANNER: {
        idFromName: (name: string) => name,
        get: () => ({ dispose: containerDestroy }),
      },
      SECURITY_ASSESSMENT_COORDINATOR: {},
    } as unknown as SecurityAssessmentBindings);

    const staleId = jobId(21);
    const activeId = jobId(22);
    await coordinatorCreate(coordinator, staleId, "stale.example", ["8.8.8.8"], "aa".repeat(32));
    await coordinatorCreate(coordinator, activeId, "active.example", ["1.1.1.1"], "bb".repeat(32));
    const now = Date.now();
    const stale = sql.rows.get(staleId);
    const active = sql.rows.get(activeId);
    if (!stale || !active) throw new Error("Missing fake job rows.");
    stale.updated_at = now - SECURITY_ASSESSMENT_STALE_RUNNING_MS - 1;
    active.updated_at = now - SECURITY_ASSESSMENT_STALE_RUNNING_MS + 60_000;

    const replacement = await coordinatorCreate(
      coordinator,
      jobId(23),
      "replacement.example",
      ["9.9.9.9"],
      "cc".repeat(32),
    );
    expect(replacement.job.status).toBe("running");
    expect(sql.rows.get(staleId)?.status).toBe("failed");
    expect(sql.rows.get(activeId)?.status).toBe("running");
    expect(workflowTerminate).toHaveBeenCalledOnce();
    expect(containerDestroy).toHaveBeenCalledTimes(4);
    expect(workflowCreate).toHaveBeenCalledTimes(3);
  });

  it("repeats the terminal all-endpoint sweep when earlier release RPCs were unavailable", async () => {
    const sql = new FakeAssessmentSql();
    const containerDispose = vi.fn(async () => { throw new Error("temporary Container RPC outage"); });
    const coordinator = new SecurityAssessmentCoordinator({
      storage: { sql: sql as unknown as SqlStorage },
    } as DurableObjectState, {
      SECURITY_ASSESSMENT_WORKFLOW: {
        create: async () => ({ id: "workflow" }),
        get: async () => ({ terminate: async () => undefined }),
      },
      DEEP_TLS_SCANNER: {
        idFromName: (name: string) => name,
        get: () => ({ dispose: containerDispose }),
      },
      SECURITY_ASSESSMENT_COORDINATOR: {},
    } as unknown as SecurityAssessmentBindings);

    const id = jobId(28);
    await coordinatorCreate(coordinator, id, "cleanup-retry.example.com", ["8.8.8.8"], "aa".repeat(32));
    const result = completedJob([deepReport("cleanup-retry.example.com", "8.8.8.8")]).result;
    if (!result) throw new Error("Missing completion fixture.");
    result.hostname = "cleanup-retry.example.com";
    result.web.hostname = "cleanup-retry.example.com";
    result.web.effectiveUrl = "https://cleanup-retry.example.com/";

    const first = await coordinator.fetch(jsonInternalRequest(`/jobs/${id}/complete`, { result }));
    expect(first.status).toBe(200);
    expect(containerDispose).toHaveBeenCalledTimes(4);

    const retriedPublication = await coordinator.fetch(jsonInternalRequest(`/jobs/${id}/complete`, { result }));
    expect(retriedPublication.status).toBe(200);
    expect(containerDispose).toHaveBeenCalledTimes(8);
  });

  it("awaits even rejected Workflow termination before its final sweep and rejects late progress", async () => {
    const sql = new FakeAssessmentSql();
    let rejectTermination: ((error: Error) => void) | undefined;
    let markTerminationStarted: (() => void) | undefined;
    const terminationStarted = new Promise<void>((resolve) => { markTerminationStarted = resolve; });
    const workflowTerminate = vi.fn(() => new Promise<void>((_resolve, reject) => {
      rejectTermination = reject;
      markTerminationStarted?.();
    }));
    const containerDispose = vi.fn(async () => undefined);
    const coordinator = new SecurityAssessmentCoordinator({
      storage: { sql: sql as unknown as SqlStorage },
    } as DurableObjectState, {
      SECURITY_ASSESSMENT_WORKFLOW: {
        create: async () => ({ id: "workflow" }),
        get: async () => ({ terminate: workflowTerminate }),
      },
      DEEP_TLS_SCANNER: {
        idFromName: (name: string) => name,
        get: () => ({ dispose: containerDispose }),
      },
      SECURITY_ASSESSMENT_COORDINATOR: {},
    } as unknown as SecurityAssessmentBindings);

    const id = jobId(27);
    await coordinatorCreate(coordinator, id, "termination-race.example.com", ["8.8.8.8"], "aa".repeat(32));
    const cancellation = coordinator.fetch(new Request(
      `https://security-assessment.internal/jobs/${id}`,
      { method: "DELETE", headers: { "X-Assessment-Cancel-Hash": "aa".repeat(32) } },
    ));

    await terminationStarted;
    expect(containerDispose).not.toHaveBeenCalled();
    rejectTermination?.(new Error("termination RPC outcome was uncertain"));
    expect((await cancellation).status).toBe(200);
    expect(containerDispose).toHaveBeenCalledTimes(4);

    const lateProgress = await coordinator.fetch(jsonInternalRequest(`/jobs/${id}/progress`, {
      phase: "tls-scanning",
      message: "This Workflow should stop.",
      completedEndpoints: 0,
      totalEndpoints: 1,
      percent: 20,
      updatedAt: new Date().toISOString(),
    }));
    expect(lateProgress.status).toBe(409);
  });

  it("self-heals persisted queued work with free capacity during an ordinary status read", async () => {
    const sql = new FakeAssessmentSql();
    const workflowCreate = vi.fn(async () => ({ id: "workflow" }));
    const coordinator = new SecurityAssessmentCoordinator({
      storage: { sql: sql as unknown as SqlStorage },
    } as DurableObjectState, {
      SECURITY_ASSESSMENT_WORKFLOW: {
        create: workflowCreate,
        get: async () => ({ terminate: async () => undefined }),
      },
      DEEP_TLS_SCANNER: {
        idFromName: (name: string) => name,
        get: () => ({ dispose: async () => undefined }),
      },
      SECURITY_ASSESSMENT_COORDINATOR: {},
    } as unknown as SecurityAssessmentBindings);

    const first = await coordinatorCreate(coordinator, jobId(24), "first.example.com", ["1.1.1.1"], "aa".repeat(32));
    const second = await coordinatorCreate(coordinator, jobId(25), "second.example.com", ["8.8.8.8"], "bb".repeat(32));
    const waiting = await coordinatorCreate(coordinator, jobId(26), "waiting.example.com", ["9.9.9.9"], "cc".repeat(32));
    const firstRow = sql.rows.get(first.job.jobId);
    const secondRow = sql.rows.get(second.job.jobId);
    if (!firstRow || !secondRow) throw new Error("Missing running rows.");
    firstRow.status = "failed";
    secondRow.status = "failed";

    const response = await coordinator.fetch(new Request(
      `https://security-assessment.internal/jobs/${waiting.job.jobId}`,
    ));

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual(expect.objectContaining({ status: "running" }));
    expect(workflowCreate).toHaveBeenCalledTimes(3);
  });

  it("skips expired queue entries and keeps filling a slot after a Workflow start failure", async () => {
    const sql = new FakeAssessmentSql();
    const workflowTerminate = vi.fn(async () => undefined);
    const containerDestroy = vi.fn(async () => undefined);
    const workflowCreate = vi.fn()
      .mockResolvedValueOnce({ id: "workflow-1" })
      .mockResolvedValueOnce({ id: "workflow-2" })
      .mockRejectedValueOnce(new Error("temporary Workflow start failure"))
      .mockResolvedValueOnce({ id: "workflow-4" });
    const coordinator = new SecurityAssessmentCoordinator({
      storage: { sql: sql as unknown as SqlStorage },
    } as DurableObjectState, {
      SECURITY_ASSESSMENT_WORKFLOW: {
        create: workflowCreate,
        get: async () => ({ terminate: workflowTerminate }),
      },
      DEEP_TLS_SCANNER: {
        idFromName: (name: string) => name,
        get: () => ({ dispose: containerDestroy }),
      },
      SECURITY_ASSESSMENT_COORDINATOR: {},
    } as unknown as SecurityAssessmentBindings);

    const runningOne = await coordinatorCreate(coordinator, jobId(30), "one.example", ["1.1.1.1"], "aa".repeat(32));
    await coordinatorCreate(coordinator, jobId(31), "two.example", ["8.8.8.8"], "bb".repeat(32));
    const expired = await coordinatorCreate(coordinator, jobId(32), "expired.example", ["9.9.9.9"], "cc".repeat(32));
    const failedStart = await coordinatorCreate(coordinator, jobId(33), "failed.example", ["208.67.222.222"], "dd".repeat(32));
    const promoted = await coordinatorCreate(coordinator, jobId(34), "promoted.example", ["1.0.0.1"], "ee".repeat(32));
    const expiredRow = sql.rows.get(expired.job.jobId);
    if (!expiredRow) throw new Error("Missing queued job row.");
    expiredRow.expires_at = Date.now() - 1;

    const cancelled = await coordinator.fetch(new Request(
      `https://security-assessment.internal/jobs/${runningOne.job.jobId}`,
      { method: "DELETE", headers: { "X-Assessment-Cancel-Hash": "aa".repeat(32) } },
    ));

    expect(cancelled.status).toBe(200);
    expect(sql.rows.has(expired.job.jobId)).toBe(false);
    expect(sql.rows.get(failedStart.job.jobId)?.status).toBe("failed");
    expect(sql.rows.get(promoted.job.jobId)?.status).toBe("running");
    expect(workflowCreate).toHaveBeenCalledTimes(4);
    // One termination/container cleanup belongs to the creator cancellation;
    // the rest clean up the ambiguously failed Workflow start.
    expect(workflowTerminate).toHaveBeenCalledTimes(2);
    expect(containerDestroy).toHaveBeenCalledTimes(8);
  });

  it("rejects a unique job when the bounded global pending queue is full", async () => {
    const sql = new FakeAssessmentSql();
    const workflowCreate = vi.fn(async () => ({ id: "workflow" }));
    const coordinator = new SecurityAssessmentCoordinator({
      storage: { sql: sql as unknown as SqlStorage },
    } as DurableObjectState, {
      SECURITY_ASSESSMENT_WORKFLOW: {
        create: workflowCreate,
        get: async () => ({ terminate: async () => undefined }),
      },
      DEEP_TLS_SCANNER: {
        idFromName: (name: string) => name,
        get: () => ({ dispose: async () => undefined }),
      },
      SECURITY_ASSESSMENT_COORDINATOR: {},
    } as unknown as SecurityAssessmentBindings);

    await coordinatorCreate(coordinator, jobId(40), "running-one.example.com", ["1.1.1.1"], "aa".repeat(32));
    await coordinatorCreate(coordinator, jobId(41), "running-two.example.com", ["8.8.8.8"], "bb".repeat(32));
    for (let index = 0; index < SECURITY_ASSESSMENT_MAX_QUEUED; index += 1) {
      const queued = await coordinatorCreate(
        coordinator,
        jobId(42 + index),
        `queued-${index}.example.com`,
        ["9.9.9.9"],
        (index + 3).toString(16).padStart(2, "0").repeat(32),
      );
      expect(queued.job.status).toBe("queued");
    }

    const rejectedId = jobId(42 + SECURITY_ASSESSMENT_MAX_QUEUED);
    const rejected = await coordinator.fetch(jsonInternalRequest("/jobs", {
      jobId: rejectedId,
      hostname: "over-capacity.example.com",
      addresses: ["208.67.222.222"],
      createdAt: new Date().toISOString(),
      cancelTokenHash: "ff".repeat(32),
    }));

    expect(rejected.status).toBe(503);
    await expect(rejected.json()).resolves.toEqual({ error: "The global assessment queue is at capacity." });
    expect(sql.rows.has(rejectedId)).toBe(false);
    expect(workflowCreate).toHaveBeenCalledTimes(2);
  });

  it("refills stale running slots before applying pending-queue admission", async () => {
    const sql = new FakeAssessmentSql();
    const workflowCreate = vi.fn(async () => ({ id: "workflow" }));
    const coordinator = new SecurityAssessmentCoordinator({
      storage: { sql: sql as unknown as SqlStorage },
    } as DurableObjectState, {
      SECURITY_ASSESSMENT_WORKFLOW: {
        create: workflowCreate,
        get: async () => ({ terminate: async () => undefined }),
      },
      DEEP_TLS_SCANNER: {
        idFromName: (name: string) => name,
        get: () => ({ dispose: async () => undefined }),
      },
      SECURITY_ASSESSMENT_COORDINATOR: {},
    } as unknown as SecurityAssessmentBindings);

    const first = await coordinatorCreate(coordinator, jobId(500), "stale-one.example.com", ["1.1.1.1"], "aa".repeat(32));
    const second = await coordinatorCreate(coordinator, jobId(501), "stale-two.example.com", ["8.8.8.8"], "bb".repeat(32));
    const queuedIds: string[] = [];
    for (let index = 0; index < SECURITY_ASSESSMENT_MAX_QUEUED; index += 1) {
      const id = jobId(502 + index);
      queuedIds.push(id);
      const queued = await coordinatorCreate(
        coordinator,
        id,
        `waiting-${index}.example.com`,
        ["9.9.9.9"],
        (index + 10).toString(16).padStart(2, "0").repeat(32),
      );
      expect(queued.job.status).toBe("queued");
    }
    const staleAt = Date.now() - SECURITY_ASSESSMENT_STALE_RUNNING_MS - 1;
    const firstRow = sql.rows.get(first.job.jobId);
    const secondRow = sql.rows.get(second.job.jobId);
    if (!firstRow || !secondRow) throw new Error("Missing running job rows.");
    firstRow.updated_at = staleAt;
    secondRow.updated_at = staleAt;

    const admitted = await coordinatorCreate(
      coordinator,
      jobId(600),
      "admitted-after-reap.example.com",
      ["208.67.222.222"],
      "ff".repeat(32),
    );

    expect(admitted.job.status).toBe("queued");
    expect(sql.rows.get(queuedIds[0] ?? "")?.status).toBe("running");
    expect(sql.rows.get(queuedIds[1] ?? "")?.status).toBe("running");
    expect(workflowCreate).toHaveBeenCalledTimes(4);
  });

  it("bounds retained job rows while allowing an existing cache hit without duplicating its report", async () => {
    const sql = new FakeAssessmentSql();
    const coordinator = new SecurityAssessmentCoordinator({
      storage: { sql: sql as unknown as SqlStorage },
    } as DurableObjectState, {
      SECURITY_ASSESSMENT_WORKFLOW: {
        create: async () => ({ id: "workflow" }),
        get: async () => ({ terminate: async () => undefined }),
      },
      DEEP_TLS_SCANNER: {
        idFromName: (name: string) => name,
        get: () => ({ dispose: async () => undefined }),
      },
      SECURITY_ASSESSMENT_COORDINATOR: {},
    } as unknown as SecurityAssessmentBindings);

    const first = await coordinatorCreate(coordinator, jobId(70), "cached.example.com", ["1.1.1.1"], "aa".repeat(32));
    const result = completedJob([deepReport("cached.example.com", "1.1.1.1")]).result;
    if (!result) throw new Error("Missing completed result fixture.");
    result.hostname = "cached.example.com";
    result.web.hostname = "cached.example.com";
    result.web.effectiveUrl = "https://cached.example.com/";
    const completion = await coordinator.fetch(jsonInternalRequest(`/jobs/${first.job.jobId}/complete`, { result }));
    expect(completion.status).toBe(200);
    const retained = sql.rows.get(first.job.jobId);
    if (!retained) throw new Error("Missing completed job row.");

    for (let index = 1; index < SECURITY_ASSESSMENT_MAX_RETAINED_JOBS; index += 1) {
      const clone = structuredClone(retained);
      clone.job_id = jobId(70 + index);
      clone.hostname = `retained-${index}.example.com`;
      clone.target_key = `${clone.hostname}\n${clone.addresses_json}`;
      clone.status = "failed";
      clone.result_json = null;
      clone.completed_at = Date.now();
      clone.error_json = JSON.stringify({ code: "ORCHESTRATION_FAILED", message: "Retained failure." });
      sql.rows.set(clone.job_id, clone);
    }

    const cached = await coordinatorCreate(coordinator, jobId(400), "cached.example.com", ["1.1.1.1"], "bb".repeat(32));
    expect(cached.reuse).toBe("cache-hit");
    expect(cached.job.jobId).toBe(first.job.jobId);
    expect(sql.rows.size).toBe(SECURITY_ASSESSMENT_MAX_RETAINED_JOBS);

    const rejectedId = jobId(401);
    const rejected = await coordinator.fetch(jsonInternalRequest("/jobs", {
      jobId: rejectedId,
      hostname: "new-target.example.com",
      addresses: ["8.8.8.8"],
      createdAt: new Date().toISOString(),
      cancelTokenHash: "cc".repeat(32),
    }));
    expect(rejected.status).toBe(503);
    expect(sql.rows.has(rejectedId)).toBe(false);
  });

  it("alarms away expired retained reports even when no later API traffic arrives", async () => {
    const sql = new FakeAssessmentSql();
    let alarmAt: number | null = null;
    const setAlarm = vi.fn(async (value: number) => { alarmAt = value; });
    const deleteAlarm = vi.fn(async () => { alarmAt = null; });
    const coordinator = new SecurityAssessmentCoordinator({
      storage: {
        sql: sql as unknown as SqlStorage,
        getAlarm: async () => alarmAt,
        setAlarm,
        deleteAlarm,
      },
    } as unknown as DurableObjectState, {
      SECURITY_ASSESSMENT_WORKFLOW: {
        create: async () => ({ id: "workflow" }),
        get: async () => ({ terminate: async () => undefined }),
      },
      DEEP_TLS_SCANNER: {
        idFromName: (name: string) => name,
        get: () => ({ dispose: async () => undefined }),
      },
      SECURITY_ASSESSMENT_COORDINATOR: {},
    } as unknown as SecurityAssessmentBindings);

    const created = await coordinatorCreate(
      coordinator,
      jobId(410),
      "retention.example.com",
      ["8.8.8.8"],
      "aa".repeat(32),
    );
    expect(setAlarm).toHaveBeenCalled();
    const row = sql.rows.get(created.job.jobId);
    if (!row) throw new Error("Missing retained job row.");
    row.status = "complete";
    row.expires_at = Date.now() - 1;

    await coordinator.alarm();

    expect(sql.rows.has(created.job.jobId)).toBe(false);
    expect(deleteAlarm).toHaveBeenCalled();
    expect(alarmAt).toBeNull();
  });
});

describe("Workflow publication", () => {
  it("publishes failures through a bounded retrying durable step", async () => {
    const publish = vi.fn()
      .mockRejectedValueOnce(new Error("transient coordinator failure"))
      .mockResolvedValueOnce(undefined);
    const doStep = vi.fn(async (
      _name: string,
      options: { retries: { limit: number } },
      callback: () => Promise<void>,
    ) => {
      let lastError: unknown;
      for (let attempt = 0; attempt <= options.retries.limit; attempt += 1) {
        try {
          return await callback();
        } catch (error) {
          lastError = error;
        }
      }
      throw lastError;
    });

    await publishWorkflowFailure(
      { do: doStep } as unknown as Parameters<typeof publishWorkflowFailure>[0],
      publish,
    );

    expect(doStep).toHaveBeenCalledWith(
      "publish assessment failure",
      expect.objectContaining({ retries: expect.objectContaining({ limit: 3 }) }),
      publish,
    );
    expect(publish).toHaveBeenCalledTimes(2);
  });
});

function grade(): DeepTlsGrade {
  return {
    value: "A",
    score: 100,
    coverage: { evaluatedWeight: 100, totalWeight: 100 },
    methodology: "cresswell-tls-v1",
    caps: [],
  };
}

function section(): DeepTlsSection {
  return {
    status: "complete",
    grade: grade(),
    observations: [{
      id: "tested-observation",
      status: "pass",
      evidenceKind: "tested",
      severity: "none",
      summary: "The fixed observation passed.",
    }],
  };
}

function deepReport(hostname: string, address: string): DeepTlsResponseV1 {
  return {
    schemaVersion: "tls-deep-v1",
    scanner: {
      engine: "testssl.sh",
      version: "3.2.4",
      commit: "97763a411c525720a5f9bd9d2cded416b10f210a",
      sourceUrl: "https://github.com/testssl/testssl.sh",
      license: "GPL-2.0-only",
      profileRevision: "safe-v1",
    },
    target: {
      hostname,
      address,
      addressFamily: address.includes(":") ? 6 : 4,
      port: 443,
      sni: hostname,
      profile: "safe",
    },
    status: "complete",
    startedAt: "2026-08-16T12:00:00.000Z",
    durationMs: 20_000,
    grade: grade(),
    budget: {
      deadlineMs: 180_000,
      maxProcesses: 3,
      processesStarted: 3,
      processesCompleted: 3,
      maxConcurrentConnections: 5,
      maxConnections: 128,
      connectionsOpened: 90,
      maxPhaseOutputBytes: 393_216,
      outputBytes: 100_000,
      maxResponseBytes: 163_840,
    },
    phases: [
      { id: "identity", status: "complete", exitCode: 0, durationMs: 5_000, outputBytes: 10_000 },
      { id: "cryptography", status: "complete", exitCode: 0, durationMs: 10_000, outputBytes: 20_000 },
      { id: "compatibility", status: "complete", exitCode: 0, durationMs: 5_000, outputBytes: 30_000 },
    ],
    sections: {
      certificate: section(),
      protocols: section(),
      ciphers: section(),
      keyExchange: section(),
      features: section(),
      clientSimulations: section(),
      knownIssues: section(),
    },
    issues: [],
    limitations: ["Bounded safe profile."],
  };
}

function completedJob(endpoints: DeepTlsResponseV1[]): SecurityAssessmentJobResource {
  const result: SecurityAssessmentResult = {
    schemaVersion: "security-assessment-v1",
    hostname: "example.com",
    startedAt: "2026-08-16T12:00:00.000Z",
    completedAt: "2026-08-16T12:01:00.000Z",
    durationMs: 60_000,
    web: {
      hostname: "example.com",
      effectiveUrl: "https://example.com/",
      scannedAt: "2026-08-16T12:00:00.000Z",
      durationMs: 1_000,
      score: 100,
      grade: "A",
      headline: "Strong observable web hardening",
      summary: "All bounded web checks completed.",
      checks: checkIds.map((id) => ({
        id,
        status: "pass",
        title: id,
        summary: "The bounded observation passed.",
        evidence: [],
        remediation: "Continue monitoring.",
        owasp: { top10: ["A02:2025"], wstg: ["WSTG-CONF-02"] },
      })),
      coverage: { evaluated: 20, total: 20, unknown: 0, notApplicable: 0 },
      requestBudget: { httpRequests: 6, tlsConnections: 0, maxResponseBytes: 131_072, redirectHopsFollowed: 2 },
      disclaimer: WEB_SECURITY_DISCLAIMER,
    },
    tls: {
      status: "complete",
      grade: grade(),
      summary: "Every selected endpoint completed.",
      resolvedAddresses: endpoints.map((endpoint) => endpoint.target.address),
      endpoints,
      endpointsTruncated: false,
      limitations: ["Independent bounded methodology."],
    },
    disclaimer: SECURITY_ASSESSMENT_DISCLAIMER,
  };
  return {
    jobId: `sa_${"ab".repeat(24)}`,
    hostname: "example.com",
    status: "complete",
    createdAt: "2026-08-16T12:00:00.000Z",
    updatedAt: "2026-08-16T12:01:00.000Z",
    expiresAt: "2026-08-17T12:00:00.000Z",
    progress: {
      phase: "complete",
      message: "Complete.",
      completedEndpoints: endpoints.length,
      totalEndpoints: endpoints.length,
      percent: 100,
      updatedAt: "2026-08-16T12:01:00.000Z",
    },
    result,
  };
}

function byteLength(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function containerEnv(container: {
  setAllowedHosts(hosts: string[]): Promise<void>;
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  claimScan(identity: unknown): Promise<
    { status: "claimed"; ownerToken: string }
    | { status: "in-progress" }
    | { status: "complete"; result: DeepTlsResponseV1 }
  >;
  storeScanResult(identity: unknown, ownerToken: string, result: DeepTlsResponseV1): Promise<void>;
  dispose(): Promise<void>;
}): SecurityAssessmentBindings {
  return {
    DEEP_TLS_SCANNER: {
      idFromName: (name: string) => name,
      get: () => container,
    },
    SECURITY_ASSESSMENT_WORKFLOW: {},
    SECURITY_ASSESSMENT_COORDINATOR: {},
  } as unknown as SecurityAssessmentBindings;
}

function jobId(value: number): string {
  return `sa_${value.toString(16).padStart(2, "0").repeat(24).slice(0, 48)}`;
}

async function coordinatorCreate(
  coordinator: SecurityAssessmentCoordinator,
  id: string,
  hostname: string,
  addresses: string[],
  cancelTokenHash: string,
): Promise<{ job: SecurityAssessmentJobResource; reuse: string; pollAfterSeconds: number }> {
  const response = await coordinator.fetch(jsonInternalRequest("/jobs", {
    jobId: id,
    hostname,
    addresses,
    createdAt: new Date().toISOString(),
    cancelTokenHash,
  }));
  expect(response.status).toBe(200);
  return response.json() as Promise<{ job: SecurityAssessmentJobResource; reuse: string; pollAfterSeconds: number }>;
}

function jsonInternalRequest(path: string, body: unknown): Request {
  return new Request(`https://security-assessment.internal${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

interface FakeJobRow {
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

class FakeAssessmentSql {
  readonly rows = new Map<string, FakeJobRow>();

  exec<T>(query: string, ...bindings: unknown[]): Iterable<T> {
    const sql = query.replace(/\s+/gu, " ").trim().toLowerCase();
    if (sql.startsWith("create table") || sql.startsWith("create index")) return [];
    if (sql.startsWith("select min(expires_at) as earliest")) {
      const values = [...this.rows.values()].map((row) => row.expires_at);
      return this.output([{ earliest: values.length > 0 ? Math.min(...values) : null }]);
    }
    if (sql.startsWith("select min(updated_at) as earliest")) {
      const values = [...this.rows.values()]
        .filter((row) => row.status === "running")
        .map((row) => row.updated_at);
      return this.output([{ earliest: values.length > 0 ? Math.min(...values) : null }]);
    }
    if (sql.startsWith("delete from security_assessment_jobs")) {
      const cutoff = Number(bindings[0]);
      for (const [id, row] of this.rows) if (row.expires_at <= cutoff && row.status !== "running") this.rows.delete(id);
      return [];
    }
    if (sql.includes("where target_key = ? and status in ('queued', 'running')")) {
      const targetKey = String(bindings[0]);
      return this.output([...this.rows.values()]
        .filter((row) => row.target_key === targetKey && (row.status === "queued" || row.status === "running"))
        .sort((left, right) => left.created_at - right.created_at)
        .slice(0, 1));
    }
    if (sql.includes("where target_key = ? and status = 'complete'")) {
      const targetKey = String(bindings[0]);
      const cutoff = Number(bindings[1]);
      return this.output([...this.rows.values()]
        .filter((row) => row.target_key === targetKey && row.status === "complete"
          && (row.completed_at ?? 0) > cutoff && row.result_json !== null)
        .sort((left, right) => (right.completed_at ?? 0) - (left.completed_at ?? 0))
        .slice(0, 1));
    }
    if (sql.startsWith("insert into security_assessment_jobs") && sql.includes("'complete'")) {
      const row: FakeJobRow = {
        job_id: String(bindings[0]), hostname: String(bindings[1]), target_key: String(bindings[2]),
        addresses_json: String(bindings[3]), status: "complete", created_at: Number(bindings[4]),
        updated_at: Number(bindings[5]), expires_at: Number(bindings[6]), completed_at: Number(bindings[7]),
        progress_json: String(bindings[8]), result_json: String(bindings[9]), error_json: null,
        source_job_id: String(bindings[10]), cancel_token_hash: null,
      };
      this.rows.set(row.job_id, row);
      return [];
    }
    if (sql.startsWith("insert into security_assessment_jobs") && sql.includes("'queued'")) {
      const row: FakeJobRow = {
        job_id: String(bindings[0]), hostname: String(bindings[1]), target_key: String(bindings[2]),
        addresses_json: String(bindings[3]), status: "queued", created_at: Number(bindings[4]),
        updated_at: Number(bindings[5]), expires_at: Number(bindings[6]), completed_at: null,
        progress_json: String(bindings[7]), result_json: null, error_json: null, source_job_id: null,
        cancel_token_hash: String(bindings[8]),
      };
      this.rows.set(row.job_id, row);
      return [];
    }
    if (sql.includes("where job_id = ? limit 1")) {
      const row = this.rows.get(String(bindings[0]));
      return this.output(row ? [row] : []);
    }
    if (sql.startsWith("select count(*) as count")) {
      if (sql.includes("status = 'queued'")) {
        const cutoff = Number(bindings[0]);
        return this.output([{ count: [...this.rows.values()].filter((row) => (
          row.status === "queued" && row.expires_at > cutoff
        )).length }]);
      }
      if (sql.includes("status = 'running'")) {
        return this.output([{ count: [...this.rows.values()].filter((row) => row.status === "running").length }]);
      }
      return this.output([{ count: this.rows.size }]);
    }
    if (sql.includes("where status = 'queued' and expires_at > ? order by created_at")) {
      const cutoff = Number(bindings[0]);
      return this.output([...this.rows.values()].filter((row) => row.status === "queued" && row.expires_at > cutoff)
        .sort((left, right) => left.created_at - right.created_at)
        .slice(0, 1));
    }
    if (sql.includes("where status = 'queued' order by created_at")) {
      return this.output([...this.rows.values()].filter((row) => row.status === "queued")
        .sort((left, right) => left.created_at - right.created_at)
        .slice(0, Number(bindings[0])));
    }
    if (sql.includes("where status = 'running' and updated_at <= ?")) {
      const cutoff = Number(bindings[0]);
      return this.output([...this.rows.values()].filter((row) => row.status === "running" && row.updated_at <= cutoff)
        .sort((left, right) => left.updated_at - right.updated_at));
    }
    if (sql.startsWith("update security_assessment_jobs set status = 'running'")) {
      const row = this.require(String(bindings[2]));
      if (row.status === "queued") Object.assign(row, {
        status: "running", updated_at: Number(bindings[0]), progress_json: String(bindings[1]),
      });
      return [];
    }
    if (sql.startsWith("update security_assessment_jobs set cancel_token_hash = null")) {
      const row = this.require(String(bindings[0]));
      if (row.status === "queued" || row.status === "running") row.cancel_token_hash = null;
      return [];
    }
    if (sql.startsWith("update security_assessment_jobs set status = 'cancelled'")) {
      Object.assign(this.require(String(bindings[3])), {
        status: "cancelled", updated_at: Number(bindings[0]), completed_at: Number(bindings[1]),
        progress_json: String(bindings[2]), error_json: null,
      });
      return [];
    }
    if (sql.startsWith("update security_assessment_jobs set updated_at")) {
      Object.assign(this.require(String(bindings[2])), {
        updated_at: Number(bindings[0]), progress_json: String(bindings[1]),
      });
      return [];
    }
    if (sql.startsWith("update security_assessment_jobs set status = 'complete'")) {
      Object.assign(this.require(String(bindings[4])), {
        status: "complete", updated_at: Number(bindings[0]), completed_at: Number(bindings[1]),
        progress_json: String(bindings[2]), result_json: String(bindings[3]), error_json: null,
      });
      return [];
    }
    if (sql.startsWith("update security_assessment_jobs set status = 'failed'")) {
      Object.assign(this.require(String(bindings[4])), {
        status: "failed", updated_at: Number(bindings[0]), completed_at: Number(bindings[1]),
        progress_json: String(bindings[2]), error_json: String(bindings[3]),
      });
      return [];
    }
    throw new Error(`Unhandled fake SQL: ${sql}`);
  }

  private require(id: string): FakeJobRow {
    const row = this.rows.get(id);
    if (!row) throw new Error(`Missing fake row ${id}`);
    return row;
  }

  private output<T>(rows: unknown[]): Iterable<T> {
    return rows.map((row) => structuredClone(row)) as T[];
  }
}
