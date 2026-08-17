import { describe, expect, it, vi } from "vitest";
import {
  SECURITY_ASSESSMENT_DISCLAIMER_VERSION,
  type SecurityAssessmentJobResource,
} from "../shared/types";
import { createWorker, type Env } from "./index";
import type { RateLimitDecision } from "./rate-limiter";
import { UnsafeScanTargetError } from "./target-safety";

const resetAt = "2026-08-16T13:00:00.000Z";
const quotaDecision: RateLimitDecision = {
  allowed: true,
  quota: { limit: 5, remaining: 4, resetAt, windowSeconds: 3600 },
  retryAfterSeconds: 0,
  timestamps: [Date.parse("2026-08-16T12:00:00.000Z")],
};

const env = {
  ASSETS: { fetch: async () => new Response("asset") },
} as unknown as Env;

describe("combined security assessment API", () => {
  it("creates one asynchronous combined job with one quota slot and creator-only token", async () => {
    const resolve = vi.fn(async () => ["8.8.8.8"]);
    const create = vi.fn(async () => ({ job: queuedJob(), reuse: "new" as const, pollAfterSeconds: 2 }));
    const consume = vi.fn(async () => quotaDecision);
    const worker = createWorker({
      consumeWebScanQuota: consume,
      resolvePublicHost: resolve,
      createSecurityAssessmentJob: create,
      generateSecurityAssessmentJobId: () => queuedJob().jobId,
      generateSecurityAssessmentCancelToken: () => `sc_${"cd".repeat(32)}`,
      digestSecurityAssessmentCancelToken: async () => "ef".repeat(32),
      now: () => Date.parse("2026-08-16T12:00:00.000Z"),
    });
    const response = await worker.fetch(assessmentRequest(), env);
    const body = await response.json() as Record<string, unknown>;

    expect(response.status).toBe(202);
    expect(response.headers.get("location")).toBe(`/api/security-assessments/${queuedJob().jobId}`);
    expect(response.headers.get("retry-after")).toBe("2");
    expect(response.headers.get("ratelimit-remaining")).toBe("4");
    expect(body).toEqual(expect.objectContaining({
      jobId: queuedJob().jobId,
      status: "queued",
      reuse: "new",
      cancelToken: `sc_${"cd".repeat(32)}`,
      quota: quotaDecision.quota,
    }));
    expect(consume).toHaveBeenCalledOnce();
    expect(resolve).toHaveBeenCalledWith("example.com");
    expect(create).toHaveBeenCalledWith(env, expect.objectContaining({
      jobId: queuedJob().jobId,
      hostname: "example.com",
      addresses: ["8.8.8.8"],
      cancelTokenHash: "ef".repeat(32),
    }));
  });

  it("does not disclose a cancellation token for cached or single-flight work", async () => {
    for (const reuse of ["cache-hit", "single-flight"] as const) {
      const job = reuse === "cache-hit" ? { ...queuedJob(), status: "complete" as const } : queuedJob();
      if (job.status === "complete") {
        // A real cached job includes a validated result. Route behavior only
        // forwards the already-validated coordinator resource.
        (job as SecurityAssessmentJobResource).status = "cancelled";
        (job as SecurityAssessmentJobResource).progress.phase = "cancelled";
      }
      const worker = createWorker({
        consumeWebScanQuota: async () => quotaDecision,
        resolvePublicHost: async () => ["8.8.8.8"],
        createSecurityAssessmentJob: async () => ({ job, reuse, pollAfterSeconds: reuse === "cache-hit" ? 0 : 2 }),
        generateSecurityAssessmentJobId: () => queuedJob().jobId,
        generateSecurityAssessmentCancelToken: () => `sc_${"cd".repeat(32)}`,
        digestSecurityAssessmentCancelToken: async () => "ef".repeat(32),
      });
      const response = await worker.fetch(assessmentRequest(), env);
      const body = await response.json() as Record<string, unknown>;
      expect(body.reuse).toBe(reuse);
      expect(body).not.toHaveProperty("cancelToken");
    }
  });

  it("requires the deep versioned consent before quota or DNS work", async () => {
    const consume = vi.fn();
    const resolve = vi.fn();
    const worker = createWorker({ consumeWebScanQuota: consume, resolvePublicHost: resolve });
    const response = await worker.fetch(assessmentRequest({ disclaimerVersion: "stale" }), env);

    expect(response.status).toBe(403);
    expect(consume).not.toHaveBeenCalled();
    expect(resolve).not.toHaveBeenCalled();
  });

  it("rejects a cross-origin-simple disguised JSON media type before quota or job work", async () => {
    const consume = vi.fn();
    const resolve = vi.fn();
    const create = vi.fn();
    const worker = createWorker({
      consumeWebScanQuota: consume,
      resolvePublicHost: resolve,
      createSecurityAssessmentJob: create,
    });
    const response = await worker.fetch(new Request("https://scanner.example/api/security-assessments", {
      method: "POST",
      headers: {
        "Content-Type": "text/plain;foo=application/json",
        "CF-Connecting-IP": "203.0.113.7",
      },
      body: JSON.stringify({
        hostname: "example.com",
        authorizedUse: true,
        disclaimerVersion: SECURITY_ASSESSMENT_DISCLAIMER_VERSION,
      }),
    }), env);

    expect(response.status).toBe(400);
    expect(consume).not.toHaveBeenCalled();
    expect(resolve).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
  });

  it("rate-limits before DNS work and returns the exact rolling-window metadata", async () => {
    const resolve = vi.fn();
    const worker = createWorker({
      consumeWebScanQuota: async () => ({
        allowed: false,
        quota: { limit: 5, remaining: 0, resetAt, windowSeconds: 3600 },
        retryAfterSeconds: 120,
        timestamps: [1, 2, 3, 4, 5],
      }),
      resolvePublicHost: resolve,
    });
    const response = await worker.fetch(assessmentRequest(), env);

    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("120");
    expect(resolve).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual(expect.objectContaining({
      code: "RATE_LIMITED",
      quota: expect.objectContaining({ remaining: 0 }),
    }));
  });

  it("fails closed on an unsafe pre-job address after consuming the bounded attempt", async () => {
    const create = vi.fn();
    const worker = createWorker({
      consumeWebScanQuota: async () => quotaDecision,
      resolvePublicHost: async () => { throw new UnsafeScanTargetError("The target resolves to a non-public address."); },
      createSecurityAssessmentJob: create,
    });
    const response = await worker.fetch(assessmentRequest(), env);

    expect(response.status).toBe(400);
    expect(create).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual(expect.objectContaining({
      code: "UNSAFE_TARGET",
      quota: quotaDecision.quota,
    }));
  });

  it("serves bearer status but requires the independent creator token for DELETE", async () => {
    const get = vi.fn(async () => queuedJob());
    const cancel = vi.fn(async () => ({ cancelled: true, job: {
      ...queuedJob(),
      status: "cancelled" as const,
      progress: { ...queuedJob().progress, phase: "cancelled" as const, percent: 100 },
    } }));
    const digest = vi.fn(async () => "ef".repeat(32));
    const worker = createWorker({
      consumeSecurityAssessmentPollQuota: async () => allowedPollDecision(),
      getSecurityAssessmentJob: get,
      cancelSecurityAssessmentJob: cancel,
      digestSecurityAssessmentCancelToken: digest,
    });
    const status = await worker.fetch(new Request(
      `https://scanner.example/api/security-assessments/${queuedJob().jobId}`,
      { headers: { "CF-Connecting-IP": "203.0.113.7" } },
    ), env);
    expect(status.status).toBe(200);
    expect(status.headers.get("retry-after")).toBe("2");
    expect(status.headers.get("ratelimit-limit")).toBe("60");

    const unauthorized = await worker.fetch(new Request(
      `https://scanner.example/api/security-assessments/${queuedJob().jobId}`,
      { method: "DELETE", headers: { "CF-Connecting-IP": "203.0.113.7" } },
    ), env);
    expect(unauthorized.status).toBe(404);
    expect(cancel).not.toHaveBeenCalled();

    const authorized = await worker.fetch(new Request(
      `https://scanner.example/api/security-assessments/${queuedJob().jobId}`,
      {
        method: "DELETE",
        headers: {
          "CF-Connecting-IP": "203.0.113.7",
          "X-Assessment-Cancel-Token": `sc_${"cd".repeat(32)}`,
        },
      },
    ), env);
    expect(authorized.status).toBe(200);
    expect(digest).toHaveBeenCalledWith(`sc_${"cd".repeat(32)}`);
    expect(cancel).toHaveBeenCalledWith(env, queuedJob().jobId, "ef".repeat(32));
  });

  it("rate-limits random valid capability polling before the global coordinator", async () => {
    const get = vi.fn();
    const worker = createWorker({
      consumeSecurityAssessmentPollQuota: async () => ({
        allowed: false,
        limit: 60,
        remaining: 0,
        retryAfterSeconds: 17,
        resetAfterSeconds: 17,
      }),
      getSecurityAssessmentJob: get,
    });
    const response = await worker.fetch(new Request(
      `https://scanner.example/api/security-assessments/sa_${"ef".repeat(24)}`,
      { headers: { "CF-Connecting-IP": "203.0.113.7" } },
    ), env);

    expect(response.status).toBe(429);
    expect(response.headers.get("ratelimit-limit")).toBe("60");
    expect(response.headers.get("ratelimit-remaining")).toBe("0");
    expect(response.headers.get("ratelimit-reset")).toBe("17");
    expect(response.headers.get("retry-after")).toBe("17");
    expect(get).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual(expect.objectContaining({ code: "RATE_LIMITED" }));
  });

  it("rejects cross-site browser status requests before per-IP or coordinator dispatch", async () => {
    const consumePoll = vi.fn();
    const get = vi.fn();
    const worker = createWorker({
      consumeSecurityAssessmentPollQuota: consumePoll,
      getSecurityAssessmentJob: get,
    });
    const response = await worker.fetch(new Request(
      `https://scanner.example/api/security-assessments/sa_${"ef".repeat(24)}`,
      { headers: { "Sec-Fetch-Site": "cross-site" } },
    ), env);

    expect(response.status).toBe(403);
    expect(consumePoll).not.toHaveBeenCalled();
    expect(get).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual(expect.objectContaining({ code: "BAD_REQUEST" }));
  });
});

function assessmentRequest(overrides: Record<string, unknown> = {}): Request {
  return new Request("https://scanner.example/api/security-assessments", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.7" },
    body: JSON.stringify({
      hostname: "Example.COM.",
      authorizedUse: true,
      disclaimerVersion: SECURITY_ASSESSMENT_DISCLAIMER_VERSION,
      ...overrides,
    }),
  });
}

function queuedJob(): SecurityAssessmentJobResource {
  return {
    jobId: `sa_${"ab".repeat(24)}`,
    hostname: "example.com",
    status: "queued",
    createdAt: "2026-08-16T12:00:00.000Z",
    updatedAt: "2026-08-16T12:00:00.000Z",
    expiresAt: "2026-08-17T12:00:00.000Z",
    progress: {
      phase: "queued",
      message: "Waiting for a slot.",
      completedEndpoints: 0,
      totalEndpoints: 1,
      percent: 0,
      updatedAt: "2026-08-16T12:00:00.000Z",
    },
  };
}

function allowedPollDecision() {
  return {
    allowed: true,
    limit: 60 as const,
    remaining: 59,
    retryAfterSeconds: 0,
    resetAfterSeconds: 60,
  };
}
