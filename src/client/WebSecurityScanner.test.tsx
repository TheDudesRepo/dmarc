// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  DeepTlsAssessmentResult,
  DeepTlsGrade,
  DeepTlsObservation,
  DeepTlsResponseV1,
  DeepTlsSection,
  DeepTlsSectionName,
  SecurityAssessmentCreateResponse,
  SecurityAssessmentJobResource,
  SecurityAssessmentJobStatus,
  SecurityAssessmentResult,
  SecurityAssessmentWebResult,
  WebScanQuota,
  WebSecurityCheck,
  WebSecurityCheckStatus,
  WebSecurityScanResult,
} from "../shared/types";
import {
  SECURITY_ASSESSMENT_DISCLAIMER,
  SECURITY_ASSESSMENT_DISCLAIMER_VERSION,
  WEB_SECURITY_DISCLAIMER,
} from "../shared/types";
import {
  WEB_SECURITY_CHECK_IDS,
  SECURITY_ASSESSMENT_CLIENT_WAIT_MS,
  WebSecurityScanner,
  isSecurityAssessmentApiError,
  isSecurityAssessmentCreateResponse,
  isSecurityAssessmentJobResource,
  isSecurityAssessmentResult,
  isWebSecurityScanError,
  isWebSecurityScanResult,
} from "./WebSecurityScanner";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("combined assessment response validation", () => {
  it("accepts complete, queued, and running resources with the exact bounded contract", () => {
    expect(isSecurityAssessmentResult(assessmentResult(), "example.com")).toBe(true);
    expect(isSecurityAssessmentJobResource(jobResource("queued"), "example.com")).toBe(true);
    expect(isSecurityAssessmentJobResource(jobResource("running"), "example.com")).toBe(true);
    expect(isSecurityAssessmentCreateResponse(createResponse("queued"), "example.com")).toBe(true);
    expect(isSecurityAssessmentCreateResponse(createResponse("complete", { pollAfterSeconds: 0 }), "example.com")).toBe(true);
  });

  it.each([
    { name: "guessable job id", change: (value: SecurityAssessmentJobResource) => ({ ...value, jobId: "job-1" }) },
    { name: "unexpected top-level key", change: (value: SecurityAssessmentJobResource) => ({ ...value, attacker: "value" }) },
    { name: "mismatched hostname", change: (value: SecurityAssessmentJobResource) => ({ ...value, hostname: "other.example.com" }) },
    { name: "too many endpoints in progress", change: (value: SecurityAssessmentJobResource) => ({ ...value, progress: { ...value.progress, totalEndpoints: 5 } }) },
    { name: "completed count above total", change: (value: SecurityAssessmentJobResource) => ({ ...value, progress: { ...value.progress, completedEndpoints: 2, totalEndpoints: 1 } }) },
    { name: "running job with complete phase", change: (value: SecurityAssessmentJobResource) => ({ ...value, progress: { ...value.progress, phase: "complete" } }) },
    { name: "queued job carrying a result", change: (value: SecurityAssessmentJobResource) => ({ ...value, result: assessmentResult() }) },
    { name: "complete job missing result", change: () => ({ ...jobResource("complete"), result: undefined }) },
    { name: "failed job missing error", change: () => ({ ...jobResource("failed"), error: undefined }) },
  ])("rejects $name", ({ change }) => {
    expect(isSecurityAssessmentJobResource(change(jobResource("running")), "example.com")).toBe(false);
  });

  it("binds the result, web destination, and every deep endpoint to the submitted target", () => {
    const result = assessmentResult();
    expect(isSecurityAssessmentResult(result, "example.com")).toBe(true);
    expect(isSecurityAssessmentResult(result, "other.example.com")).toBe(false);
    expect(isSecurityAssessmentResult({ ...result, web: { ...result.web, effectiveUrl: "https://attacker.example/" } }, "example.com")).toBe(false);
    expect(isSecurityAssessmentResult({
      ...result,
      tls: {
        ...result.tls,
        endpoints: result.tls.endpoints.map((endpoint) => ({
          ...endpoint,
          target: { ...endpoint.target, address: "203.0.113.90" },
        })),
      },
    }, "example.com")).toBe(false);
  });

  it.each([
    ["loopback IPv4", "127.0.0.1", 4],
    ["private IPv4", "10.0.0.8", 4],
    ["loopback IPv6", "::1", 6],
    ["unique-local IPv6", "fd00::8", 6],
    ["IPv4-mapped IPv6", "::ffff:7f00:1", 6],
    ["NAT64 IPv6", "64:ff9b::808:808", 6],
    ["local-use NAT64 IPv6", "64:ff9b:1::808:808", 6],
    ["Teredo IPv6", "2001:0:4136:e378:8000:63bf:3fff:fdd2", 6],
    ["6to4 IPv6", "2002:808:808::1", 6],
  ] as const)("rejects %s in a purported deep report", (_name, address, family) => {
    const result = assessmentResult({ tls: deepAssessment([deepEndpoint(address, family)]) });
    expect(isSecurityAssessmentResult(result, "example.com")).toBe(false);
  });

  it.each([
    { name: "wrong scanner source", change: (endpoint: DeepTlsResponseV1) => ({ ...endpoint, scanner: { ...endpoint.scanner, sourceUrl: "https://evil.example/tool" } }) },
    { name: "duplicate phase", change: (endpoint: DeepTlsResponseV1) => ({ ...endpoint, phases: endpoint.phases.map((phase, index) => index === 1 ? { ...phase, id: "identity" as const } : phase) }) },
    { name: "oversized details", change: (endpoint: DeepTlsResponseV1) => ({ ...endpoint, sections: mutateObservation(endpoint.sections, "protocols", { details: Object.fromEntries(Array.from({ length: 65 }, (_, index) => [`key${index}`, "x"])) }) }) },
    { name: "unknown observation status", change: (endpoint: DeepTlsResponseV1) => ({ ...endpoint, sections: mutateObservation(endpoint.sections, "protocols", { status: "vulnerable" }) }) },
    { name: "unlinked issue", change: (endpoint: DeepTlsResponseV1) => ({ ...endpoint, issues: endpoint.issues.map((issue) => ({ ...issue, observationId: "protocols:testssl:not-real" })) }) },
    { name: "unsafe extra section", change: (endpoint: DeepTlsResponseV1) => ({ ...endpoint, sections: { ...endpoint.sections, exploitPayloads: endpoint.sections.knownIssues } }) },
  ])("rejects deep TLS evidence with $name", ({ change }) => {
    const result = assessmentResult();
    expect(isSecurityAssessmentResult({
      ...result,
      tls: { ...result.tls, endpoints: [change(result.tls.endpoints[0])] },
    }, "example.com")).toBe(false);
  });

  it("accepts partial endpoint evidence with fewer than three started phases and a bounded 128-item detail array", () => {
    const endpoint = deepEndpoint();
    const partialEndpoint: DeepTlsResponseV1 = {
      ...endpoint,
      status: "partial",
      phases: endpoint.phases.slice(0, 1),
      sections: mutateObservation(endpoint.sections, "ciphers", {
        details: { ciphers: Array.from({ length: 128 }, (_, index) => `TLS_TEST_${index}`) },
      }),
    };
    const result = assessmentResult({
      tls: { ...deepAssessment([partialEndpoint]), status: "partial" },
    });
    expect(isSecurityAssessmentResult(result, "example.com")).toBe(true);
  });

  it("accepts a live-shaped empty summary only for non-actionable tested information", () => {
    const endpoint = deepEndpoint();
    endpoint.sections.certificate.observations.push(observation(
      "certificate",
      "certificate_compression",
      "info",
      "tested",
      "",
      undefined,
      "info",
    ));
    const result = assessmentResult({ tls: deepAssessment([endpoint]) });

    expect(isSecurityAssessmentResult(result, "example.com")).toBe(true);
    expect(isSecurityAssessmentResult({
      ...result,
      tls: {
        ...result.tls,
        endpoints: [{
          ...endpoint,
          sections: mutateObservation(endpoint.sections, "certificate", { summary: "", status: "warning" }),
        }],
      },
    }, "example.com")).toBe(false);
  });

  it("enforces the final deep connection and response budgets", () => {
    const result = assessmentResult();
    const endpoint = result.tls.endpoints[0];
    expect(isSecurityAssessmentResult({
      ...result,
      tls: { ...result.tls, endpoints: [{ ...endpoint, budget: { ...endpoint.budget, maxConnections: 96 } }] },
    }, "example.com")).toBe(false);
    expect(isSecurityAssessmentResult({
      ...result,
      tls: { ...result.tls, endpoints: [{ ...endpoint, budget: { ...endpoint.budget, maxResponseBytes: 786_432 } }] },
    }, "example.com")).toBe(false);
  });

  it("accepts at most 128 normalized observations per deep section", () => {
    const endpoint = deepEndpoint();
    const boundedObservations = [
      ...endpoint.sections.protocols.observations,
      ...Array.from({ length: 125 }, (_, index) => observation(
        "protocols",
        `extra_${index}`,
        "info",
        "tested",
        `Bounded extra protocol observation ${index}.`,
      )),
    ];
    const withObservations = (observations: DeepTlsObservation[]): DeepTlsResponseV1 => ({
      ...endpoint,
      sections: {
        ...endpoint.sections,
        protocols: { ...endpoint.sections.protocols, observations },
      },
    });
    expect(isSecurityAssessmentResult(assessmentResult({ tls: deepAssessment([withObservations(boundedObservations)]) }), "example.com")).toBe(true);
    expect(isSecurityAssessmentResult(assessmentResult({ tls: deepAssessment([withObservations([
      ...boundedObservations,
      observation("protocols", "overflow", "info", "tested", "This row exceeds the fixed section limit."),
    ])]) }), "example.com")).toBe(false);
  });

  it("requires exactly twenty unique web checks and both current disclaimers", () => {
    const result = assessmentResult();
    expect(isSecurityAssessmentResult({ ...result, web: { ...result.web, checks: result.web.checks.slice(1) } })).toBe(false);
    expect(isSecurityAssessmentResult({
      ...result,
      web: {
        ...result.web,
        checks: result.web.checks.map((check, index) => index === 0 ? { ...check, rawResponse: "must not pass through" } : check),
      },
    })).toBe(false);
    expect(isSecurityAssessmentResult({ ...result, disclaimer: "Authorized use." })).toBe(false);
    expect(isSecurityAssessmentResult({ ...result, web: { ...result.web, disclaimer: "Old web boundary." } })).toBe(false);
  });

  it("allows the creator-only cancellation capability only on new work", () => {
    expect(isSecurityAssessmentCreateResponse(createResponse("queued", {
      reuse: "new",
      cancelToken: `sc_${"a".repeat(64)}`,
    }))).toBe(true);
    expect(isSecurityAssessmentCreateResponse(createResponse("queued", {
      reuse: "single-flight",
      cancelToken: `sc_${"a".repeat(64)}`,
    }))).toBe(false);
    expect(isSecurityAssessmentCreateResponse(createResponse("queued", {
      reuse: "new",
      cancelToken: "sc_short",
    }))).toBe(false);
  });

  it("validates combined API errors and rejects malformed quota data", () => {
    expect(isSecurityAssessmentApiError({ error: "Limit reached.", code: "RATE_LIMITED", quota: quota(0) })).toBe(true);
    expect(isSecurityAssessmentApiError({ error: "Missing.", code: "JOB_NOT_FOUND" })).toBe(true);
    expect(isSecurityAssessmentApiError({ error: "Limit reached.", code: "RATE_LIMITED", quota: { ...quota(0), remaining: 6 } })).toBe(false);
    expect(isSecurityAssessmentApiError({ error: "Limit reached.", code: "RATE_LIMITED", quota: { ...quota(0), clientIp: "203.0.113.5" } })).toBe(false);
  });
});

describe("combined assessment interactions", () => {
  it("requires deep authorization, creates one job, polls real progress, and renders separate TLS and web sections", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(createResponse("queued"), 202, rateHeaders(quota(4))))
      .mockResolvedValueOnce(jsonResponse(jobResource("running", {
        progress: progress("tls-scanning", 1, 2, 50, "One selected endpoint is complete."),
      }), 200, { "Retry-After": "1" }))
      .mockResolvedValueOnce(jsonResponse(jobResource("complete")));
    vi.stubGlobal("fetch", fetchMock);
    const { container } = render(<WebSecurityScanner suggestedDomain="example.com" />);

    expect(screen.getByText(SECURITY_ASSESSMENT_DISCLAIMER)).toBeTruthy();
    expect(screen.getByText(new RegExp(`version ${SECURITY_ASSESSMENT_DISCLAIMER_VERSION}`, "u"))).toBeTruthy();
    const submit = screen.getByRole("button", { name: "Run combined assessment" }) as HTMLButtonElement;
    const hostnameInput = screen.getByRole("textbox", { name: "Public website hostname" });
    const consent = screen.getByRole("checkbox", { name: /I confirm I own or administer/u });
    expect(Boolean(hostnameInput.compareDocumentPosition(consent) & Node.DOCUMENT_POSITION_FOLLOWING)).toBe(true);
    expect(Boolean(consent.compareDocumentPosition(submit) & Node.DOCUMENT_POSITION_FOLLOWING)).toBe(true);
    expect(submit.disabled).toBe(true);
    fireEvent.click(consent);
    expect(submit.disabled).toBe(false);
    fireEvent.click(submit);
    await flushPromises();

    expect(screen.getByRole("progressbar", { name: "Assessment progress" })).toBeTruthy();
    expect(screen.getByText(/Endpoint totals appear after fresh target validation/u)).toBeTruthy();

    await advancePolling(2_000);
    expect(screen.getByText("One selected endpoint is complete.")).toBeTruthy();
    expect(screen.getAllByText(/1 of 2 selected TLS endpoints finished/u)).toHaveLength(2);

    await advancePolling(1_000);
    expect(screen.getByRole("heading", { name: "example.com" })).toBeTruthy();
    await advancePolling(100);
    expect(document.activeElement).toBe(screen.getByRole("region", { name: "example.com" }));
    expect(screen.getByRole("heading", { name: "TLS endpoint laboratory" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Known-vulnerability inventory" })).toBeTruthy();
    expect(screen.getAllByRole("link", { name: /testssl\.sh 3\.2\.4/u })[0]?.getAttribute("href")).toBe("https://github.com/testssl/testssl.sh");
    expect(screen.getAllByText(/GPL-2\.0-only/u).length).toBeGreaterThan(0);
    expect(screen.getByText("20 OWASP-aligned configuration checks")).toBeTruthy();
    expect(container.querySelectorAll(".web-check-row")).toHaveLength(20);
    expect(screen.getAllByText("Tested").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Not Testable").length).toBeGreaterThan(0);

    expect(fetchMock).toHaveBeenCalledTimes(3);
    const [postUrl, postRequest] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(postUrl).toBe("/api/security-assessments");
    expect(postRequest.method).toBe("POST");
    expect(postRequest.cache).toBe("no-store");
    expect(JSON.parse(String(postRequest.body))).toEqual({
      hostname: "example.com",
      authorizedUse: true,
      disclaimerVersion: SECURITY_ASSESSMENT_DISCLAIMER_VERSION,
    });
    expect(fetchMock.mock.calls[1]?.[0]).toBe(`/api/security-assessments/${JOB_ID}`);
    expect((fetchMock.mock.calls[1]?.[1] as RequestInit).method).toBe("GET");
  });

  it("renders an immediate cache hit without polling and labels report provenance", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(createResponse("complete", {
      reuse: "cache-hit",
      pollAfterSeconds: 0,
      cancelToken: undefined,
    })));
    vi.stubGlobal("fetch", fetchMock);
    render(<WebSecurityScanner suggestedDomain="example.com" />);

    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    fireEvent.click(screen.getByRole("button", { name: "Run combined assessment" }));
    await screen.findByRole("heading", { name: "example.com" });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Reused valid cached report")).toBeTruthy();
  });

  it("renders a clear fallback for a safe informational observation with no producer summary", async () => {
    const endpoint = deepEndpoint();
    endpoint.sections.certificate.observations.push(observation(
      "certificate",
      "certificate_compression",
      "info",
      "tested",
      "",
      undefined,
      "info",
    ));
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(createResponse("complete", {
      reuse: "cache-hit",
      pollAfterSeconds: 0,
      cancelToken: undefined,
      result: assessmentResult({ tls: deepAssessment([endpoint]) }),
    }))));
    render(<WebSecurityScanner suggestedDomain="example.com" />);

    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    fireEvent.click(screen.getByRole("button", { name: "Run combined assessment" }));
    await screen.findByRole("heading", { name: "example.com" });

    expect(screen.getByText("Certificate Compression")).toBeTruthy();
    expect(screen.getByText("The scanner reported this informational measurement without a narrative summary.")).toBeTruthy();
  });

  it("keeps neutral TLS information out of remediation priority counts", async () => {
    const endpoint = deepEndpoint();
    endpoint.sections.features.observations.push(observation(
      "features",
      "informational-note",
      "info",
      "inferred",
      "This is neutral scanner context, not a remediation item.",
    ));
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(createResponse("complete", {
      reuse: "cache-hit",
      pollAfterSeconds: 0,
      cancelToken: undefined,
      result: assessmentResult({ tls: deepAssessment([endpoint]) }),
    }))));
    const { container } = render(<WebSecurityScanner suggestedDomain="example.com" />);

    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    fireEvent.click(screen.getByRole("button", { name: "Run combined assessment" }));
    await screen.findByRole("heading", { name: "example.com" });

    expect(container.querySelector(".severity-low strong")?.textContent).toBe("0");
    expect(container.querySelector(".security-priority-list")?.textContent).not.toContain(
      "This is neutral scanner context, not a remediation item.",
    );
  });

  it("labels single-flight reuse and Stop waiting only aborts local polling without DELETE", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(createResponse("running", {
      reuse: "single-flight",
      cancelToken: undefined,
    }), 200));
    vi.stubGlobal("fetch", fetchMock);
    render(<WebSecurityScanner suggestedDomain="example.com" />);

    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    fireEvent.click(screen.getByRole("button", { name: "Run combined assessment" }));
    await flushPromises();
    expect(screen.getByText(/joined an assessment already in progress/u)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Stop waiting" }));
    expect(screen.getByRole("alert").textContent).toContain("Stopped waiting in this browser");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls.some(([url, request]) => String(url).includes(JOB_ID) && (request as RequestInit | undefined)?.method === "DELETE")).toBe(false);
  });

  it("keeps waiting beyond 30 minutes for a valid tail-queue job and stops at the two-hour ceiling", async () => {
    vi.useFakeTimers();
    let markPollStarted: (() => void) | undefined;
    const pollStarted = new Promise<void>((resolve) => { markPollStarted = resolve; });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(createResponse("queued")))
      .mockImplementationOnce((_url: string, request: RequestInit) => new Promise<Response>((_resolve, reject) => {
        markPollStarted?.();
        request.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
      }));
    vi.stubGlobal("fetch", fetchMock);
    render(<WebSecurityScanner suggestedDomain="example.com" />);

    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    fireEvent.click(screen.getByRole("button", { name: "Run combined assessment" }));
    await flushPromises();
    await advancePolling(2_000);
    await pollStarted;

    await advancePolling(30 * 60_000);
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByRole("button", { name: "Stop waiting" })).toBeTruthy();

    await advancePolling(SECURITY_ASSESSMENT_CLIENT_WAIT_MS - (30 * 60_000));
    expect(screen.getByRole("alert").textContent).toContain("stopped before completion");
  });

  it("backs off and continues a valid job when shared-network status polling returns 429", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(createResponse("queued")))
      .mockResolvedValueOnce(jsonResponse({
        error: "This client is checking assessment status too frequently.",
        code: "RATE_LIMITED",
      }, 429, { "Retry-After": "45", "RateLimit-Limit": "60", "RateLimit-Remaining": "0" }))
      .mockResolvedValueOnce(jsonResponse(jobResource("complete")));
    vi.stubGlobal("fetch", fetchMock);
    render(<WebSecurityScanner suggestedDomain="example.com" />);

    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    fireEvent.click(screen.getByRole("button", { name: "Run combined assessment" }));
    await flushPromises();
    await advancePolling(2_000);
    expect(screen.queryByRole("alert")).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await advancePolling(45_000);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(screen.getByRole("heading", { name: "example.com" })).toBeTruthy();
  });

  it.each([
    ["URL", "https://example.com/admin"],
    ["credentials", "user@example.com"],
    ["path", "example.com/admin"],
    ["custom port", "example.com:8443"],
    ["IPv4 literal", "104.16.1.10"],
    ["IPv6 literal", "[2606:4700::1111]"],
    ["single-label name", "intranet"],
    ["special-use suffix", "service.local"],
    ["invalid label", "api_example.com"],
    ["overlong label", `${"a".repeat(64)}.example`],
  ])("rejects a %s target locally and never consumes a quota slot", async (_label, unsafeTarget) => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<WebSecurityScanner suggestedDomain={unsafeTarget} />);
    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    fireEvent.click(screen.getByRole("button", { name: "Run combined assessment" }));

    expect(screen.getByRole("alert").textContent).toContain("Enter one public hostname only");
    expect(screen.getByRole("textbox", { name: "Public website hostname" }).getAttribute("aria-invalid")).toBe("true");
    expect(screen.getByRole("textbox", { name: "Public website hostname" }).getAttribute("aria-errormessage")).toBe("web-security-error");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("locks this scanner on 429, preserves returned quota, and resets consent after the window expires", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-16T20:00:00.000Z"));
    const blocked = quota(0, "2026-08-16T20:00:10.000Z");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      error: "This network has used its five combined assessments in the rolling hour.",
      code: "RATE_LIMITED",
      quota: blocked,
    }, 429, { ...rateHeaders(blocked), "Retry-After": "10" })));
    render(<WebSecurityScanner suggestedDomain="example.com" />);

    const checkbox = screen.getByRole("checkbox", { name: /I confirm I own or administer/u }) as HTMLInputElement;
    fireEvent.click(checkbox);
    fireEvent.click(screen.getByRole("button", { name: "Run combined assessment" }));
    await flushPromises();
    expect(screen.getByRole("alert").textContent).toContain("five combined assessments");
    expect(screen.getByText(/0 of 5 scans remaining/u)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Hourly limit reached" }) as HTMLButtonElement).disabled).toBe(true);

    await act(async () => { vi.advanceTimersByTime(15_000); });
    expect(screen.getByText(/Limit: 5 combined security assessments/u)).toBeTruthy();
    expect(checkbox.disabled).toBe(false);
  });

  it("shows post-consumption quota when job creation fails", async () => {
    const consumed = quota(3);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      error: "The target could not be assessed right now.",
      code: "UPSTREAM_ERROR",
      quota: consumed,
    }, 502, rateHeaders(consumed))));
    render(<WebSecurityScanner suggestedDomain="example.com" />);
    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    fireEvent.click(screen.getByRole("button", { name: "Run combined assessment" }));
    await screen.findByRole("alert");
    expect(screen.getByRole("textbox", { name: "Public website hostname" }).getAttribute("aria-invalid")).toBe("false");
    expect(screen.getByText(/3 of 5 scans remaining/u)).toBeTruthy();
  });

  it("expires a stale nonzero rolling quota without clearing an unrelated scan error", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-16T20:00:00.000Z"));
    const consumed = quota(3, "2026-08-16T20:00:10.000Z");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      error: "The target could not be assessed right now.",
      code: "UPSTREAM_ERROR",
      quota: consumed,
    }, 502, rateHeaders(consumed))));
    render(<WebSecurityScanner suggestedDomain="example.com" />);
    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    fireEvent.click(screen.getByRole("button", { name: "Run combined assessment" }));
    await flushPromises();

    expect(screen.getByText(/3 of 5 scans remaining/u)).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain("could not be assessed");
    await act(async () => { vi.advanceTimersByTime(15_000); });
    expect(screen.getByText(/Limit: 5 combined security assessments/u)).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain("could not be assessed");
  });

  it("stops a stale polled job with an honest retry message", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-16T20:26:00.000Z"));
    const stale = jobResource("running", {
      createdAt: "2026-08-16T19:00:00.000Z",
      updatedAt: "2026-08-16T20:00:00.000Z",
      expiresAt: "2026-08-17T19:00:00.000Z",
      progress: { ...progress("tls-scanning", 0, 1, 10, "Waiting."), updatedAt: "2026-08-16T20:00:00.000Z" },
    });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(createResponse("queued", {
        createdAt: "2026-08-16T19:00:00.000Z",
        updatedAt: "2026-08-16T19:59:00.000Z",
        expiresAt: "2026-08-17T19:00:00.000Z",
        progress: { ...progress("queued", 0, 0, 0, "Queued."), updatedAt: "2026-08-16T19:59:00.000Z" },
      })))
      .mockResolvedValueOnce(jsonResponse(stale));
    vi.stubGlobal("fetch", fetchMock);
    render(<WebSecurityScanner suggestedDomain="example.com" />);
    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    fireEvent.click(screen.getByRole("button", { name: "Run combined assessment" }));
    await flushPromises();
    await advancePolling(2_000);

    expect(screen.getByRole("alert").textContent).toContain("stopped reporting progress for 25 minutes");
  });

  it("switches endpoint tabs by keyboard and exposes certificate, cipher, compatibility, and issue detail", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(createResponse("complete", {
      reuse: "cache-hit",
      pollAfterSeconds: 0,
      cancelToken: undefined,
      result: assessmentResult({ tls: deepAssessment([deepEndpoint(), deepEndpoint("2606:4700::1111", 6)] ) }),
    }))));
    render(<WebSecurityScanner suggestedDomain="example.com" />);
    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    fireEvent.click(screen.getByRole("button", { name: "Run combined assessment" }));
    await screen.findByRole("heading", { name: "example.com" });

    const tabs = screen.getAllByRole("tab");
    expect(tabs).toHaveLength(2);
    expect(tabs[0].getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(tabs[0], { key: "ArrowRight" });
    expect(tabs[1].getAttribute("aria-selected")).toBe("true");
    expect(document.activeElement).toBe(tabs[1]);
    expect(screen.getAllByText("Named groups and signature algorithms")).toHaveLength(2);
    expect(screen.getAllByText("Client compatibility")).toHaveLength(2);
    expect(screen.getAllByText(/Disable obsolete versions/u).length).toBeGreaterThan(0);
  });

  it("copies and shares only completed report content, then prints every web check without exposing the bearer job id", async () => {
    const result = assessmentResult();
    const print = vi.fn();
    vi.stubGlobal("print", print);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(createResponse("complete", {
      reuse: "cache-hit", pollAfterSeconds: 0, cancelToken: undefined, result,
    }))));
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    render(<WebSecurityScanner suggestedDomain="example.com" />);
    await user.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    await user.click(screen.getByRole("button", { name: "Run combined assessment" }));
    await screen.findByRole("heading", { name: "example.com" });
    await user.click(screen.getByRole("button", { name: "Copy JSON" }));

    expect(writeText).toHaveBeenCalledWith(JSON.stringify(result, null, 2));
    expect(String(writeText.mock.calls[0]?.[0])).not.toContain(JOB_ID);
    expect(screen.getByRole("button", { name: "JSON copied" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Share summary" }));
    expect(writeText).toHaveBeenCalledTimes(2);
    expect(String(writeText.mock.calls[1]?.[0])).toContain("example.com security snapshot");
    expect(String(writeText.mock.calls[1]?.[0])).not.toContain(JOB_ID);
    expect(screen.getByRole("button", { name: "Summary copied" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: /Needs attention/u }));
    expect(document.querySelectorAll(".web-check-row")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: "Print report" }));
    await act(async () => { await new Promise((resolve) => window.setTimeout(resolve, 0)); });
    expect(print).toHaveBeenCalledTimes(1);
    expect(document.querySelectorAll(".web-check-row")).toHaveLength(20);
  });
});

describe("legacy bounded response validation", () => {
  it("continues validating the internal legacy endpoint without using it in the UI", () => {
    const result = legacyScanResult();
    expect(isWebSecurityScanResult(result, "example.com")).toBe(true);
    expect(isWebSecurityScanResult({ ...result, effectiveUrl: "https://attacker.example/" }, "example.com")).toBe(false);
    expect(isWebSecurityScanError({ error: "Limit reached.", code: "RATE_LIMITED", quota: quota(0) })).toBe(true);
  });
});

const JOB_ID = `sa_${"1".repeat(48)}`;
const JOB_CREATED = "2099-08-16T20:00:00.000Z";
const JOB_UPDATED = "2099-08-16T20:01:00.000Z";
const JOB_EXPIRES = "2099-08-17T20:00:00.000Z";

function createResponse(
  status: SecurityAssessmentJobStatus,
  overrides: Partial<SecurityAssessmentCreateResponse> = {},
): SecurityAssessmentCreateResponse {
  const reuse = overrides.reuse ?? "new";
  return {
    ...jobResource(status),
    quota: quota(4, JOB_EXPIRES),
    reuse,
    pollAfterSeconds: status === "complete" ? 0 : 2,
    ...(reuse === "new" ? { cancelToken: `sc_${"2".repeat(64)}` } : {}),
    ...overrides,
  };
}

function jobResource(
  status: SecurityAssessmentJobStatus,
  overrides: Partial<SecurityAssessmentJobResource> = {},
): SecurityAssessmentJobResource {
  const resource: SecurityAssessmentJobResource = {
    jobId: JOB_ID,
    hostname: "example.com",
    status,
    createdAt: JOB_CREATED,
    updatedAt: JOB_UPDATED,
    expiresAt: JOB_EXPIRES,
    progress: status === "queued"
      ? progress("queued", 0, 0, 0, "Assessment queued.")
      : status === "running"
        ? progress("tls-scanning", 0, 1, 20, "Scanning the selected endpoint.")
        : status === "complete"
          ? progress("complete", 1, 1, 100, "Assessment complete.")
          : status === "cancelled"
            ? progress("cancelled", 0, 1, 0, "Assessment cancelled.")
            : progress("failed", 0, 1, 0, "Assessment failed."),
    ...(status === "complete" ? { result: assessmentResult() } : {}),
    ...(status === "failed" ? { error: { code: "ORCHESTRATION_FAILED", message: "Assessment failed." } } : {}),
  };
  return { ...resource, ...overrides };
}

function progress(
  phase: SecurityAssessmentJobResource["progress"]["phase"],
  completedEndpoints: number,
  totalEndpoints: number,
  percent: number,
  message: string,
): SecurityAssessmentJobResource["progress"] {
  return { phase, message, completedEndpoints, totalEndpoints, percent, updatedAt: JOB_UPDATED };
}

function assessmentResult(overrides: Partial<SecurityAssessmentResult> = {}): SecurityAssessmentResult {
  return {
    schemaVersion: "security-assessment-v1",
    hostname: "example.com",
    startedAt: "2026-08-16T20:00:00.000Z",
    completedAt: "2026-08-16T20:03:00.000Z",
    durationMs: 180_000,
    web: webResult(),
    tls: deepAssessment(),
    disclaimer: SECURITY_ASSESSMENT_DISCLAIMER,
    ...overrides,
  };
}

function webResult(overrides: Partial<SecurityAssessmentWebResult> = {}): SecurityAssessmentWebResult {
  const nextChecks = overrides.checks ?? checks();
  const unknown = nextChecks.filter((check) => check.status === "unknown").length;
  const notApplicable = nextChecks.filter((check) => check.status === "not-applicable").length;
  return {
    hostname: "example.com",
    effectiveUrl: "https://example.com/",
    scannedAt: "2026-08-16T20:00:02.000Z",
    durationMs: 842,
    score: 88,
    grade: "B",
    headline: "Observable web controls need review",
    summary: "The fixed web-control set completed.",
    checks: nextChecks,
    coverage: { evaluated: 20 - unknown - notApplicable, total: 20, unknown, notApplicable },
    requestBudget: { httpRequests: 4, tlsConnections: 0, maxResponseBytes: 131_072, redirectHopsFollowed: 1 },
    disclaimer: WEB_SECURITY_DISCLAIMER,
    ...overrides,
  };
}

function deepAssessment(endpoints = [deepEndpoint()]): DeepTlsAssessmentResult {
  const resolvedAddresses = endpoints.map((endpoint) => endpoint.target.address);
  return {
    status: "complete",
    grade: grade("B", 86),
    summary: "The fixed deep TLS profile completed for the selected public endpoints.",
    resolvedAddresses,
    endpoints,
    endpointsTruncated: false,
    limitations: ["This is a fixed safe profile, not proof that the service is secure or compliant."],
  };
}

function deepEndpoint(address = "104.16.1.10", addressFamily: 4 | 6 = 4): DeepTlsResponseV1 {
  const sections = deepSections();
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
    target: { hostname: "example.com", address, addressFamily, port: 443, sni: "example.com", profile: "safe" },
    status: "complete",
    startedAt: "2026-08-16T20:00:05.000Z",
    durationMs: 42_000,
    grade: grade("B", 86),
    budget: {
      deadlineMs: 180_000,
      maxProcesses: 3,
      processesStarted: 3,
      processesCompleted: 3,
      maxConcurrentConnections: 5,
      maxConnections: 128,
      connectionsOpened: 44,
      maxPhaseOutputBytes: 393_216,
      outputBytes: 42_000,
      maxResponseBytes: 163_840,
    },
    phases: ["identity", "cryptography", "compatibility"].map((id) => ({
      id: id as "identity" | "cryptography" | "compatibility",
      status: "complete" as const,
      exitCode: 0,
      durationMs: 14_000,
      outputBytes: 14_000,
    })),
    sections,
    issues: [{
      id: "legacy-protocol",
      section: "protocols",
      observationId: "protocols:testssl:TLS1",
      severity: "high",
      evidenceKind: "tested",
      summary: "TLS 1.0 was accepted by the endpoint.",
    }],
    limitations: ["Live revocation and cross-service DROWN testing were excluded."],
  };
}

function deepSections(): Record<DeepTlsSectionName, DeepTlsSection> {
  return {
    certificate: section([
      observation("certificate", "cert", "pass", "tested", "The leaf certificate and presented material were parsed.", { materialOmitted: true, subject: "CN=example.com", issuer: "CN=Example CA" }),
      observation("certificate", "cert_chain_of_trust", "pass", "tested", "The presented path was trusted.", { supported: true }),
      observation("certificate", "cert_notAfter", "pass", "tested", "The leaf certificate is not near expiry.", { date: "2026-11-01T00:00:00Z" }),
    ], "A", 96),
    protocols: section([
      observation("protocols", "TLS1", "fail", "tested", "TLS 1.0 was negotiated.", { supported: true, values: ["TLSv1"] }, "high"),
      observation("protocols", "TLS1_2", "pass", "tested", "TLS 1.2 was negotiated.", { supported: true, values: ["TLSv1.2"] }),
      observation("protocols", "TLS1_3", "pass", "tested", "TLS 1.3 was negotiated.", { supported: true, values: ["TLSv1.3"] }),
    ], "C", 74),
    ciphers: section([
      observation("ciphers", "cipher-tls1_3_x1301", "pass", "tested", "A TLS 1.3 AEAD suite was enumerated.", {
        protocol: "TLSv1.3", code: "0x1301", opensslName: "TLS_AES_128_GCM_SHA256", ianaName: "TLS_AES_128_GCM_SHA256", keyExchange: "TLS 1.3", bits: 128, aead: true, cbc: false, forwardSecrecy: true,
      }),
    ], "A", 95),
    keyExchange: section([
      observation("keyExchange", "FS_ECDHE_curves", "pass", "tested", "Current ECDHE groups were offered.", { groups: ["X25519", "secp256r1"] }),
      observation("keyExchange", "FS_TLS13_sig_algs", "pass", "tested", "TLS 1.3 signature algorithms were enumerated.", { algorithms: ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"] }),
    ], "A", 94),
    features: section([
      observation("features", "ALPN", "pass", "tested", "ALPN negotiated an HTTP protocol.", { supported: true, values: ["h2", "http/1.1"] }),
      observation("features", "OCSP_stapling", "warning", "tested", "OCSP stapling was not observed.", { supported: false }, "low"),
    ], "B", 86),
    clientSimulations: section([
      observation("clientSimulations", "clientsimulation-modern-browser", "pass", "tested", "The fixed modern-browser profile connected.", { profile: "Modern browser", connected: true, protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256" }),
    ], "A", 92),
    knownIssues: section([
      observation("knownIssues", "heartbleed", "pass", "tested", "The safe Heartbleed probe did not identify the flaw.", { cve: ["CVE-2014-0160"], cwe: ["CWE-126"] }),
      observation("knownIssues", "breach", "not-tested", "not-testable", "BREACH requires application-response context outside the TLS-only safe profile.", undefined, "none", true),
    ], "A", 93),
  };
}

function section(observations: DeepTlsObservation[], value: DeepTlsGrade["value"], score: number): DeepTlsSection {
  return { status: "complete", grade: grade(value, score), observations };
}

function observation(
  sectionName: DeepTlsSectionName,
  sourceId: string,
  status: DeepTlsObservation["status"],
  evidenceKind: DeepTlsObservation["evidenceKind"],
  summary: string,
  details?: DeepTlsObservation["details"],
  severity: DeepTlsObservation["severity"] = "none",
  syntheticNotTested = false,
): DeepTlsObservation {
  return {
    id: syntheticNotTested
      ? `${sectionName}:scanner:not-tested:${sourceId}`
      : `${sectionName}:testssl:${sourceId}`,
    sourceId,
    status,
    evidenceKind,
    severity,
    summary,
    ...(details ? { details } : {}),
  };
}

function grade(value: DeepTlsGrade["value"], score: number | null): DeepTlsGrade {
  return {
    value,
    score: value === "N/A" ? null : score,
    coverage: { evaluatedWeight: value === "N/A" ? 0 : 90, totalWeight: 100 },
    methodology: "cresswell-tls-v1",
    caps: value === "C" ? [{ id: "legacy-tls", maxGrade: "C", reason: "TLS 1.0 was accepted." }] : [],
  };
}

function mutateObservation(
  sections: Record<DeepTlsSectionName, DeepTlsSection>,
  sectionName: DeepTlsSectionName,
  change: Record<string, unknown>,
): Record<DeepTlsSectionName, DeepTlsSection> {
  const target = sections[sectionName];
  return {
    ...sections,
    [sectionName]: {
      ...target,
      observations: target.observations.map((item, index) => index === 0 ? { ...item, ...change } as DeepTlsObservation : item),
    },
  };
}

function checks(overrides: Partial<Record<(typeof WEB_SECURITY_CHECK_IDS)[number], WebSecurityCheckStatus>> = {}): WebSecurityCheck[] {
  return WEB_SECURITY_CHECK_IDS.map((id) => ({
    id,
    status: overrides[id] ?? "pass",
    title: id.split("-").map((part) => `${part[0]?.toUpperCase()}${part.slice(1)}`).join(" "),
    summary: `Bounded ${id} evidence was reviewed.`,
    evidence: [`Observed evidence for ${id}.`],
    remediation: `Keep the ${id} configuration current.`,
    owasp: { top10: ["A02:2025 Security Misconfiguration"], wstg: ["WSTG-CONF-14"] },
  }));
}

function legacyScanResult(): WebSecurityScanResult {
  const web = webResult();
  return {
    ...web,
    tls: {
      status: "unavailable",
      grade: "N/A",
      summary: "Legacy TLS evidence was unavailable.",
      resolvedAddresses: [],
      endpoints: [],
      endpointsTruncated: false,
      reportUrl: "https://www.ssllabs.com/ssltest/analyze.html?d=example.com&hideResults=on",
      limitations: ["Legacy route only."],
    },
    quota: quota(4),
  };
}

function quota(remaining: number, resetAt = "2099-08-16T21:00:00.000Z"): WebScanQuota {
  return { limit: 5, remaining, resetAt, windowSeconds: 3600 };
}

function rateHeaders(value: WebScanQuota): Record<string, string> {
  return {
    "RateLimit-Limit": String(value.limit),
    "RateLimit-Remaining": String(value.remaining),
    "RateLimit-Reset": String(Math.max(0, Math.ceil((Date.parse(value.resetAt) - Date.now()) / 1_000))),
  };
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

async function flushPromises(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

async function advancePolling(milliseconds: number): Promise<void> {
  await act(async () => {
    vi.advanceTimersByTime(milliseconds);
    await Promise.resolve();
    await Promise.resolve();
  });
}
