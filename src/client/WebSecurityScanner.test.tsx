// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  TlsAssessment,
  WebScanQuota,
  WebSecurityCheck,
  WebSecurityCheckStatus,
  WebSecurityScanResult,
} from "../shared/types";
import { WEB_SECURITY_DISCLAIMER } from "../shared/types";
import {
  WEB_SECURITY_CHECK_IDS,
  WebSecurityScanner,
  isWebSecurityScanError,
  isWebSecurityScanResult,
} from "./WebSecurityScanner";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("web-security response validation", () => {
  it("accepts the complete bounded contract with exactly twenty fixed checks", () => {
    const result = scanResult();
    expect(result.checks).toHaveLength(20);
    expect(isWebSecurityScanResult(result)).toBe(true);
    expect(isWebSecurityScanResult({ ...result, grade: "N/A" })).toBe(true);
  });

  it.each([
    { name: "missing check", change: (result: WebSecurityScanResult) => ({ ...result, checks: result.checks.slice(1) }) },
    {
      name: "duplicate check",
      change: (result: WebSecurityScanResult) => ({
        ...result,
        checks: result.checks.map((check, index) => index === 1 ? { ...check, id: result.checks[0].id } : check),
      }),
    },
    {
      name: "unknown check",
      change: (result: WebSecurityScanResult) => ({
        ...result,
        checks: result.checks.map((check, index) => index === 0 ? { ...check, id: "sql-injection" } : check),
      }),
    },
    { name: "unsafe effective URL", change: (result: WebSecurityScanResult) => ({ ...result, effectiveUrl: "http://127.0.0.1/admin" }) },
    { name: "private HTTPS effective URL", change: (result: WebSecurityScanResult) => ({ ...result, effectiveUrl: "https://127.0.0.1/" }) },
    { name: "off-target effective URL", change: (result: WebSecurityScanResult) => ({ ...result, effectiveUrl: "https://attacker.example/" }) },
    { name: "unsafe report link", change: (result: WebSecurityScanResult) => ({ ...result, tls: { ...result.tls, reportUrl: "https://evil.example/report" } }) },
    { name: "mismatched report target", change: (result: WebSecurityScanResult) => ({ ...result, tls: { ...result.tls, reportUrl: "https://www.ssllabs.com/ssltest/analyze.html?d=other.example.com" } }) },
    { name: "loose date", change: (result: WebSecurityScanResult) => ({ ...result, scannedAt: "August 16, 2026" }) },
    { name: "outdated disclaimer", change: (result: WebSecurityScanResult) => ({ ...result, disclaimer: "Authorized use only." }) },
    { name: "invalid quota", change: (result: WebSecurityScanResult) => ({ ...result, quota: { ...result.quota, remaining: 6 } }) },
    { name: "oversized request budget", change: (result: WebSecurityScanResult) => ({ ...result, requestBudget: { ...result.requestBudget, httpRequests: 7 } }) },
    { name: "wrong response cap", change: (result: WebSecurityScanResult) => ({ ...result, requestBudget: { ...result.requestBudget, maxResponseBytes: 262_144 } }) },
    { name: "bad coverage", change: (result: WebSecurityScanResult) => ({ ...result, coverage: { ...result.coverage, evaluated: 19 } }) },
    {
      name: "duplicate protocol",
      change: (result: WebSecurityScanResult) => ({
        ...result,
        tls: {
          ...result.tls,
          endpoints: result.tls.endpoints.map((endpoint) => ({
            ...endpoint,
            protocols: endpoint.protocols.map((protocol, index) => index === 1 ? { ...protocol, version: "TLSv1" as const } : protocol),
          })),
        },
      }),
    },
    {
      name: "endpoint outside resolved addresses",
      change: (result: WebSecurityScanResult) => ({
        ...result,
        tls: {
          ...result.tls,
          endpoints: result.tls.endpoints.map((endpoint) => ({ ...endpoint, address: "203.0.113.10" })),
        },
      }),
    },
    {
      name: "oversized evidence list",
      change: (result: WebSecurityScanResult) => ({
        ...result,
        checks: result.checks.map((check, index) => index === 0
          ? { ...check, evidence: Array.from({ length: 13 }, (_, evidenceIndex) => `Evidence ${evidenceIndex}`) }
          : check),
      }),
    },
  ])("rejects $name", ({ change }) => {
    expect(isWebSecurityScanResult(change(scanResult()))).toBe(false);
  });

  it("binds a valid response to the hostname submitted by the user", () => {
    const result = scanResult();
    expect(isWebSecurityScanResult(result, "example.com")).toBe(true);
    expect(isWebSecurityScanResult(result, "other.example.com")).toBe(false);
  });

  it("accepts the Worker's bounded long effective URL but rejects values over 4,096 characters", () => {
    const result = scanResult();
    const withinWorkerBound = `https://example.com/${"a".repeat(3_000)}`;
    expect(isWebSecurityScanResult({ ...result, effectiveUrl: withinWorkerBound }, "example.com")).toBe(true);
    expect(isWebSecurityScanResult({
      ...result,
      effectiveUrl: `https://example.com/${"a".repeat(4_096)}`,
    }, "example.com")).toBe(false);
  });

  it("validates rate-limit errors without trusting malformed quota data", () => {
    expect(isWebSecurityScanError({
      error: "Limit reached.",
      code: "RATE_LIMITED",
      quota: quota(0),
    })).toBe(true);
    expect(isWebSecurityScanError({
      error: "Limit reached.",
      code: "RATE_LIMITED",
      quota: { ...quota(0), resetAt: "tomorrow" },
    })).toBe(false);
  });
});

describe("web-security scanner interactions", () => {
  it("requires authorization, posts the versioned consent, and renders partial TLS separately from failed checks", async () => {
    const responseBody = scanResult({
      tls: tlsAssessment("partial"),
      checks: checks({ hsts: "warning", "content-security-policy": "fail", "http-methods": "unknown", "cross-origin-isolation": "not-applicable" }),
    });
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(responseBody, 200, rateHeaders(responseBody.quota)));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    const { container } = render(<WebSecurityScanner suggestedDomain="example.com" />);

    expect(screen.getByText(WEB_SECURITY_DISCLAIMER)).toBeTruthy();
    expect(screen.getByText(/Authorized-use notice · version 2026-08-16/u)).toBeTruthy();
    const submit = screen.getByRole("button", { name: "Run security scan" }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    await user.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    expect(submit.disabled).toBe(false);
    await user.click(submit);

    await screen.findByRole("heading", { name: "example.com" });
    expect(screen.getByText(/Some TLS evidence is indeterminate/u)).toBeTruthy();
    expect(screen.getByText("Fixed assessment scope").textContent).toBe("Fixed assessment scope");
    expect(container.querySelectorAll(".web-check-row")).toHaveLength(20);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, request] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/web-security");
    expect(request.method).toBe("POST");
    expect(JSON.parse(String(request.body))).toEqual({
      hostname: "example.com",
      authorizedUse: true,
      disclaimerVersion: "2026-08-16",
    });
  });

  it("renders unavailable TLS as indeterminate rather than a TLS failure", async () => {
    const responseBody = scanResult({ tls: tlsAssessment("unavailable") });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(responseBody)));
    const user = userEvent.setup();
    render(<WebSecurityScanner suggestedDomain="example.com" />);

    await user.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    await user.click(screen.getByRole("button", { name: "Run security scan" }));

    await screen.findByText(/Raw TLS evidence was unavailable from the scanner network/u);
    expect(screen.queryByText(/Unknown probes are not counted as failures/u)).toBeNull();
    expect(screen.getByText("N/A").textContent).toBe("N/A");
  });

  it("styles a grade-F TLS result and supported legacy TLS as risks", async () => {
    const tls = tlsAssessment("complete");
    tls.grade = "F";
    tls.endpoints[0].protocols = tls.endpoints[0].protocols.map((protocol) => protocol.version === "TLSv1"
      ? { ...protocol, status: "supported", note: "Legacy TLS accepted." }
      : protocol);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(scanResult({ tls }))));
    const user = userEvent.setup();
    const { container } = render(<WebSecurityScanner suggestedDomain="example.com" />);

    await user.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    await user.click(screen.getByRole("button", { name: "Run security scan" }));

    await screen.findByText(/Complete evidence · Grade F/u);
    expect(container.querySelector(".tls-panel-grade-f")).not.toBeNull();
    expect(screen.getByText("TLSv1").closest(".tls-protocol")?.classList.contains("tls-protocol-warning")).toBe(true);
  });

  it("locks only this scanner on a 429 and resets consent when the target changes", async () => {
    const blockedQuota = quota(0, "2099-08-16T21:00:00.000Z");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      error: "This client has used its five web security scans in the rolling one-hour window.",
      code: "RATE_LIMITED",
      quota: blockedQuota,
    }, 429, {
      ...rateHeaders(blockedQuota),
      "Retry-After": "3600",
    })));
    const user = userEvent.setup();
    render(<WebSecurityScanner suggestedDomain="example.com" />);

    const checkbox = screen.getByRole("checkbox", { name: /I confirm I own or administer/u }) as HTMLInputElement;
    await user.click(checkbox);
    await user.click(screen.getByRole("button", { name: "Run security scan" }));

    expect((await screen.findByRole("alert")).textContent).toContain("five web security scans");
    expect((screen.getByRole("button", { name: "Hourly limit reached" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/0 of 5 scans remaining/u)).toBeTruthy();
    await user.type(screen.getByLabelText("Public website hostname"), "x");
    expect(checkbox.checked).toBe(false);
  });

  it("updates consumed quota from headers even when a target scan fails", async () => {
    const consumed = quota(3);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      error: "The target could not be assessed right now.",
      code: "UPSTREAM_ERROR",
      quota: consumed,
    }, 502, rateHeaders(consumed))));
    const user = userEvent.setup();
    render(<WebSecurityScanner suggestedDomain="example.com" />);

    await user.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    await user.click(screen.getByRole("button", { name: "Run security scan" }));

    await screen.findByRole("alert");
    expect(screen.getByText(/3 of 5 scans remaining/u)).toBeTruthy();
  });

  it("clears a nonzero quota display when its rolling window expires", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-16T20:00:00.000Z"));
    const expiringQuota = quota(3, "2026-08-16T20:00:10.000Z");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(
      scanResult({ quota: expiringQuota }),
      200,
      rateHeaders(expiringQuota),
    )));
    render(<WebSecurityScanner suggestedDomain="example.com" />);

    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    fireEvent.click(screen.getByRole("button", { name: "Run security scan" }));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByText(/3 of 5 scans remaining/u)).toBeTruthy();

    await act(async () => {
      vi.advanceTimersByTime(15_000);
      await Promise.resolve();
    });
    expect(screen.getByText(/Limit: 5 web-security scans/u)).toBeTruthy();
    expect(screen.queryByText(/3 of 5 scans remaining/u)).toBeNull();
  });

  it("keeps the hostname editable so an edit aborts and clears an active scan", async () => {
    let signal: AbortSignal | undefined;
    vi.stubGlobal("fetch", vi.fn().mockImplementation((_url: string, request: RequestInit) => {
      signal = request.signal as AbortSignal;
      return new Promise<Response>(() => undefined);
    }));
    const user = userEvent.setup();
    render(<WebSecurityScanner suggestedDomain="example.com" />);

    await user.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    await user.click(screen.getByRole("button", { name: "Run security scan" }));
    expect(signal?.aborted).toBe(false);
    await user.type(screen.getByLabelText("Public website hostname"), "x");

    expect(signal?.aborted).toBe(true);
    expect(screen.queryByText("Assessing example.com")).toBeNull();
    expect((screen.getByRole("checkbox", { name: /I confirm I own or administer/u }) as HTMLInputElement).checked).toBe(false);
  });

  it("ignores a late response after the suggested domain changes", async () => {
    let resolveFetch: ((response: Response) => void) | undefined;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => new Promise<Response>((resolve) => { resolveFetch = resolve; })));
    const user = userEvent.setup();
    const { rerender } = render(<WebSecurityScanner suggestedDomain="old.example.com" />);

    await user.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    await user.click(screen.getByRole("button", { name: "Run security scan" }));
    rerender(<WebSecurityScanner suggestedDomain="new.example.com" />);
    await waitFor(() => expect((screen.getByLabelText("Public website hostname") as HTMLInputElement).value).toBe("new.example.com"));

    await act(async () => {
      resolveFetch?.(jsonResponse(scanResult({ hostname: "old.example.com", effectiveUrl: "https://old.example.com/" })));
      await Promise.resolve();
    });
    expect(screen.queryByRole("heading", { name: "old.example.com" })).toBeNull();
  });

  it("does not cancel a manually targeted scan when the suggested domain changes", async () => {
    let signal: AbortSignal | undefined;
    vi.stubGlobal("fetch", vi.fn().mockImplementation((_url: string, request: RequestInit) => {
      signal = request.signal as AbortSignal;
      return new Promise<Response>(() => undefined);
    }));
    const user = userEvent.setup();
    const { rerender } = render(<WebSecurityScanner suggestedDomain="old.example.com" />);
    const input = screen.getByLabelText("Public website hostname") as HTMLInputElement;

    await user.clear(input);
    await user.type(input, "manual.example.com");
    await user.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    await user.click(screen.getByRole("button", { name: "Run security scan" }));
    expect(signal?.aborted).toBe(false);

    rerender(<WebSecurityScanner suggestedDomain="new.example.com" />);
    expect(input.value).toBe("manual.example.com");
    expect(signal?.aborted).toBe(false);
    expect(screen.getByText("Assessing manual.example.com")).toBeTruthy();
  });

  it("copies the complete structured result as JSON", async () => {
    const responseBody = scanResult();
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(responseBody)));
    render(<WebSecurityScanner suggestedDomain="example.com" />);

    await user.click(screen.getByRole("checkbox", { name: /I confirm I own or administer/u }));
    await user.click(screen.getByRole("button", { name: "Run security scan" }));
    await screen.findByRole("heading", { name: "example.com" });
    await user.click(screen.getByRole("button", { name: "Copy JSON" }));

    expect(writeText).toHaveBeenCalledWith(JSON.stringify(responseBody, null, 2));
    expect(screen.getByRole("button", { name: "Copied JSON" })).toBeTruthy();
  });
});

function scanResult(overrides: Partial<WebSecurityScanResult> = {}): WebSecurityScanResult {
  const nextChecks = overrides.checks ?? checks();
  const unknown = nextChecks.filter((check) => check.status === "unknown").length;
  const notApplicable = nextChecks.filter((check) => check.status === "not-applicable").length;
  return {
    hostname: "example.com",
    effectiveUrl: "https://example.com/",
    scannedAt: "2026-08-16T20:00:00.000Z",
    durationMs: 842,
    score: 92,
    grade: "A",
    headline: "Strong observable web hardening",
    summary: "The bounded scan found strong browser-facing configuration.",
    tls: tlsAssessment("complete"),
    checks: nextChecks,
    coverage: { evaluated: 20 - unknown - notApplicable, total: 20, unknown, notApplicable },
    quota: quota(4),
    requestBudget: {
      httpRequests: 4,
      tlsConnections: 6,
      maxResponseBytes: 131_072,
      redirectHopsFollowed: 1,
    },
    disclaimer: WEB_SECURITY_DISCLAIMER,
    ...overrides,
  };
}

function checks(overrides: Partial<Record<(typeof WEB_SECURITY_CHECK_IDS)[number], WebSecurityCheckStatus>> = {}): WebSecurityCheck[] {
  return WEB_SECURITY_CHECK_IDS.map((id) => ({
    id,
    status: overrides[id] ?? "pass",
    title: id.split("-").map((part) => `${part[0].toUpperCase()}${part.slice(1)}`).join(" "),
    summary: `Bounded ${id} evidence was reviewed.`,
    evidence: [`Observed evidence for ${id}.`],
    remediation: `Keep the ${id} configuration current.`,
    owasp: {
      top10: ["A02:2025 Security Misconfiguration"],
      wstg: ["WSTG-CONF-14"],
    },
  }));
}

function tlsAssessment(status: TlsAssessment["status"]): TlsAssessment {
  const unavailable = status === "unavailable";
  const partial = status === "partial";
  return {
    status,
    grade: unavailable ? "N/A" : partial ? "B" : "A",
    summary: unavailable
      ? "Raw endpoint TLS evidence was unavailable; no TLS failure was inferred."
      : partial ? "Partial TLS evidence was collected." : "Fixed TLS profiles completed.",
    resolvedAddresses: ["192.0.2.10"],
    endpoints: [{
      address: "192.0.2.10",
      status: unavailable ? "platform-blocked" : "ready",
      summary: unavailable ? "The Worker platform blocked raw TLS evidence." : "The TLS handshake completed.",
      ...(unavailable ? {} : { authorized: true, hostnameValid: true, negotiatedProtocol: "TLSv1.3" }),
      ...(!unavailable ? {
        cipher: { name: "TLS_AES_256_GCM_SHA384", standardName: "TLS_AES_256_GCM_SHA384", version: "TLSv1.3", bits: 256 },
        alpnProtocol: "h2",
        ephemeralKey: "ECDH X25519 253 bits",
        certificate: certificate(),
      } : {}),
      certificateChain: unavailable ? [] : [certificate(), { ...certificate(), subject: "CN=Example Root", issuer: "CN=Example Root", ca: true }],
      protocols: (["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"] as const).map((version) => ({
        version,
        status: unavailable || (partial && version === "TLSv1.1")
          ? "unknown" as const
          : version === "TLSv1.2" || version === "TLSv1.3" ? "supported" as const : "not-supported" as const,
        ...(unavailable || (partial && version === "TLSv1.1") ? { note: "Evidence unavailable." } : {}),
      })),
      weakCipher: unavailable || partial
        ? { status: "unknown", note: "Legacy profile evidence unavailable." }
        : { status: "not-supported", note: "Legacy profile was rejected." },
    }],
    endpointsTruncated: false,
    reportUrl: "https://www.ssllabs.com/ssltest/analyze.html?d=example.com&hideResults=on",
    limitations: ["This is a bounded TLS snapshot, not an SSL Labs-equivalent assessment."],
  };
}

function certificate() {
  return {
    subject: "CN=example.com",
    issuer: "CN=Example CA",
    subjectAltNames: ["example.com", "www.example.com"],
    validFrom: "2026-01-01T00:00:00.000Z",
    validTo: "2026-11-01T00:00:00.000Z",
    daysRemaining: 77,
    serialNumber: "01AABBCC",
    fingerprint256: "AA:BB:CC:DD",
    bits: 256,
    signatureAlgorithm: "ecdsa-with-SHA256",
    ca: false,
  };
}

function quota(remaining: number, resetAt = "2026-08-16T21:00:00.000Z"): WebScanQuota {
  return { limit: 5, remaining, resetAt, windowSeconds: 3600 } as WebScanQuota;
}

function rateHeaders(value: WebScanQuota): Record<string, string> {
  return {
    "RateLimit-Limit": String(value.limit),
    "RateLimit-Remaining": String(value.remaining),
    "RateLimit-Reset": String(Math.floor(Date.parse(value.resetAt) / 1_000)),
  };
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}
