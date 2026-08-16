// @vitest-environment jsdom

import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  CheckResult,
  DnsLookupResult,
  DnsLookupType,
  ScanResult,
  SpfLookupAnalysis,
} from "../shared/types";
import App, { AdvancedDnsExplorer, DNS_LOOKUP_MODES, DNS_LOOKUP_TYPES, isDnsLookupResult, isScanResult } from "./App";

function lookupResult(type: DnsLookupType = "A", overrides: Partial<DnsLookupResult> = {}): DnsLookupResult {
  return {
    input: "example.com",
    queryName: "example.com",
    type,
    scannedAt: "2026-08-11T20:00:00.000Z",
    durationMs: 12,
    summary: `One ${type} record returned.`,
    records: [{ name: "example.com", type, value: "192.0.2.25", ttl: 300 }],
    ...overrides,
  };
}

function validSpfAnalysis(overrides: Partial<SpfLookupAnalysis> = {}): SpfLookupAnalysis {
  return {
    status: "valid",
    recordCount: 1,
    valid: true,
    syntaxValid: true,
    mechanisms: [
      { raw: "include:_spf.example.net", qualifier: "+", name: "include", domainSpec: "_spf.example.net", causesDnsLookup: true },
      { raw: "-all", qualifier: "-", name: "all", causesDnsLookup: false },
    ],
    terminalPolicy: "-all",
    lookupEstimate: {
      count: 3,
      exceedsLimit: false,
      truncated: false,
      expandedDomains: ["_spf.example.net"],
      issues: [],
    },
    warnings: [],
    errors: [],
    issues: [],
    correctionGuidance: {
      summary: "Keep the single SPF policy current.",
      steps: ["Confirm every mechanism maps to an authorized sender.", "Rescan after provider changes."],
    },
    ...overrides,
  };
}

function spfLookupResult(
  overrides: Partial<DnsLookupResult<"SPF">> = {},
): DnsLookupResult<"SPF"> {
  return {
    input: "example.com",
    queryName: "example.com",
    type: "SPF",
    scannedAt: "2026-08-11T20:00:00.000Z",
    durationMs: 18,
    summary: "One valid SPF policy was found for example.com; the recursive lookup estimate is 3.",
    records: [{ name: "example.com", type: "TXT", value: "v=spf1 include:_spf.example.net -all", ttl: 300 }],
    spfAnalysis: validSpfAnalysis(),
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("application navigation", () => {
  it("links the web-security scanner from desktop and compact navigation", () => {
    const { container } = render(<App />);
    const desktop = screen.getByRole("navigation", { name: "Primary navigation" });
    const mobile = screen.getByRole("navigation", { name: "Mobile navigation" });

    expect(within(desktop).getByRole("link", { name: "Web security" }).getAttribute("href")).toBe("#web-security");
    expect(within(mobile).getByRole("link", { name: "Web security" }).getAttribute("href")).toBe("#web-security");
    expect(container.querySelector("#web-security")).not.toBeNull();
  });
});

describe("DNS lookup response validation", () => {
  it.each(DNS_LOOKUP_TYPES)("accepts a complete %s response", (type) => {
    expect(isDnsLookupResult(lookupResult(type), type)).toBe(true);
  });

  it("rejects a response for a different request type", () => {
    expect(isDnsLookupResult(lookupResult("AAAA"), "A")).toBe(false);
  });

  it("accepts a truthful SPF analysis backed by TXT evidence", () => {
    expect(DNS_LOOKUP_MODES).toContain("SPF");
    expect(isDnsLookupResult(spfLookupResult(), "SPF")).toBe(true);
  });

  it.each([
    { ...spfLookupResult(), spfAnalysis: undefined },
    { ...spfLookupResult(), records: [{ name: "example.com", type: "SPF", value: "v=spf1 -all" }] },
    { ...spfLookupResult(), spfAnalysis: { ...validSpfAnalysis(), recordCount: 257 } },
    { ...spfLookupResult(), spfAnalysis: { ...validSpfAnalysis(), terminalPolicy: "hardfail" } },
    { ...spfLookupResult(), spfAnalysis: { ...validSpfAnalysis(), lookupEstimate: { count: -1 } } },
    { ...lookupResult(), spfAnalysis: validSpfAnalysis() },
  ])("rejects malformed or misplaced SPF analysis data", (value) => {
    expect(isDnsLookupResult(value, value.type === "SPF" ? "SPF" : "A")).toBe(false);
  });

  it.each([
    null,
    {},
    { ...lookupResult(), durationMs: Number.NaN },
    { ...lookupResult(), durationMs: -1 },
    { ...lookupResult(), scannedAt: "not-a-date" },
    { ...lookupResult(), canonicalName: "" },
    { ...lookupResult(), summary: "" },
    { ...lookupResult(), type: "ANY" },
    { ...lookupResult(), records: [{ name: "example.com", type: "MX", value: "mail.example.com" }] },
    { ...lookupResult(), records: [{ name: "example.com", type: "A", value: 123 }] },
    { ...lookupResult(), records: [{ name: "example.com", type: "A", value: "192.0.2.1", ttl: -1 }] },
    { ...lookupResult(), records: [{ name: "", type: "A", value: "192.0.2.1" }] },
    { ...lookupResult(), records: [{ name: "example.com", type: "A", value: "x".repeat(262_145) }] },
    { ...lookupResult(), records: Array.from({ length: 257 }, () => ({ name: "example.com", type: "A", value: "192.0.2.1" })) },
  ])("rejects malformed or unsafe response data", (value) => {
    expect(isDnsLookupResult(value, "A")).toBe(false);
  });
});

describe("DNS record explorer interactions", () => {
  it("posts the selected lookup and renders raw evidence with correction guidance", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(lookupResult()));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<AdvancedDnsExplorer suggestedDomain="" />);

    await user.type(screen.getByLabelText("DNS owner name"), "example.com");
    await user.click(screen.getByRole("button", { name: "Look up record" }));

    await screen.findByText("One A record returned.");
    expect(screen.getByText("192.0.2.25").textContent).toBe("192.0.2.25");
    expect(screen.getByText("How to validate this answer").textContent).toBe("How to validate this answer");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, request] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/lookup");
    expect(request.method).toBe("POST");
    expect(JSON.parse(String(request.body))).toEqual({ name: "example.com", type: "A" });
  });

  it("preserves a compatible custom owner across type changes and resets it for PTR", async () => {
    const user = userEvent.setup();
    render(<AdvancedDnsExplorer suggestedDomain="example.com" />);
    const input = screen.getByLabelText("DNS owner name") as HTMLInputElement;
    await waitFor(() => expect(input.value).toBe("example.com"));

    await user.clear(input);
    await user.type(input, "mail.example.com");
    await user.selectOptions(screen.getByLabelText("Record type"), "AAAA");
    expect((screen.getByLabelText("DNS owner name") as HTMLInputElement).value).toBe("mail.example.com");

    await user.selectOptions(screen.getByLabelText("Record type"), "PTR");
    expect((screen.getByLabelText("IP address") as HTMLInputElement).value).toBe("");
  });

  it("offers first-class SPF analysis and renders lookup evidence with correction steps", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(spfLookupResult()));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<AdvancedDnsExplorer suggestedDomain="example.com" />);

    await user.selectOptions(screen.getByLabelText("Record type"), "SPF");
    expect((screen.getByLabelText("SPF domain or owner") as HTMLInputElement).value).toBe("example.com");
    await user.click(screen.getByRole("button", { name: "Analyze SPF" }));

    await screen.findByText("SPF policy analysis");
    expect(screen.getByText("3 / 10").textContent).toBe("3 / 10");
    expect(screen.getByText("include:_spf.example.net").textContent).toBe("include:_spf.example.net");
    expect(screen.getByText("How to correct or maintain it").textContent).toBe("How to correct or maintain it");
    expect(screen.getByText("Confirm every mechanism maps to an authorized sender.").textContent).toMatch(/authorized sender/u);
    const [url, request] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/lookup");
    expect(JSON.parse(String(request.body))).toEqual({ name: "example.com", type: "SPF" });
  });

  it("shows missing-SPF guidance without inventing a replacement record", async () => {
    const analysis = validSpfAnalysis({
      status: "missing",
      recordCount: 0,
      valid: false,
      syntaxValid: false,
      mechanisms: [],
      terminalPolicy: "none",
      lookupEstimate: undefined,
      issues: ["No v=spf1 policy was found in the TXT records at this domain."],
      correctionGuidance: {
        summary: "Inventory outbound senders before publishing one SPF TXT policy.",
        steps: ["List every legitimate sender."],
        caution: "Do not publish a generic SPF value.",
      },
    });
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(spfLookupResult({
      summary: "No SPF policy was found in the TXT records for example.com.",
      records: [],
      spfAnalysis: analysis,
    })));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<AdvancedDnsExplorer suggestedDomain="example.com" />);

    await user.selectOptions(screen.getByLabelText("Record type"), "SPF");
    await user.click(screen.getByRole("button", { name: "Analyze SPF" }));

    await screen.findByText("No SPF policy was found in this domain's TXT records.");
    expect(screen.getByText("Do not publish a generic SPF value.").textContent).toMatch(/generic SPF/u);
  });

  it("invalidates an old in-flight answer when a newly scanned domain replaces it", async () => {
    let resolveFetch: ((response: Response) => void) | undefined;
    const fetchMock = vi.fn().mockImplementation(() => new Promise<Response>((resolve) => {
      resolveFetch = resolve;
    }));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    const { rerender } = render(<AdvancedDnsExplorer suggestedDomain="old.example.com" />);
    await waitFor(() => expect((screen.getByLabelText("DNS owner name") as HTMLInputElement).value).toBe("old.example.com"));

    await user.click(screen.getByRole("button", { name: "Look up record" }));
    rerender(<AdvancedDnsExplorer suggestedDomain="new.example.com" />);
    await waitFor(() => expect((screen.getByLabelText("DNS owner name") as HTMLInputElement).value).toBe("new.example.com"));

    await act(async () => {
      resolveFetch?.(jsonResponse(lookupResult("A", {
        input: "old.example.com",
        queryName: "old.example.com",
        records: [{ name: "old.example.com", type: "A", value: "192.0.2.99" }],
      })));
      await Promise.resolve();
    });

    expect(screen.queryByText("192.0.2.99")).toBeNull();
    expect(screen.queryByText("One A record returned.")).toBeNull();
  });

  it("shows empty-answer remediation without labeling optional DNS as broken", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(lookupResult("CAA", {
      type: "CAA",
      summary: "No CAA records were returned for example.com.",
      records: [],
    })));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<AdvancedDnsExplorer suggestedDomain="example.com" />);
    await user.selectOptions(screen.getByLabelText("Record type"), "CAA");
    await user.click(screen.getByRole("button", { name: "Look up record" }));

    await screen.findByText("No records were returned for this name and type.");
    expect(screen.getByText(/CAA is optional and may be inherited/u).textContent).toMatch(/Add it only after identifying every CA/u);
  });

  it("renders PTR translation with no trailing separator", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(lookupResult("PTR", {
      input: "8.8.8.8",
      queryName: "8.8.8.8.in-addr.arpa",
      type: "PTR",
      summary: "One PTR record returned.",
      records: [{ name: "8.8.8.8.in-addr.arpa", type: "PTR", value: "dns.google" }],
    })));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    const { container } = render(<AdvancedDnsExplorer suggestedDomain="" />);
    await user.selectOptions(screen.getByLabelText("Record type"), "PTR");
    await user.type(screen.getByLabelText("IP address"), "8.8.8.8");
    await user.click(screen.getByRole("button", { name: "Look up record" }));

    await screen.findByText("dns.google");
    expect(container.querySelectorAll(".dns-query-translation svg")).toHaveLength(1);
  });

  it("surfaces an API failure and does not infer record absence", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      error: "DNS data is temporarily unavailable. Please try again.",
      code: "UPSTREAM_ERROR",
    }, 502));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<AdvancedDnsExplorer suggestedDomain="example.com" />);
    await user.click(screen.getByRole("button", { name: "Look up record" }));

    await screen.findByRole("alert");
    expect(screen.getByRole("alert").textContent).toContain("temporarily unavailable");
    expect(screen.queryByText("No records were returned for this name and type.")).toBeNull();
  });
});

function checkResult(): CheckResult {
  return {
    status: "pass",
    title: "Check",
    summary: "Complete",
    details: [{ label: "Result", value: "Pass" }],
    records: [{ name: "example.com", type: "TXT", value: "v=spf1 -all", ttl: 300 }],
  };
}

function scanResult(): ScanResult {
  const check = checkResult();
  return {
    domain: "example.com",
    scannedAt: "2026-08-11T20:00:00.000Z",
    durationMs: 25,
    score: 100,
    grade: "A",
    posture: "reject",
    postureLabel: "Reject",
    headline: "DMARC is enforced.",
    summary: "The published record requests rejection.",
    checks: { dmarc: check, spf: check, dkim: check, transport: check, dns: check },
    dkimSelectors: [{ selector: "selector1", found: true, kind: "TXT", value: "v=DKIM1; p=key" }],
    findings: [{
      id: "finding",
      severity: "success",
      title: "Configured",
      detail: "Evidence found.",
      remediation: { summary: "Keep monitoring.", steps: ["Review reports."] },
    }],
    metadata: {
      mxProviders: ["mx.example.com"],
      nameservers: ["ns1.example.com"],
      hasBimi: false,
      hasMtaSts: true,
      hasTlsRpt: true,
    },
    disclaimer: "Point-in-time evidence only.",
  };
}

describe("scan response validation", () => {
  it("accepts the complete nested scan contract", () => {
    expect(isScanResult(scanResult())).toBe(true);
  });

  it.each([
    null,
    {},
    { ...scanResult(), score: Number.NaN },
    { ...scanResult(), grade: "A+" },
    { ...scanResult(), checks: { ...scanResult().checks, dns: {} } },
    { ...scanResult(), metadata: {} },
    { ...scanResult(), metadata: { ...scanResult().metadata, mxProviders: null } },
    { ...scanResult(), findings: [{}] },
    { ...scanResult(), dkimSelectors: [{ selector: "selector1", found: "yes" }] },
    { ...scanResult(), checks: { ...scanResult().checks, spf: { ...checkResult(), details: [{}] } } },
  ])("rejects malformed nested scan data", (value) => {
    expect(isScanResult(value)).toBe(false);
  });
});
