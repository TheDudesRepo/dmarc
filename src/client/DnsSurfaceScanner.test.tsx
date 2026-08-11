// @vitest-environment jsdom

import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  DnsSnapshotResult,
  HostDiscoveryProfile,
  HostDiscoveryResult,
  SnapshotRecordType,
} from "../shared/types";
import { DnsSurfaceScanner, isDnsSnapshotResult, isHostDiscoveryResult } from "./DnsSurfaceScanner";

const TYPES: SnapshotRecordType[] = ["A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "TXT"];

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("DNS surface response validation", () => {
  it("accepts complete snapshot and host-discovery contracts", () => {
    expect(isDnsSnapshotResult(snapshotResult())).toBe(true);
    expect(isHostDiscoveryResult(hostResult("core"))).toBe(true);
    expect(isHostDiscoveryResult(hostResult("extended"))).toBe(true);
    const addresses = Array.from({ length: 512 }, (_value, index) => `2001:db8::${index.toString(16)}`);
    const combinedAddressResult = hostResult("core");
    expect(isHostDiscoveryResult({
      ...combinedAddressResult,
      hosts: combinedAddressResult.hosts.map((host) => ({ ...host, addresses })),
      wildcardProbe: { ...combinedAddressResult.wildcardProbe, addresses },
    })).toBe(true);
  });

  it.each([
    null,
    {},
    { ...snapshotResult(), durationMs: Number.NaN },
    { ...snapshotResult(), groups: snapshotResult().groups.slice(1) },
    { ...snapshotResult(), groups: snapshotResult().groups.map((group) => ({ ...group, type: "A" })) },
    { ...snapshotResult(), groups: snapshotResult().groups.map((group) => group.type === "A" ? { ...group, records: [{ name: "example.com", type: "MX", value: "bad" }] } : group) },
    { ...snapshotResult(), securityRecords: [] },
    { ...snapshotResult(), findings: [{ id: "x", severity: "urgent", title: "x", detail: "x", steps: [] }] },
    { ...snapshotResult(), recordCount: -1 },
  ])("rejects malformed snapshot data", (value) => {
    expect(isDnsSnapshotResult(value)).toBe(false);
  });

  it.each([
    null,
    {},
    { ...hostResult("core"), profile: "all" },
    { ...hostResult("core"), testedNames: [] },
    { ...hostResult("core"), wildcardProbe: undefined },
    { ...hostResult("core"), wildcardProbe: { hostname: "probe.example.com", detected: "yes", addresses: [], unavailable: false } },
    { ...hostResult("core"), hosts: [{ hostname: "bad", source: "common-name", addresses: [], reverseNames: [] }] },
    { ...hostResult("core"), hosts: [{ hostname: "www.example.com", source: "scanner", addresses: [], reverseNames: [] }] },
    { ...hostResult("core"), hosts: [{ hostname: "www.example.com", source: "common-name", addresses: [], unavailableAddressTypes: ["TXT"], reverseNames: [] }] },
    { ...hostResult("core"), unavailableNames: [123] },
  ])("rejects malformed host-discovery data", (value) => {
    expect(isHostDiscoveryResult(value)).toBe(false);
  });
});

describe("DNS surface interactions", () => {
  it("runs separately budgeted passes and renders records, hosts, and correction steps", async () => {
    const fetchMock = vi.fn().mockImplementation((url: string, request: RequestInit) => {
      const body = JSON.parse(String(request.body)) as { profile?: HostDiscoveryProfile };
      if (url === "/api/dns-snapshot") return Promise.resolve(jsonResponse(snapshotResult()));
      if (url === "/api/host-discovery") return Promise.resolve(jsonResponse(hostResult(body.profile ?? "core")));
      throw new Error("unexpected endpoint");
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<DnsSurfaceScanner suggestedDomain="example.com" />);

    await waitFor(() => expect((screen.getByLabelText("Domain to discover") as HTMLInputElement).value).toBe("example.com"));
    await user.click(screen.getByRole("button", { name: "Scan DNS surface" }));

    await screen.findByText("Observed public DNS");
    expect(screen.getAllByText("192.0.2.10")).toHaveLength(2);
    expect(screen.getByText("www.example.com").textContent).toBe("www.example.com");
    expect(screen.getByText("Compare returned records with the asset inventory.").textContent).toMatch(/asset inventory/u);
    expect(screen.getByText("Why this says “discovered,” not “every record”").textContent).toMatch(/discovered/u);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual([
      "/api/dns-snapshot",
      "/api/host-discovery",
      "/api/host-discovery",
    ]);
    const profiles = fetchMock.mock.calls.slice(1).map((call) => JSON.parse(String((call[1] as RequestInit).body)).profile);
    expect(profiles).toEqual(["core", "extended"]);
  });

  it("keeps successful data visible when one discovery pass fails", async () => {
    const fetchMock = vi.fn().mockImplementation((url: string, request: RequestInit) => {
      const body = JSON.parse(String(request.body)) as { profile?: HostDiscoveryProfile };
      if (url === "/api/dns-snapshot") return Promise.resolve(jsonResponse(snapshotResult()));
      if (body.profile === "core") return Promise.resolve(jsonResponse(hostResult("core")));
      return Promise.resolve(jsonResponse({ error: "DNS data is temporarily unavailable.", code: "UPSTREAM_ERROR" }, 502));
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<DnsSurfaceScanner suggestedDomain="example.com" />);

    await user.click(screen.getByRole("button", { name: "Scan DNS surface" }));

    await screen.findByText("Partial result");
    expect(screen.getByText("Observed public DNS").textContent).toBe("Observed public DNS");
    expect(screen.getByRole("alert").textContent).toContain("Extended host discovery");
  });

  it("counts and warns about an unavailable wildcard control", async () => {
    const fetchMock = vi.fn().mockImplementation((url: string, request: RequestInit) => {
      const body = JSON.parse(String(request.body)) as { profile?: HostDiscoveryProfile };
      if (url === "/api/dns-snapshot") return Promise.resolve(jsonResponse(snapshotResult()));
      const result = hostResult(body.profile ?? "core");
      return Promise.resolve(jsonResponse(
        body.profile === "core"
          ? { ...result, wildcardProbe: { ...result.wildcardProbe, unavailable: true } }
          : result,
      ));
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<DnsSurfaceScanner suggestedDomain="example.com" />);

    await user.click(screen.getByRole("button", { name: "Scan DNS surface" }));

    await screen.findByText("Wildcard control unavailable");
    expect(screen.getByText(/wildcard behavior is unknown/iu).textContent).toMatch(/catch-all responses/iu);
    const metric = screen.getByText("Indeterminate queries").parentElement;
    expect(metric?.querySelector("strong")?.textContent).toBe("1");
  });

  it("distinguishes a partial wildcard control from wholly unknown behavior", async () => {
    const fetchMock = vi.fn().mockImplementation((url: string, request: RequestInit) => {
      const body = JSON.parse(String(request.body)) as { profile?: HostDiscoveryProfile };
      if (url === "/api/dns-snapshot") return Promise.resolve(jsonResponse(snapshotResult()));
      const result = hostResult(body.profile ?? "core");
      return Promise.resolve(jsonResponse(
        body.profile === "core"
          ? {
              ...result,
              wildcardProbe: {
                ...result.wildcardProbe,
                detected: true,
                addresses: ["192.0.2.99"],
                unavailable: true,
              },
            }
          : result,
      ));
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<DnsSurfaceScanner suggestedDomain="example.com" />);

    await user.click(screen.getByRole("button", { name: "Scan DNS surface" }));

    await screen.findByText("Wildcard control partially available");
    expect(screen.getByText(/positive wildcard evidence/iu)).toBeTruthy();
    expect(screen.queryByText("Wildcard DNS response detected")).toBeNull();
    expect(screen.queryByText(/wildcard behavior is unknown/iu)).toBeNull();
  });

  it("renders infrastructure address failures and includes them in the indeterminate metric", async () => {
    const snapshot = snapshotResult();
    snapshot.infrastructureHosts = snapshot.infrastructureHosts.map((host) => ({
      ...host,
      addresses: [],
      unavailableAddressTypes: ["A", "AAAA"],
    }));
    snapshot.unavailableCount = 2;
    const fetchMock = vi.fn().mockImplementation((url: string, request: RequestInit) => {
      const body = JSON.parse(String(request.body)) as { profile?: HostDiscoveryProfile };
      if (url === "/api/dns-snapshot") return Promise.resolve(jsonResponse(snapshot));
      return Promise.resolve(jsonResponse(hostResult(body.profile ?? "core")));
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<DnsSurfaceScanner suggestedDomain="example.com" />);

    await user.click(screen.getByRole("button", { name: "Scan DNS surface" }));

    await screen.findByText(/Indeterminate address queries/iu);
    expect(screen.getByText(/mail\.example\.com \(A, AAAA\)/u)).toBeTruthy();
    const metric = screen.getByText("Indeterminate queries").parentElement;
    expect(metric?.querySelector("strong")?.textContent).toBe("2");
  });

  it("invalidates old in-flight results when the suggested domain changes", async () => {
    const pending: Array<(response: Response) => void> = [];
    const fetchMock = vi.fn().mockImplementation(() => new Promise<Response>((resolve) => pending.push(resolve)));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    const { rerender } = render(<DnsSurfaceScanner suggestedDomain="old.example.com" />);
    await waitFor(() => expect((screen.getByLabelText("Domain to discover") as HTMLInputElement).value).toBe("old.example.com"));
    await user.click(screen.getByRole("button", { name: "Scan DNS surface" }));
    rerender(<DnsSurfaceScanner suggestedDomain="new.example.com" />);
    await waitFor(() => expect((screen.getByLabelText("Domain to discover") as HTMLInputElement).value).toBe("new.example.com"));

    await act(async () => {
      pending[0]?.(jsonResponse(snapshotResult("old.example.com")));
      pending[1]?.(jsonResponse(hostResult("core", "old.example.com")));
      pending[2]?.(jsonResponse(hostResult("extended", "old.example.com")));
      await Promise.resolve();
    });

    expect(screen.queryByText("Observed public DNS")).toBeNull();
    expect(screen.queryByText("old.example.com")).toBeNull();
  });

  it("aborts an active scan when the user edits the target", async () => {
    let capturedSignal: AbortSignal | undefined;
    const fetchMock = vi.fn().mockImplementation((_url: string, request: RequestInit) => {
      capturedSignal = request.signal as AbortSignal;
      return new Promise<Response>(() => undefined);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<DnsSurfaceScanner suggestedDomain="example.com" />);

    await user.click(screen.getByRole("button", { name: "Scan DNS surface" }));
    expect(capturedSignal?.aborted).toBe(false);
    await user.type(screen.getByLabelText("Domain to discover"), "x");
    expect(capturedSignal?.aborted).toBe(true);
    expect(screen.queryByText("Mapping DNS")).toBeNull();
  });
});

function snapshotResult(domain = "example.com"): DnsSnapshotResult {
  return {
    domain,
    scannedAt: "2026-08-11T21:00:00.000Z",
    durationMs: 25,
    groups: TYPES.map((type) => ({
      type,
      status: type === "A" || type === "MX" || type === "NS" || type === "SOA" || type === "TXT" ? "found" : "empty",
      records: type === "A"
        ? [{ name: domain, type, value: "192.0.2.10", ttl: 300 }]
        : type === "MX"
          ? [{ name: domain, type, value: `10 mail.${domain}`, ttl: 300 }]
          : type === "NS"
            ? [{ name: domain, type, value: `ns1.${domain}`, ttl: 300 }]
            : type === "SOA"
              ? [{ name: domain, type, value: `ns1.${domain} hostmaster.${domain} 1 3600 600 1209600 300`, ttl: 300 }]
              : type === "TXT"
                ? [{ name: domain, type, value: "v=spf1 -all", ttl: 300 }]
                : [],
    })),
    securityRecords: [
      { key: "dmarc", label: "DMARC", ownerName: `_dmarc.${domain}`, status: "found", records: [{ name: `_dmarc.${domain}`, type: "TXT", value: "v=DMARC1; p=reject", ttl: 300 }] },
      { key: "mta-sts", label: "MTA-STS", ownerName: `_mta-sts.${domain}`, status: "empty", records: [] },
      { key: "tls-rpt", label: "TLS-RPT", ownerName: `_smtp._tls.${domain}`, status: "empty", records: [] },
      { key: "bimi", label: "BIMI", ownerName: `default._bimi.${domain}`, status: "empty", records: [] },
    ],
    infrastructureHosts: [{ hostname: `mail.${domain}`, source: "mail", addresses: ["192.0.2.25"], reverseNames: [] }],
    findings: [{
      id: "review-inventory",
      severity: "success",
      title: "No obvious conflict detected",
      detail: "Review every returned relationship.",
      steps: ["Compare returned records with the asset inventory."],
    }],
    recordCount: 6,
    unavailableCount: 0,
    summary: "Six public DNS records were returned.",
    disclaimer: "This is an explicit live RRset sweep, not an ANY query or a complete zone listing.",
  };
}

function hostResult(profile: HostDiscoveryProfile, domain = "example.com"): HostDiscoveryResult {
  const labels = profile === "core"
    ? ["www", "mail", "autodiscover", "api", "vpn", "portal", "remote"]
    : ["smtp", "webmail", "admin", "dev", "staging", "status", "ftp"];
  return {
    domain,
    profile,
    scannedAt: "2026-08-11T21:00:00.000Z",
    durationMs: 15,
    testedNames: labels.map((label) => `${label}.${domain}`),
    hosts: profile === "core"
      ? [{ hostname: `www.${domain}`, source: "common-name", profile, addresses: ["192.0.2.10"], reverseNames: ["edge.example.net"] }]
      : [{ hostname: `status.${domain}`, source: "common-name", profile, alias: "status.provider.example", addresses: ["192.0.2.30"], reverseNames: [] }],
    unavailableNames: [],
    wildcardProbe: {
      hostname: `dmarc-ready-probe-0011223344556677.${domain}`,
      detected: false,
      addresses: [],
      unavailable: false,
    },
    summary: "One common public hostname resolved.",
    disclaimer: "Common-name discovery checks a documented bounded label set and does not brute-force the namespace.",
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
