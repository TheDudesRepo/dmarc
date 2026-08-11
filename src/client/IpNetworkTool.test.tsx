// @vitest-environment jsdom

import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { IpToolsResult } from "../shared/types";
import { IpNetworkTool, isIpToolsResult } from "./IpNetworkTool";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("IP tool response validation", () => {
  it("accepts complete IPv4 and IPv6 result contracts", () => {
    expect(isIpToolsResult(globalResult())).toBe(true);
    expect(isIpToolsResult(ipv6Result())).toBe(true);
    expect(isIpToolsResult(privateSubnetResult())).toBe(true);
  });

  it.each([
    null,
    {},
    { ...globalResult(), version: 5 },
    { ...globalResult(), prefix: 33 },
    { ...globalResult(), totalAddresses: "1e9" },
    { ...globalResult(), ipv4: undefined },
    { ...globalResult(), classification: { ...globalResult().classification, global: false } },
    { ...globalResult(), enrichment: { ...globalResult().enrichment, queryCount: 5 } },
    { ...globalResult(), enrichment: { ...globalResult().enrichment, ptr: { status: "found", names: Array(9).fill("dns.google") } } },
    { ...globalResult(), enrichment: { ...globalResult().enrichment, attribution: { ptr: "Native DNS PTR", asn: { name: "x", url: "https://evil.example" } } } },
    { ...ipv6Result(), ipv4: { netmask: "255.255.255.0", wildcard: "0.0.0.255", broadcast: "192.0.2.255" } },
  ])("rejects malformed or unbounded API data", (value) => {
    expect(isIpToolsResult(value)).toBe(false);
  });
});

describe("IP and subnet interactions", () => {
  it("calculates a global address and renders PTR, ASN, and exact network evidence", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(globalResult()));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<IpNetworkTool />);

    await user.click(screen.getByRole("button", { name: "8.8.8.8" }));
    await user.click(screen.getByRole("button", { name: "Inspect IP / subnet" }));

    await screen.findByText("Canonical input");
    expect(screen.getByRole("heading", { name: "8.8.8.8/32" })).toBeTruthy();
    expect(screen.getByText("dns.google")).toBeTruthy();
    expect(screen.getByText("AS15169")).toBeTruthy();
    expect(screen.getByText("GOOGLE, US")).toBeTruthy();
    expect(screen.getByText("8.8.8.0/24")).toBeTruthy();
    expect(screen.getByText("3 of 4 logical DNS queries used")).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledWith("/api/ip-network", expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ input: "8.8.8.8" }),
    }));
  });

  it("renders subnet arithmetic and explains why DNS enrichment is not applicable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(privateSubnetResult())));
    const user = userEvent.setup();
    render(<IpNetworkTool />);

    await user.type(screen.getByLabelText("IP address or CIDR"), "192.168.10.42/24");
    await user.click(screen.getByRole("button", { name: "Inspect IP / subnet" }));

    await screen.findByRole("heading", { name: "192.168.10.42/24" });
    expect(screen.getByText("192.168.10.0/24")).toBeTruthy();
    expect(screen.getByText("255.255.255.0")).toBeTruthy();
    expect(screen.getByText("254")).toBeTruthy();
    expect(screen.getByText(/limited to one globally routable IP address/u)).toBeTruthy();
  });

  it("shows sanitized API errors without retaining an old result", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(globalResult()))
      .mockResolvedValueOnce(jsonResponse({ error: "Enter a valid IPv4 or IPv6 address.", code: "BAD_REQUEST" }, 400));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<IpNetworkTool />);

    await user.click(screen.getByRole("button", { name: "8.8.8.8" }));
    await user.click(screen.getByRole("button", { name: "Inspect IP / subnet" }));
    await screen.findByText("dns.google");
    await user.clear(screen.getByLabelText("IP address or CIDR"));
    await user.type(screen.getByLabelText("IP address or CIDR"), "example.com");
    await user.click(screen.getByRole("button", { name: "Inspect IP / subnet" }));

    expect((await screen.findByRole("alert")).textContent).toContain("Enter a valid IPv4 or IPv6 address.");
    expect(screen.queryByText("dns.google")).toBeNull();
  });

  it("aborts an in-flight request and ignores its stale result when the input changes", async () => {
    let capturedSignal: AbortSignal | undefined;
    let resolveRequest: ((response: Response) => void) | undefined;
    vi.stubGlobal("fetch", vi.fn().mockImplementation((_url: string, options: RequestInit) => {
      capturedSignal = options.signal as AbortSignal;
      return new Promise<Response>((resolve) => { resolveRequest = resolve; });
    }));
    const user = userEvent.setup();
    render(<IpNetworkTool />);

    await user.click(screen.getByRole("button", { name: "8.8.8.8" }));
    await user.click(screen.getByRole("button", { name: "Inspect IP / subnet" }));
    expect(capturedSignal?.aborted).toBe(false);
    await user.type(screen.getByLabelText("IP address or CIDR"), "1");
    expect(capturedSignal?.aborted).toBe(true);

    await act(async () => {
      resolveRequest?.(jsonResponse(globalResult()));
      await Promise.resolve();
    });
    expect(screen.queryByText("Canonical input")).toBeNull();
  });
});

function globalResult(): IpToolsResult {
  return {
    address: "8.8.8.8",
    canonical: "8.8.8.8/32",
    cidr: "8.8.8.8/32",
    version: 4,
    prefix: 32,
    network: "8.8.8.8",
    networkCidr: "8.8.8.8/32",
    lastAddress: "8.8.8.8",
    totalAddresses: "1",
    isSingleAddress: true,
    classification: classification("global"),
    usable: { first: "8.8.8.8", last: "8.8.8.8", count: "1", convention: "ipv4-host" },
    ipv4: { netmask: "255.255.255.255", wildcard: "0.0.0.0", broadcast: "8.8.8.8" },
    enrichment: {
      status: "complete",
      queryCount: 3,
      ptr: { status: "found", owner: "8.8.8.8.in-addr.arpa", names: ["dns.google"] },
      origin: {
        status: "found",
        owner: "8.8.8.8.origin.asn.cymru.com",
        record: { asn: "15169", asns: ["15169"], prefix: "8.8.8.0/24", country: "US", registry: "arin", allocated: "1992-12-01" },
        records: [{ asn: "15169", asns: ["15169"], prefix: "8.8.8.0/24", country: "US", registry: "arin", allocated: "1992-12-01" }],
      },
      asName: { status: "found", asn: "15169", owner: "as15169.asn.cymru.com", name: "GOOGLE, US" },
      asNames: [{ status: "found", asn: "15169", owner: "as15169.asn.cymru.com", name: "GOOGLE, US" }],
      attribution: {
        ptr: "Native DNS PTR",
        asn: { name: "Team Cymru IP to ASN Mapping", url: "https://www.team-cymru.com/ip-asn-mapping" },
      },
    },
  };
}

function privateSubnetResult(): IpToolsResult {
  return {
    address: "192.168.10.42",
    canonical: "192.168.10.42/24",
    cidr: "192.168.10.42/24",
    version: 4,
    prefix: 24,
    network: "192.168.10.0",
    networkCidr: "192.168.10.0/24",
    lastAddress: "192.168.10.255",
    totalAddresses: "256",
    isSingleAddress: false,
    classification: classification("private"),
    usable: { first: "192.168.10.1", last: "192.168.10.254", count: "254", convention: "ipv4-traditional" },
    ipv4: { netmask: "255.255.255.0", wildcard: "0.0.0.255", broadcast: "192.168.10.255" },
    enrichment: {
      status: "not-applicable",
      queryCount: 0,
      ptr: { status: "not-requested", names: [] },
      origin: { status: "not-requested" },
      reason: "DNS enrichment is limited to one globally routable IP address.",
      attribution: {
        ptr: "Native DNS PTR",
        asn: { name: "Team Cymru IP to ASN Mapping", url: "https://www.team-cymru.com/ip-asn-mapping" },
      },
    },
  };
}

function ipv6Result(): IpToolsResult {
  return {
    address: "2001:4860:4860::8888",
    canonical: "2001:4860:4860::8888/128",
    cidr: "2001:4860:4860::8888/128",
    version: 6,
    prefix: 128,
    network: "2001:4860:4860::8888",
    networkCidr: "2001:4860:4860::8888/128",
    lastAddress: "2001:4860:4860::8888",
    totalAddresses: "1",
    isSingleAddress: true,
    classification: classification("global"),
    usable: { first: "2001:4860:4860::8888", last: "2001:4860:4860::8888", count: "1", convention: "ipv6-addresses" },
    enrichment: {
      status: "complete",
      queryCount: 2,
      ptr: { status: "not-found", names: [] },
      origin: { status: "not-found" },
      attribution: {
        ptr: "Native DNS PTR",
        asn: { name: "Team Cymru IP to ASN Mapping", url: "https://www.team-cymru.com/ip-asn-mapping" },
      },
    },
  };
}

function classification(kind: "private" | "global") {
  return {
    kind,
    private: kind === "private",
    loopback: false,
    linkLocal: false,
    multicast: false,
    documentation: false,
    reserved: false,
    global: kind === "global",
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
