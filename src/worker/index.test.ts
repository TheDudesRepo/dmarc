import dns from "node:dns";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WEB_SECURITY_DISCLAIMER } from "../shared/types";
import worker, { createPinnedLegacyWebSecurityScanner, createWorker } from "./index";
import { WebSecurityTargetError, type WebSecurityScanExecution } from "./web-security";

const env = {
  ASSETS: {
    fetch: async () => new Response("asset-response", { status: 200 }),
  },
} as unknown as Parameters<typeof worker.fetch>[1];

describe("Worker API boundary", () => {
  beforeEach(() => {
    vi.spyOn(dns.promises, "resolveCname").mockResolvedValue([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("forces the compatibility web route through the pinned socket fetcher without a global fallback", async () => {
    const pinnedFetcher = vi.fn();
    const scanner = vi.fn(async () => ({} as WebSecurityScanExecution));
    const compatibilityScanner = createPinnedLegacyWebSecurityScanner(
      scanner as never,
      () => pinnedFetcher as never,
    );

    await compatibilityScanner("example.com");

    expect(scanner).toHaveBeenCalledWith("example.com", { fetcher: pinnedFetcher });
  });

  it("returns a health response with hardened headers", async () => {
    const response = await worker.fetch(new Request("https://scanner.example/api/health"), env);
    const body = (await response.json()) as { status: string; version: string; deploymentId: string | null };

    expect(response.status).toBe(200);
    expect(body).toEqual(expect.objectContaining({
      status: "ok",
      service: "cresswell-security-lab",
      version: "0.5.0",
      deploymentId: null,
    }));
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("cache-control")).toContain("no-store");
  });

  it("returns the rolling web-scan quota with a relative RateLimit-Reset header", async () => {
    const resetAt = "2026-08-16T15:30:00.250Z";
    const now = Date.parse("2026-08-16T14:30:00.250Z");
    const scanResult = {
      hostname: "example.com",
      effectiveUrl: "https://example.com/",
      scannedAt: "2026-08-16T14:30:00.000Z",
      durationMs: 10,
      score: 100,
      grade: "A",
      headline: "Strong observable web hardening",
      summary: "Bounded test result.",
      tls: {
        status: "unavailable",
        grade: "N/A",
        summary: "Unavailable in unit test.",
        resolvedAddresses: ["203.0.113.10"],
        endpoints: [],
        endpointsTruncated: false,
        reportUrl: "https://www.ssllabs.com/ssltest/analyze.html?d=example.com&hideResults=on",
        limitations: [],
      },
      checks: [],
      coverage: { evaluated: 0, total: 20, unknown: 20, notApplicable: 0 },
      requestBudget: { httpRequests: 0, tlsConnections: 0, maxResponseBytes: 131_072, redirectHopsFollowed: 0 },
      disclaimer: WEB_SECURITY_DISCLAIMER,
    } satisfies WebSecurityScanExecution;
    const scan = vi.fn(async () => scanResult);
    const webWorker = createWorker({
      scanWebSecurity: scan,
      consumeWebScanQuota: async () => ({
        allowed: true,
        quota: { limit: 5, remaining: 4, resetAt, windowSeconds: 3600 },
        retryAfterSeconds: 0,
        timestamps: [Date.parse("2026-08-16T14:30:00.250Z")],
      }),
      now: () => now,
    });
    const response = await webWorker.fetch(
      new Request("https://scanner.example/api/web-security", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "cf-connecting-ip": "203.0.113.7",
        },
        body: JSON.stringify({
          hostname: "Example.COM.",
          authorizedUse: true,
          disclaimerVersion: "2026-08-16",
        }),
      }),
      env,
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("ratelimit-limit")).toBe("5");
    expect(response.headers.get("ratelimit-remaining")).toBe("4");
    expect(response.headers.get("ratelimit-reset")).toBe("3600");
    expect(scan).toHaveBeenCalledWith("example.com");
    await expect(response.json()).resolves.toEqual(expect.objectContaining({
      hostname: "example.com",
      quota: { limit: 5, remaining: 4, resetAt, windowSeconds: 3600 },
    }));
  });

  it("returns quota and delta Retry-After headers without scanning when the web quota is exhausted", async () => {
    const scan = vi.fn();
    const resetAt = "2026-08-16T15:30:00.250Z";
    const now = Date.parse(resetAt) - 725_000;
    const webWorker = createWorker({
      scanWebSecurity: scan,
      consumeWebScanQuota: async () => ({
        allowed: false,
        quota: { limit: 5, remaining: 0, resetAt, windowSeconds: 3600 },
        retryAfterSeconds: 725,
        timestamps: [1, 2, 3, 4, 5],
      }),
      now: () => now,
    });
    const response = await webWorker.fetch(
      new Request("https://scanner.example/api/web-security", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.7" },
        body: JSON.stringify({
          hostname: "example.com",
          authorizedUse: true,
          disclaimerVersion: "2026-08-16",
        }),
      }),
      env,
    );

    expect(response.status).toBe(429);
    expect(response.headers.get("ratelimit-limit")).toBe("5");
    expect(response.headers.get("ratelimit-remaining")).toBe("0");
    expect(response.headers.get("ratelimit-reset")).toBe("725");
    expect(response.headers.get("retry-after")).toBe("725");
    expect(scan).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual({
      error: "This client has used its five web security scans in the rolling one-hour window.",
      code: "RATE_LIMITED",
      quota: { limit: 5, remaining: 0, resetAt, windowSeconds: 3600 },
    });
  });

  it("requires current authorized-use consent before consuming web quota", async () => {
    const consume = vi.fn();
    const scan = vi.fn();
    const webWorker = createWorker({ scanWebSecurity: scan, consumeWebScanQuota: consume });
    const response = await webWorker.fetch(
      new Request("https://scanner.example/api/web-security", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.7" },
        body: JSON.stringify({
          hostname: "example.com",
          authorizedUse: true,
          disclaimerVersion: "stale-version",
        }),
      }),
      env,
    );

    expect(response.status).toBe(403);
    expect(consume).not.toHaveBeenCalled();
    expect(scan).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual(expect.objectContaining({ code: "AUTHORIZATION_REQUIRED" }));
  });

  it("cancels a chunked oversized web-security body before consuming quota", async () => {
    const consume = vi.fn();
    const scan = vi.fn();
    const webWorker = createWorker({ scanWebSecurity: scan, consumeWebScanQuota: consume });
    const encoded = new TextEncoder().encode(JSON.stringify({
      hostname: "example.com",
      authorizedUse: true,
      disclaimerVersion: "2026-08-16",
      padding: "x".repeat(3_000),
    }));
    const chunks = [encoded.slice(0, 1_024), encoded.slice(1_024, 2_049), encoded.slice(2_049)];
    let pulls = 0;
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        const chunk = chunks[pulls];
        pulls += 1;
        if (chunk === undefined) {
          controller.close();
          return;
        }
        controller.enqueue(chunk);
      },
      cancel() {
        cancelled = true;
      },
    }, { highWaterMark: 0 });

    const response = await webWorker.fetch(
      new Request("https://scanner.example/api/web-security", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.7" },
        body,
        duplex: "half",
      } as RequestInit & { duplex: "half" }),
      env,
    );

    expect(response.status).toBe(413);
    expect(pulls).toBe(2);
    expect(cancelled).toBe(true);
    expect(consume).not.toHaveBeenCalled();
    expect(scan).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual(expect.objectContaining({ code: "BAD_REQUEST" }));
  });

  it("rejects an invalid hostname before consuming a quota slot", async () => {
    const consume = vi.fn();
    const scan = vi.fn();
    const webWorker = createWorker({ scanWebSecurity: scan, consumeWebScanQuota: consume });
    const response = await webWorker.fetch(
      new Request("https://scanner.example/api/web-security", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.7" },
        body: JSON.stringify({
          hostname: "https://127.0.0.1/admin",
          authorizedUse: true,
          disclaimerVersion: "2026-08-16",
        }),
      }),
      env,
    );

    expect(response.status).toBe(400);
    expect(consume).not.toHaveBeenCalled();
    expect(scan).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual(expect.objectContaining({ code: "INVALID_DOMAIN" }));
  });

  it("returns quota metadata when a target rejection consumes an accepted slot", async () => {
    const resetAt = "2026-08-16T15:30:00.000Z";
    const scan = vi.fn(async () => {
      throw new WebSecurityTargetError("The target resolves to a non-public address.");
    });
    const webWorker = createWorker({
      scanWebSecurity: scan,
      consumeWebScanQuota: async () => ({
        allowed: true,
        quota: { limit: 5, remaining: 2, resetAt, windowSeconds: 3600 },
        retryAfterSeconds: 0,
        timestamps: [1, 2, 3],
      }),
    });
    const response = await webWorker.fetch(
      new Request("https://scanner.example/api/web-security", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.7" },
        body: JSON.stringify({
          hostname: "example.com",
          authorizedUse: true,
          disclaimerVersion: "2026-08-16",
        }),
      }),
      env,
    );

    expect(response.status).toBe(400);
    expect(response.headers.get("ratelimit-remaining")).toBe("2");
    expect(scan).toHaveBeenCalledWith("example.com");
    await expect(response.json()).resolves.toEqual({
      error: "The target resolves to a non-public address.",
      code: "UNSAFE_TARGET",
      quota: { limit: 5, remaining: 2, resetAt, windowSeconds: 3600 },
    });
  });

  it("fails closed when CF-Connecting-IP is absent even if X-Forwarded-For is supplied", async () => {
    const scan = vi.fn();
    const webWorker = createWorker({ scanWebSecurity: scan });
    const response = await webWorker.fetch(
      new Request("https://scanner.example/api/web-security", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": "203.0.113.7" },
        body: JSON.stringify({
          hostname: "example.com",
          authorizedUse: true,
          disclaimerVersion: "2026-08-16",
        }),
      }),
      env,
    );

    expect(response.status).toBe(503);
    expect(scan).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual(expect.objectContaining({ code: "SERVICE_UNAVAILABLE" }));
  });

  it("exposes the immutable deployment identifier when the binding is configured", async () => {
    const versionedEnv = {
      ...env,
      VERSION_METADATA: { id: "deployment-123" },
    } as unknown as Parameters<typeof worker.fetch>[1];
    const response = await worker.fetch(new Request("https://scanner.example/api/health"), versionedEnv);

    await expect(response.json()).resolves.toEqual(expect.objectContaining({ deploymentId: "deployment-123" }));
  });

  it("rejects unsupported methods without scanning", async () => {
    const response = await worker.fetch(new Request("https://scanner.example/api/scan"), env);
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
  });

  it("rejects malformed and unsafe scan requests at the boundary", async () => {
    const malformed = await worker.fetch(
      new Request("https://scanner.example/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "not-json",
      }),
      env,
    );
    const unsafe = await worker.fetch(
      new Request("https://scanner.example/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ domain: "https://127.0.0.1/admin" }),
      }),
      env,
    );

    expect(malformed.status).toBe(400);
    expect(unsafe.status).toBe(400);
    await expect(unsafe.json()).resolves.toEqual(expect.objectContaining({ code: "INVALID_DOMAIN" }));
  });

  it("delegates non-API routes to static assets", async () => {
    const response = await worker.fetch(new Request("https://scanner.example/how-it-works"), env);
    expect(await response.text()).toBe("asset-response");
  });

  it("allows only POST for the DNS lookup route", async () => {
    const getResponse = await worker.fetch(new Request("https://scanner.example/api/lookup"), env);
    const optionsResponse = await worker.fetch(
      new Request("https://scanner.example/api/lookup", { method: "OPTIONS" }),
      env,
    );

    expect(getResponse.status).toBe(405);
    expect(getResponse.headers.get("allow")).toBe("POST");
    expect(optionsResponse.status).toBe(405);
    expect(optionsResponse.headers.get("allow")).toBe("POST");
  });

  it("enforces JSON content type, valid JSON, required fields, and the body limit", async () => {
    const wrongContentType = await worker.fetch(
      new Request("https://scanner.example/api/lookup", { method: "POST", body: "{}" }),
      env,
    );
    const malformed = await lookupRequest("not-json");
    const missingField = await lookupRequest(JSON.stringify({ name: "example.com" }));
    const tooLarge = await lookupRequest(JSON.stringify({ name: "a".repeat(2_100), type: "A" }));

    expect(wrongContentType.status).toBe(400);
    expect(malformed.status).toBe(400);
    expect(missingField.status).toBe(400);
    expect(tooLarge.status).toBe(413);
    await expect(missingField.json()).resolves.toEqual(expect.objectContaining({ code: "BAD_REQUEST" }));
    await expect(tooLarge.json()).resolves.toEqual(expect.objectContaining({ code: "BAD_REQUEST" }));
  });

  it.each([
    { name: "example.com", type: "txt" },
    { name: "localhost", type: "A" },
    { name: "https://example.com", type: "MX" },
    { name: "example.com", type: "ANY" },
    { name: "example.com", type: "TLSA" },
    { name: "example.com", type: "DNSKEY" },
    { name: "example.com", type: 16 },
  ])("rejects invalid lookup fields before resolving: $name $type", async (payload) => {
    const resolve4 = vi.spyOn(dns.promises, "resolve4");
    const resolveMx = vi.spyOn(dns.promises, "resolveMx");
    const response = await lookupRequest(JSON.stringify(payload));

    expect(response.status).toBe(400);
    expect(resolve4).not.toHaveBeenCalled();
    expect(resolveMx).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual(expect.objectContaining({ code: "BAD_REQUEST" }));
  });

  it("resolves an allowlisted type through the fixed native DNS client and returns hardened record views", async () => {
    const resolveMx = vi.spyOn(dns.promises, "resolveMx").mockResolvedValue([
      { priority: 10, exchange: "mail.example.net." },
    ]);

    const response = await lookupRequest(JSON.stringify({ name: "Example.COM.", type: "MX" }));
    const body = (await response.json()) as {
      input: string;
      queryName: string;
      type: string;
      records: Array<{ name: string; type: string; value: string; ttl?: number }>;
      summary: string;
    };

    expect(response.status).toBe(200);
    expect(resolveMx).toHaveBeenCalledOnce();
    expect(resolveMx).toHaveBeenCalledWith("example.com");
    expect(body).toEqual(expect.objectContaining({
      input: "example.com",
      queryName: "example.com",
      type: "MX",
      records: [{ name: "example.com", type: "MX", value: "10 mail.example.net" }],
      summary: "1 MX record returned for example.com.",
    }));
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(response.headers.get("cache-control")).toContain("no-store");
  });

  it("resolves terminal records at a CNAME target without returning a mislabeled alias", async () => {
    vi.mocked(dns.promises.resolveCname).mockImplementation(async (name) =>
      name === "www.example.com" ? ["origin.example.net."] : [],
    );
    const resolve4 = vi.spyOn(dns.promises, "resolve4").mockResolvedValue([
      { address: "192.0.2.25", ttl: 300 },
    ]);

    const response = await lookupRequest(JSON.stringify({ name: "www.example.com", type: "A" }));

    expect(response.status).toBe(200);
    expect(resolve4).toHaveBeenCalledWith("origin.example.net", { ttl: true });
    await expect(response.json()).resolves.toEqual(expect.objectContaining({
      queryName: "www.example.com",
      canonicalName: "origin.example.net",
      records: [{ name: "origin.example.net", type: "A", value: "192.0.2.25", ttl: 300 }],
    }));
  });

  it("converts PTR address input before resolving", async () => {
    const resolvePtr = vi.spyOn(dns.promises, "resolvePtr").mockResolvedValue(["host.example.com."]);

    const response = await lookupRequest(JSON.stringify({ name: "192.0.2.45", type: "PTR" }));

    expect(response.status).toBe(200);
    expect(resolvePtr).toHaveBeenCalledWith("45.2.0.192.in-addr.arpa");
    await expect(response.json()).resolves.toEqual(expect.objectContaining({
      input: "192.0.2.45",
      queryName: "45.2.0.192.in-addr.arpa",
      records: [expect.objectContaining({ value: "host.example.com" })],
    }));
  });

  it("returns an empty lookup as a successful result without inventing an issue", async () => {
    vi.spyOn(dns.promises, "resolveTxt").mockResolvedValue([]);
    const response = await lookupRequest(JSON.stringify({ name: "_dmarc.example.com", type: "TXT" }));
    const body = (await response.json()) as { records: unknown[]; summary: string };

    expect(response.status).toBe(200);
    expect(body.records).toEqual([]);
    expect(body.summary).toBe("No TXT records were returned for _dmarc.example.com.");
  });

  it("exposes analyzed SPF through the lookup route while returning only SPF TXT evidence", async () => {
    const resolveTxt = vi.spyOn(dns.promises, "resolveTxt").mockResolvedValue([
      ["verification=not-spf"],
      ["v=spf1", " include:mail.example.net", " -all"],
    ]);
    resolveTxt.mockImplementation(async (name) => (
      name === "mail.example.net"
        ? [["v=spf1 ip4:192.0.2.0/24 -all"]]
        : [
            ["verification=not-spf"],
            ["v=spf1", " include:mail.example.net", " -all"],
          ]
    ));

    const response = await lookupRequest(JSON.stringify({ name: "Example.COM.", type: "SPF" }));
    const body = (await response.json()) as {
      type: string;
      queryName: string;
      records: Array<{ name: string; type: string; value: string }>;
      spfAnalysis: {
        status: string;
        valid: boolean;
        syntaxValid: boolean;
        terminalPolicy: string;
        lookupEstimate: { count: number; expandedDomains: string[] };
        correctionGuidance: { steps: string[] };
      };
    };

    expect(response.status).toBe(200);
    expect(body.type).toBe("SPF");
    expect(body.queryName).toBe("example.com");
    expect(body.records).toEqual([
      { name: "example.com", type: "TXT", value: "v=spf1 include:mail.example.net -all" },
    ]);
    expect(body.spfAnalysis).toEqual(expect.objectContaining({
      status: "valid",
      valid: true,
      syntaxValid: true,
      terminalPolicy: "-all",
      lookupEstimate: expect.objectContaining({
        count: 1,
        expandedDomains: ["mail.example.net"],
      }),
    }));
    expect(body.spfAnalysis.correctionGuidance.steps.length).toBeGreaterThan(0);
    expect(resolveTxt).toHaveBeenCalledWith("example.com");
    expect(resolveTxt).toHaveBeenCalledWith("mail.example.net");
  });

  it("analyzes an underscore-prefixed public SPF policy owner", async () => {
    const resolveTxt = vi.spyOn(dns.promises, "resolveTxt").mockResolvedValue([["v=spf1 -all"]]);
    const response = await lookupRequest(JSON.stringify({ name: "_spf.example.com", type: "SPF" }));
    const body = (await response.json()) as { queryName: string; spfAnalysis: { status: string } };

    expect(response.status).toBe(200);
    expect(body.queryName).toBe("_spf.example.com");
    expect(body.spfAnalysis.status).toBe("valid");
    expect(resolveTxt).toHaveBeenCalledWith("_spf.example.com");
  });

  it("maps resolver failures to a hardened 502 response", async () => {
    const refusal = Object.assign(new Error("query refused"), { code: "EREFUSED" });
    vi.spyOn(dns.promises, "resolve4").mockRejectedValue(refusal);
    const response = await lookupRequest(JSON.stringify({ name: "example.com", type: "A" }));

    expect(response.status).toBe(502);
    expect(response.headers.get("cache-control")).toContain("no-store");
    await expect(response.json()).resolves.toEqual(expect.objectContaining({ code: "UPSTREAM_ERROR" }));
  });

  it("maps a failed root SPF TXT query to the same hardened upstream boundary", async () => {
    const refusal = Object.assign(new Error("query refused"), { code: "EREFUSED" });
    vi.spyOn(dns.promises, "resolveTxt").mockRejectedValue(refusal);
    const response = await lookupRequest(JSON.stringify({ name: "example.com", type: "SPF" }));

    expect(response.status).toBe(502);
    expect(response.headers.get("cache-control")).toContain("no-store");
    await expect(response.json()).resolves.toEqual(expect.objectContaining({ code: "UPSTREAM_ERROR" }));
  });

  it.each(["/api/dns-snapshot", "/api/host-discovery", "/api/ip-network"])(
    "allows only POST for %s",
    async (path) => {
      const getResponse = await worker.fetch(new Request(`https://scanner.example${path}`), env);
      const optionsResponse = await worker.fetch(
        new Request(`https://scanner.example${path}`, { method: "OPTIONS" }),
        env,
      );

      expect(getResponse.status).toBe(405);
      expect(getResponse.headers.get("allow")).toBe("POST");
      expect(optionsResponse.status).toBe(405);
      expect(optionsResponse.headers.get("allow")).toBe("POST");
    },
  );

  it("enforces the shared JSON boundary for DNS snapshots", async () => {
    const resolve4 = vi.spyOn(dns.promises, "resolve4");
    const wrongContentType = await apiRequest("/api/dns-snapshot", "{}");
    const malformed = await apiRequest("/api/dns-snapshot", "not-json", { "content-type": "application/json" });
    const primitive = await apiRequest("/api/dns-snapshot", "[]", { "content-type": "application/json" });
    const missingDomain = await apiRequest(
      "/api/dns-snapshot",
      JSON.stringify({}),
      { "content-type": "application/json" },
    );
    const oversizedBody = await apiRequest(
      "/api/dns-snapshot",
      JSON.stringify({ domain: `${"a".repeat(2_100)}.com` }),
      { "content-type": "application/json" },
    );

    expect(wrongContentType.status).toBe(400);
    expect(malformed.status).toBe(400);
    expect(primitive.status).toBe(400);
    expect(missingDomain.status).toBe(400);
    expect(oversizedBody.status).toBe(413);
    expect(resolve4).not.toHaveBeenCalled();
    await expect(missingDomain.json()).resolves.toEqual(expect.objectContaining({ code: "BAD_REQUEST" }));
    await expect(oversizedBody.json()).resolves.toEqual(expect.objectContaining({ code: "BAD_REQUEST" }));
  });

  it("enforces the shared JSON boundary for host discovery", async () => {
    const resolve4 = vi.spyOn(dns.promises, "resolve4");
    const wrongContentType = await apiRequest("/api/host-discovery", "{}");
    const malformed = await apiRequest("/api/host-discovery", "not-json", { "content-type": "application/json" });
    const missingProfile = await apiRequest(
      "/api/host-discovery",
      JSON.stringify({ domain: "example.com" }),
      { "content-type": "application/json" },
    );
    const oversizedDeclared = await apiRequest(
      "/api/host-discovery",
      JSON.stringify({ domain: "example.com", profile: "core" }),
      { "content-type": "application/json", "content-length": "2049" },
    );

    expect(wrongContentType.status).toBe(400);
    expect(malformed.status).toBe(400);
    expect(missingProfile.status).toBe(400);
    expect(oversizedDeclared.status).toBe(413);
    expect(resolve4).not.toHaveBeenCalled();
    await expect(missingProfile.json()).resolves.toEqual(expect.objectContaining({ code: "BAD_REQUEST" }));
    await expect(oversizedDeclared.json()).resolves.toEqual(expect.objectContaining({ code: "BAD_REQUEST" }));
  });

  it("enforces the shared JSON boundary for IP and subnet tools", async () => {
    const resolve4 = vi.spyOn(dns.promises, "resolve4");
    const wrongContentType = await apiRequest("/api/ip-network", "{}");
    const malformed = await apiRequest("/api/ip-network", "not-json", { "content-type": "application/json" });
    const missingInput = await endpointJson("/api/ip-network", {});
    const oversizedBody = await endpointJson("/api/ip-network", { input: "1".repeat(2_100) });

    expect(wrongContentType.status).toBe(400);
    expect(malformed.status).toBe(400);
    expect(missingInput.status).toBe(400);
    expect(oversizedBody.status).toBe(413);
    expect(resolve4).not.toHaveBeenCalled();
    await expect(missingInput.json()).resolves.toEqual(expect.objectContaining({ code: "BAD_REQUEST" }));
  });

  it("calculates a subnet without making DNS enrichment queries", async () => {
    const resolveCname = vi.mocked(dns.promises.resolveCname);
    const resolvePtr = vi.spyOn(dns.promises, "resolvePtr");
    const resolveTxt = vi.spyOn(dns.promises, "resolveTxt");

    const response = await endpointJson("/api/ip-network", { input: "192.168.7.42/255.255.255.0" });
    const body = (await response.json()) as {
      canonical: string;
      networkCidr: string;
      totalAddresses: string;
      classification: { kind: string };
      ipv4: { netmask: string; wildcard: string; broadcast: string };
      enrichment: { status: string; queryCount: number };
    };

    expect(response.status).toBe(200);
    expect(body).toEqual(expect.objectContaining({
      canonical: "192.168.7.42/24",
      networkCidr: "192.168.7.0/24",
      totalAddresses: "256",
      classification: expect.objectContaining({ kind: "private" }),
      ipv4: {
        netmask: "255.255.255.0",
        wildcard: "0.0.0.255",
        broadcast: "192.168.7.255",
      },
      enrichment: expect.objectContaining({ status: "not-applicable", queryCount: 0 }),
    }));
    expect(resolveCname).not.toHaveBeenCalled();
    expect(resolvePtr).not.toHaveBeenCalled();
    expect(resolveTxt).not.toHaveBeenCalled();
  });

  it("adds bounded PTR and Team Cymru evidence for one global address", async () => {
    const ptrOwner = "4.4.8.8.in-addr.arpa";
    const originOwner = "4.4.8.8.origin.asn.cymru.com";
    vi.spyOn(dns.promises, "resolvePtr").mockImplementation(async (name) => (
      name === ptrOwner ? ["dns.google."] : []
    ));
    vi.spyOn(dns.promises, "resolveTxt").mockImplementation(async (name) => {
      if (name === originOwner) return [["15169 | 8.8.4.0/24 | US | arin | 1992-12-01"]];
      if (name === "as15169.asn.cymru.com") {
        return [["15169 | US | arin | 2000-03-30 | GOOGLE, US"]];
      }
      return [];
    });

    const response = await endpointJson("/api/ip-network", { input: "8.8.4.4" });
    const body = (await response.json()) as {
      canonical: string;
      classification: { kind: string };
      enrichment: {
        status: string;
        queryCount: number;
        ptr: { status: string; names: string[] };
        origin: { status: string; record: { asn: string; prefix: string } };
        asName: { status: string; name: string };
      };
    };

    expect(response.status).toBe(200);
    expect(body.canonical).toBe("8.8.4.4/32");
    expect(body.classification.kind).toBe("global");
    expect(body.enrichment).toEqual(expect.objectContaining({
      status: "complete",
      queryCount: 3,
      ptr: expect.objectContaining({ status: "found", names: ["dns.google"] }),
      origin: expect.objectContaining({
        status: "found",
        record: expect.objectContaining({ asn: "15169", prefix: "8.8.4.0/24" }),
      }),
      asName: expect.objectContaining({ status: "found", name: "GOOGLE, US" }),
    }));
  });

  it.each([
    "example.com",
    "https://127.0.0.1/admin",
    "192.0.2.1-192.0.2.20",
    "2001:db8::1%eth0",
  ])("rejects unsafe IP-tool input before DNS resolution: %s", async (input) => {
    const resolvePtr = vi.spyOn(dns.promises, "resolvePtr");
    const resolveTxt = vi.spyOn(dns.promises, "resolveTxt");
    const response = await endpointJson("/api/ip-network", { input });

    expect(response.status).toBe(400);
    expect(resolvePtr).not.toHaveBeenCalled();
    expect(resolveTxt).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual(expect.objectContaining({ code: "BAD_REQUEST" }));
  });

  it("rejects unsafe discovery domains and undocumented profiles before resolving", async () => {
    const resolve4 = vi.spyOn(dns.promises, "resolve4");
    const unsafeSnapshot = await endpointJson("/api/dns-snapshot", { domain: "https://127.0.0.1/admin" });
    const unsafeDiscovery = await endpointJson("/api/host-discovery", {
      domain: "localhost",
      profile: "core",
    });
    const invalidProfile = await endpointJson("/api/host-discovery", {
      domain: "example.com",
      profile: "all",
    });
    const nonStringProfile = await endpointJson("/api/host-discovery", {
      domain: "example.com",
      profile: 1,
    });

    expect(unsafeSnapshot.status).toBe(400);
    expect(unsafeDiscovery.status).toBe(400);
    expect(invalidProfile.status).toBe(400);
    expect(nonStringProfile.status).toBe(400);
    expect(resolve4).not.toHaveBeenCalled();
    await expect(unsafeSnapshot.json()).resolves.toEqual(expect.objectContaining({ code: "INVALID_DOMAIN" }));
    await expect(unsafeDiscovery.json()).resolves.toEqual(expect.objectContaining({ code: "INVALID_DOMAIN" }));
    await expect(invalidProfile.json()).resolves.toEqual({
      error: "Profile must be core or extended.",
      code: "BAD_REQUEST",
    });
  });

  it("returns a complete explicit DNS snapshot through the hardened API boundary", async () => {
    const mocks = mockEmptyDiscoveryDns();
    mocks.resolve4.mockImplementation(async (name) => {
      if (name === "example.com") return [{ address: "192.0.2.10", ttl: 300 }];
      if (name === "mail.example.com") return [{ address: "192.0.2.25", ttl: 300 }];
      if (name === "ns1.example.net") return [{ address: "192.0.2.53", ttl: 300 }];
      return [];
    });
    mocks.resolveCaa.mockResolvedValue([{ critical: 0, issue: "letsencrypt.org" }]);
    mocks.resolveMx.mockResolvedValue([{ priority: 10, exchange: "mail.example.com." }]);
    mocks.resolveNs.mockResolvedValue(["ns1.example.net."]);
    mocks.resolveSoa.mockResolvedValue({
      nsname: "ns1.example.net.",
      hostmaster: "hostmaster.example.net.",
      serial: 2026081101,
      refresh: 3600,
      retry: 600,
      expire: 1_209_600,
      minttl: 300,
    });
    mocks.resolveTxt.mockImplementation(async (name) => {
      if (name === "example.com") return [["v=spf1 -all"]];
      if (name === "_dmarc.example.com") return [["v=DMARC1; p=quarantine"]];
      if (name === "_mta-sts.example.com") return [["v=STSv1; id=20260811"]];
      if (name === "_smtp._tls.example.com") return [["v=TLSRPTv1; rua=mailto:tls@example.com"]];
      return [];
    });

    const response = await endpointJson("/api/dns-snapshot", { domain: "Example.COM." });
    const body = (await response.json()) as {
      domain: string;
      groups: Array<{ type: string; status: string; records: Array<{ value: string }> }>;
      securityRecords: Array<{ key: string; status: string }>;
      infrastructureHosts: Array<{ hostname: string; addresses: string[] }>;
      recordCount: number;
    };

    expect(response.status).toBe(200);
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(body.domain).toBe("example.com");
    expect(body.groups).toHaveLength(8);
    expect(body.groups.find((group) => group.type === "A")).toEqual(expect.objectContaining({
      status: "found",
      records: [expect.objectContaining({ value: "192.0.2.10" })],
    }));
    expect(body.securityRecords.find((record) => record.key === "dmarc")?.status).toBe("found");
    expect(body.infrastructureHosts).toEqual(expect.arrayContaining([
      expect.objectContaining({ hostname: "mail.example.com", addresses: ["192.0.2.25"] }),
      expect.objectContaining({ hostname: "ns1.example.net", addresses: ["192.0.2.53"] }),
    ]));
    expect(body.recordCount).toBeGreaterThan(0);
  });

  it("keeps partial DNS snapshot failures in a successful structured response", async () => {
    const mocks = mockEmptyDiscoveryDns();
    const secret = Object.assign(new Error("resolver-secret-caa"), { code: "EREFUSED" });
    mocks.resolveCaa.mockRejectedValue(secret);
    mocks.resolveSoa.mockResolvedValue({
      nsname: "ns1.example.net",
      hostmaster: "hostmaster.example.net",
      serial: 1,
      refresh: 3600,
      retry: 600,
      expire: 1_209_600,
      minttl: 300,
    });
    mocks.resolveTxt.mockImplementation(async (name) => {
      if (name === "_dmarc.example.com") throw Object.assign(new Error("resolver-secret-dmarc"), { code: "EREFUSED" });
      return [];
    });

    const response = await endpointJson("/api/dns-snapshot", { domain: "example.com" });
    const text = await response.text();
    const body = JSON.parse(text) as {
      groups: Array<{ type: string; status: string }>;
      securityRecords: Array<{ key: string; status: string }>;
      unavailableCount: number;
    };

    expect(response.status).toBe(200);
    expect(body.groups.find((group) => group.type === "CAA")?.status).toBe("unavailable");
    expect(body.securityRecords.find((record) => record.key === "dmarc")?.status).toBe("unavailable");
    expect(body.unavailableCount).toBe(2);
    expect(text).not.toContain("resolver-secret");
    expect(text).not.toContain("EREFUSED");
  });

  it("maps total apex snapshot failure to a sanitized 502 without leaking resolver details", async () => {
    mockEmptyDiscoveryDns();
    const secret = Object.assign(new Error("resolver-secret-token"), { code: "EREFUSED" });
    vi.mocked(dns.promises.resolveCname).mockImplementation(async (name) => {
      if (name === "example.com") throw secret;
      return [];
    });

    const response = await endpointJson("/api/dns-snapshot", { domain: "example.com" });
    const text = await response.text();

    expect(response.status).toBe(502);
    expect(JSON.parse(text)).toEqual({
      error: "DNS data is temporarily unavailable. Please try again.",
      code: "UPSTREAM_ERROR",
    });
    expect(text).not.toContain("resolver-secret-token");
    expect(text).not.toContain("EREFUSED");
  });

  it.each([
    { profile: "core", label: "www" },
    { profile: "extended", label: "status" },
  ])("returns bounded $profile host discovery results", async ({ profile, label }) => {
    const mocks = mockEmptyDiscoveryDns();
    mocks.resolve4.mockImplementation(async (name) => (
      name === `${label}.example.com` ? [{ address: "192.0.2.44", ttl: 300 }] : []
    ));

    const response = await endpointJson("/api/host-discovery", { domain: "Example.COM.", profile });
    const body = (await response.json()) as {
      domain: string;
      profile: string;
      testedNames: string[];
      hosts: Array<{ hostname: string; profile: string; addresses: string[]; reverseNames: string[] }>;
      unavailableNames: string[];
      wildcardProbe: { hostname: string; detected: boolean; addresses: string[]; unavailable: boolean };
    };

    expect(response.status).toBe(200);
    expect(body.domain).toBe("example.com");
    expect(body.profile).toBe(profile);
    expect(body.testedNames).toHaveLength(7);
    expect(body.hosts).toEqual([
      expect.objectContaining({
        hostname: `${label}.example.com`,
        profile,
        addresses: ["192.0.2.44"],
        reverseNames: [],
      }),
    ]);
    expect(body.unavailableNames).toEqual([]);
    expect(body.wildcardProbe.hostname).toMatch(/^dmarc-ready-probe-[a-f0-9]{16}\.example\.com$/u);
    expect(body.wildcardProbe.detected).toBe(false);
    expect(mocks.resolvePtr).not.toHaveBeenCalled();
  });

  it("reports partial and total common-host resolver failures without inferring absence or leaking errors", async () => {
    const partialMocks = mockEmptyDiscoveryDns();
    partialMocks.resolve4.mockImplementation(async (name) => {
      if (name === "api.example.com") {
        throw Object.assign(new Error("partial-secret"), { code: "EREFUSED" });
      }
      return [];
    });

    const partial = await endpointJson("/api/host-discovery", { domain: "example.com", profile: "core" });
    const partialText = await partial.text();
    const partialBody = JSON.parse(partialText) as { unavailableNames: string[]; hosts: unknown[] };
    expect(partial.status).toBe(200);
    expect(partialBody.unavailableNames).toContain("api.example.com");
    expect(partialBody.hosts).toEqual([]);
    expect(partialText).not.toContain("partial-secret");

    vi.restoreAllMocks();
    vi.spyOn(dns.promises, "resolveCname").mockRejectedValue(
      Object.assign(new Error("total-secret"), { code: "EREFUSED" }),
    );
    vi.spyOn(dns.promises, "resolve4").mockResolvedValue([]);
    vi.spyOn(dns.promises, "resolve6").mockResolvedValue([]);
    vi.spyOn(dns.promises, "resolvePtr").mockResolvedValue([]);

    const total = await endpointJson("/api/host-discovery", { domain: "example.com", profile: "core" });
    const totalText = await total.text();
    const totalBody = JSON.parse(totalText) as { unavailableNames: string[]; hosts: unknown[] };
    expect(total.status).toBe(200);
    expect(totalBody.unavailableNames).toHaveLength(7);
    expect(totalBody.hosts).toEqual([]);
    expect(totalText).not.toContain("total-secret");
    expect(totalText).not.toContain("EREFUSED");
  });
});

function lookupRequest(body: string): Promise<Response> {
  return worker.fetch(
    new Request("https://scanner.example/api/lookup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    }),
    env,
  );
}

function endpointJson(path: string, body: unknown): Promise<Response> {
  return apiRequest(path, JSON.stringify(body), { "content-type": "application/json" });
}

function apiRequest(path: string, body: string, headers: Record<string, string> = {}): Promise<Response> {
  return worker.fetch(
    new Request(`https://scanner.example${path}`, {
      method: "POST",
      headers,
      body,
    }),
    env,
  );
}

function mockEmptyDiscoveryDns() {
  const resolveCname = vi.mocked(dns.promises.resolveCname);
  resolveCname.mockResolvedValue([]);
  const resolve4 = vi.spyOn(dns.promises, "resolve4").mockResolvedValue([]);
  const resolve6 = vi.spyOn(dns.promises, "resolve6").mockResolvedValue([]);
  const resolveCaa = vi.spyOn(dns.promises, "resolveCaa").mockResolvedValue([]);
  const resolveMx = vi.spyOn(dns.promises, "resolveMx").mockResolvedValue([]);
  const resolveNs = vi.spyOn(dns.promises, "resolveNs").mockResolvedValue([]);
  const resolveSoa = vi.spyOn(dns.promises, "resolveSoa").mockRejectedValue(dnsError("ENODATA"));
  const resolveTxt = vi.spyOn(dns.promises, "resolveTxt").mockResolvedValue([]);
  const resolvePtr = vi.spyOn(dns.promises, "resolvePtr").mockResolvedValue([]);
  return {
    resolve4,
    resolve6,
    resolveCaa,
    resolveCname,
    resolveMx,
    resolveNs,
    resolvePtr,
    resolveSoa,
    resolveTxt,
  };
}

function dnsError(code: string): Error & { code: string } {
  return Object.assign(new Error(code), { code });
}
