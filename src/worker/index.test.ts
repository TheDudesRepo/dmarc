import dns from "node:dns";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "./index";

const env = {
  ASSETS: {
    fetch: async () => new Response("asset-response", { status: 200 }),
  },
} as unknown as Parameters<typeof worker.fetch>[1];

describe("Worker API boundary", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns a health response with hardened headers", async () => {
    const response = await worker.fetch(new Request("https://scanner.example/api/health"), env);
    const body = (await response.json()) as { status: string; version: string; deploymentId: string | null };

    expect(response.status).toBe(200);
    expect(body).toEqual(expect.objectContaining({ status: "ok", version: "0.2.2", deploymentId: null }));
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("cache-control")).toContain("no-store");
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

  it("maps resolver failures to a hardened 502 response", async () => {
    const refusal = Object.assign(new Error("query refused"), { code: "EREFUSED" });
    vi.spyOn(dns.promises, "resolve4").mockRejectedValue(refusal);
    const response = await lookupRequest(JSON.stringify({ name: "example.com", type: "A" }));

    expect(response.status).toBe(502);
    expect(response.headers.get("cache-control")).toContain("no-store");
    await expect(response.json()).resolves.toEqual(expect.objectContaining({ code: "UPSTREAM_ERROR" }));
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
