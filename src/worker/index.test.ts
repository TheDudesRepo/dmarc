import { describe, expect, it } from "vitest";
import worker from "./index";

const env = {
  ASSETS: {
    fetch: async () => new Response("asset-response", { status: 200 }),
  },
} as unknown as Parameters<typeof worker.fetch>[1];

describe("Worker API boundary", () => {
  it("returns a health response with hardened headers", async () => {
    const response = await worker.fetch(new Request("https://scanner.example/api/health"), env);
    const body = (await response.json()) as { status: string; version: string };

    expect(response.status).toBe(200);
    expect(body).toEqual(expect.objectContaining({ status: "ok", version: "0.1.0" }));
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("cache-control")).toContain("no-store");
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
});
