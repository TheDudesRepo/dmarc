import type { ScanError } from "../shared/types";
import { DomainValidationError, normalizeDomain } from "./domain";
import { lookupDns, LookupUpstreamError, LookupValidationError } from "./lookup";
import { scanDomain, ScanUpstreamError } from "./scanner";

interface Env {
  ASSETS: Fetcher;
  VERSION_METADATA?: WorkerVersionMetadata;
}

const API_SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "Cache-Control": "no-store, max-age=0",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

const MAX_REQUEST_BODY_BYTES = 2_048;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    if (url.pathname === "/api/health") {
      if (request.method !== "GET") return methodNotAllowed(["GET"]);
      return jsonResponse({
        status: "ok",
        service: "dmarc-ready-scanner",
        version: "0.2.2",
        deploymentId: env.VERSION_METADATA?.id ?? null,
      });
    }

    if (url.pathname === "/api/scan") {
      if (request.method === "OPTIONS") return methodNotAllowed(["POST"]);
      if (request.method !== "POST") return methodNotAllowed(["POST"]);
      return handleScan(request);
    }

    if (url.pathname === "/api/lookup") {
      if (request.method === "OPTIONS") return methodNotAllowed(["POST"]);
      if (request.method !== "POST") return methodNotAllowed(["POST"]);
      return handleLookup(request);
    }

    return errorResponse("API route not found.", "NOT_FOUND", 404);
  },
};

async function handleScan(request: Request): Promise<Response> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/json")) {
    return errorResponse("Send a JSON body containing a domain field.", "BAD_REQUEST", 400);
  }

  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BODY_BYTES) {
    return errorResponse("Request body is too large.", "BAD_REQUEST", 413);
  }

  let payload: unknown;
  try {
    const body = await request.text();
    if (new TextEncoder().encode(body).byteLength > MAX_REQUEST_BODY_BYTES) {
      return errorResponse("Request body is too large.", "BAD_REQUEST", 413);
    }
    payload = JSON.parse(body) as unknown;
  } catch {
    return errorResponse("Request body must be valid JSON.", "BAD_REQUEST", 400);
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload) || !("domain" in payload)) {
    return errorResponse("JSON body must contain a domain field.", "BAD_REQUEST", 400);
  }

  try {
    const domain = normalizeDomain((payload as { domain?: unknown }).domain);
    const result = await scanDomain(domain);
    return jsonResponse(result);
  } catch (error) {
    if (error instanceof DomainValidationError) {
      return errorResponse(error.message, "INVALID_DOMAIN", 400);
    }
    if (error instanceof ScanUpstreamError) {
      return errorResponse("DNS data is temporarily unavailable. Please try again.", "UPSTREAM_ERROR", 502);
    }
    return errorResponse("The scan could not be completed. Please try again.", "UPSTREAM_ERROR", 502);
  }
}

async function handleLookup(request: Request): Promise<Response> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/json")) {
    return errorResponse("Send a JSON body containing name and type fields.", "BAD_REQUEST", 400);
  }

  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BODY_BYTES) {
    return errorResponse("Request body is too large.", "BAD_REQUEST", 413);
  }

  let payload: unknown;
  try {
    const body = await request.text();
    if (new TextEncoder().encode(body).byteLength > MAX_REQUEST_BODY_BYTES) {
      return errorResponse("Request body is too large.", "BAD_REQUEST", 413);
    }
    payload = JSON.parse(body) as unknown;
  } catch {
    return errorResponse("Request body must be valid JSON.", "BAD_REQUEST", 400);
  }

  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    !("name" in payload) ||
    !("type" in payload)
  ) {
    return errorResponse("JSON body must contain name and type fields.", "BAD_REQUEST", 400);
  }

  try {
    const lookup = payload as { name?: unknown; type?: unknown };
    const result = await lookupDns(lookup.name, lookup.type);
    return jsonResponse(result);
  } catch (error) {
    if (error instanceof LookupValidationError) {
      return errorResponse(error.message, "BAD_REQUEST", 400);
    }
    if (error instanceof LookupUpstreamError) {
      return errorResponse("DNS data is temporarily unavailable. Please try again.", "UPSTREAM_ERROR", 502);
    }
    return errorResponse("The DNS lookup could not be completed. Please try again.", "UPSTREAM_ERROR", 502);
  }
}

function methodNotAllowed(allowed: string[]): Response {
  const response = errorResponse("Method not allowed.", "METHOD_NOT_ALLOWED", 405);
  response.headers.set("Allow", allowed.join(", "));
  return response;
}

function errorResponse(error: string, code: ScanError["code"], status: number): Response {
  return jsonResponse({ error, code } satisfies ScanError, status);
}

function jsonResponse(body: unknown, status = 200): Response {
  const headers = new Headers(API_SECURITY_HEADERS);
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}
