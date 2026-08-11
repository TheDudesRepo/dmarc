import type { ScanError } from "../shared/types";
import {
  createDnsSnapshot,
  discoverCommonHosts,
  DiscoveryUpstreamError,
  normalizeHostDiscoveryProfile,
} from "./discovery";
import { DomainValidationError, normalizeDomain } from "./domain";
import { inspectIpNetwork, IpToolsValidationError } from "./ip-tools";
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
        version: "0.3.0",
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

    if (url.pathname === "/api/dns-snapshot") {
      if (request.method === "OPTIONS") return methodNotAllowed(["POST"]);
      if (request.method !== "POST") return methodNotAllowed(["POST"]);
      return handleDnsSnapshot(request);
    }

    if (url.pathname === "/api/host-discovery") {
      if (request.method === "OPTIONS") return methodNotAllowed(["POST"]);
      if (request.method !== "POST") return methodNotAllowed(["POST"]);
      return handleHostDiscovery(request);
    }

    if (url.pathname === "/api/ip-network") {
      if (request.method === "OPTIONS") return methodNotAllowed(["POST"]);
      if (request.method !== "POST") return methodNotAllowed(["POST"]);
      return handleIpNetwork(request);
    }

    return errorResponse("API route not found.", "NOT_FOUND", 404);
  },
};

async function handleScan(request: Request): Promise<Response> {
  const parsed = await readJsonObject(request, ["domain"], "a domain field");
  if (!parsed.ok) return parsed.response;

  try {
    const domain = normalizeDomain(parsed.payload.domain);
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
  const parsed = await readJsonObject(request, ["name", "type"], "name and type fields");
  if (!parsed.ok) return parsed.response;

  try {
    const result = await lookupDns(parsed.payload.name, parsed.payload.type);
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

async function handleDnsSnapshot(request: Request): Promise<Response> {
  const parsed = await readJsonObject(request, ["domain"], "a domain field");
  if (!parsed.ok) return parsed.response;

  try {
    const domain = normalizeDomain(parsed.payload.domain);
    return jsonResponse(await createDnsSnapshot(domain));
  } catch (error) {
    if (error instanceof DomainValidationError) {
      return errorResponse(error.message, "INVALID_DOMAIN", 400);
    }
    if (error instanceof DiscoveryUpstreamError) {
      return errorResponse("DNS data is temporarily unavailable. Please try again.", "UPSTREAM_ERROR", 502);
    }
    return errorResponse("The DNS snapshot could not be completed. Please try again.", "UPSTREAM_ERROR", 502);
  }
}

async function handleHostDiscovery(request: Request): Promise<Response> {
  const parsed = await readJsonObject(request, ["domain", "profile"], "domain and profile fields");
  if (!parsed.ok) return parsed.response;

  let domain: string;
  try {
    domain = normalizeDomain(parsed.payload.domain);
  } catch (error) {
    if (error instanceof DomainValidationError) {
      return errorResponse(error.message, "INVALID_DOMAIN", 400);
    }
    return errorResponse("Host discovery could not be completed. Please try again.", "UPSTREAM_ERROR", 502);
  }

  let profile: ReturnType<typeof normalizeHostDiscoveryProfile>;
  try {
    profile = normalizeHostDiscoveryProfile(parsed.payload.profile);
  } catch {
    return errorResponse("Profile must be core or extended.", "BAD_REQUEST", 400);
  }

  try {
    return jsonResponse(await discoverCommonHosts(domain, profile));
  } catch {
    return errorResponse("Host discovery could not be completed. Please try again.", "UPSTREAM_ERROR", 502);
  }
}

async function handleIpNetwork(request: Request): Promise<Response> {
  const parsed = await readJsonObject(request, ["input"], "an input field");
  if (!parsed.ok) return parsed.response;

  try {
    const result = await inspectIpNetwork(parsed.payload.input, {
      enrich: true,
      includeAsName: true,
    });
    return jsonResponse(result);
  } catch (error) {
    if (error instanceof IpToolsValidationError) {
      return errorResponse(error.message, "BAD_REQUEST", 400);
    }
    return errorResponse("The IP or subnet calculation could not be completed. Please try again.", "UPSTREAM_ERROR", 502);
  }
}

type JsonObjectResult =
  | { ok: true; payload: Record<string, unknown> }
  | { ok: false; response: Response };

async function readJsonObject(
  request: Request,
  requiredFields: readonly string[],
  fieldDescription: string,
): Promise<JsonObjectResult> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/json")) {
    return {
      ok: false,
      response: errorResponse(`Send a JSON body containing ${fieldDescription}.`, "BAD_REQUEST", 400),
    };
  }

  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BODY_BYTES) {
    return { ok: false, response: errorResponse("Request body is too large.", "BAD_REQUEST", 413) };
  }

  let payload: unknown;
  try {
    const body = await request.text();
    if (new TextEncoder().encode(body).byteLength > MAX_REQUEST_BODY_BYTES) {
      return { ok: false, response: errorResponse("Request body is too large.", "BAD_REQUEST", 413) };
    }
    payload = JSON.parse(body) as unknown;
  } catch {
    return {
      ok: false,
      response: errorResponse("Request body must be valid JSON.", "BAD_REQUEST", 400),
    };
  }

  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    requiredFields.some((field) => !(field in payload))
  ) {
    return {
      ok: false,
      response: errorResponse(`JSON body must contain ${fieldDescription}.`, "BAD_REQUEST", 400),
    };
  }

  return { ok: true, payload: payload as Record<string, unknown> };
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
