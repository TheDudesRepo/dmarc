import { createServer } from "node:http";
import { CONTRACT_VERSION, LIMITS, TESTSSL } from "./constants.mjs";
import { executeDeepScan } from "./scanner.mjs";
import { readJsonBody, RequestValidationError, validateScanRequest } from "./validation.mjs";

const RESPONSE_HEADERS = Object.freeze({
  "Cache-Control": "no-store, max-age=0",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Content-Type": "application/json; charset=utf-8",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Content-Type-Options": "nosniff",
});

export function createScannerServer({ executeScan = executeDeepScan, readBody = readJsonBody } = {}) {
  let active = false;
  return createServer(async (request, response) => {
    const path = request.url?.split("?", 1)[0] ?? "";
    if (path === "/healthz") {
      if (request.method !== "GET") return sendError(response, 405, "METHOD_NOT_ALLOWED", "method not allowed", { Allow: "GET" });
      return sendJson(response, 200, { status: "ok", schemaVersion: CONTRACT_VERSION, scanner: TESTSSL });
    }
    if (path !== "/scan") return sendError(response, 404, "BAD_REQUEST", "route not found");
    if (request.method !== "POST") return sendError(response, 405, "METHOD_NOT_ALLOWED", "method not allowed", { Allow: "POST" });
    if (active) return sendError(response, 429, "BUSY", "this scanner instance is already running a job", { "Retry-After": "2" });

    active = true;
    try {
      let scanRequest;
      try {
        scanRequest = validateScanRequest(await readBody(request));
      } catch (error) {
        if (error instanceof RequestValidationError) {
          return sendError(response, error.status, error.code, error.message, error.status === 413 ? { Connection: "close" } : {});
        }
        return sendError(response, 400, "BAD_REQUEST", "request body could not be processed");
      }

      const cancellation = new AbortController();
      const cancel = () => cancellation.abort(new Error("container request disconnected"));
      request.once("aborted", cancel);
      response.once("close", () => {
        if (!response.writableEnded) cancel();
      });
      try {
        const result = await executeScan(scanRequest, { signal: cancellation.signal });
        const encoded = Buffer.from(JSON.stringify(result));
        if (encoded.byteLength > LIMITS.maximumResponseBytes) {
          return sendError(response, 500, "SCAN_FAILED", "normalized scan result exceeded its hard size limit");
        }
        return sendEncodedJson(response, 200, encoded);
      } catch {
        return sendError(response, 502, "SCAN_FAILED", "the bounded TLS scan could not be completed");
      } finally {
        request.removeListener("aborted", cancel);
      }
    } finally {
      active = false;
    }
  });
}

function sendError(response, status, code, error, headers = {}) {
  return sendJson(response, status, { error, code }, headers);
}

function sendJson(response, status, value, headers = {}) {
  return sendEncodedJson(response, status, Buffer.from(JSON.stringify(value)), headers);
}

function sendEncodedJson(response, status, encoded, headers = {}) {
  if (response.headersSent || response.destroyed) return;
  response.writeHead(status, {
    ...RESPONSE_HEADERS,
    ...headers,
    "Content-Length": String(encoded.byteLength),
  });
  response.end(encoded);
}
