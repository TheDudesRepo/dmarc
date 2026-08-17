import { isIP } from "node:net";
import { assertPublicAddress } from "./ip-policy.mjs";
import { LIMITS, PROFILE } from "./constants.mjs";

const NON_PUBLIC_SUFFIXES = new Set([
  "local",
  "localhost",
  "internal",
  "invalid",
  "test",
  "home",
  "lan",
  "localdomain",
  "onion",
]);
const REQUEST_KEYS = Object.freeze(["address", "deadlineMs", "hostname", "profile"]);

export class RequestValidationError extends Error {
  constructor(message, code = "BAD_REQUEST", status = 400) {
    super(message);
    this.name = "RequestValidationError";
    this.code = code;
    this.status = status;
  }
}

export function validateScanRequest(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new RequestValidationError("request body must be a JSON object");
  }
  const keys = Object.keys(input).sort();
  if (keys.length !== REQUEST_KEYS.length || keys.some((key, index) => key !== REQUEST_KEYS[index])) {
    throw new RequestValidationError("request body must contain only hostname, address, profile, and deadlineMs");
  }
  const hostname = validateHostname(input.hostname);
  const address = assertPublicAddress(input.address);
  if (input.profile !== PROFILE) {
    throw new RequestValidationError("profile must be safe");
  }
  if (!Number.isInteger(input.deadlineMs)
    || input.deadlineMs < LIMITS.minimumDeadlineMs
    || input.deadlineMs > LIMITS.maximumDeadlineMs) {
    throw new RequestValidationError(
      `deadlineMs must be an integer from ${LIMITS.minimumDeadlineMs} through ${LIMITS.maximumDeadlineMs}`,
    );
  }
  return {
    hostname,
    address: address.address,
    addressFamily: address.family,
    profile: PROFILE,
    deadlineMs: input.deadlineMs,
  };
}

export function validateHostname(input) {
  if (typeof input !== "string" || input.length === 0 || input.length > 253 || input !== input.trim()) {
    throw new RequestValidationError("hostname must be a normalized DNS hostname");
  }
  if (input !== input.toLowerCase() || !/^[a-z0-9.-]+$/u.test(input) || isIP(input) !== 0) {
    throw new RequestValidationError("hostname must be a lowercase ASCII DNS hostname, not an IP address");
  }
  const labels = input.split(".");
  if (labels.length < 2 || labels.some((label) =>
    label.length === 0
    || label.length > 63
    || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))) {
    throw new RequestValidationError("hostname has invalid DNS labels");
  }
  const topLevel = labels.at(-1);
  if (!/[a-z]/u.test(topLevel) || NON_PUBLIC_SUFFIXES.has(topLevel)) {
    throw new RequestValidationError("hostname must use a public DNS suffix");
  }
  return input;
}

export async function readJsonBody(request) {
  const mediaType = String(request.headers["content-type"] ?? "").split(";", 1)[0].trim().toLowerCase();
  if (mediaType !== "application/json") {
    throw new RequestValidationError("content-type must be application/json", "UNSUPPORTED_MEDIA_TYPE", 415);
  }
  const declared = Number(request.headers["content-length"]);
  if (Number.isFinite(declared) && declared > LIMITS.requestBodyBytes) {
    throw new RequestValidationError("request body is too large", "PAYLOAD_TOO_LARGE", 413);
  }

  const chunks = [];
  let byteLength = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    byteLength += bytes.byteLength;
    if (byteLength > LIMITS.requestBodyBytes) {
      request.pause();
      throw new RequestValidationError("request body is too large", "PAYLOAD_TOO_LARGE", 413);
    }
    chunks.push(bytes);
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, byteLength));
  } catch {
    throw new RequestValidationError("request body must be valid UTF-8 JSON");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new RequestValidationError("request body must be valid JSON");
  }
}
