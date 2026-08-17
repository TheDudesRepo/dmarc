import { connect } from "cloudflare:sockets";
import type { WebSecurityFetcher } from "./web-security";

const MAX_HTTP_RESPONSE_BYTES = 131_072;
const MAX_HTTP_HEADER_BYTES = 65_536;
const MAX_HTTP_WIRE_BYTES = MAX_HTTP_HEADER_BYTES + MAX_HTTP_RESPONSE_BYTES + 65_536;
const MAX_HTTP_HEADERS = 200;
const MAX_HTTP_LINE_BYTES = 8_192;

export type SocketConnector = (address: SocketAddress, options?: SocketOptions) => Socket;

export interface PinnedHttpTelemetry {
  pinnedSocketAttempts: number;
  platformFetchFallbacks: number;
}

export interface PinnedHttpFetcherOptions {
  connector?: SocketConnector;
  /**
   * Workers raw sockets reject Cloudflare-owned destinations. This bounded
   * fallback still receives the analyzer's fresh pre/post DNS validation, but
   * cannot promise IP pinning and is therefore recorded for result disclosure.
   */
  platformFallback?: typeof fetch;
  telemetry?: PinnedHttpTelemetry;
}

/**
 * Build the HTTP adapter used by the combined Workflow. It connects to a
 * validated literal IP and supplies the original hostname only as Host/SNI,
 * so DNS cannot change the destination after validation.
 */
export function createPinnedHttpFetcher(options: PinnedHttpFetcherOptions = {}): WebSecurityFetcher {
  const connector = options.connector ?? connect;
  return async (input, init, target) => {
    const url = new URL(input);
    if (
      (url.protocol !== "http:" && url.protocol !== "https:")
      || url.hostname.toLowerCase() !== target.hostname.toLowerCase()
      || url.username
      || url.password
      || url.port
      || target.validatedAddresses.length === 0
    ) {
      throw new Error("The pinned HTTP request was rejected by the destination policy.");
    }
    const method = String(init.method ?? "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
      throw new Error("The pinned HTTP request used a method outside the scan policy.");
    }

    let lastError: unknown;
    for (const address of target.validatedAddresses.slice(0, 2)) {
      options.telemetry && (options.telemetry.pinnedSocketAttempts += 1);
      try {
        return await fetchPinnedAddress(connector, address, url, method, init, target.hostname);
      } catch (error) {
        lastError = error;
        if (init.signal?.aborted) throw error;
      }
    }
    if (options.platformFallback) {
      options.telemetry && (options.telemetry.platformFetchFallbacks += 1);
      return options.platformFallback(input, init);
    }
    throw lastError ?? new Error("No validated destination was available.");
  };
}

async function fetchPinnedAddress(
  connector: SocketConnector,
  address: string,
  url: URL,
  method: string,
  init: RequestInit,
  hostname: string,
): Promise<Response> {
  const port = url.protocol === "https:" ? 443 : 80;
  let socket = connector(
    { hostname: address, port },
    { secureTransport: url.protocol === "https:" ? "starttls" : "off", allowHalfOpen: true },
  );
  if (url.protocol === "https:") {
    socket = socket.startTls({ expectedServerHostname: hostname });
  }

  try {
    await abortable(socket.opened, init.signal);
    const writer = (socket.writable as WritableStream<Uint8Array>).getWriter();
    try {
      await abortable(writer.write(encodeRequest(url, method, init.headers)), init.signal);
    } finally {
      writer.releaseLock();
    }

    const wire = await readHttpWireResponse(socket, method, init.signal);
    const parsed = parseHttpResponse(wire, method);
    return new Response(parsed.body === null ? null : copyArrayBuffer(parsed.body), {
      status: parsed.status,
      statusText: parsed.statusText,
      headers: parsed.headers,
    });
  } finally {
    await socket.close().catch(() => undefined);
  }
}

function encodeRequest(url: URL, method: string, initHeaders: HeadersInit | undefined): Uint8Array {
  const supplied = new Headers(initHeaders);
  const headers = new Headers();
  for (const [name, value] of supplied) {
    if (!isSafeHeader(name, value)) throw new Error("The pinned HTTP request contained an unsafe header.");
    const lower = name.toLowerCase();
    if (["host", "connection", "content-length", "transfer-encoding", "accept-encoding"].includes(lower)) continue;
    headers.append(name, value);
  }
  headers.set("Host", url.hostname);
  headers.set("Connection", "close");
  headers.set("Accept-Encoding", "identity");

  const path = `${url.pathname || "/"}${url.search}`;
  const lines = [`${method} ${path} HTTP/1.1`];
  for (const [name, value] of headers) lines.push(`${name}: ${value}`);
  return new TextEncoder().encode(`${lines.join("\r\n")}\r\n\r\n`);
}

function isSafeHeader(name: string, value: string): boolean {
  return /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name)
    && !/[\r\n\0]/u.test(value)
    && value.length <= MAX_HTTP_LINE_BYTES;
}

async function readHttpWireResponse(
  socket: Socket,
  method: string,
  signal: AbortSignal | null | undefined,
): Promise<Uint8Array> {
  const reader = (socket.readable as ReadableStream<Uint8Array>).getReader();
  const chunks: Uint8Array[] = [];
  const headerBytes = new Uint8Array(MAX_HTTP_HEADER_BYTES + 4);
  let length = 0;
  let headerEnd = -1;
  let headerLength = 0;
  let headerDelimiterState = 0;
  let bodyLength = 0;
  let expectedBodyLength: number | undefined;
  let chunked = false;
  let chunkedTracker: ChunkedFramingTracker | undefined;

  try {
    for (;;) {
      const result: ReadableStreamReadResult<Uint8Array> = await abortable(reader.read(), signal);
      if (result.done) break;
      const value = result.value as Uint8Array;
      if (value.byteLength === 0) continue;
      length += value.byteLength;
      if (length > MAX_HTTP_WIRE_BYTES) throw new Error("The HTTP response exceeded the wire safety limit.");
      chunks.push(value);
      let bodyOffset = 0;

      if (headerEnd < 0) {
        for (let index = 0; index < value.byteLength; index += 1) {
          if (headerLength >= headerBytes.byteLength) {
            throw new Error("The HTTP response headers were too large.");
          }
          const byte = value[index] ?? 0;
          headerBytes[headerLength] = byte;
          headerLength += 1;
          headerDelimiterState = nextHeaderDelimiterState(headerDelimiterState, byte);
          if (headerDelimiterState === 4) {
            headerEnd = headerLength - 4;
            bodyOffset = index + 1;
            break;
          }
        }
        if (headerEnd < 0) continue;
        const metadata = parseResponseMetadata(headerBytes.subarray(0, headerEnd));
        expectedBodyLength = metadata.contentLength;
        chunked = metadata.chunked;
        if (chunked) chunkedTracker = new ChunkedFramingTracker(MAX_HTTP_RESPONSE_BYTES);
        if (method === "HEAD" || metadata.noBody) return headerBytes.slice(0, headerLength);
      }

      const bodyPart = value.subarray(bodyOffset);
      bodyLength += bodyPart.byteLength;
      if (expectedBodyLength !== undefined && bodyLength >= Math.min(expectedBodyLength, MAX_HTTP_RESPONSE_BYTES + 1)) {
        return concatBytes(chunks, length);
      }
      if (chunked) {
        const state = chunkedTracker?.consume(bodyPart);
        if (state?.complete || state?.overLimit) return concatBytes(chunks, length);
      } else if (expectedBodyLength === undefined && bodyLength > MAX_HTTP_RESPONSE_BYTES) {
        return concatBytes(chunks, length);
      }
    }
  } finally {
    reader.releaseLock();
  }
  return concatBytes(chunks, length);
}

class ChunkedFramingTracker {
  private state: "size" | "size-lf" | "data" | "data-cr" | "data-lf" | "trailers" = "size";
  private readonly sizeLine: number[] = [];
  private remaining = 0;
  private decodedBytes = 0;
  private trailerBytes = 0;
  private trailerDelimiterState = 0;
  private trailerStartedWithCr = false;
  private complete = false;

  constructor(private readonly decodedLimit: number) {}

  consume(input: Uint8Array): { complete: boolean; overLimit: boolean } {
    for (const byte of input) {
      if (this.complete || this.decodedBytes > this.decodedLimit) break;
      if (this.state === "size") {
        if (byte === 13) {
          this.state = "size-lf";
        } else {
          if (byte === 10 || this.sizeLine.length >= 128) this.malformed();
          this.sizeLine.push(byte);
        }
      } else if (this.state === "size-lf") {
        if (byte !== 10) this.malformed();
        const line = new TextDecoder("ascii", { fatal: true }).decode(Uint8Array.from(this.sizeLine));
        const sizeText = line.split(";", 1)[0] ?? "";
        if (!/^[0-9A-Fa-f]{1,8}$/u.test(sizeText)) this.malformed();
        this.remaining = Number.parseInt(sizeText, 16);
        this.sizeLine.length = 0;
        if (this.remaining === 0) {
          this.state = "trailers";
          this.trailerBytes = 0;
          this.trailerDelimiterState = 0;
          this.trailerStartedWithCr = false;
        } else {
          this.state = "data";
        }
      } else if (this.state === "data") {
        this.remaining -= 1;
        this.decodedBytes += 1;
        if (this.remaining === 0) this.state = "data-cr";
      } else if (this.state === "data-cr") {
        if (byte !== 13) this.malformed();
        this.state = "data-lf";
      } else if (this.state === "data-lf") {
        if (byte !== 10) this.malformed();
        this.state = "size";
      } else {
        this.trailerBytes += 1;
        if (this.trailerBytes > MAX_HTTP_HEADER_BYTES) this.malformed();
        if (this.trailerBytes === 1) {
          this.trailerStartedWithCr = byte === 13;
          this.trailerDelimiterState = nextHeaderDelimiterState(0, byte);
        } else if (this.trailerBytes === 2 && this.trailerStartedWithCr) {
          if (byte === 10) {
            this.complete = true;
            break;
          }
          this.malformed();
        } else {
          this.trailerDelimiterState = nextHeaderDelimiterState(this.trailerDelimiterState, byte);
          if (this.trailerDelimiterState === 4) {
            this.complete = true;
            break;
          }
        }
      }
    }
    return { complete: this.complete, overLimit: this.decodedBytes > this.decodedLimit };
  }

  private malformed(): never {
    throw new Error("The chunked HTTP response was malformed.");
  }
}

function nextHeaderDelimiterState(state: number, byte: number): number {
  const expected = [13, 10, 13, 10] as const;
  if (byte === expected[state]) return state + 1;
  return byte === 13 ? 1 : 0;
}

interface ParsedHttpResponse {
  status: number;
  statusText: string;
  headers: Headers;
  body: Uint8Array | null;
}

export function parseHttpResponse(wire: Uint8Array, method: string): ParsedHttpResponse {
  const headerEnd = indexOfHeaderEnd(wire);
  if (headerEnd < 0 || headerEnd > MAX_HTTP_HEADER_BYTES) throw new Error("The HTTP response was malformed.");
  const headerText = new TextDecoder("latin1", { fatal: true }).decode(wire.subarray(0, headerEnd));
  const lines = headerText.split("\r\n");
  const statusLine = lines.shift() ?? "";
  const match = /^HTTP\/1\.[01] ([1-5]\d{2})(?: ([^\r\n]{0,256}))?$/u.exec(statusLine);
  if (!match) throw new Error("The HTTP status line was malformed.");
  const status = Number(match[1]);
  if (status < 200) throw new Error("An unsupported informational HTTP response was received.");

  const headers = new Headers();
  const contentLengths: number[] = [];
  if (lines.length > MAX_HTTP_HEADERS) throw new Error("The HTTP response contained too many headers.");
  for (const line of lines) {
    if (line.length === 0 || line.length > MAX_HTTP_LINE_BYTES || /^[ \t]/u.test(line)) {
      throw new Error("The HTTP response headers were malformed.");
    }
    const separator = line.indexOf(":");
    if (separator <= 0) throw new Error("The HTTP response headers were malformed.");
    const name = line.slice(0, separator);
    const value = line.slice(separator + 1).trim();
    if (!isSafeHeader(name, value)) throw new Error("The HTTP response headers were malformed.");
    if (name.toLowerCase() === "content-length") {
      if (!/^\d+$/u.test(value)) throw new Error("The HTTP Content-Length was malformed.");
      const parsed = Number(value);
      if (!Number.isSafeInteger(parsed)) throw new Error("The HTTP Content-Length was malformed.");
      contentLengths.push(parsed);
    }
    headers.append(name, value);
  }
  if (new Set(contentLengths).size > 1) throw new Error("Conflicting HTTP Content-Length values were received.");
  const encoding = headers.get("content-encoding")?.trim().toLowerCase();
  if (encoding && encoding !== "identity") throw new Error("The server ignored the identity encoding requirement.");

  const noBody = method === "HEAD" || status === 204 || status === 304;
  let body: Uint8Array | null = noBody ? null : wire.subarray(headerEnd + 4);
  const transferEncoding = headers.get("transfer-encoding")?.toLowerCase() ?? "";
  if (body && transferEncoding) {
    if (transferEncoding !== "chunked") throw new Error("An unsupported HTTP transfer encoding was received.");
    const decoded = decodeChunked(body, MAX_HTTP_RESPONSE_BYTES + 1);
    if (!decoded.complete && decoded.body.byteLength <= MAX_HTTP_RESPONSE_BYTES) {
      throw new Error("The chunked HTTP response ended before its terminator.");
    }
    body = decoded.body;
    headers.delete("transfer-encoding");
    headers.delete("content-length");
  } else if (body) {
    const declared = contentLengths[0];
    if (declared !== undefined && body.byteLength < Math.min(declared, MAX_HTTP_RESPONSE_BYTES + 1)) {
      throw new Error("The HTTP response ended before its declared length.");
    }
    body = body.subarray(0, Math.min(body.byteLength, MAX_HTTP_RESPONSE_BYTES + 1));
  }
  headers.delete("connection");
  return { status, statusText: match[2] ?? "", headers, body };
}

function parseResponseMetadata(headerBytes: Uint8Array): {
  contentLength?: number;
  chunked: boolean;
  noBody: boolean;
} {
  const text = new TextDecoder("latin1", { fatal: true }).decode(headerBytes);
  const lines = text.split("\r\n");
  const status = Number(/^HTTP\/1\.[01] ([1-5]\d{2})/u.exec(lines[0] ?? "")?.[1] ?? "0");
  if (status < 200 || status > 599) throw new Error("The HTTP status line was malformed.");
  const lengths = lines
    .slice(1)
    .filter((line) => line.toLowerCase().startsWith("content-length:"))
    .map((line) => Number(line.slice(line.indexOf(":") + 1).trim()));
  if (lengths.some((value) => !Number.isSafeInteger(value) || value < 0) || new Set(lengths).size > 1) {
    throw new Error("The HTTP Content-Length was malformed.");
  }
  const transferEncodingLine = lines
    .slice(1)
    .find((line) => line.toLowerCase().startsWith("transfer-encoding:"));
  const transferEncoding = transferEncodingLine
    ?.slice(transferEncodingLine.indexOf(":") + 1)
    .trim()
    .toLowerCase();
  return {
    ...(lengths[0] !== undefined ? { contentLength: lengths[0] } : {}),
    chunked: transferEncoding === "chunked",
    noBody: status === 204 || status === 304,
  };
}

function decodeChunked(input: Uint8Array, limit: number): { complete: boolean; body: Uint8Array } {
  const parts: Uint8Array[] = [];
  let total = 0;
  let offset = 0;
  while (offset < input.byteLength) {
    const lineEnd = indexOfCrlf(input, offset);
    if (lineEnd < 0) return { complete: false, body: concatBytes(parts, total) };
    const line = new TextDecoder("ascii", { fatal: true }).decode(input.subarray(offset, lineEnd));
    const sizeText = line.split(";", 1)[0] ?? "";
    if (!/^[0-9A-Fa-f]{1,8}$/u.test(sizeText)) throw new Error("The chunked HTTP response was malformed.");
    const size = Number.parseInt(sizeText, 16);
    offset = lineEnd + 2;
    if (size === 0) {
      if (input.byteLength < offset + 2) {
        return { complete: false, body: concatBytes(parts, total) };
      }
      if (input[offset] === 13 && input[offset + 1] === 10) {
        return { complete: true, body: concatBytes(parts, total) };
      }
      const trailerEnd = indexOfHeaderEnd(input, offset);
      if (trailerEnd < 0) return { complete: false, body: concatBytes(parts, total) };
      validateTrailerBlock(input.subarray(offset, trailerEnd));
      return { complete: true, body: concatBytes(parts, total) };
    }
    if (input.byteLength < offset + size + 2) return { complete: false, body: concatBytes(parts, total) };
    if (input[offset + size] !== 13 || input[offset + size + 1] !== 10) {
      throw new Error("The chunked HTTP response was malformed.");
    }
    const remaining = Math.max(0, limit - total);
    if (remaining > 0) {
      const part = input.subarray(offset, offset + Math.min(size, remaining));
      parts.push(part);
      total += part.byteLength;
    }
    offset += size + 2;
    if (total >= limit) return { complete: false, body: concatBytes(parts, total) };
  }
  return { complete: false, body: concatBytes(parts, total) };
}

function validateTrailerBlock(input: Uint8Array): void {
  const text = new TextDecoder("latin1", { fatal: true }).decode(input);
  const lines = text.split("\r\n");
  if (lines.length === 0 || lines.length > MAX_HTTP_HEADERS) {
    throw new Error("The chunked HTTP response trailers were malformed.");
  }
  for (const line of lines) {
    if (line.length === 0 || line.length > MAX_HTTP_LINE_BYTES || /^[ \t]/u.test(line)) {
      throw new Error("The chunked HTTP response trailers were malformed.");
    }
    const separator = line.indexOf(":");
    if (separator <= 0 || !isSafeHeader(line.slice(0, separator), line.slice(separator + 1).trim())) {
      throw new Error("The chunked HTTP response trailers were malformed.");
    }
  }
}

function indexOfHeaderEnd(input: Uint8Array, from = 0): number {
  for (let index = Math.max(0, from); index <= input.byteLength - 4; index += 1) {
    if (input[index] === 13 && input[index + 1] === 10 && input[index + 2] === 13 && input[index + 3] === 10) {
      return index;
    }
  }
  return -1;
}

function indexOfCrlf(input: Uint8Array, from: number): number {
  for (let index = from; index <= input.byteLength - 2; index += 1) {
    if (input[index] === 13 && input[index + 1] === 10) return index;
  }
  return -1;
}

function concatBytes(chunks: readonly Uint8Array[], length: number): Uint8Array {
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function copyArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function abortable<T>(operation: Promise<T>, signal: AbortSignal | null | undefined): Promise<T> {
  if (!signal) return operation;
  if (signal.aborted) return Promise.reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
    signal.addEventListener("abort", abort, { once: true });
    operation.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
