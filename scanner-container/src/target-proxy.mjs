import { createServer as createNetServer, connect as connectTcp } from "node:net";
import { LIMITS } from "./constants.mjs";

export class ConnectionBudget {
  constructor({
    maximumConnections = LIMITS.maximumConnections,
    maximumConcurrentConnections = LIMITS.maximumConcurrentConnections,
  } = {}) {
    this.maximumConnections = maximumConnections;
    this.maximumConcurrentConnections = maximumConcurrentConnections;
    this.opened = 0;
    this.active = 0;
    this.rejected = 0;
  }

  acquire() {
    if (this.opened >= this.maximumConnections) {
      this.rejected += 1;
      return { ok: false, reason: "total-limit" };
    }
    if (this.active >= this.maximumConcurrentConnections) {
      this.rejected += 1;
      return { ok: false, reason: "concurrency-limit" };
    }
    this.opened += 1;
    this.active += 1;
    let released = false;
    return {
      ok: true,
      release: () => {
        if (released) return;
        released = true;
        this.active = Math.max(0, this.active - 1);
      },
    };
  }
}

export function allowedConnectAuthorities(address) {
  return new Set(address.includes(":")
    ? [`[${address}]:443`, `${address}:443`]
    : [`${address}:443`]);
}

export function parseConnectRequest(buffer, address) {
  if (buffer.byteLength > LIMITS.connectHeaderBytes) return { ok: false, status: 431 };
  const text = buffer.toString("latin1");
  const crlfEnd = text.indexOf("\r\n\r\n");
  const lfEnd = text.indexOf("\n\n");
  const useCrlf = crlfEnd !== -1 && (lfEnd === -1 || crlfEnd < lfEnd);
  const end = useCrlf ? crlfEnd : lfEnd;
  if (end === -1) return { ok: false, incomplete: true };

  const header = text.slice(0, end);
  const withoutLineEndings = useCrlf ? header.replaceAll("\r\n", "") : header;
  if (header.includes("\u0000")
    || (useCrlf && /[\r\n]/u.test(withoutLineEndings))
    || (!useCrlf && header.includes("\r"))) {
    return { ok: false, status: 400 };
  }
  const lines = header.split(useCrlf ? "\r\n" : "\n");
  if (lines.length > 16) return { ok: false, status: 431 };
  const match = /^CONNECT ([^ ]{1,128}) HTTP\/1\.[01]$/u.exec(lines[0] ?? "");
  if (!match || !allowedConnectAuthorities(address).has(match[1])) return { ok: false, status: 403 };
  if (lines.slice(1).some((line) =>
    !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e]{0,512}$/u.test(line))) {
    return { ok: false, status: 400 };
  }
  return {
    ok: true,
    remainder: buffer.subarray(end + (useCrlf ? 4 : 2)),
  };
}

/**
 * Every testssl.sh socket is forced through this fixed-target CONNECT proxy.
 * The request cannot change the dial address or external port.
 */
export async function startTargetProxy({
  address,
  signal,
  dial = ({ host, port }) => connectTcp({ host, port }),
  budget = new ConnectionBudget(),
} = {}) {
  const sockets = new Set();
  const server = createNetServer((client) => {
    sockets.add(client);
    client.setNoDelay(true);
    client.setTimeout(LIMITS.connectHeaderTimeoutMs, () => client.destroy());
    let header = Buffer.alloc(0);
    let parsed = false;

    const cleanupClient = () => sockets.delete(client);
    client.once("close", cleanupClient);
    client.once("error", () => {});
    client.on("data", function onData(chunk) {
      if (parsed) return;
      header = Buffer.concat([header, chunk], header.byteLength + chunk.byteLength);
      const result = parseConnectRequest(header, address);
      if (!result.ok) {
        if (result.incomplete && header.byteLength <= LIMITS.connectHeaderBytes) return;
        client.end(`HTTP/1.1 ${result.status ?? 400} Rejected\r\nConnection: close\r\n\r\n`);
        return;
      }
      parsed = true;
      client.removeListener("data", onData);
      const permit = budget.acquire();
      if (!permit.ok) {
        client.end("HTTP/1.1 503 Connection budget exhausted\r\nConnection: close\r\n\r\n");
        return;
      }

      const upstream = dial({ host: address, port: 443 });
      sockets.add(upstream);
      upstream.setTimeout?.(LIMITS.connectionLifetimeMs, () => upstream.destroy());
      upstream.once("error", () => client.destroy());
      upstream.once("close", () => {
        sockets.delete(upstream);
        permit.release();
      });
      client.once("close", () => upstream.destroy());
      upstream.once("connect", () => {
        client.setTimeout(0);
        upstream.setTimeout?.(LIMITS.connectionLifetimeMs);
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (result.remainder.byteLength > 0) upstream.write(result.remainder);
        client.pipe(upstream);
        upstream.pipe(client);
      });
    });
  });

  server.on("error", () => {});
  let closing;
  let aborted = false;
  const abortError = () => signal?.reason ?? new Error("proxy start was cancelled");
  const close = async () => {
    if (closing) return closing;
    signal?.removeEventListener("abort", abort);
    closing = new Promise((resolve) => {
      for (const socket of sockets) socket.destroy();
      if (!server.listening) {
        resolve();
        return;
      }
      server.close(() => resolve());
    });
    return closing;
  };
  const abort = () => {
    aborted = true;
    if (server.listening) void close();
  };
  if (signal) {
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  }
  if (aborted) {
    signal?.removeEventListener("abort", abort);
    throw abortError();
  }

  try {
    await new Promise((resolve, reject) => {
      const onError = (error) => {
        signal?.removeEventListener("abort", abort);
        reject(error);
      };
      server.once("error", onError);
      server.listen(0, "127.0.0.1", () => {
        server.removeListener("error", onError);
        if (aborted) {
          void close().then(() => reject(abortError()), reject);
          return;
        }
        resolve();
      });
    });
  } catch (error) {
    signal?.removeEventListener("abort", abort);
    throw error;
  }
  if (aborted) {
    await close();
    throw abortError();
  }
  const location = server.address();
  if (location === null || typeof location === "string") {
    await close();
    throw new Error("proxy did not bind a TCP port");
  }
  return { host: "127.0.0.1", port: location.port, budget, close };
}
