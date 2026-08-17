import { describe, expect, it, vi } from "vitest";
import {
  createPinnedHttpFetcher,
  parseHttpResponse,
  type PinnedHttpTelemetry,
  type SocketConnector,
} from "./pinned-http";

describe("IP-pinned bounded HTTP transport", () => {
  it("recognizes and decodes chunked wire responses", async () => {
    const connector = responseSocket(
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
      + "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
    );
    const fetcher = createPinnedHttpFetcher({ connector });
    const response = await fetcher("http://example.com/", { method: "GET" }, {
      hostname: "example.com",
      validatedAddresses: ["8.8.8.8"],
    });

    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe("Wikipedia");
    expect(response.headers.get("transfer-encoding")).toBeNull();
  });

  it("parses a highly fragmented chunked response in linear bounded work", async () => {
    const body = "x".repeat(30_000);
    const wire = new TextEncoder().encode(
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
      + `${body.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`,
    );
    const connector = chunkedResponseSocket([...wire].map((byte) => Uint8Array.of(byte)));
    const fetcher = createPinnedHttpFetcher({ connector });
    const started = performance.now();
    const response = await fetcher("http://example.com/", { method: "GET" }, {
      hostname: "example.com",
      validatedAddresses: ["8.8.8.8"],
    });

    await expect(response.text()).resolves.toBe(body);
    expect(performance.now() - started).toBeLessThan(3_000);
  });

  it("tries at most two validated addresses before the explicit platform fallback", async () => {
    const attempts: string[] = [];
    const telemetry: PinnedHttpTelemetry = { pinnedSocketAttempts: 0, platformFetchFallbacks: 0 };
    const fallback = vi.fn(async () => new Response("fallback", { status: 200 }));
    const fetcher = createPinnedHttpFetcher({
      connector: ((address) => {
        attempts.push(address.hostname);
        throw new Error("raw sockets are platform-blocked for this destination");
      }) as SocketConnector,
      platformFallback: fallback,
      telemetry,
    });
    const response = await fetcher("https://example.com/", { method: "GET" }, {
      hostname: "example.com",
      validatedAddresses: ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
    });

    expect(attempts).toEqual(["1.1.1.1", "8.8.8.8"]);
    expect(telemetry).toEqual({ pinnedSocketAttempts: 2, platformFetchFallbacks: 1 });
    expect(fallback).toHaveBeenCalledOnce();
    await expect(response.text()).resolves.toBe("fallback");
  });

  it("rejects conflicting Content-Length evidence", () => {
    const wire = new TextEncoder().encode(
      "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\ntest",
    );
    expect(() => parseHttpResponse(wire, "GET")).toThrow(/Conflicting/u);
  });

  it("rejects malformed bytes after a zero-size chunk", () => {
    const missingTerminalCrlf = new TextEncoder().encode(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nXX",
    );
    const malformedTrailer = new TextEncoder().encode(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nnot-a-header\r\n\r\n",
    );

    expect(() => parseHttpResponse(missingTerminalCrlf, "GET")).toThrow(/terminator/u);
    expect(() => parseHttpResponse(malformedTrailer, "GET")).toThrow(/trailers were malformed/u);
  });
});

function responseSocket(wireText: string): SocketConnector {
  return chunkedResponseSocket([new TextEncoder().encode(wireText)]);
}

function chunkedResponseSocket(chunks: Uint8Array[]): SocketConnector {
  return (() => {
    const socket = {
      readable: new ReadableStream<Uint8Array>({
        start(controller) {
          for (const chunk of chunks) controller.enqueue(chunk);
          controller.close();
        },
      }),
      writable: new WritableStream<Uint8Array>(),
      opened: Promise.resolve({}),
      closed: Promise.resolve(),
      upgraded: false,
      secureTransport: "off" as const,
      close: async () => undefined,
      startTls() { return socket; },
    };
    return socket as unknown as Socket;
  }) as SocketConnector;
}
