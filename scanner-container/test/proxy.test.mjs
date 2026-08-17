import assert from "node:assert/strict";
import { connect, createServer } from "node:net";
import { test } from "node:test";
import {
  ConnectionBudget,
  parseConnectRequest,
  startTargetProxy,
} from "../src/target-proxy.mjs";
import { LIMITS } from "../src/constants.mjs";

test("proxy lifetime exceeds the longest fixed active-probe wait", () => {
  assert.ok(LIMITS.connectionLifetimeMs >= 15_000);
});

test("CONNECT parser accepts pinned testssl LF and conventional CRLF framing only", () => {
  assert.equal(parseConnectRequest(Buffer.from("CONNECT 93.184.216.34:443 HTTP/1.0\r\n\r\n"), "93.184.216.34").ok, true);
  const testsslFrame = parseConnectRequest(
    Buffer.concat([
      Buffer.from("CONNECT 93.184.216.34:443 HTTP/1.0\n\n"),
      Buffer.from([0x16, 0x03, 0x01]),
    ]),
    "93.184.216.34",
  );
  assert.equal(testsslFrame.ok, true);
  assert.deepEqual(testsslFrame.remainder, Buffer.from([0x16, 0x03, 0x01]));
  assert.equal(parseConnectRequest(Buffer.from("CONNECT [2606:4700::1111]:443 HTTP/1.1\r\n\r\n"), "2606:4700::1111").ok, true);
  for (const authority of ["example.com:443", "93.184.216.35:443", "93.184.216.34:80"]) {
    for (const ending of ["\r\n\r\n", "\n\n"]) {
      assert.equal(parseConnectRequest(Buffer.from(`CONNECT ${authority} HTTP/1.1${ending}`), "93.184.216.34").status, 403);
    }
  }
  for (const malformed of [
    "CONNECT 93.184.216.34:443 HTTP/1.0\r\n\n",
    "CONNECT 93.184.216.34:443 HTTP/1.0\nHeader: ok\r\n\r\n",
    "GET 93.184.216.34:443 HTTP/1.0\n\n",
  ]) {
    assert.notEqual(parseConnectRequest(Buffer.from(malformed), "93.184.216.34").ok, true);
  }
});

test("connection budget caps both concurrent and total outbound dials", () => {
  const budget = new ConnectionBudget({ maximumConnections: 2, maximumConcurrentConnections: 1 });
  const first = budget.acquire();
  assert.equal(first.ok, true);
  assert.equal(budget.acquire().reason, "concurrency-limit");
  first.release();
  const second = budget.acquire();
  assert.equal(second.ok, true);
  second.release();
  assert.equal(budget.acquire().reason, "total-limit");
  assert.equal(budget.opened, 2);
});

test("proxy always dials the configured literal and external port 443", async (context) => {
  const target = createServer((socket) => socket.pipe(socket));
  await new Promise((resolve) => target.listen(0, "127.0.0.1", resolve));
  context.after(() => target.close());
  const targetPort = target.address().port;
  let dialArguments;
  const proxy = await startTargetProxy({
    address: "93.184.216.34",
    dial: (args) => {
      dialArguments = args;
      return connect({ host: "127.0.0.1", port: targetPort });
    },
  });
  context.after(() => proxy.close());

  const client = connect({ host: proxy.host, port: proxy.port });
  context.after(() => client.destroy());
  // Pinned testssl.sh 3.2.4's fd_socket() uses LF-only HTTP/1.0 framing.
  client.write("CONNECT 93.184.216.34:443 HTTP/1.0\n\n");
  const response = await new Promise((resolve, reject) => {
    client.once("data", (data) => resolve(data.toString("latin1")));
    client.once("error", reject);
  });
  assert.match(response, /^HTTP\/1\.1 200/u);
  assert.deepEqual(dialArguments, { host: "93.184.216.34", port: 443 });
  assert.equal(proxy.budget.opened, 1);
});

test("rejects a pre-aborted proxy start without binding", async () => {
  const controller = new AbortController();
  controller.abort(new Error("pre-aborted proxy"));
  await assert.rejects(
    startTargetProxy({ address: "93.184.216.34", signal: controller.signal }),
    /pre-aborted proxy/u,
  );
});

test("closes and rejects when cancellation lands during listen", async () => {
  const controller = new AbortController();
  const pending = startTargetProxy({ address: "93.184.216.34", signal: controller.signal });
  controller.abort(new Error("cancel during listen"));
  await assert.rejects(pending, /cancel during listen/u);
});
