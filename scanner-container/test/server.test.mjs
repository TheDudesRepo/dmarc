import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { test } from "node:test";
import { CONTRACT_VERSION } from "../src/constants.mjs";
import { createScannerServer } from "../src/server.mjs";

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

const validBody = {
  hostname: "example.com",
  address: "93.184.216.34",
  profile: "safe",
  deadlineMs: 180_000,
};

test("serves health and a strict scan route", async (context) => {
  let received;
  const server = createScannerServer({ executeScan: async (input) => {
    received = input;
    return { schemaVersion: CONTRACT_VERSION, ok: true };
  } });
  context.after(() => server.close());
  const origin = await listen(server);
  const health = await fetch(`${origin}/healthz`);
  assert.equal(health.status, 200);
  assert.equal((await health.json()).scanner.commit, "97763a411c525720a5f9bd9d2cded416b10f210a");

  const response = await fetch(`${origin}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(validBody),
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store, max-age=0");
  assert.equal((await response.json()).ok, true);
  assert.deepEqual(received, { ...validBody, addressFamily: 4 });
});

test("rejects unsupported media, extra keys, private addresses, and methods", async (context) => {
  const server = createScannerServer({ executeScan: async () => ({}) });
  context.after(() => server.close());
  const origin = await listen(server);
  const cases = [
    fetch(`${origin}/scan`, { method: "GET" }),
    fetch(`${origin}/scan`, { method: "POST", body: JSON.stringify(validBody) }),
    fetch(`${origin}/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...validBody, port: 443 }) }),
    fetch(`${origin}/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...validBody, address: "127.0.0.1" }) }),
  ];
  const responses = await Promise.all(cases);
  assert.deepEqual(responses.map((response) => response.status), [405, 415, 400, 400]);
});

test("rejects a chunked body as soon as it crosses 2 KiB", async (context) => {
  const server = createScannerServer({ executeScan: async () => ({}) });
  context.after(() => server.close());
  const origin = new URL(await listen(server));
  const result = await new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: origin.hostname,
      port: origin.port,
      path: "/scan",
      method: "POST",
      headers: { "content-type": "application/json" },
    }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { body += chunk; });
      response.on("end", () => resolve({ status: response.statusCode, body }));
    });
    request.once("error", reject);
    request.write("{");
    request.write(`"padding":"${"x".repeat(2_100)}"}`);
    request.end();
  });
  assert.equal(result.status, 413);
  assert.equal(JSON.parse(result.body).code, "PAYLOAD_TOO_LARGE");
});

test("allows only one active scan per container instance", async (context) => {
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  const server = createScannerServer({ executeScan: async () => {
    await blocked;
    return { schemaVersion: CONTRACT_VERSION };
  } });
  context.after(() => server.close());
  const origin = await listen(server);
  const first = fetch(`${origin}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(validBody),
  });
  await new Promise((resolve) => setImmediate(resolve));
  const second = await fetch(`${origin}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(validBody),
  });
  assert.equal(second.status, 429);
  release();
  assert.equal((await first).status, 200);
});

test("reserves the active slot while the first request body is still being read", async (context) => {
  let releaseBody;
  let markBodyReadStarted;
  const bodyReadStarted = new Promise((resolve) => { markBodyReadStarted = resolve; });
  const blockedBody = new Promise((resolve) => { releaseBody = resolve; });
  const server = createScannerServer({
    readBody: async () => {
      markBodyReadStarted();
      await blockedBody;
      return validBody;
    },
    executeScan: async () => ({ schemaVersion: CONTRACT_VERSION }),
  });
  context.after(() => server.close());
  const origin = await listen(server);
  const first = fetch(`${origin}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(validBody),
  });
  await bodyReadStarted;

  const second = await fetch(`${origin}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(validBody),
  });
  assert.equal(second.status, 429);
  assert.equal((await second.json()).code, "BUSY");

  releaseBody();
  assert.equal((await first).status, 200);
});
