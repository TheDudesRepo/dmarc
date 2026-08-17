import assert from "node:assert/strict";
import { test } from "node:test";
import { executeDeepScan } from "../src/scanner.mjs";

test("propagates a pre-aborted request before proxy or phase execution", async () => {
  const controller = new AbortController();
  controller.abort(new Error("request already cancelled"));
  let proxyStarted = false;

  await assert.rejects(executeDeepScan({
    hostname: "example.com",
    address: "93.184.216.34",
    addressFamily: 4,
    profile: "safe",
    deadlineMs: 180_000,
  }, {
    signal: controller.signal,
    startProxy: async () => {
      proxyStarted = true;
      throw new Error("must not start");
    },
    runPhase: async () => { throw new Error("must not run"); },
  }), /request already cancelled/u);

  assert.equal(proxyStarted, false);
});
