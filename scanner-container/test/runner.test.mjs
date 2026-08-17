import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { LIMITS, PHASES } from "../src/constants.mjs";
import { buildTestsslArguments, buildTestsslInvocation, runTestsslPhase } from "../src/testssl-runner.mjs";

test("builds only fixed pinned-target testssl arguments", () => {
  const phase = PHASES.find((entry) => entry.id === "compatibility");
  const args = buildTestsslArguments({
    hostname: "example.com",
    address: "93.184.216.34",
    proxyPort: 32123,
    outputPath: "/tmp/result.json",
    phase,
  });
  assert.deepEqual(args.slice(-1), ["example.com:443"]);
  assert.deepEqual(args.slice(args.indexOf("--ip"), args.indexOf("--ip") + 2), ["--ip", "93.184.216.34"]);
  assert.deepEqual(args.slice(args.indexOf("--proxy"), args.indexOf("--proxy") + 2), ["--proxy", "127.0.0.1:32123"]);
  assert.equal(args.includes("--openssl"), false, "testssl must auto-select its pinned bundled legacy-capable binary");
  assert.equal(args.includes("/usr/bin/openssl"), false);
  for (const flag of ["--heartbleed", "--ccs-injection", "--ticketbleed", "--robot", "--client-simulation"]) {
    assert.ok(args.includes(flag), flag);
  }
  assert.equal(args.includes("--ids-friendly"), false);
  assert.equal(args.includes("--phone-out"), false);
  assert.equal(args.includes("--file"), false);
});

test("rejects a caller-created phase or option injection", () => {
  assert.throws(() => buildTestsslArguments({
    hostname: "example.com",
    address: "93.184.216.34",
    proxyPort: 32123,
    outputPath: "/tmp/result.json",
    phase: { id: "identity", options: ["--file", "/etc/passwd"] },
  }), /unknown fixed scan phase/u);
});

test("brackets only the testssl --ip value for a canonical IPv6 endpoint", () => {
  const phase = PHASES.find((entry) => entry.id === "identity");
  const args = buildTestsslArguments({
    hostname: "example.com",
    address: "2606:4700::1111",
    proxyPort: 32123,
    outputPath: "/tmp/result.json",
    phase,
  });

  assert.deepEqual(
    args.slice(args.indexOf("--ip"), args.indexOf("--ip") + 2),
    ["--ip", "[2606:4700::1111]"],
  );
  assert.deepEqual(args.slice(-1), ["example.com:443"]);
});

test("starts every testssl process under the fixed phase file-size rlimit", () => {
  const invocation = buildTestsslInvocation("/opt/testssl/testssl.sh", ["--quiet", "example.com:443"]);
  assert.equal(invocation.command, "/usr/bin/prlimit");
  assert.deepEqual(invocation.args, [
    `--fsize=${LIMITS.maximumPhaseOutputBytes}:${LIMITS.maximumPhaseOutputBytes}`,
    "--",
    "/opt/testssl/testssl.sh",
    "--quiet",
    "example.com:443",
  ]);
});

test("does not spawn a phase for a pre-aborted signal", async () => {
  const controller = new AbortController();
  controller.abort(new Error("pre-aborted"));
  let spawned = false;
  const result = await runTestsslPhase({
    hostname: "example.com",
    address: "93.184.216.34",
    proxyPort: 32123,
    phase: PHASES[0],
    signal: controller.signal,
    spawnProcess: () => {
      spawned = true;
      throw new Error("must not spawn");
    },
  });
  assert.equal(spawned, false);
  assert.equal(result.status, "timed-out");
});

test("delivers cancellation that fires during the spawn/listener window", async () => {
  const controller = new AbortController();
  const child = new EventEmitter();
  child.pid = 424242;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  const childKills = [];
  child.kill = (signal) => { childKills.push(signal); };
  const groupKills = [];

  const result = await runTestsslPhase({
    hostname: "example.com",
    address: "93.184.216.34",
    proxyPort: 32123,
    phase: PHASES[0],
    signal: controller.signal,
    spawnProcess: () => {
      controller.abort(new Error("abort during spawn"));
      queueMicrotask(() => child.emit("close", null, "SIGTERM"));
      return child;
    },
    killProcess: (pid, signal) => {
      groupKills.push([pid, signal]);
      throw new Error("fake process group");
    },
  });

  assert.equal(result.status, "timed-out");
  assert.deepEqual(groupKills, [[-424242, "SIGTERM"]]);
  assert.deepEqual(childKills, ["SIGTERM"]);
});
