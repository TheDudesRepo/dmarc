import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LIMITS, PHASES } from "./constants.mjs";

const DEFAULT_TESTSSL_PATH = "/opt/testssl/testssl.sh";
const PRLIMIT_PATH = "/usr/bin/prlimit";
const SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

export function buildTestsslArguments({ hostname, address, proxyPort, outputPath, phase }) {
  if (!PHASES.some((candidate) => candidate.id === phase.id && candidate.options === phase.options)) {
    throw new Error("unknown fixed scan phase");
  }
  // testssl.sh requires an IPv6 literal passed to --ip to be bracketed. Keep
  // the validated contract/proxy address canonical and format only this argv
  // boundary; the pinned CONNECT proxy accepts the resulting authority form.
  const testsslAddress = address.includes(":") ? `[${address}]` : address;
  return [
    "--quiet",
    "--warnings", "batch",
    "--color", "0",
    "--mapping", "rfc",
    "--nodns", "none",
    "--ip", testsslAddress,
    "--proxy", `127.0.0.1:${proxyPort}`,
    "--connect-timeout", "2",
    "--openssl-timeout", "2",
    "--jsonfile-pretty", outputPath,
    "--overwrite",
    ...phase.options,
    `${hostname}:443`,
  ];
}

export function buildTestsslInvocation(testsslPath, testsslArguments) {
  const fileSizeLimit = `${LIMITS.maximumPhaseOutputBytes}:${LIMITS.maximumPhaseOutputBytes}`;
  return {
    command: PRLIMIT_PATH,
    args: [`--fsize=${fileSizeLimit}`, "--", testsslPath, ...testsslArguments],
  };
}

function childEnvironment(jobDirectory) {
  return {
    HOME: "/home/scanner",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATH: SAFE_PATH,
    TERM: "dumb",
    TMPDIR: jobDirectory,
    PHONE_OUT: "false",
    MAX_OSSL_FAIL: "2",
    MAX_SOCKET_FAIL: "2",
    HEADER_MAXSLEEP: "2",
  };
}

export async function runTestsslPhase({
  hostname,
  address,
  proxyPort,
  phase,
  signal,
  testsslPath = process.env.TESTSSL_PATH || DEFAULT_TESTSSL_PATH,
  spawnProcess = spawn,
  killProcess = process.kill,
  now = () => Date.now(),
}) {
  const started = now();
  const jobDirectory = await mkdtemp(join(tmpdir(), `tls-${phase.id}-`));
  const outputPath = join(jobDirectory, "result.json");
  const args = buildTestsslArguments({ hostname, address, proxyPort, outputPath, phase });
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let outputLimited = false;
  let timedOut = signal?.aborted === true;
  let child;
  let forcedKillTimer;
  let abort;

  const killGroup = (killSignal) => {
    if (!child?.pid) return;
    try {
      killProcess(-child.pid, killSignal);
    } catch {
      try { child.kill(killSignal); } catch { /* already exited */ }
    }
  };

  try {
    if (timedOut) {
      return phaseFailure(phase.id, "timed-out", started, now(), 0);
    }
    const invocation = buildTestsslInvocation(testsslPath, args);
    child = spawnProcess(invocation.command, invocation.args, {
      cwd: jobDirectory,
      detached: true,
      env: childEnvironment(jobDirectory),
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let abortHandled = false;
    abort = () => {
      if (abortHandled) return;
      abortHandled = true;
      timedOut = true;
      killGroup("SIGTERM");
      forcedKillTimer = setTimeout(() => killGroup("SIGKILL"), LIMITS.processKillGraceMs);
      forcedKillTimer.unref?.();
    };
    signal?.addEventListener("abort", abort, { once: true });
    // The signal can fire inside spawnProcess before the listener exists.
    if (signal?.aborted) abort();
    const account = (stream, kind) => stream?.on("data", (chunk) => {
      if (kind === "stdout") stdoutBytes += chunk.byteLength;
      else stderrBytes += chunk.byteLength;
      if (stdoutBytes + stderrBytes > LIMITS.maximumLogBytes) {
        outputLimited = true;
        killGroup("SIGTERM");
      }
    });
    account(child.stdout, "stdout");
    account(child.stderr, "stderr");

    const exit = await new Promise((resolve) => {
      child.once("error", (error) => resolve({ code: null, error }));
      child.once("close", (code, childSignal) => resolve({ code, signal: childSignal }));
    });
    if (forcedKillTimer !== undefined) clearTimeout(forcedKillTimer);

    let outputBytes = 0;
    let report;
    try {
      const metadata = await stat(outputPath);
      outputBytes = metadata.size;
      if (metadata.size > LIMITS.maximumPhaseOutputBytes) {
        outputLimited = true;
      } else if (metadata.isFile()) {
        const content = await readFile(outputPath, "utf8");
        report = JSON.parse(content);
      }
    } catch {
      // An interrupted testssl process may leave no file or incomplete JSON.
    }

    const status = outputLimited
      ? "output-limit"
      : timedOut
        ? "timed-out"
        : exit.code === 0 && report
          ? "complete"
          : report
            ? "failed"
            : "unavailable";
    return {
      id: phase.id,
      status,
      exitCode: Number.isInteger(exit.code) ? exit.code : null,
      durationMs: Math.max(0, now() - started),
      outputBytes,
      report,
    };
  } finally {
    if (forcedKillTimer !== undefined) clearTimeout(forcedKillTimer);
    if (abort) signal?.removeEventListener("abort", abort);
    await rm(jobDirectory, { recursive: true, force: true });
  }
}

function phaseFailure(id, status, started, finished, outputBytes) {
  return {
    id,
    status,
    exitCode: null,
    durationMs: Math.max(0, finished - started),
    outputBytes,
  };
}
