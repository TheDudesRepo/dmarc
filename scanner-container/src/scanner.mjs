import { LIMITS, PHASES } from "./constants.mjs";
import { normalizeDeepTlsResult } from "./normalize.mjs";
import { startTargetProxy } from "./target-proxy.mjs";
import { runTestsslPhase } from "./testssl-runner.mjs";

export async function executeDeepScan(request, {
  signal,
  now = () => Date.now(),
  startProxy = startTargetProxy,
  runPhase = runTestsslPhase,
} = {}) {
  const started = now();
  const startedAt = new Date(started).toISOString();
  const deadlineController = new AbortController();
  const externalAbort = () => deadlineController.abort(signal?.reason ?? new Error("scan request was cancelled"));
  signal?.addEventListener("abort", externalAbort, { once: true });
  // AbortSignal does not replay an event to listeners attached after abort.
  // Recheck after registration to close that one-shot delivery race.
  if (signal?.aborted) externalAbort();
  const timer = setTimeout(
    () => deadlineController.abort(new Error("scan deadline reached")),
    Math.max(1, request.deadlineMs - 1_000),
  );
  timer.unref?.();

  let proxy;
  let phaseResults = [];
  try {
    if (deadlineController.signal.aborted) {
      throw deadlineController.signal.reason ?? new Error("scan request was cancelled");
    }
    proxy = await startProxy({ address: request.address, signal: deadlineController.signal });
    phaseResults = await Promise.all(PHASES.map(async (phase) => {
      try {
        return await runPhase({
          hostname: request.hostname,
          address: request.address,
          proxyPort: proxy.port,
          phase,
          signal: deadlineController.signal,
        });
      } catch {
        return {
          id: phase.id,
          status: deadlineController.signal.aborted ? "timed-out" : "failed",
          exitCode: null,
          durationMs: Math.max(0, now() - started),
          outputBytes: 0,
        };
      }
    }));
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", externalAbort);
    await proxy?.close();
  }

  return normalizeDeepTlsResult({
    request,
    phaseResults,
    connectionBudget: proxy?.budget,
    startedAt,
    durationMs: Math.max(0, now() - started),
  });
}

export function unavailablePhaseResults(status = "unavailable") {
  return PHASES.slice(0, LIMITS.maximumProcesses).map((phase) => ({
    id: phase.id,
    status,
    exitCode: null,
    durationMs: 0,
    outputBytes: 0,
  }));
}
