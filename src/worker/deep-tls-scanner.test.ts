import { describe, expect, it, vi } from "vitest";
import { beginTwoPhaseDispose, runDisposeAlarm } from "./deep-tls-scanner";

describe("deep TLS Container disposal", () => {
  it("marks recovery before stop and defers the wipe until a later alarm", async () => {
    const events: string[] = [];
    let marker: unknown;
    const mark = vi.fn(async (value: unknown) => {
      marker = value;
      events.push(`mark:${String((value as { phase?: unknown }).phase)}`);
    });
    const clear = vi.fn(async () => { events.push("clear"); });

    await beginTwoPhaseDispose({
      mark,
      stop: async () => { events.push("stop"); },
    });

    expect(events).toEqual(["mark:stop-required", "stop", "mark:stopped"]);
    expect(clear).not.toHaveBeenCalled();
    // Simulate an already-running base alarm finishing after destroy. Only the
    // subsequently scheduled native alarm may delete persistent state.
    events.push("base-alarm-unwound");
    await runDisposeAlarm(marker, {
      stop: async () => { throw new Error("a confirmed stop must not be repeated"); },
      mark,
      clear,
      fallback: async () => { throw new Error("base alarm must not run after the wipe"); },
    });
    expect(events).toEqual([
      "mark:stop-required",
      "stop",
      "mark:stopped",
      "base-alarm-unwound",
      "clear",
    ]);
  });

  it("preserves the stop-required marker when destroy rejects", async () => {
    const failure = new Error("container stop was not confirmed");
    const marks: unknown[] = [];

    await expect(beginTwoPhaseDispose({
      mark: async (marker) => { marks.push(marker); },
      stop: async () => { throw failure; },
    })).rejects.toBe(failure);

    expect(marks).toEqual([
      { phase: "stop-required", attempt: 1 },
      { phase: "stop-required", attempt: 1 },
    ]);
  });

  it("uses separate alarms to confirm a pending stop and then clear state", async () => {
    let marker: unknown = { phase: "stop-required", attempt: 1 };
    const clear = vi.fn(async () => undefined);
    const operations = {
      stop: vi.fn(async () => undefined),
      mark: vi.fn(async (value: unknown) => { marker = value; }),
      clear,
      fallback: vi.fn(async () => undefined),
    };

    await runDisposeAlarm(marker, operations);
    expect(operations.stop).toHaveBeenCalledOnce();
    expect(clear).not.toHaveBeenCalled();
    expect(marker).toEqual({ phase: "stopped", attempt: 1 });

    await runDisposeAlarm(marker, operations);
    expect(clear).toHaveBeenCalledOnce();
    expect(operations.fallback).not.toHaveBeenCalled();
  });

  it("retains a stopped marker and recovery alarm when state deletion rejects", async () => {
    const failure = new Error("persistent state deletion failed");
    const mark = vi.fn(async () => undefined);

    await runDisposeAlarm({ phase: "stopped", attempt: 1 }, {
      stop: async () => undefined,
      clear: async () => { throw failure; },
      mark,
      fallback: async () => undefined,
    });

    expect(mark).toHaveBeenCalledWith({ phase: "stopped", attempt: 2 }, 60_000);
  });

  it("delegates ordinary library alarms only when no cleanup marker exists", async () => {
    const fallback = vi.fn(async () => undefined);
    await runDisposeAlarm(undefined, {
      stop: async () => undefined,
      clear: async () => undefined,
      mark: async () => undefined,
      fallback,
    });
    expect(fallback).toHaveBeenCalledOnce();
  });

  it("rejects the native alarm when a failed stop cannot be re-armed", async () => {
    const rearmFailure = new Error("alarm storage unavailable");
    await expect(runDisposeAlarm({ phase: "stop-required", attempt: 1 }, {
      stop: async () => { throw new Error("stop failed"); },
      clear: async () => undefined,
      mark: async () => { throw rearmFailure; },
      fallback: async () => undefined,
    })).rejects.toBe(rearmFailure);
  });

  it("rejects the native alarm when a failed wipe cannot be re-armed", async () => {
    const rearmFailure = new Error("alarm storage unavailable");
    await expect(runDisposeAlarm({ phase: "stopped", attempt: 1 }, {
      stop: async () => undefined,
      clear: async () => { throw new Error("wipe failed"); },
      mark: async () => { throw rearmFailure; },
      fallback: async () => undefined,
    })).rejects.toBe(rearmFailure);
  });
});
