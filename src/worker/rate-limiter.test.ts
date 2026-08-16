import { describe, expect, it } from "vitest";
import {
  canonicalizeClientIp,
  digestClientIp,
  evaluateWebScanWindow,
  RateLimitConfigurationError,
  WEB_SCAN_LIMIT,
  WEB_SCAN_WINDOW_MS,
} from "./rate-limiter";

describe("web security scan rolling rate limit", () => {
  it("allows exactly five events in the preceding hour and denies the sixth", () => {
    const start = Date.UTC(2026, 7, 16, 12, 0, 0);
    let timestamps: number[] = [];

    for (let attempt = 0; attempt < WEB_SCAN_LIMIT; attempt += 1) {
      const decision = evaluateWebScanWindow(timestamps, start + attempt * 1_000);
      expect(decision.allowed).toBe(true);
      expect(decision.quota.remaining).toBe(WEB_SCAN_LIMIT - attempt - 1);
      timestamps = decision.timestamps;
    }

    const denied = evaluateWebScanWindow(timestamps, start + WEB_SCAN_LIMIT * 1_000);
    expect(denied.allowed).toBe(false);
    expect(denied.timestamps).toEqual(timestamps);
    expect(denied.quota).toEqual({
      limit: 5,
      remaining: 0,
      resetAt: new Date(start + WEB_SCAN_WINDOW_MS).toISOString(),
      windowSeconds: 3600,
    });
    expect(denied.retryAfterSeconds).toBe(3_595);
  });

  it("uses a true rolling boundary and expires an event exactly one hour old", () => {
    const now = Date.UTC(2026, 7, 16, 13, 0, 0);
    const timestamps = [
      now - WEB_SCAN_WINDOW_MS,
      now - WEB_SCAN_WINDOW_MS + 1,
      now - 3_000,
      now - 2_000,
      now - 1_000,
    ];

    const decision = evaluateWebScanWindow(timestamps, now);

    expect(decision.allowed).toBe(true);
    expect(decision.timestamps).toEqual([
      now - WEB_SCAN_WINDOW_MS + 1,
      now - 3_000,
      now - 2_000,
      now - 1_000,
      now,
    ]);
    expect(decision.quota.remaining).toBe(0);
    expect(decision.quota.resetAt).toBe(new Date(now + 1).toISOString());
  });

  it("discards invalid and future storage rows and retains only the newest five valid rows", () => {
    const now = Date.UTC(2026, 7, 16, 14, 0, 0);
    const decision = evaluateWebScanWindow([
      Number.NaN,
      Number.POSITIVE_INFINITY,
      now - 5_500.5,
      -1,
      now + 1,
      now - WEB_SCAN_WINDOW_MS,
      now - 10_000,
      now - 9_000,
      now - 8_000,
      now - 7_000,
      now - 6_000,
      now - 5_000,
    ], now);

    expect(decision.allowed).toBe(false);
    expect(decision.timestamps).toEqual([
      now - 9_000,
      now - 8_000,
      now - 7_000,
      now - 6_000,
      now - 5_000,
    ]);
    expect(decision.retryAfterSeconds).toBe(3_591);
  });
});

describe("trusted client IP keys", () => {
  it("canonicalizes equivalent IPv6 spellings and accepts a bare IPv4 address", () => {
    expect(canonicalizeClientIp("203.0.113.7")).toBe("203.0.113.7");
    expect(canonicalizeClientIp("2001:0db8:0:0:0:0:0:1")).toBe("2001:db8::1");
    expect(canonicalizeClientIp("2001:db8::1")).toBe("2001:db8::1");
  });

  it.each([
    null,
    "",
    " 203.0.113.7",
    "203.0.113.7 ",
    "203.0.113.7, 198.51.100.4",
    "203.0.113.7/32",
    "[2001:db8::1]",
    "fe80::1%eth0",
    "999.0.0.1",
    "example.com",
  ])("rejects an unavailable or non-bare trusted address: %s", (value) => {
    expect(() => canonicalizeClientIp(value)).toThrow(RateLimitConfigurationError);
  });

  it("derives stable, secret-keyed object names", async () => {
    const secret = "test-only-web-scan-rate-limit-key-1234567890";
    const first = await digestClientIp(canonicalizeClientIp("2001:0db8::1"), secret);
    const equivalent = await digestClientIp(canonicalizeClientIp("2001:db8::1"), secret);
    const different = await digestClientIp(canonicalizeClientIp("2001:db8::2"), secret);

    expect(first).toMatch(/^[a-f0-9]{64}$/u);
    expect(equivalent).toBe(first);
    expect(different).not.toBe(first);
  });

  it("uses a stable domain-separated digest when no optional secret is configured", async () => {
    const first = await digestClientIp("203.0.113.7", undefined);
    const repeat = await digestClientIp("203.0.113.7", undefined);
    const different = await digestClientIp("203.0.113.8", undefined);

    expect(first).toMatch(/^[a-f0-9]{64}$/u);
    expect(repeat).toBe(first);
    expect(different).not.toBe(first);
  });

  it.each(["", "short-secret"])("fails closed for a configured but short HMAC secret", async (secret) => {
    await expect(digestClientIp("203.0.113.7", secret)).rejects.toBeInstanceOf(RateLimitConfigurationError);
  });
});
