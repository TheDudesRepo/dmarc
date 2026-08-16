import type { WebScanQuota } from "../shared/types";
import { calculateIpNetwork, IpToolsValidationError } from "./ip-tools";

export const WEB_SCAN_LIMIT = 5 as const;
export const WEB_SCAN_WINDOW_MS = 60 * 60 * 1_000;
const MIN_RATE_LIMIT_SECRET_LENGTH = 32;

export interface RateLimitDecision {
  allowed: boolean;
  quota: WebScanQuota;
  retryAfterSeconds: number;
  timestamps: number[];
}

export class RateLimitConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RateLimitConfigurationError";
  }
}

/**
 * Accept only the Cloudflare-provided bare client address and normalize IPv6
 * spellings so one client cannot receive multiple counters for equivalent
 * textual forms. The caller is responsible for reading CF-Connecting-IP and
 * must not substitute X-Forwarded-For or another caller-controlled header.
 */
export function canonicalizeClientIp(input: string | null): string {
  if (
    input === null
    || !input
    || input.length > 128
    || input !== input.trim()
    || /\s/u.test(input)
    || input.includes(",")
    || input.includes("/")
    || input.includes("[")
    || input.includes("]")
    || input.includes("%")
  ) {
    throw new RateLimitConfigurationError("A trusted client IP address is unavailable.");
  }

  try {
    const calculation = calculateIpNetwork(input);
    if (!calculation.isSingleAddress) {
      throw new RateLimitConfigurationError("A trusted client IP address is unavailable.");
    }
    return calculation.address;
  } catch (error) {
    if (error instanceof RateLimitConfigurationError) throw error;
    if (error instanceof IpToolsValidationError) {
      throw new RateLimitConfigurationError("A trusted client IP address is unavailable.");
    }
    throw error;
  }
}

/**
 * Create a stable object name without persisting the raw IP. A configured
 * secret uses HMAC; deployments without one use a domain-separated SHA-256
 * digest so the abuse control remains available after a Git-based deploy.
 */
export async function digestClientIp(clientIp: string, secret: string | undefined): Promise<string> {
  const encoded = new TextEncoder().encode(`dmarc-ready:web-scan-rate-limit:v1:${clientIp}`);
  if (secret === undefined) {
    const digest = await crypto.subtle.digest("SHA-256", encoded);
    return bytesToHex(digest);
  }
  if (secret.length < MIN_RATE_LIMIT_SECRET_LENGTH) {
    throw new RateLimitConfigurationError("The scan rate limiter is not configured.");
  }

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoded);
  return bytesToHex(signature);
}

function bytesToHex(value: ArrayBuffer): string {
  return [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Pure rolling-window calculation shared by the Durable Object and tests. */
export function evaluateWebScanWindow(stored: readonly number[], now = Date.now()): RateLimitDecision {
  const cutoff = now - WEB_SCAN_WINDOW_MS;
  const current = stored
    .filter((timestamp) => Number.isSafeInteger(timestamp) && timestamp >= 0 && timestamp > cutoff && timestamp <= now)
    .sort((left, right) => left - right)
    .slice(-WEB_SCAN_LIMIT);
  const allowed = current.length < WEB_SCAN_LIMIT;
  const timestamps = allowed ? [...current, now].sort((left, right) => left - right) : current;
  const oldest = timestamps[0] ?? now;
  const resetAtMs = oldest + WEB_SCAN_WINDOW_MS;
  const remaining = Math.max(0, WEB_SCAN_LIMIT - timestamps.length);

  return {
    allowed,
    quota: {
      limit: WEB_SCAN_LIMIT,
      remaining,
      resetAt: new Date(resetAtMs).toISOString(),
      windowSeconds: 3600,
    },
    retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil((resetAtMs - now) / 1_000)),
    timestamps,
  };
}

/**
 * One SQLite-backed Durable Object instance is addressed by a digest of one
 * Cloudflare-authenticated client IP. Synchronous SQL keeps each decision
 * serialized and makes the rolling five-per-hour limit durable across isolates.
 */
export class WebScanRateLimiter {
  private readonly storage: DurableObjectStorage;
  private readonly sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.storage = state.storage;
    this.sql = state.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS web_scan_events (
        occurred_at INTEGER NOT NULL
      )
    `);
  }

  fetch(request: Request): Response {
    if (new URL(request.url).pathname !== "/consume") {
      return new Response("Not found.", {
        status: 404,
        headers: { "Cache-Control": "no-store" },
      });
    }
    if (request.method !== "POST") {
      return new Response("Method not allowed.", {
        status: 405,
        headers: { Allow: "POST", "Cache-Control": "no-store" },
      });
    }

    const decision = this.storage.transactionSync(() => {
      const timestamps = [...this.sql.exec<{ occurred_at: number }>(
        "SELECT occurred_at FROM web_scan_events ORDER BY occurred_at ASC",
      )].map((row) => Number(row.occurred_at));
      const evaluated = evaluateWebScanWindow(timestamps);

      this.sql.exec("DELETE FROM web_scan_events");
      for (const timestamp of evaluated.timestamps) {
        this.sql.exec("INSERT INTO web_scan_events (occurred_at) VALUES (?)", timestamp);
      }
      return evaluated;
    });

    return Response.json(decision, {
      headers: { "Cache-Control": "no-store" },
    });
  }
}
