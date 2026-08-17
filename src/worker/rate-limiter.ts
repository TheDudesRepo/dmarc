import type { WebScanQuota } from "../shared/types";
import { calculateIpNetwork, IpToolsValidationError } from "./ip-tools";

export const WEB_SCAN_LIMIT = 5 as const;
export const WEB_SCAN_WINDOW_MS = 60 * 60 * 1_000;
export const SECURITY_ASSESSMENT_POLL_LIMIT = 60 as const;
export const SECURITY_ASSESSMENT_POLL_WINDOW_MS = 60 * 1_000;
const MIN_RATE_LIMIT_SECRET_LENGTH = 32;

export interface RateLimitDecision {
  allowed: boolean;
  quota: WebScanQuota;
  retryAfterSeconds: number;
  timestamps: number[];
}

export interface PollRateLimitDecision {
  allowed: boolean;
  limit: typeof SECURITY_ASSESSMENT_POLL_LIMIT;
  remaining: number;
  retryAfterSeconds: number;
  resetAfterSeconds: number;
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

/** Pure rolling-window calculation for bearer job status/cancellation traffic. */
export function evaluateSecurityAssessmentPollWindow(
  stored: readonly number[],
  now = Date.now(),
): PollRateLimitDecision & { timestamps: number[] } {
  const cutoff = now - SECURITY_ASSESSMENT_POLL_WINDOW_MS;
  const current = stored
    .filter((timestamp) => Number.isSafeInteger(timestamp) && timestamp >= 0 && timestamp > cutoff && timestamp <= now)
    .sort((left, right) => left - right)
    .slice(-SECURITY_ASSESSMENT_POLL_LIMIT);
  const allowed = current.length < SECURITY_ASSESSMENT_POLL_LIMIT;
  const timestamps = allowed ? [...current, now].sort((left, right) => left - right) : current;
  const resetAtMs = (timestamps[0] ?? now) + SECURITY_ASSESSMENT_POLL_WINDOW_MS;

  return {
    allowed,
    limit: SECURITY_ASSESSMENT_POLL_LIMIT,
    remaining: Math.max(0, SECURITY_ASSESSMENT_POLL_LIMIT - timestamps.length),
    retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil((resetAtMs - now) / 1_000)),
    resetAfterSeconds: Math.max(0, Math.ceil((resetAtMs - now) / 1_000)),
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
    this.ensureSchema();
  }

  private ensureSchema(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS web_scan_events (
        occurred_at INTEGER NOT NULL
      )
    `);
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS assessment_poll_events (
        occurred_at INTEGER NOT NULL
      )
    `);
    this.sql.exec("CREATE INDEX IF NOT EXISTS assessment_poll_events_occurred_at ON assessment_poll_events (occurred_at)");
  }

  async fetch(request: Request): Promise<Response> {
    const pathname = new URL(request.url).pathname;
    if (pathname !== "/consume" && pathname !== "/poll") {
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

    this.ensureSchema();
    const now = Date.now();
    const decision = this.storage.transactionSync(() => {
      if (pathname === "/poll") {
        this.sql.exec(
          "DELETE FROM assessment_poll_events WHERE occurred_at <= ? OR occurred_at > ?",
          now - SECURITY_ASSESSMENT_POLL_WINDOW_MS,
          now,
        );
        const stats = firstSqlRow<{ count: number; oldest: number | null }>(this.sql, `
          SELECT COUNT(*) AS count, MIN(occurred_at) AS oldest
          FROM assessment_poll_events
        `) ?? { count: 0, oldest: null };
        const count = Math.max(0, Math.min(SECURITY_ASSESSMENT_POLL_LIMIT, Number(stats.count)));
        const allowed = count < SECURITY_ASSESSMENT_POLL_LIMIT;
        if (allowed) {
          this.sql.exec("INSERT INTO assessment_poll_events (occurred_at) VALUES (?)", now);
        }
        const finalCount = count + (allowed ? 1 : 0);
        const oldest = count > 0 && Number.isSafeInteger(Number(stats.oldest)) ? Number(stats.oldest) : now;
        const resetAfterSeconds = Math.max(
          0,
          Math.ceil((oldest + SECURITY_ASSESSMENT_POLL_WINDOW_MS - now) / 1_000),
        );
        return {
          allowed,
          limit: SECURITY_ASSESSMENT_POLL_LIMIT,
          remaining: Math.max(0, SECURITY_ASSESSMENT_POLL_LIMIT - finalCount),
          retryAfterSeconds: allowed ? 0 : Math.max(1, resetAfterSeconds),
          resetAfterSeconds,
        } satisfies PollRateLimitDecision;
      }

      const timestamps = [...this.sql.exec<{ occurred_at: number }>(
        "SELECT occurred_at FROM web_scan_events ORDER BY occurred_at ASC",
      )].map((row) => Number(row.occurred_at));
      const evaluated = evaluateWebScanWindow(timestamps, now);

      this.sql.exec("DELETE FROM web_scan_events");
      for (const timestamp of evaluated.timestamps) {
        this.sql.exec("INSERT INTO web_scan_events (occurred_at) VALUES (?)", timestamp);
      }
      return evaluated;
    });

    await this.scheduleNextCleanup(now);

    return Response.json(decision, {
      headers: { "Cache-Control": "no-store" },
    });
  }

  async alarm(): Promise<void> {
    this.ensureSchema();
    const now = Date.now();
    const active = this.storage.transactionSync(() => {
      this.sql.exec(
        "DELETE FROM web_scan_events WHERE occurred_at <= ? OR occurred_at > ?",
        now - WEB_SCAN_WINDOW_MS,
        now,
      );
      this.sql.exec(
        "DELETE FROM assessment_poll_events WHERE occurred_at <= ? OR occurred_at > ?",
        now - SECURITY_ASSESSMENT_POLL_WINDOW_MS,
        now,
      );
      return {
        oldestScan: oldestTimestamp(this.sql, "web_scan_events"),
        oldestPoll: oldestTimestamp(this.sql, "assessment_poll_events"),
      };
    });

    if (active.oldestScan === null && active.oldestPoll === null) {
      await this.storage.deleteAll();
      return;
    }
    await this.setCleanupAlarm(active.oldestScan, active.oldestPoll, true);
  }

  private async scheduleNextCleanup(now: number): Promise<void> {
    const events = this.storage.transactionSync(() => ({
      oldestScan: oldestActiveTimestamp(this.sql, "web_scan_events", now - WEB_SCAN_WINDOW_MS, now),
      oldestPoll: oldestActiveTimestamp(
        this.sql,
        "assessment_poll_events",
        now - SECURITY_ASSESSMENT_POLL_WINDOW_MS,
        now,
      ),
    }));
    await this.setCleanupAlarm(events.oldestScan, events.oldestPoll, false);
  }

  private async setCleanupAlarm(
    oldestScan: number | null,
    oldestPoll: number | null,
    replaceExisting: boolean,
  ): Promise<void> {
    const nextExpiry = Math.min(
      oldestScan !== null ? oldestScan + WEB_SCAN_WINDOW_MS + 1 : Number.POSITIVE_INFINITY,
      oldestPoll !== null
        ? oldestPoll + SECURITY_ASSESSMENT_POLL_WINDOW_MS + 1
        : Number.POSITIVE_INFINITY,
    );
    if (!Number.isFinite(nextExpiry)) return;
    const existing = replaceExisting ? null : await this.storage.getAlarm();
    if (replaceExisting || existing === null || nextExpiry < existing) {
      await this.storage.setAlarm(nextExpiry);
    }
  }
}

type EventTable = "web_scan_events" | "assessment_poll_events";

function oldestActiveTimestamp(
  sql: SqlStorage,
  table: EventTable,
  cutoff: number,
  now: number,
): number | null {
  const row = firstSqlRow<{ oldest: number | null }>(sql, `
    SELECT MIN(occurred_at) AS oldest
    FROM ${table}
    WHERE occurred_at > ? AND occurred_at <= ?
  `, cutoff, now);
  const value = row?.oldest;
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

function oldestTimestamp(sql: SqlStorage, table: EventTable): number | null {
  const row = firstSqlRow<{ oldest: number | null }>(sql, `SELECT MIN(occurred_at) AS oldest FROM ${table}`);
  const value = row?.oldest;
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

function firstSqlRow<T extends Record<string, SqlStorageValue>>(
  sql: SqlStorage,
  query: string,
  ...bindings: unknown[]
): T | undefined {
  return [...sql.exec<T>(query, ...bindings)][0];
}
