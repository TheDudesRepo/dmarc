import { DnsClient } from "./dns";
import { calculateIpNetwork } from "./ip-tools";

export const MAX_PUBLIC_TARGET_ADDRESSES = 16;
export const MAX_DEEP_TLS_ENDPOINTS = 4;
const DNS_VALIDATION_TIMEOUT_MS = 2_000;

export type PublicHostResolver = (hostname: string) => Promise<readonly string[]>;

export class UnsafeScanTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsafeScanTargetError";
  }
}

export class ScanTargetResolutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanTargetResolutionError";
  }
}

/** Resolve a fresh A/AAAA view. A new client avoids reusing a prior DNS cache. */
export async function resolvePublicHost(
  hostname: string,
  resolver: PublicHostResolver = resolveWithFreshDnsClient,
): Promise<string[]> {
  let values: readonly string[];
  try {
    values = await withDeadline(
      resolver(hostname),
      DNS_VALIDATION_TIMEOUT_MS,
      new ScanTargetResolutionError("The target address could not be resolved within the safety deadline."),
    );
  } catch (error) {
    if (error instanceof UnsafeScanTargetError || error instanceof ScanTargetResolutionError) throw error;
    throw new ScanTargetResolutionError("The target address could not be resolved safely.");
  }

  if (values.length > MAX_PUBLIC_TARGET_ADDRESSES) {
    throw new UnsafeScanTargetError("The target returned too many addresses for a bounded assessment.");
  }

  const unique = new Set<string>();
  for (const rawValue of values) {
    const value = rawValue.trim();
    if (!value) continue;
    let canonical: string;
    try {
      const calculation = calculateIpNetwork(value);
      if (!calculation.isSingleAddress || !calculation.classification.global) {
        throw new UnsafeScanTargetError("The target resolves to a non-public address.");
      }
      canonical = calculation.address;
    } catch (error) {
      if (error instanceof UnsafeScanTargetError) throw error;
      throw new UnsafeScanTargetError("The target returned an invalid address.");
    }
    if (isTranslationOrTransitionAddress(canonical)) {
      throw new UnsafeScanTargetError(
        "The target resolves to an address-translation or transition range that cannot be assessed safely.",
      );
    }
    unique.add(canonical);
  }

  if (unique.size === 0) {
    throw new ScanTargetResolutionError("The target did not resolve to a public address.");
  }
  if (unique.size > MAX_PUBLIC_TARGET_ADDRESSES) {
    throw new UnsafeScanTargetError("The target returned too many addresses for a bounded assessment.");
  }
  return [...unique].sort();
}

export function canonicalPublicScanAddress(value: string): string {
  let calculation: ReturnType<typeof calculateIpNetwork>;
  try {
    calculation = calculateIpNetwork(value);
  } catch {
    throw new UnsafeScanTargetError("The target returned an invalid address.");
  }
  if (!calculation.isSingleAddress || !calculation.classification.global) {
    throw new UnsafeScanTargetError("The target resolves to a non-public address.");
  }
  if (isTranslationOrTransitionAddress(calculation.address)) {
    throw new UnsafeScanTargetError(
      "The target resolves to an address-translation or transition range that cannot be assessed safely.",
    );
  }
  return calculation.address;
}

/** Deterministically retain both address families while bounding paid active work. */
export function selectDeepTlsEndpoints(addresses: readonly string[]): string[] {
  const ipv4: string[] = [];
  const ipv6: string[] = [];
  for (const address of [...new Set(addresses)].sort()) {
    const calculation = calculateIpNetwork(address);
    (calculation.version === 4 ? ipv4 : ipv6).push(calculation.address);
  }

  const selected = [...ipv4.slice(0, 2), ...ipv6.slice(0, 2)];
  const remaining = [...ipv4.slice(2), ...ipv6.slice(2)];
  for (const address of remaining) {
    if (selected.length >= MAX_DEEP_TLS_ENDPOINTS) break;
    selected.push(address);
  }
  return selected;
}

export function sameAddressSet(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  const expected = new Set(left);
  return expected.size === right.length && right.every((address) => expected.has(address));
}

async function resolveWithFreshDnsClient(hostname: string): Promise<readonly string[]> {
  const dns = new DnsClient({ timeoutMs: DNS_VALIDATION_TIMEOUT_MS });
  try {
    const [ipv4, ipv6] = await Promise.all([
      dns.query(hostname, "A"),
      dns.query(hostname, "AAAA"),
    ]);
    return [...ipv4, ...ipv6].map((answer) => answer.data);
  } catch {
    throw new ScanTargetResolutionError("The target address could not be resolved safely.");
  }
}

function isTranslationOrTransitionAddress(address: string): boolean {
  const normalized = address.toLowerCase();
  return normalized.startsWith("64:ff9b:")
    || normalized.startsWith("64:ff9b:1:")
    || normalized.startsWith("2002:")
    || normalized.startsWith("2001:0:")
    || normalized.startsWith("2001::");
}

function withDeadline<T>(operation: Promise<T>, timeoutMs: number, timeoutError: Error): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => reject(timeoutError), timeoutMs);
  });
  return Promise.race([operation, deadline]).finally(() => {
    if (timeout !== undefined) clearTimeout(timeout);
  });
}
