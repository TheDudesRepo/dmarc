const MAX_INPUT_LENGTH = 512;
const MAX_DOMAIN_LENGTH = 253;
const NON_PUBLIC_SUFFIXES = ["local", "localhost", "internal", "invalid", "test", "home", "lan", "localdomain", "onion"];

export class DomainValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DomainValidationError";
  }
}

/**
 * Normalizes a user-supplied hostname without ever turning it into a fetch URL.
 * The scanner only accepts DNS hostnames (not URLs, email addresses, ports, IPs,
 * wildcards, or internal single-label names).
 */
export function normalizeDomain(input: unknown): string {
  if (typeof input !== "string") {
    throw new DomainValidationError("Domain must be a string.");
  }

  const trimmed = input.trim();
  if (!trimmed) {
    throw new DomainValidationError("Enter a domain to scan.");
  }
  if (trimmed.length > MAX_INPUT_LENGTH) {
    throw new DomainValidationError("Domain is too long.");
  }
  if (/\s/u.test(trimmed)) {
    throw new DomainValidationError("Domain cannot contain whitespace.");
  }
  if (/[\\/@:?#%*]/u.test(trimmed)) {
    throw new DomainValidationError("Enter a hostname only, without a URL, path, port, email address, or wildcard.");
  }
  if (!/^[\p{L}\p{N}\p{M}.-]+$/u.test(trimmed)) {
    throw new DomainValidationError("Domain contains unsupported characters.");
  }
  if (trimmed.endsWith("..")) {
    throw new DomainValidationError("Domain has an invalid trailing dot.");
  }

  const withoutTrailingDot = trimmed.endsWith(".") ? trimmed.slice(0, -1) : trimmed;
  let ascii: string;

  try {
    // URL applies the platform's IDNA conversion. The input is already limited
    // to hostname characters, so no URL component can be smuggled in here.
    ascii = new URL(`https://${withoutTrailingDot}`).hostname.toLowerCase();
  } catch {
    throw new DomainValidationError("Domain is not a valid DNS hostname.");
  }

  if (!ascii || ascii.length > MAX_DOMAIN_LENGTH) {
    throw new DomainValidationError("Domain must be 253 characters or fewer.");
  }

  const labels = ascii.split(".");
  if (labels.length < 2) {
    throw new DomainValidationError("Enter a public domain with at least two labels.");
  }

  for (const label of labels) {
    if (!label || label.length > 63) {
      throw new DomainValidationError("Each domain label must be between 1 and 63 characters.");
    }
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)) {
      throw new DomainValidationError("Domain labels cannot begin or end with a hyphen or contain underscores.");
    }
  }

  const topLevelLabel = labels.at(-1) ?? "";
  if (!/[a-z]/u.test(topLevelLabel)) {
    throw new DomainValidationError("The top-level domain must contain a letter.");
  }
  if (isIpv4Literal(ascii)) {
    throw new DomainValidationError("IP addresses cannot be scanned as domains.");
  }
  if (NON_PUBLIC_SUFFIXES.includes(topLevelLabel)) {
    throw new DomainValidationError("Enter a domain published in the public DNS.");
  }

  return ascii;
}

function isIpv4Literal(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/u.test(part) && Number(part) <= 255);
}
