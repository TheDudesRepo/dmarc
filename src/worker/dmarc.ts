export type DmarcPolicy = "none" | "quarantine" | "reject";

export interface ParsedDmarcRecord {
  raw: string;
  valid: boolean;
  tags: Record<string, string>;
  policy?: DmarcPolicy;
  subdomainPolicy?: DmarcPolicy;
  nonexistentSubdomainPolicy?: DmarcPolicy;
  testing: boolean;
  legacyPercentage?: number;
  errors: string[];
  warnings: string[];
}

const KNOWN_TAGS = new Set(["v", "p", "sp", "np", "psd", "t", "rua", "ruf", "adkim", "aspf", "fo"]);
const LEGACY_TAGS = new Set(["pct", "rf", "ri"]);
const POLICIES = new Set<DmarcPolicy>(["none", "quarantine", "reject"]);

export function findDmarcRecords(txtRecords: string[]): string[] {
  return txtRecords.filter((record) => /^\s*v\s*=\s*dmarc1(?:\s*;|\s*$)/iu.test(record));
}

export function parseDmarcRecord(raw: string): ParsedDmarcRecord {
  const errors: string[] = [];
  const warnings: string[] = [];
  const tags: Record<string, string> = {};

  if (raw.length > 8_192) {
    errors.push("Record exceeds the scanner's safe parsing limit.");
  }

  const segments = raw
    .split(";")
    .map((segment) => segment.trim())
    .filter(Boolean);

  for (const segment of segments) {
    const separator = segment.indexOf("=");
    if (separator <= 0) {
      errors.push(`Tag is missing an equals sign: ${segment.slice(0, 40)}`);
      continue;
    }

    const name = segment.slice(0, separator).trim().toLowerCase();
    const value = segment.slice(separator + 1).trim();
    if (!/^[a-z]+$/u.test(name) || !value) {
      errors.push(`Malformed DMARC tag: ${segment.slice(0, 40)}`);
      continue;
    }
    if (Object.hasOwn(tags, name)) {
      errors.push(`Duplicate ${name} tag.`);
      continue;
    }
    tags[name] = value;
    if (LEGACY_TAGS.has(name)) warnings.push(`${name} is a historic tag removed by RFC 9989 and is ignored by current DMARC processing.`);
    else if (!KNOWN_TAGS.has(name)) warnings.push(`Unrecognized ${name} tag is ignored by DMARC receivers.`);
  }

  const firstTagName = segments[0]?.split("=", 1)[0]?.trim().toLowerCase();
  if (firstTagName !== "v") errors.push("The v=DMARC1 tag must be first.");
  if (tags.v !== "DMARC1") errors.push("Version must be exactly v=DMARC1.");

  const normalizedPolicy = tags.p?.toLowerCase();
  const policy = tags.p ? (isDmarcPolicy(normalizedPolicy) ? normalizedPolicy : undefined) : "none";
  if (tags.p && !policy) errors.push("Policy must be none, quarantine, or reject.");
  if (!tags.p) warnings.push("No p tag is present; RFC 9989 uses p=none as the policy default in applicable records.");

  const normalizedSubdomainPolicy = tags.sp?.toLowerCase();
  const subdomainPolicy = isDmarcPolicy(normalizedSubdomainPolicy) ? normalizedSubdomainPolicy : undefined;
  if (tags.sp && !subdomainPolicy) errors.push("Subdomain policy must be none, quarantine, or reject.");

  const normalizedNonexistentPolicy = tags.np?.toLowerCase();
  const nonexistentSubdomainPolicy = isDmarcPolicy(normalizedNonexistentPolicy) ? normalizedNonexistentPolicy : undefined;
  if (tags.np && !nonexistentSubdomainPolicy) errors.push("Non-existent subdomain policy must be none, quarantine, or reject.");

  const testing = tags.t?.toLowerCase() === "y";
  if (tags.t && !/^[yn]$/iu.test(tags.t)) errors.push("t must be y or n.");
  if (tags.psd && !/^[ynu]$/iu.test(tags.psd)) errors.push("psd must be y, n, or u.");

  const legacyPercentage = tags.pct !== undefined && /^\d{1,3}$/u.test(tags.pct) && Number(tags.pct) <= 100
    ? Number(tags.pct)
    : undefined;

  for (const alignmentTag of ["adkim", "aspf"] as const) {
    if (tags[alignmentTag] && !/^[rs]$/iu.test(tags[alignmentTag])) {
      errors.push(`${alignmentTag} must be r or s.`);
    }
  }

  for (const reportTag of ["rua", "ruf"] as const) {
    if (!tags[reportTag]) continue;
    const destinations = tags[reportTag].split(",").map((destination) => destination.trim());
    if (destinations.some((destination) => !isDmarcReportUri(destination))) {
      errors.push(`${reportTag} contains an invalid reporting URI.`);
    }
  }

  if (tags.fo) {
    const options = tags.fo.toLowerCase().split(":");
    const hasDuplicates = new Set(options).size !== options.length;
    if (options.some((option) => !["0", "1", "d", "s"].includes(option)) || hasDuplicates) {
      errors.push("fo contains an unsupported failure-report option.");
    }
    if (options.includes("0") && options.includes("1")) errors.push("fo cannot contain both 0 and 1.");
  }

  if (policy === "none") {
    warnings.push("p=none requests monitoring but does not ask receivers to quarantine or reject failing mail.");
  }
  if (testing && (policy === "quarantine" || policy === "reject")) {
    warnings.push(`t=y requests testing behavior one policy level below p=${policy}.`);
  }
  if (!tags.rua) {
    warnings.push("No aggregate report destination (rua) is published.");
  }

  return {
    raw,
    valid: errors.length === 0,
    tags,
    ...(policy ? { policy } : {}),
    ...(subdomainPolicy ? { subdomainPolicy } : {}),
    ...(nonexistentSubdomainPolicy ? { nonexistentSubdomainPolicy } : {}),
    testing,
    ...(legacyPercentage === undefined ? {} : { legacyPercentage }),
    errors,
    warnings,
  };
}

function isDmarcPolicy(value: string | undefined): value is DmarcPolicy {
  return value !== undefined && POLICIES.has(value as DmarcPolicy);
}

function isDmarcReportUri(value: string): boolean {
  if (!value || /\s/u.test(value)) return false;
  const withoutObsoleteSize = value.replace(/!\d+(?:[kmgt])?$/iu, "");
  try {
    const uri = new URL(withoutObsoleteSize);
    return Boolean(uri.protocol && withoutObsoleteSize.includes(":"));
  } catch {
    return false;
  }
}
