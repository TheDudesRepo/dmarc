export type SpfQualifier = "+" | "-" | "~" | "?";

export interface SpfMechanism {
  raw: string;
  qualifier: SpfQualifier;
  name: string;
  domainSpec?: string;
  cidr4?: number;
  cidr6?: number;
  causesDnsLookup: boolean;
}

export interface ParsedSpfRecord {
  raw: string;
  valid: boolean;
  mechanisms: SpfMechanism[];
  modifiers: Record<string, string>;
  directLookupTerms: number;
  terminalAll?: SpfQualifier;
  errors: string[];
  warnings: string[];
}

export interface SpfLookupEstimate {
  count: number;
  exceedsLimit: boolean;
  truncated: boolean;
  expandedDomains: string[];
  issues: string[];
}

export type SpfTxtResolver = (domain: string) => Promise<string[]>;

const LOOKUP_MECHANISMS = new Set(["include", "a", "mx", "ptr", "exists"]);
const MAX_RECURSION_DEPTH = 12;
// Keep operational headroom for alias following and transient retries after
// the scanner's fixed DNS checks. Deeper paths are reported as lower bounds.
const MAX_EXPANDED_RECORDS = 5;

export function findSpfRecords(txtRecords: string[]): string[] {
  return txtRecords.filter((record) => /^\s*v=spf1(?:\s|$)/iu.test(record));
}

export function parseSpfRecord(raw: string): ParsedSpfRecord {
  const errors: string[] = [];
  const warnings: string[] = [];
  const mechanisms: SpfMechanism[] = [];
  const modifiers: Record<string, string> = {};
  const tokens = raw.trim().split(/\s+/u).filter(Boolean);

  if (raw.length > 8_192) errors.push("Record exceeds the scanner's safe parsing limit.");
  if (!tokens.length || tokens[0]?.toLowerCase() !== "v=spf1") {
    errors.push("SPF record must begin with v=spf1.");
  }

  for (const token of tokens.slice(1)) {
    const modifierMatch = /^([a-z][a-z0-9_.-]*)=(.+)$/iu.exec(token);
    if (modifierMatch) {
      const name = (modifierMatch[1] ?? "").toLowerCase();
      const value = modifierMatch[2] ?? "";
      if (Object.hasOwn(modifiers, name)) errors.push(`Duplicate ${name} modifier.`);
      else modifiers[name] = value;
      if (name === "redirect" && !isPlausibleDomainSpec(value)) errors.push("redirect has an invalid domain-spec.");
      else if (name === "exp" && !isPlausibleDomainSpec(value)) errors.push("exp has an invalid domain-spec.");
      else if (name !== "redirect" && name !== "exp") warnings.push(`Unknown ${name} modifier will normally be ignored by receivers.`);
      continue;
    }

    const parsed = parseMechanism(token);
    if (typeof parsed === "string") errors.push(parsed);
    else mechanisms.push(parsed);
  }

  const allIndex = mechanisms.findIndex((mechanism) => mechanism.name === "all");
  if (allIndex >= 0 && allIndex !== mechanisms.length - 1) {
    warnings.push("Mechanisms after all are unreachable and will not be evaluated.");
  }

  const terminalAll = allIndex >= 0 ? mechanisms[allIndex]?.qualifier : undefined;
  if (!terminalAll && !modifiers.redirect) {
    warnings.push("Record has neither an all mechanism nor a redirect modifier.");
  }
  if (terminalAll === "+") {
    warnings.push("+all authorizes every sender and defeats SPF's intended restriction.");
  }
  if (terminalAll && modifiers.redirect) {
    warnings.push("redirect is unreachable because the all mechanism always matches.");
  }
  if (mechanisms.some((mechanism) => mechanism.name === "ptr")) {
    warnings.push("The ptr mechanism is deprecated and can be slow or unreliable.");
  }

  const directLookupTerms = mechanisms
    .slice(0, allIndex >= 0 ? allIndex : undefined)
    .filter((mechanism) => mechanism.causesDnsLookup).length + (modifiers.redirect && allIndex < 0 ? 1 : 0);

  return {
    raw,
    valid: errors.length === 0,
    mechanisms,
    modifiers,
    directLookupTerms,
    ...(terminalAll ? { terminalAll } : {}),
    errors,
    warnings,
  };
}

export async function estimateSpfLookups(
  domain: string,
  record: ParsedSpfRecord,
  resolveTxt: SpfTxtResolver,
): Promise<SpfLookupEstimate> {
  let count = 0;
  let expandedRecordCount = 0;
  let truncated = false;
  const expandedDomains = new Set<string>();
  const issues = new Set<string>();

  const walk = async (currentDomain: string, current: ParsedSpfRecord, stack: string[], depth: number): Promise<void> => {
    if (depth > MAX_RECURSION_DEPTH) {
      truncated = true;
      issues.add("SPF recursion depth exceeded the scanner safety limit.");
      return;
    }

    const allIndex = current.mechanisms.findIndex((mechanism) => mechanism.name === "all");
    const evaluated = current.mechanisms.slice(0, allIndex >= 0 ? allIndex : undefined);

    for (const mechanism of evaluated) {
      if (!mechanism.causesDnsLookup) continue;
      count += 1;

      if (mechanism.name !== "include") continue;
      const target = normalizeLookupTarget(mechanism.domainSpec);
      if (!target) {
        if (mechanism.domainSpec?.includes("%{")) {
          issues.add(`Macro-based include in ${currentDomain} could not be expanded statically.`);
        } else {
          issues.add(`Invalid include target in ${currentDomain} was not expanded.`);
        }
        continue;
      }
      await expandTarget(target, stack, depth);
    }

    if (allIndex < 0 && current.modifiers.redirect) {
      count += 1;
      const target = normalizeLookupTarget(current.modifiers.redirect);
      if (!target) {
        issues.add(`Redirect in ${currentDomain} could not be expanded statically.`);
      } else {
        await expandTarget(target, stack, depth);
      }
    }
  };

  const expandTarget = async (target: string, stack: string[], depth: number): Promise<void> => {
    if (stack.includes(target)) {
      issues.add(`SPF include/redirect cycle detected at ${target}.`);
      return;
    }
    if (expandedRecordCount >= MAX_EXPANDED_RECORDS) {
      truncated = true;
      issues.add("SPF expansion stopped at the scanner's DNS safety limit.");
      return;
    }

    expandedRecordCount += 1;
    expandedDomains.add(target);

    let txtRecords: string[];
    try {
      txtRecords = await resolveTxt(target);
    } catch {
      issues.add(`Could not resolve the included SPF record at ${target}.`);
      return;
    }

    const spfRecords = findSpfRecords(txtRecords);
    if (spfRecords.length === 0) {
      issues.add(`No SPF record was found at included domain ${target}.`);
      return;
    }
    if (spfRecords.length > 1) {
      issues.add(`Included domain ${target} publishes multiple SPF records.`);
      return;
    }

    const parsed = parseSpfRecord(spfRecords[0] ?? "");
    if (!parsed.valid) {
      issues.add(`Included domain ${target} has an invalid SPF record.`);
      return;
    }
    await walk(target, parsed, [...stack, target], depth + 1);
  };

  await walk(domain, record, [domain], 0);

  return {
    count,
    exceedsLimit: count > 10,
    truncated,
    expandedDomains: [...expandedDomains].sort(),
    issues: [...issues],
  };
}

function parseMechanism(token: string): SpfMechanism | string {
  const qualifier = isQualifier(token[0]) ? token[0] : "+";
  const body = isQualifier(token[0]) ? token.slice(1) : token;
  const lowerBody = body.toLowerCase();

  if (lowerBody === "all") {
    return { raw: token, qualifier, name: "all", causesDnsLookup: false };
  }

  const namedMatch = /^(include|exists|ptr)(?::(.+))?$/iu.exec(body);
  if (namedMatch) {
    const name = (namedMatch[1] ?? "").toLowerCase();
    const domainSpec = namedMatch[2];
    if ((name === "include" || name === "exists") && !domainSpec) return `${name} requires a domain-spec.`;
    if (domainSpec && !isPlausibleDomainSpec(domainSpec)) return `${name} has an invalid domain-spec.`;
    return {
      raw: token,
      qualifier,
      name,
      ...(domainSpec ? { domainSpec } : {}),
      causesDnsLookup: LOOKUP_MECHANISMS.has(name),
    };
  }

  const hostMatch = /^(a|mx)(?::([^/]+))?(?:\/(\d{1,2}))?(?:\/\/(\d{1,3}))?$/iu.exec(body);
  if (hostMatch) {
    const name = (hostMatch[1] ?? "").toLowerCase();
    const domainSpec = hostMatch[2];
    const cidr4 = hostMatch[3] === undefined ? undefined : Number(hostMatch[3]);
    const cidr6 = hostMatch[4] === undefined ? undefined : Number(hostMatch[4]);
    if (domainSpec && !isPlausibleDomainSpec(domainSpec)) return `${name} has an invalid domain-spec.`;
    if (cidr4 !== undefined && cidr4 > 32) return `${name} has an IPv4 prefix longer than 32 bits.`;
    if (cidr6 !== undefined && cidr6 > 128) return `${name} has an IPv6 prefix longer than 128 bits.`;
    return {
      raw: token,
      qualifier,
      name,
      ...(domainSpec ? { domainSpec } : {}),
      ...(cidr4 === undefined ? {} : { cidr4 }),
      ...(cidr6 === undefined ? {} : { cidr6 }),
      causesDnsLookup: LOOKUP_MECHANISMS.has(name),
    };
  }

  const ip4Match = /^ip4:([^/]+)(?:\/(\d{1,2}))?$/iu.exec(body);
  if (ip4Match) {
    const address = ip4Match[1] ?? "";
    const cidr4 = ip4Match[2] === undefined ? undefined : Number(ip4Match[2]);
    if (!isIpv4(address)) return "ip4 contains an invalid IPv4 address.";
    if (cidr4 !== undefined && cidr4 > 32) return "ip4 prefix cannot exceed 32 bits.";
    return {
      raw: token,
      qualifier,
      name: "ip4",
      domainSpec: address,
      ...(cidr4 === undefined ? {} : { cidr4 }),
      causesDnsLookup: false,
    };
  }

  const ip6Match = /^ip6:(.+?)(?:\/(\d{1,3}))?$/iu.exec(body);
  if (ip6Match) {
    const address = ip6Match[1] ?? "";
    const cidr6 = ip6Match[2] === undefined ? undefined : Number(ip6Match[2]);
    if (!isIpv6(address)) return "ip6 contains an invalid IPv6 address.";
    if (cidr6 !== undefined && cidr6 > 128) return "ip6 prefix cannot exceed 128 bits.";
    return {
      raw: token,
      qualifier,
      name: "ip6",
      domainSpec: address,
      ...(cidr6 === undefined ? {} : { cidr6 }),
      causesDnsLookup: false,
    };
  }

  const mechanismName = /^([a-z0-9]+)/iu.exec(lowerBody)?.[1] ?? body;
  return `Unknown or malformed SPF mechanism: ${mechanismName}`;
}

function isQualifier(value: string | undefined): value is SpfQualifier {
  return value === "+" || value === "-" || value === "~" || value === "?";
}

function isPlausibleDomainSpec(value: string): boolean {
  if (!value || value.length > 253 || /[\s/@?#]/u.test(value)) return false;
  // SPF macros contain '%' and are evaluated by receivers. For static parsing,
  // retain them while refusing characters that can alter a URL or query.
  return /^[a-z0-9._%{}+\-=]+$/iu.test(value);
}

function normalizeLookupTarget(value: string | undefined): string | undefined {
  if (!value || value.includes("%{")) return undefined;
  const normalized = value.toLowerCase().replace(/\.$/u, "");
  if (!normalized || normalized.length > 253) return undefined;
  const labels = normalized.split(".");
  if (labels.length < 2) return undefined;
  if (labels.some((label) => !label || label.length > 63 || !/^[a-z0-9_-]+$/u.test(label))) return undefined;
  return normalized;
}

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/u.test(part) && Number(part) <= 255);
}

function isIpv6(value: string): boolean {
  if (!value.includes(":") || !/^[a-f0-9:.]+$/iu.test(value)) return false;
  try {
    const parsed = new URL(`http://[${value}]/`);
    return parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]");
  } catch {
    return false;
  }
}
