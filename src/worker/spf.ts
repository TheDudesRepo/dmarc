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

export interface SpfLookupEstimateOptions {
  timeoutMs?: number;
}

const LOOKUP_MECHANISMS = new Set(["include", "a", "mx", "ptr", "exists"]);
const MAX_RECURSION_DEPTH = 12;
// Keep operational headroom for alias following and transient retries after
// the scanner's fixed DNS checks. Deeper paths are reported as lower bounds.
const MAX_EXPANDED_RECORDS = 5;
const DEFAULT_ESTIMATE_TIMEOUT_MS = 8_000;
const ESTIMATE_DEADLINE = Symbol("SPF estimate deadline");

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
      else if (name !== "redirect" && name !== "exp") {
        if (!validateMacroString(value, false).valid) errors.push(`Unknown ${name} modifier has invalid macro syntax.`);
        warnings.push(`Unknown ${name} modifier will normally be ignored by receivers.`);
      }
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
  options: SpfLookupEstimateOptions = {},
): Promise<SpfLookupEstimate> {
  let count = 0;
  let expandedRecordCount = 0;
  let truncated = false;
  const expandedDomains = new Set<string>();
  const issues = new Set<string>();
  const requestedTimeout = options.timeoutMs ?? DEFAULT_ESTIMATE_TIMEOUT_MS;
  const timeoutMs = Number.isFinite(requestedTimeout) && requestedTimeout > 0
    ? Math.min(Math.floor(requestedTimeout), DEFAULT_ESTIMATE_TIMEOUT_MS)
    : DEFAULT_ESTIMATE_TIMEOUT_MS;
  const deadline = performance.now() + timeoutMs;

  const markDeadline = (): void => {
    truncated = true;
    issues.add("SPF expansion stopped at the scanner's overall analysis deadline; the lookup count is a lower bound.");
  };

  const deadlineReached = (): boolean => {
    if (performance.now() < deadline) return false;
    markDeadline();
    return true;
  };

  const walk = async (currentDomain: string, current: ParsedSpfRecord, stack: string[], depth: number): Promise<void> => {
    if (deadlineReached()) return;
    if (depth > MAX_RECURSION_DEPTH) {
      truncated = true;
      issues.add("SPF recursion depth exceeded the scanner safety limit.");
      return;
    }

    const allIndex = current.mechanisms.findIndex((mechanism) => mechanism.name === "all");
    const evaluated = current.mechanisms.slice(0, allIndex >= 0 ? allIndex : undefined);

    for (const mechanism of evaluated) {
      if (deadlineReached()) return;
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
    if (deadlineReached()) return;
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
      txtRecords = await resolveBeforeDeadline(target);
    } catch (error) {
      if (error === ESTIMATE_DEADLINE) {
        markDeadline();
        return;
      }
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

  const resolveBeforeDeadline = async (target: string): Promise<string[]> => {
    const remainingMs = deadline - performance.now();
    if (remainingMs <= 0) throw ESTIMATE_DEADLINE;

    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timeoutHandle = setTimeout(() => reject(ESTIMATE_DEADLINE), remainingMs);
    });
    try {
      return await Promise.race([resolveTxt(target), timeout]);
    } finally {
      if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
    }
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

  const hostNameMatch = /^(a|mx)(?=[:/]|$)/iu.exec(body);
  if (hostNameMatch) {
    const name = (hostNameMatch[1] ?? "").toLowerCase();
    const parsedHost = parseHostMechanismBody(body, name);
    if (typeof parsedHost === "string") return parsedHost;
    const { domainSpec, cidr4, cidr6 } = parsedHost;
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
  if (!value || value.length > 253 || /\s/u.test(value)) return false;
  const macroState = validateMacroString(value, true);
  if (!macroState.valid) return false;
  // A receiver supplies the message- and connection-dependent values. Once
  // the macro grammar is valid, keep the branch as statically incomplete.
  if (macroState.hasMacro) {
    if (macroState.endsWithMacro) return true;
    const finalLabel = /\.([a-z0-9-]+)\.?$/iu.exec(value)?.[1];
    return finalLabel !== undefined && isSpfTopLabel(finalLabel);
  }
  return normalizeStaticDomainSpec(value) !== undefined;
}

function validateMacroString(
  value: string,
  domainLiteralsOnly: boolean,
): { valid: boolean; hasMacro: boolean; endsWithMacro: boolean } {
  let hasMacro = false;
  let endsWithMacro = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index] ?? "";
    if (character !== "%") {
      const validLiteral = domainLiteralsOnly
        ? /[a-z0-9._-]/iu.test(character)
        : /^[\x21-\x24\x26-\x7e]$/u.test(character);
      if (!validLiteral) return { valid: false, hasMacro, endsWithMacro };
      endsWithMacro = false;
      continue;
    }

    hasMacro = true;
    const next = value[index + 1];
    if (next === "%" || next === "_" || next === "-") {
      endsWithMacro = true;
      index += 1;
      continue;
    }
    if (next !== "{") return { valid: false, hasMacro, endsWithMacro };

    const close = value.indexOf("}", index + 2);
    if (close < 0) return { valid: false, hasMacro, endsWithMacro };
    const expression = value.slice(index + 2, close);
    const match = /^([slodiphv])(\d*)(r?)([.\-+,/_=]*)$/iu.exec(expression);
    if (!match) return { valid: false, hasMacro, endsWithMacro };
    const transformerDigits = match[2] ?? "";
    if (transformerDigits && Number(transformerDigits) === 0) {
      return { valid: false, hasMacro, endsWithMacro };
    }
    endsWithMacro = true;
    index = close;
  }
  return { valid: true, hasMacro, endsWithMacro };
}

function normalizeLookupTarget(value: string | undefined): string | undefined {
  if (!value || value.includes("%{")) return undefined;
  return normalizeStaticDomainSpec(value);
}

function normalizeStaticDomainSpec(value: string): string | undefined {
  const normalized = value.toLowerCase().replace(/\.$/u, "");
  if (!normalized || normalized.length > 253) return undefined;
  const labels = normalized.split(".");
  if (labels.length < 2) return undefined;
  if (labels.some((label) => (
    !label
    || label.length > 63
    || !/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/iu.test(label)
  ))) return undefined;
  if (!isSpfTopLabel(labels.at(-1) ?? "")) return undefined;
  return normalized;
}

function isSpfTopLabel(label: string): boolean {
  if (!label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/iu.test(label)) return false;
  return /[a-z]/iu.test(label) || label.includes("-");
}

function parseHostMechanismBody(
  body: string,
  name: string,
): { domainSpec?: string; cidr4?: number; cidr6?: number } | string {
  const tail = body.slice(name.length);
  const slashIndexes: number[] = [];
  let inMacro = false;
  for (let index = 0; index < tail.length; index += 1) {
    if (!inMacro && tail[index] === "%" && tail[index + 1] === "{") {
      inMacro = true;
      index += 1;
      continue;
    }
    if (inMacro && tail[index] === "}") {
      inMacro = false;
      continue;
    }
    if (!inMacro && tail[index] === "/") slashIndexes.push(index);
  }

  let suffixStart = tail.length;
  let suffixMatch: RegExpExecArray | null = null;
  for (const index of slashIndexes) {
    const candidate = tail.slice(index);
    const match = /^(?:\/(\d{1,2}))?(?:\/\/(\d{1,3}))?$/u.exec(candidate);
    if (match && candidate) {
      suffixStart = index;
      suffixMatch = match;
      break;
    }
  }

  const ownerPart = tail.slice(0, suffixStart);
  if (slashIndexes.some((index) => index < suffixStart)) return `${name} has malformed CIDR syntax.`;
  let domainSpec: string | undefined;
  if (ownerPart) {
    if (!ownerPart.startsWith(":") || ownerPart.length === 1) return `${name} has a malformed domain-spec.`;
    domainSpec = ownerPart.slice(1);
  }
  const cidr4 = suffixMatch?.[1] === undefined ? undefined : Number(suffixMatch[1]);
  const cidr6 = suffixMatch?.[2] === undefined ? undefined : Number(suffixMatch[2]);
  return {
    ...(domainSpec ? { domainSpec } : {}),
    ...(cidr4 === undefined ? {} : { cidr4 }),
    ...(cidr6 === undefined ? {} : { cidr6 }),
  };
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
