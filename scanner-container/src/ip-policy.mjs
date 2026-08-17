import { isIP } from "node:net";

const IPV4_WIDTH = 32;
const IPV6_WIDTH = 128;

export class AddressPolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = "AddressPolicyError";
  }
}

/**
 * Independently validates the Worker-provided literal. DNS names, zones,
 * private/special-use space, transition mechanisms, and NAT64 are rejected.
 */
export function assertPublicAddress(input) {
  if (typeof input !== "string" || input.length === 0 || input.length > 64 || input !== input.trim()) {
    throw new AddressPolicyError("address must be one canonical IP literal");
  }
  const family = isIP(input);
  if (family === 4) {
    const value = parseIpv4(input);
    if (!isGlobalIpv4(value)) throw new AddressPolicyError("address is not globally routable IPv4");
    return { address: input, family: 4, value };
  }
  if (family === 6) {
    if (input.includes("%")) throw new AddressPolicyError("IPv6 zone identifiers are not allowed");
    const value = parseIpv6(input);
    if (!isGlobalIpv6(value) || isTransitionIpv6(value)) {
      throw new AddressPolicyError("address is not globally routable native IPv6");
    }
    return { address: input.toLowerCase(), family: 6, value };
  }
  throw new AddressPolicyError("address must be an IPv4 or IPv6 literal");
}

function isGlobalIpv4(value) {
  if (inPrefix(value, ipv4Number("10.0.0.0"), 8, IPV4_WIDTH)
    || inPrefix(value, ipv4Number("172.16.0.0"), 12, IPV4_WIDTH)
    || inPrefix(value, ipv4Number("192.168.0.0"), 16, IPV4_WIDTH)
    || inPrefix(value, ipv4Number("127.0.0.0"), 8, IPV4_WIDTH)
    || inPrefix(value, ipv4Number("169.254.0.0"), 16, IPV4_WIDTH)
    || inPrefix(value, ipv4Number("224.0.0.0"), 4, IPV4_WIDTH)
    || inPrefix(value, ipv4Number("192.0.2.0"), 24, IPV4_WIDTH)
    || inPrefix(value, ipv4Number("198.51.100.0"), 24, IPV4_WIDTH)
    || inPrefix(value, ipv4Number("203.0.113.0"), 24, IPV4_WIDTH)
    || inPrefix(value, 0n, 8, IPV4_WIDTH)
    || inPrefix(value, ipv4Number("100.64.0.0"), 10, IPV4_WIDTH)
    || inPrefix(value, ipv4Number("192.88.99.0"), 24, IPV4_WIDTH)
    || inPrefix(value, ipv4Number("198.18.0.0"), 15, IPV4_WIDTH)
    || inPrefix(value, ipv4Number("240.0.0.0"), 4, IPV4_WIDTH)) return false;

  if (inPrefix(value, ipv4Number("192.0.0.0"), 24, IPV4_WIDTH)) {
    return value === ipv4Number("192.0.0.9") || value === ipv4Number("192.0.0.10");
  }
  return true;
}

function isGlobalIpv6(value) {
  if (inPrefix(value, 0xfcn << 120n, 7, IPV6_WIDTH)
    || value === 0n
    || value === 1n
    || inPrefix(value, 0xfe80n << 112n, 10, IPV6_WIDTH)
    || inPrefix(value, 0xffn << 120n, 8, IPV6_WIDTH)
    || inPrefix(value, 0x20010db8n << 96n, 32, IPV6_WIDTH)
    || inPrefix(value, 0x3fff0n << 108n, 20, IPV6_WIDTH)) return false;

  // Globally reachable exceptions in IANA special-purpose space.
  if (inPrefix(value, 0x0064ff9bn << 96n, 96, IPV6_WIDTH)
    || value === ((0x20010001n << 96n) | 1n)
    || value === ((0x20010001n << 96n) | 2n)
    || value === ((0x20010001n << 96n) | 3n)
    || inPrefix(value, 0x20010003n << 96n, 32, IPV6_WIDTH)
    || inPrefix(value, 0x200100040112n << 80n, 48, IPV6_WIDTH)
    || inPrefix(value, 0x20010020n << 96n, 28, IPV6_WIDTH)
    || inPrefix(value, 0x20010030n << 96n, 28, IPV6_WIDTH)) return true;

  const globalUnicast = inPrefix(value, 0x2n << 124n, 3, IPV6_WIDTH);
  const protocolAssignments = inPrefix(value, 0x200100n << 104n, 23, IPV6_WIDTH);
  return globalUnicast && !protocolAssignments;
}

function isTransitionIpv6(value) {
  return inPrefix(value, 0x0064ff9bn << 96n, 96, IPV6_WIDTH) // NAT64
    || inPrefix(value, 0x2002n << 112n, 16, IPV6_WIDTH) // 6to4
    || inPrefix(value, 0x20010000n << 96n, 32, IPV6_WIDTH) // Teredo
    || inPrefix(value, 0n, 96, IPV6_WIDTH) // IPv4-compatible/mapped
    || inPrefix(value, 0xffffn << 32n, 96, IPV6_WIDTH);
}

function parseIpv4(input) {
  const parts = input.split(".");
  if (parts.length !== 4) throw new AddressPolicyError("invalid IPv4 literal");
  let value = 0n;
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/u.test(part) || Number(part) > 255) {
      throw new AddressPolicyError("invalid IPv4 literal");
    }
    value = (value << 8n) | BigInt(part);
  }
  return value;
}

function parseIpv6(input) {
  let value = input.toLowerCase();
  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    const ipv4 = parseIpv4(value.slice(lastColon + 1));
    value = `${value.slice(0, lastColon)}:${((ipv4 >> 16n) & 0xffffn).toString(16)}:${(ipv4 & 0xffffn).toString(16)}`;
  }
  const pieces = value.split("::");
  if (pieces.length > 2) throw new AddressPolicyError("invalid IPv6 literal");
  const left = pieces[0] ? pieces[0].split(":") : [];
  const right = pieces.length === 2 && pieces[1] ? pieces[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((pieces.length === 1 && missing !== 0) || (pieces.length === 2 && missing < 1)) {
    throw new AddressPolicyError("invalid IPv6 literal");
  }
  const groups = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  if (groups.length !== 8) throw new AddressPolicyError("invalid IPv6 literal");
  let result = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/u.test(group)) throw new AddressPolicyError("invalid IPv6 literal");
    result = (result << 16n) | BigInt(`0x${group}`);
  }
  return result;
}

function ipv4Number(input) {
  return input.split(".").reduce((result, octet) => (result << 8n) | BigInt(octet), 0n);
}

function inPrefix(value, base, prefix, width) {
  if (prefix === 0) return true;
  const shift = BigInt(width - prefix);
  return value >> shift === base >> shift;
}
