import { describe, expect, it } from "vitest";
import type { DnsAnswer, DnsQueryType } from "./dns";
import {
  buildCymruOriginOwner,
  buildPtrOwner,
  calculateIpNetwork,
  inspectIpNetwork,
  IpToolsValidationError,
  parseCymruAsNameTxt,
  parseCymruOriginTxt,
  TEAM_CYMRU_ATTRIBUTION,
  type IpToolsDnsClient,
} from "./ip-tools";

class FakeDnsClient implements IpToolsDnsClient {
  readonly calls: Array<{ name: string; type: DnsQueryType }> = [];

  constructor(
    private readonly records: Readonly<Record<string, DnsAnswer[]>> = {},
    private readonly failures = new Set<string>(),
  ) {}

  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    this.calls.push({ name, type });
    const key = `${type}:${name}`;
    if (this.failures.has(key)) return Promise.reject(new Error("resolver unavailable"));
    return Promise.resolve(this.records[key] ?? []);
  }
}

describe("deterministic IPv4 subnet calculation", () => {
  it("calculates and canonicalizes /0 without number precision loss", () => {
    const result = calculateIpNetwork("203.0.113.9/0");

    expect(result).toEqual(expect.objectContaining({
      address: "203.0.113.9",
      canonical: "203.0.113.9/0",
      cidr: "203.0.113.9/0",
      version: 4,
      prefix: 0,
      network: "0.0.0.0",
      networkCidr: "0.0.0.0/0",
      lastAddress: "255.255.255.255",
      totalAddresses: "4294967296",
      isSingleAddress: false,
      ipv4: {
        netmask: "0.0.0.0",
        wildcard: "255.255.255.255",
        broadcast: "255.255.255.255",
      },
      usable: {
        first: "0.0.0.1",
        last: "255.255.255.254",
        count: "4294967294",
        convention: "ipv4-traditional",
      },
    }));
  });

  it("accepts a contiguous dotted /24 netmask and emits canonical CIDR", () => {
    const result = calculateIpNetwork("192.168.7.42/255.255.255.0");

    expect(result.canonical).toBe("192.168.7.42/24");
    expect(result.network).toBe("192.168.7.0");
    expect(result.lastAddress).toBe("192.168.7.255");
    expect(result.totalAddresses).toBe("256");
    expect(result.ipv4).toEqual({
      netmask: "255.255.255.0",
      wildcard: "0.0.0.255",
      broadcast: "192.168.7.255",
    });
    expect(result.usable).toEqual({
      first: "192.168.7.1",
      last: "192.168.7.254",
      count: "254",
      convention: "ipv4-traditional",
    });
  });

  it("uses RFC 3021 point-to-point semantics for /31", () => {
    const result = calculateIpNetwork("198.51.100.11/31");

    expect(result.network).toBe("198.51.100.10");
    expect(result.lastAddress).toBe("198.51.100.11");
    expect(result.totalAddresses).toBe("2");
    expect(result.usable).toEqual({
      first: "198.51.100.10",
      last: "198.51.100.11",
      count: "2",
      convention: "ipv4-point-to-point",
    });
  });

  it("treats a bare IPv4 address as a canonical /32 host", () => {
    const result = calculateIpNetwork("8.8.4.4");

    expect(result.canonical).toBe("8.8.4.4/32");
    expect(result.network).toBe("8.8.4.4");
    expect(result.lastAddress).toBe("8.8.4.4");
    expect(result.totalAddresses).toBe("1");
    expect(result.isSingleAddress).toBe(true);
    expect(result.usable).toEqual({
      first: "8.8.4.4",
      last: "8.8.4.4",
      count: "1",
      convention: "ipv4-host",
    });
  });

  it("accepts the boundary dotted netmasks", () => {
    expect(calculateIpNetwork("203.0.113.9/0.0.0.0").prefix).toBe(0);
    expect(calculateIpNetwork("203.0.113.9/255.255.255.255").prefix).toBe(32);
  });
});

describe("deterministic IPv6 subnet calculation", () => {
  it("canonicalizes compression and calculates /64 boundaries", () => {
    const result = calculateIpNetwork("2001:0DB8:0000:0000:0000:ff00:0042:8329/64");

    expect(result.address).toBe("2001:db8::ff00:42:8329");
    expect(result.canonical).toBe("2001:db8::ff00:42:8329/64");
    expect(result.network).toBe("2001:db8::");
    expect(result.lastAddress).toBe("2001:db8::ffff:ffff:ffff:ffff");
    expect(result.totalAddresses).toBe("18446744073709551616");
    expect(result.ipv4).toBeUndefined();
    expect(result.usable).toEqual({
      first: "2001:db8::",
      last: "2001:db8::ffff:ffff:ffff:ffff",
      count: "18446744073709551616",
      convention: "ipv6-addresses",
    });
  });

  it("calculates /0 using decimal strings for 128-bit counts", () => {
    const result = calculateIpNetwork("2001:4860::8888/0");

    expect(result.network).toBe("::");
    expect(result.lastAddress).toBe("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    expect(result.totalAddresses).toBe("340282366920938463463374607431768211456");
  });

  it("covers /127 point-to-point pairs and /128 hosts", () => {
    const pair = calculateIpNetwork("2001:4860::1/127");
    const host = calculateIpNetwork("2001:4860:4860::8888/128");

    expect(pair).toEqual(expect.objectContaining({
      network: "2001:4860::",
      lastAddress: "2001:4860::1",
      totalAddresses: "2",
      usable: {
        first: "2001:4860::",
        last: "2001:4860::1",
        count: "2",
        convention: "ipv6-addresses",
      },
    }));
    expect(host.network).toBe("2001:4860:4860::8888");
    expect(host.totalAddresses).toBe("1");
    expect(host.isSingleAddress).toBe(true);
  });

  it("uses the first longest zero run in canonical formatting", () => {
    expect(calculateIpNetwork("2001:0:0:1:0:0:1:1").address).toBe("2001::1:0:0:1:1");
  });

  it("accepts and canonicalizes a final embedded IPv4 address", () => {
    expect(calculateIpNetwork("::ffff:192.0.2.1").canonical).toBe("::ffff:c000:201/128");
  });
});

describe("special-use classification", () => {
  it.each([
    ["10.1.2.3", "private"],
    ["127.9.8.7", "loopback"],
    ["169.254.1.1", "link-local"],
    ["224.0.0.1", "multicast"],
    ["192.0.2.5", "documentation"],
    ["100.64.0.1", "reserved"],
    ["8.8.8.8", "global"],
    ["fc00::1", "private"],
    ["::1", "loopback"],
    ["fe80::1", "link-local"],
    ["ff02::1", "multicast"],
    ["2001:db8::1", "documentation"],
    ["::", "reserved"],
    ["2001:4860:4860::8888", "global"],
    ["192.0.0.9", "global"],
    ["192.0.0.10", "global"],
    ["64:ff9b::808:808", "global"],
    ["2001:1::3", "global"],
    ["2001:3::1", "global"],
    ["2001:4:112::1", "global"],
    ["2001:20::1", "global"],
    ["2001:30::1", "global"],
  ] as const)("classifies %s as %s", (input, expected) => {
    const classification = calculateIpNetwork(input).classification;
    expect(classification.kind).toBe(expected);
    expect(classification[expected === "link-local" ? "linkLocal" : expected]).toBe(true);
    expect(Object.values(classification).filter((value) => value === true)).toHaveLength(1);
  });
});

describe("strict input validation", () => {
  it.each([
    "example.com",
    "https://192.0.2.1",
    "192.0.2.1-10",
    "192.0.2.1,192.0.2.2",
    "192.0.2.1 255.255.255.0",
    "192.0.2.1/33",
    "192.0.2.1/01",
    "192.0.2.1/24/1",
    "192.0.2.256",
    "192.000.2.1",
    "192.0.2.1/255.0.255.0",
    "192.0.2.1/255.255.255.1",
    "[2001:db8::1]",
    "fe80::1%eth0",
    "2001:db8::1/129",
    "2001:db8::1/255.255.255.0",
    "2001::db8::1",
    "2001:db8:0:0:0:0:0",
    "1:2:3:4:5:6:7:8::",
    "1".repeat(129),
  ])("rejects unsafe or malformed input %s", (input) => {
    expect(() => calculateIpNetwork(input)).toThrow(IpToolsValidationError);
  });

  it("rejects non-string and empty input", () => {
    expect(() => calculateIpNetwork(undefined)).toThrow(/must be a string/u);
    expect(() => calculateIpNetwork("  ")).toThrow(/Enter an IP/u);
  });
});

describe("bounded native DNS enrichment", () => {
  it("builds exact IPv4 and IPv6 PTR and Team Cymru owners", () => {
    const reversedV6 = ["1", ...Array.from({ length: 23 }, () => "0"), "8", "b", "d", "0", "1", "0", "0", "2"].join(".");

    expect(buildPtrOwner("192.0.2.45")).toBe("45.2.0.192.in-addr.arpa");
    expect(buildCymruOriginOwner("192.0.2.45")).toBe("45.2.0.192.origin.asn.cymru.com");
    expect(buildPtrOwner("2001:db8::1")).toBe(`${reversedV6}.ip6.arpa`);
    expect(buildCymruOriginOwner("2001:db8::1")).toBe(`${reversedV6}.origin6.asn.cymru.com`);
  });

  it("parses Team Cymru origin and optional AS-name TXT defensively", () => {
    expect(parseCymruOriginTxt('"15169 | 8.8.4.0/24 | us | ARIN | 1992-12-01"', 4)).toEqual({
      asn: "15169",
      asns: ["15169"],
      prefix: "8.8.4.0/24",
      country: "US",
      registry: "arin",
      allocated: "1992-12-01",
    });
    expect(parseCymruAsNameTxt("15169 | US | arin | 2000-03-30 | GOOGLE, US", "15169")).toBe(
      "GOOGLE, US",
    );
    expect(parseCymruOriginTxt("15169 3356 | 8.8.4.0/24 | US | arin | 1992-12-01", 4).asns)
      .toEqual(["3356", "15169"]);
    expect(() => parseCymruOriginTxt("not a Cymru row", 4)).toThrow(/malformed/u);
    expect(() => parseCymruOriginTxt("4294967296 | 8.8.4.0/24 | US | arin | 1992-12-01", 4))
      .toThrow(/malformed/u);
    expect(() => parseCymruOriginTxt("15169 | 8.8.4.0/24 | US | arin | 1992-02-31", 4))
      .toThrow(/malformed/u);
    expect(() => parseCymruOriginTxt("15169 | 8.8.4.4/24 | US | arin | 1992-12-01", 4))
      .toThrow(/malformed/u);
    expect(() => parseCymruOriginTxt("15169 | 8.8.4.0/255.255.255.0 | US | arin | 1992-12-01", 4))
      .toThrow(/malformed/u);
    expect(() => parseCymruOriginTxt("Aſ15169 | 8.8.4.0/24 | US | arin | 1992-12-01", 4))
      .toThrow(/malformed/u);
    expect(() => parseCymruOriginTxt("15169 | 8.8.4.0/24 | ß | arin | 1992-12-01", 4))
      .toThrow(/malformed/u);
    expect(() => parseCymruAsNameTxt("13335 | US | arin | 2010-07-14 | CLOUDFLARENET", "15169"))
      .toThrow(/malformed/u);
  });

  it("preserves valid multi-origin rows and multiple origin TXT records", async () => {
    const owner = "4.4.8.8.origin.asn.cymru.com";
    const dnsClient = new FakeDnsClient({
      [`TXT:${owner}`]: [
        answer(owner, "TXT", "15169 3356 | 8.8.4.0/24 | US | arin | 1992-12-01"),
        answer(owner, "TXT", "15169 | 8.8.0.0/16 | US | arin | 1992-12-01"),
      ],
    });

    const result = await inspectIpNetwork("8.8.4.4", { enrich: true, dnsClient });

    expect(result.enrichment.origin.status).toBe("found");
    expect(result.enrichment.origin.record?.asns).toEqual(["3356", "15169"]);
    expect(result.enrichment.origin.records).toHaveLength(2);
    expect(result.enrichment.queryCount).toBe(2);
  });

  it("caps AS-name evidence while preserving truthful multi-origin truncation", async () => {
    const owner = "4.4.8.8.origin.asn.cymru.com";
    const firstAsns = Array.from({ length: 16 }, (_value, index) => String(10_000 + index));
    const dnsClient = new FakeDnsClient({
      [`TXT:${owner}`]: [
        answer(owner, "TXT", `${firstAsns.join(" ")} | 8.8.4.0/24 | US | arin | 1992-12-01`),
        answer(owner, "TXT", "20000 | 8.8.0.0/16 | US | arin | 1992-12-01"),
      ],
    });

    const result = await inspectIpNetwork("8.8.4.4", {
      enrich: true,
      includeAsName: true,
      dnsClient,
    });

    expect(result.enrichment.origin.records).toHaveLength(2);
    expect(result.enrichment.asNames).toHaveLength(16);
    expect(result.enrichment.asNamesTruncated).toBe(true);
    expect(result.enrichment.queryCount).toBe(4);
  });

  it("enriches only one global address and includes explicit attribution", async () => {
    const ptrOwner = "4.4.8.8.in-addr.arpa";
    const originOwner = "4.4.8.8.origin.asn.cymru.com";
    const asNameOwner = "as15169.asn.cymru.com";
    const dnsClient = new FakeDnsClient({
      [`PTR:${ptrOwner}`]: [answer(ptrOwner, "PTR", "dns.google.")],
      [`TXT:${originOwner}`]: [answer(originOwner, "TXT", "15169 | 8.8.4.0/24 | US | arin | 1992-12-01")],
      [`TXT:${asNameOwner}`]: [answer(asNameOwner, "TXT", "15169 | US | arin | 2000-03-30 | GOOGLE, US")],
    });

    const result = await inspectIpNetwork("8.8.4.4/32", {
      enrich: true,
      includeAsName: true,
      dnsClient,
    });

    expect(result.enrichment).toEqual(expect.objectContaining({
      status: "complete",
      queryCount: 3,
      ptr: { status: "found", owner: ptrOwner, names: ["dns.google"] },
      origin: expect.objectContaining({
        status: "found",
        owner: originOwner,
        record: {
          asn: "15169",
          asns: ["15169"],
          prefix: "8.8.4.0/24",
          country: "US",
          registry: "arin",
          allocated: "1992-12-01",
        },
      }),
      asName: { status: "found", asn: "15169", owner: asNameOwner, name: "GOOGLE, US" },
      asNames: [{ status: "found", asn: "15169", owner: asNameOwner, name: "GOOGLE, US" }],
      attribution: {
        ptr: "Native DNS PTR",
        asn: TEAM_CYMRU_ATTRIBUTION,
      },
    }));
    expect(dnsClient.calls).toHaveLength(3);
    expect(dnsClient.calls.length).toBeLessThanOrEqual(4);
  });

  it("does not spend an AS-name query unless explicitly requested", async () => {
    const dnsClient = new FakeDnsClient({
      "TXT:4.4.8.8.origin.asn.cymru.com": [
        answer("4.4.8.8.origin.asn.cymru.com", "TXT", "15169 | 8.8.4.0/24 | US | arin | 1992-12-01"),
      ],
    });

    const result = await inspectIpNetwork("8.8.4.4", { enrich: true, dnsClient });

    expect(result.enrichment.queryCount).toBe(2);
    expect(result.enrichment.asName).toBeUndefined();
    expect(dnsClient.calls).toHaveLength(2);
  });

  it("caps multi-origin AS-name enrichment at four total logical queries", async () => {
    const originOwner = "4.4.8.8.origin.asn.cymru.com";
    const dnsClient = new FakeDnsClient({
      [`TXT:${originOwner}`]: [
        answer(originOwner, "TXT", "4 3 2 1 | 8.8.4.0/24 | US | arin | 1992-12-01"),
      ],
      "TXT:as1.asn.cymru.com": [
        answer("as1.asn.cymru.com", "TXT", "1 | US | arin | 1991-01-01 | AS-ONE, US"),
      ],
      "TXT:as2.asn.cymru.com": [
        answer("as2.asn.cymru.com", "TXT", "2 | US | arin | 1991-01-02 | AS-TWO, US"),
      ],
    });

    const result = await inspectIpNetwork("8.8.4.4", {
      enrich: true,
      includeAsName: true,
      dnsClient,
    });

    expect(result.enrichment.queryCount).toBe(4);
    expect(result.enrichment.asNames).toEqual([
      { status: "found", asn: "1", owner: "as1.asn.cymru.com", name: "AS-ONE, US" },
      { status: "found", asn: "2", owner: "as2.asn.cymru.com", name: "AS-TWO, US" },
      { status: "not-requested", asn: "3", owner: "as3.asn.cymru.com" },
      { status: "not-requested", asn: "4", owner: "as4.asn.cymru.com" },
    ]);
    expect(result.enrichment.asNamesTruncated).toBe(true);
    expect(result.enrichment.status).toBe("complete");
    expect(result.enrichment.reason).toContain("capped at two");
    expect(dnsClient.calls).toHaveLength(4);
  });

  it("accepts PTR answers at the canonical owner after a reverse-DNS CNAME", async () => {
    const ptrOwner = "4.4.8.8.in-addr.arpa";
    const canonicalOwner = "4.4.8.8.rev.example";
    const originOwner = "4.4.8.8.origin.asn.cymru.com";
    const calls: Array<{ name: string; type: DnsQueryType }> = [];
    const dnsClient: IpToolsDnsClient = {
      query(name, type) {
        calls.push({ name, type });
        return Promise.resolve(name === originOwner
          ? [answer(originOwner, "TXT", "15169 | 8.8.4.0/24 | US | arin | 1992-12-01")]
          : []);
      },
      queryFollowingCname(name, type) {
        calls.push({ name, type });
        return Promise.resolve({
          answers: [answer(canonicalOwner, "PTR", "dns.google")],
          canonicalName: canonicalOwner,
          aliases: [answer(ptrOwner, "CNAME", canonicalOwner)],
        });
      },
    };

    const result = await inspectIpNetwork("8.8.4.4", { enrich: true, dnsClient });

    expect(result.enrichment.ptr).toEqual({
      status: "found",
      owner: ptrOwner,
      canonicalOwner,
      names: ["dns.google"],
    });
    expect(result.enrichment.queryCount).toBe(2);
    expect(calls).toHaveLength(2);
  });

  it("keeps resolver and malformed-response failures indeterminate without failing calculation", async () => {
    const ptrOwner = "4.4.8.8.in-addr.arpa";
    const originOwner = "4.4.8.8.origin.asn.cymru.com";
    const dnsClient = new FakeDnsClient(
      { [`TXT:${originOwner}`]: [answer(originOwner, "TXT", "malformed")] },
      new Set([`PTR:${ptrOwner}`]),
    );

    const result = await inspectIpNetwork("8.8.4.4", { enrich: true, dnsClient });

    expect(result.network).toBe("8.8.4.4");
    expect(result.enrichment.status).toBe("indeterminate");
    expect(result.enrichment.ptr.status).toBe("indeterminate");
    expect(result.enrichment.origin.status).toBe("indeterminate");
    expect(result.enrichment.reason).toContain("failed or returned unrecognized");
  });

  it("represents partial failure separately from a confirmed absence", async () => {
    const ptrOwner = "4.4.8.8.in-addr.arpa";
    const originOwner = "4.4.8.8.origin.asn.cymru.com";
    const partialClient = new FakeDnsClient(
      { [`PTR:${ptrOwner}`]: [answer(ptrOwner, "PTR", "dns.google")] },
      new Set([`TXT:${originOwner}`]),
    );
    const absentClient = new FakeDnsClient();

    const partial = await inspectIpNetwork("8.8.4.4", { enrich: true, dnsClient: partialClient });
    const absent = await inspectIpNetwork("8.8.4.4", { enrich: true, dnsClient: absentClient });

    expect(partial.enrichment.status).toBe("partial");
    expect(partial.enrichment.origin.status).toBe("indeterminate");
    expect(absent.enrichment.status).toBe("complete");
    expect(absent.enrichment.ptr.status).toBe("not-found");
    expect(absent.enrichment.origin.status).toBe("not-found");
  });

  it("performs no DNS queries for subnets or non-global single addresses", async () => {
    const dnsClient = new FakeDnsClient();
    const subnet = await inspectIpNetwork("8.8.4.0/24", { enrich: true, dnsClient });
    const privateAddress = await inspectIpNetwork("10.0.0.1", { enrich: true, dnsClient });
    const documentationAddress = await inspectIpNetwork("2001:db8::1", { enrich: true, dnsClient });

    expect(subnet.enrichment.status).toBe("not-applicable");
    expect(privateAddress.enrichment.status).toBe("not-applicable");
    expect(documentationAddress.enrichment.status).toBe("not-applicable");
    expect(dnsClient.calls).toHaveLength(0);
  });

  it("does not query unless enrichment is opted in", async () => {
    const dnsClient = new FakeDnsClient();
    const result = await inspectIpNetwork("8.8.4.4", { dnsClient });

    expect(result.enrichment.status).toBe("not-requested");
    expect(result.enrichment.queryCount).toBe(0);
    expect(dnsClient.calls).toHaveLength(0);
  });
});

function answer(name: string, type: DnsQueryType, data: string): DnsAnswer {
  return { name, type, data };
}
