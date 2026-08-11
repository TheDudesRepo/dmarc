import { describe, expect, it } from "vitest";
import type { DnsAnswer, DnsQueryType } from "./dns";
import {
  createDnsSnapshot,
  discoverCommonHosts,
  DiscoveryUpstreamError,
  HOST_DISCOVERY_LABELS,
  normalizeHostDiscoveryProfile,
  SNAPSHOT_RECORD_TYPES,
  type DiscoveryResolver,
} from "./discovery";

class FakeDiscoveryResolver implements DiscoveryResolver {
  readonly calls: string[] = [];

  constructor(
    private readonly records: Readonly<Record<string, DnsAnswer[]>> = {},
    private readonly failures = new Set<string>(),
  ) {}

  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    return this.resolve(name, type, "follow");
  }

  queryDirect(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    return this.resolve(name, type, "direct");
  }

  private resolve(name: string, type: DnsQueryType, mode: "follow" | "direct"): Promise<DnsAnswer[]> {
    const key = `${type}:${name}`;
    this.calls.push(`${mode}:${key}`);
    if (this.failures.has(key)) return Promise.reject(new Error("SERVFAIL"));
    return Promise.resolve(this.records[key] ?? []);
  }
}

describe("explicit DNS snapshot", () => {
  it("returns explicit RRsets, security owners, canonical evidence, and infrastructure addresses", async () => {
    const resolver = new FakeDiscoveryResolver({
      "A:example.com": [answer("edge.example.net", "A", "192.0.2.10")],
      "CNAME:example.com": [answer("example.com", "CNAME", "edge.example.net")],
      "MX:example.com": [answer("example.com", "MX", "10 mail.example.com")],
      "NS:example.com": [answer("example.com", "NS", "ns1.example.net")],
      "SOA:example.com": [answer("example.com", "SOA", "ns1.example.net hostmaster.example.net 1 3600 600 1209600 300")],
      "TXT:example.com": [answer("example.com", "TXT", "v=spf1 -all")],
      "TXT:_dmarc.example.com": [answer("_dmarc.example.com", "TXT", "v=DMARC1; p=quarantine")],
      "TXT:_mta-sts.example.com": [answer("_mta-sts.example.com", "TXT", "v=STSv1; id=20260811")],
      "TXT:_smtp._tls.example.com": [answer("_smtp._tls.example.com", "TXT", "v=TLSRPTv1; rua=mailto:tls@example.com")],
      "A:mail.example.com": [answer("mail.example.com", "A", "192.0.2.25")],
      "AAAA:mail.example.com": [answer("mail.example.com", "AAAA", "2001:db8::25")],
      "A:ns1.example.net": [answer("ns1.example.net", "A", "192.0.2.53")],
    });

    const result = await createDnsSnapshot("example.com", resolver);

    expect(result.domain).toBe("example.com");
    expect(result.groups).toHaveLength(SNAPSHOT_RECORD_TYPES.length);
    expect(result.groups.find((group) => group.type === "A")).toEqual(expect.objectContaining({
      status: "found",
      canonicalName: "edge.example.net",
      records: [expect.objectContaining({ value: "192.0.2.10" })],
    }));
    expect(result.securityRecords.find((record) => record.key === "dmarc")?.status).toBe("found");
    expect(result.infrastructureHosts).toEqual(expect.arrayContaining([
      expect.objectContaining({ hostname: "mail.example.com", source: "mail", addresses: ["192.0.2.25", "2001:db8::25"] }),
      expect.objectContaining({ hostname: "ns1.example.net", source: "nameserver", addresses: ["192.0.2.53"] }),
    ]));
    expect(result.findings.map((finding) => finding.id)).toEqual(["review-inventory"]);
    expect(result.disclaimer).toContain("not an ANY query");
  });

  it("keeps partial resolver failures indeterminate instead of reporting absence", async () => {
    const resolver = new FakeDiscoveryResolver(
      {
        "NS:example.com": [answer("example.com", "NS", "ns1.example.com")],
        "SOA:example.com": [answer("example.com", "SOA", "ns1.example.com hostmaster.example.com 1 3600 600 1209600 300")],
      },
      new Set(["CAA:example.com", "TXT:_dmarc.example.com"]),
    );

    const result = await createDnsSnapshot("example.com", resolver);

    expect(result.groups.find((group) => group.type === "CAA")?.status).toBe("unavailable");
    expect(result.securityRecords.find((record) => record.key === "dmarc")?.status).toBe("unavailable");
    expect(result.unavailableCount).toBe(2);
    expect(result.findings.map((finding) => finding.id)).not.toContain("dmarc-missing");
  });

  it("reports unavailable infrastructure address families instead of presenting them as empty", async () => {
    const resolver = new FakeDiscoveryResolver(
      {
        "MX:example.com": [answer("example.com", "MX", "10 mail.example.com")],
        "NS:example.com": [answer("example.com", "NS", "ns1.example.com")],
        "SOA:example.com": [answer("example.com", "SOA", "ns1.example.com hostmaster.example.com 1 3600 600 1209600 300")],
        "TXT:example.com": [answer("example.com", "TXT", "v=spf1 -all")],
      },
      new Set(["A:mail.example.com", "AAAA:mail.example.com"]),
    );

    const result = await createDnsSnapshot("example.com", resolver);
    const mail = result.infrastructureHosts.find((host) => host.hostname === "mail.example.com");

    expect(mail).toEqual(expect.objectContaining({ addresses: [], unavailableAddressTypes: ["A", "AAAA"] }));
    expect(result.unavailableCount).toBe(2);
    expect(result.summary).toMatch(/2 record queries were temporarily unavailable/iu);
  });

  it("uses an incomplete review finding instead of green success when evidence is unavailable", async () => {
    const resolver = new FakeDiscoveryResolver(
      {
        "NS:example.com": [answer("example.com", "NS", "ns1.example.com")],
        "SOA:example.com": [answer("example.com", "SOA", "ns1.example.com hostmaster.example.com 1 3600 600 1209600 300")],
        "TXT:example.com": [answer("example.com", "TXT", "v=spf1 -all")],
        "TXT:_dmarc.example.com": [answer("_dmarc.example.com", "TXT", "v=DMARC1; p=reject")],
        "TXT:_smtp._tls.example.com": [answer("_smtp._tls.example.com", "TXT", "v=TLSRPTv1; rua=mailto:tls@example.com")],
      },
      new Set(["CAA:example.com"]),
    );

    const result = await createDnsSnapshot("example.com", resolver);
    expect(result.findings.map((finding) => finding.id)).toEqual(["review-incomplete"]);
    expect(result.findings[0]?.severity).toBe("info");
  });

  it("fails the request only when every apex record query is unavailable", async () => {
    const failures = new Set(SNAPSHOT_RECORD_TYPES.map((type) => `${type}:example.com`));
    const resolver = new FakeDiscoveryResolver({}, failures);
    await expect(createDnsSnapshot("example.com", resolver)).rejects.toBeInstanceOf(DiscoveryUpstreamError);
  });

  it("flags multiple SPF records and gives correction steps", async () => {
    const result = await createDnsSnapshot("example.com", new FakeDiscoveryResolver({
      "NS:example.com": [answer("example.com", "NS", "ns1.example.com")],
      "SOA:example.com": [answer("example.com", "SOA", "ns1.example.com hostmaster.example.com 1 3600 600 1209600 300")],
      "TXT:example.com": [
        answer("example.com", "TXT", "v=spf1 include:a.example -all"),
        answer("example.com", "TXT", "v=spf1 include:b.example -all"),
      ],
    }));
    const finding = result.findings.find((candidate) => candidate.id === "multiple-spf-records");
    expect(finding?.severity).toBe("critical");
    expect(finding?.steps.join(" ")).toContain("Merge");
  });

  it("flags missing SPF only for an active mail domain, not an explicit null MX", async () => {
    const active = await createDnsSnapshot("example.com", new FakeDiscoveryResolver({
      "MX:example.com": [answer("example.com", "MX", "10 mail.example.com")],
      "NS:example.com": [answer("example.com", "NS", "ns1.example.com")],
      "SOA:example.com": [answer("example.com", "SOA", "ns1.example.com hostmaster.example.com 1 3600 600 1209600 300")],
    }));
    const nullMx = await createDnsSnapshot("example.net", new FakeDiscoveryResolver({
      "MX:example.net": [answer("example.net", "MX", "0 .")],
      "NS:example.net": [answer("example.net", "NS", "ns1.example.net")],
      "SOA:example.net": [answer("example.net", "SOA", "ns1.example.net hostmaster.example.net 1 3600 600 1209600 300")],
    }));

    expect(active.findings.map((finding) => finding.id)).toContain("spf-missing");
    expect(nullMx.findings.map((finding) => finding.id)).not.toContain("spf-missing");
  });

  it("keeps SPF indeterminate when an active mail domain's apex TXT query is unavailable", async () => {
    const result = await createDnsSnapshot(
      "example.com",
      new FakeDiscoveryResolver(
        {
          "MX:example.com": [answer("example.com", "MX", "10 mail.example.com")],
          "NS:example.com": [answer("example.com", "NS", "ns1.example.com")],
          "SOA:example.com": [answer("example.com", "SOA", "ns1.example.com hostmaster.example.com 1 3600 600 1209600 300")],
        },
        new Set(["TXT:example.com"]),
      ),
    );

    expect(result.groups.find((group) => group.type === "TXT")?.status).toBe("unavailable");
    expect(result.findings.map((finding) => finding.id)).not.toContain("spf-missing");
  });
});

describe("bounded common-host discovery", () => {
  it("resolves direct and aliased hosts, runs a random-label wildcard probe, and records the tested label set", async () => {
    const resolver = new FakeDiscoveryResolver({
      "A:www.example.com": [answer("www.example.com", "A", "192.0.2.10")],
      "AAAA:www.example.com": [answer("www.example.com", "AAAA", "2001:db8::10")],
      "CNAME:mail.example.com": [answer("mail.example.com", "CNAME", "mail.provider.example")],
      "A:mail.provider.example": [answer("mail.provider.example", "A", "192.0.2.20")],
    });

    const result = await discoverCommonHosts("example.com", "core", resolver);

    expect(result.testedNames).toEqual(HOST_DISCOVERY_LABELS.core.map((label) => `${label}.example.com`));
    expect(result.hosts).toEqual(expect.arrayContaining([
      expect.objectContaining({ hostname: "www.example.com", addresses: ["192.0.2.10", "2001:db8::10"] }),
      expect.objectContaining({ hostname: "mail.example.com", alias: "mail.provider.example", addresses: ["192.0.2.20"] }),
    ]));
    expect(result.wildcardProbe.hostname).toMatch(/^dmarc-ready-probe-[a-f0-9]{16}\.example\.com$/u);
    expect(result.wildcardProbe.detected).toBe(false);
    expect(resolver.calls.filter((call) => call.includes("dmarc-ready-probe-"))).toHaveLength(3);
    expect(resolver.calls).toHaveLength(24);
    expect(result.disclaimer).toContain("does not brute-force");
  });

  it("tags common-name answers that match the random-label wildcard response", async () => {
    const resolver: DiscoveryResolver = {
      query: (name, type) => Promise.resolve(type === "A" ? [answer(name, type, "203.0.113.25")] : []),
      queryDirect: (name, type) => Promise.resolve(type === "A" ? [answer(name, type, "203.0.113.25")] : []),
    };
    const result = await discoverCommonHosts("example.com", "extended", resolver);
    expect(result.wildcardProbe.detected).toBe(true);
    expect(result.wildcardProbe.addresses).toEqual(["203.0.113.25"]);
    expect(result.hosts).toHaveLength(HOST_DISCOVERY_LABELS.extended.length);
    expect(result.hosts.every((host) => host.wildcardMatch)).toBe(true);
    expect(result.summary).toContain("wildcard response was detected");
  });

  it("reports a failed candidate as unavailable rather than absent", async () => {
    const resolver = new FakeDiscoveryResolver({}, new Set(["A:api.example.com"]));
    const result = await discoverCommonHosts("example.com", "core", resolver);
    expect(result.unavailableNames).toContain("api.example.com");
    expect(result.summary).toContain("temporarily unavailable");
  });

  it("accepts only the two documented profiles", () => {
    expect(normalizeHostDiscoveryProfile("core")).toBe("core");
    expect(normalizeHostDiscoveryProfile("extended")).toBe("extended");
    expect(() => normalizeHostDiscoveryProfile("all")).toThrow(/core or extended/u);
  });
});

function answer(name: string, type: DnsQueryType, data: string): DnsAnswer {
  return { name, type, ttl: 300, data };
}
