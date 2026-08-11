import { describe, expect, it } from "vitest";
import { DnsQueryError, type DnsAnswer, type DnsQueryType } from "./dns";
import { scanDomain, ScanUpstreamError, type DnsResolver } from "./scanner";

class FakeResolver implements DnsResolver {
  constructor(
    private readonly records: Record<string, DnsAnswer[]>,
    private readonly failures = new Set<string>(),
  ) {}

  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    const key = `${type}:${name}`;
    if (this.failures.has(key)) return Promise.reject(new DnsQueryError("temporary failure"));
    return Promise.resolve(this.records[key] ?? []);
  }
}

describe("deterministic scan engine", () => {
  it("scores a DNS snapshot and applies RFC 9989 test-mode semantics", async () => {
    const records: Record<string, DnsAnswer[]> = {
      "TXT:_dmarc.example.com": [txt("_dmarc.example.com", "v=DMARC1; p=reject; t=y; rua=mailto:dmarc@example.com")],
      "TXT:example.com": [txt("example.com", "v=spf1 -all")],
      "MX:example.com": [{ name: "example.com", type: "MX", data: "10 mx.example.com", ttl: 300 }],
      "NS:example.com": [{ name: "example.com", type: "NS", data: "ns1.example.com", ttl: 300 }],
      "TXT:_mta-sts.example.com": [txt("_mta-sts.example.com", "v=STSv1; id=20260809")],
      "TXT:_smtp._tls.example.com": [txt("_smtp._tls.example.com", "v=TLSRPTv1; rua=mailto:tls@example.com")],
      "TXT:default._bimi.example.com": [txt("default._bimi.example.com", "v=BIMI1; l=https://example.com/logo.svg")],
      "CNAME:selector1._domainkey.example.com": [
        { name: "selector1._domainkey.example.com", type: "CNAME", data: "selector1.example.onmicrosoft.com", ttl: 300 },
      ],
    };

    const result = await scanDomain("example.com", new FakeResolver(records));

    expect(result.posture).toBe("quarantine");
    expect(result.headline).toMatch(/t=y/u);
    expect(result.score).toBe(95);
    expect(result.grade).toBe("A");
    expect(result.checks.dkim.summary).toMatch(/remain unverified/u);
    expect(result.disclaimer).toMatch(/not proof.*readiness/u);
  });

  it("does not turn a temporary DMARC resolver error into an absent record", async () => {
    const resolver = new FakeResolver({}, new Set(["TXT:_dmarc.example.com"]));
    await expect(scanDomain("example.com", resolver)).rejects.toBeInstanceOf(ScanUpstreamError);
  });

  it("does not offer a generic SPF record when the sender inventory is unknown", async () => {
    const result = await scanDomain("example.com", new FakeResolver({}));
    const finding = result.findings.find((candidate) => candidate.id === "spf-not-found");

    expect(finding?.remediation?.record).toBeUndefined();
    expect(finding?.remediation?.caution).toMatch(/verified sender inventory/iu);
  });

  it("surfaces weaker sp and np policies without changing the organizational-domain posture", async () => {
    const strongPolicy = await scanWithDmarc(
      "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    );
    const scopedExceptions = await scanWithDmarc(
      "v=DMARC1; p=reject; sp=none; np=quarantine; rua=mailto:dmarc@example.com",
    );
    const details = Object.fromEntries(
      scopedExceptions.checks.dmarc.details.map((detail) => [detail.label, detail.value]),
    );

    expect(scopedExceptions.posture).toBe("reject");
    expect(scopedExceptions.postureLabel).toMatch(/scoped exceptions/u);
    expect(scopedExceptions.headline).toMatch(/declares weaker policies for existing and nonexistent subdomains/u);
    expect(scopedExceptions.summary).toMatch(/existing subdomains declare none/iu);
    expect(scopedExceptions.checks.dmarc.status).toBe("warning");
    expect(details["Organizational-domain policy (p)"]).toMatch(/^reject \(explicit p tag\)$/u);
    expect(details["Existing-subdomain policy (sp)"]).toMatch(/^none \(explicit sp tag\)$/u);
    expect(details["Nonexistent-subdomain policy (np)"]).toMatch(/^quarantine \(explicit np tag\)$/u);
    expect(scopedExceptions.findings.map((finding) => finding.id)).toEqual(
      expect.arrayContaining(["dmarc-weaker-sp-policy", "dmarc-weaker-np-policy"]),
    );
    expect(scopedExceptions.score).toBeLessThan(strongPolicy.score);
  });

  it("explains sp and np inheritance and applies test mode to every policy scope", async () => {
    const inherited = await scanWithDmarc(
      "v=DMARC1; p=reject; t=y; rua=mailto:dmarc@example.com",
    );
    const details = Object.fromEntries(inherited.checks.dmarc.details.map((detail) => [detail.label, detail.value]));

    expect(inherited.posture).toBe("quarantine");
    expect(details["Organizational-domain policy (p)"]).toMatch(/t=y expects quarantine handling/u);
    expect(details["Existing-subdomain policy (sp)"]).toMatch(/inherits p=reject.*t=y expects quarantine handling/u);
    expect(details["Nonexistent-subdomain policy (np)"]).toMatch(/inherits p=reject.*t=y expects quarantine handling/u);
    expect(inherited.checks.dmarc.summary).toMatch(
      /expected handling is quarantine for the domain, quarantine for existing subdomains, and quarantine for nonexistent subdomains/u,
    );
    expect(inherited.findings.map((finding) => finding.id)).not.toEqual(
      expect.arrayContaining(["dmarc-weaker-sp-policy", "dmarc-weaker-np-policy"]),
    );
  });

  it("accepts the logical myavista SPF record and estimates six recursive lookups", async () => {
    const domain = "myavista.com";
    const records: Record<string, DnsAnswer[]> = {
      [`TXT:_dmarc.${domain}`]: [
        txt(`_dmarc.${domain}`, "v=DMARC1; p=reject; pct=100; sp=reject; rua=mailto:dmarc@example.com"),
      ],
      [`TXT:${domain}`]: [
        txt(
          domain,
          "v=spf1 include:u1791881.wl.sendgrid.net include:spf.protection.outlook.com include:aspmx.pardot.com ip4:198.181.21.221 ip4:198.181.21.222 ip4:198.181.30.101 ip4:198.251.0.114 ip4:198.251.4.1 ip4:198.251.4.2 ip4:198.251.4.3 ip4:198.251.4.4 ip4:198.251.4.5 include:_spf.salesforce.com -all",
        ),
      ],
      "TXT:u1791881.wl.sendgrid.net": [txt("u1791881.wl.sendgrid.net", "v=spf1 ip4:167.89.0.0/17 -all")],
      "TXT:spf.protection.outlook.com": [txt("spf.protection.outlook.com", "v=spf1 ip4:40.92.0.0/15 -all")],
      "TXT:aspmx.pardot.com": [txt("aspmx.pardot.com", "v=spf1 include:et._spf.pardot.com -all")],
      "TXT:et._spf.pardot.com": [txt("et._spf.pardot.com", "v=spf1 ip4:198.245.80.0/20 -all")],
      "TXT:_spf.salesforce.com": [
        txt("_spf.salesforce.com", "v=spf1 exists:%{i}._spf.mta.salesforce.com -all"),
      ],
      [`NS:${domain}`]: [
        { name: domain, type: "NS", data: "ns1.example.net" },
        { name: domain, type: "NS", data: "ns2.example.net" },
      ],
      [`SOA:${domain}`]: [
        { name: domain, type: "SOA", data: "ns1.example.net hostmaster.example.net 1 3600 600 1209600 300" },
      ],
    };

    const result = await scanDomain(domain, new FakeResolver(records));
    const lookupDetail = result.checks.spf.details.find((detail) => detail.label === "Lookup estimate");

    expect(result.checks.spf.status).toBe("pass");
    expect(lookupDetail?.value).toBe("6");
    expect(result.findings.map((finding) => finding.id)).not.toContain("invalid-spf-record");
    expect(result.findings.find((finding) => finding.id === "dmarc-legacy-pct")?.remediation?.record?.value)
      .toBe("v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com");
  });

  it("surfaces DNS health and provides repair steps for a fragile delegation", async () => {
    const domain = "example.com";
    const records: Record<string, DnsAnswer[]> = {
      [`TXT:_dmarc.${domain}`]: [txt(`_dmarc.${domain}`, "v=DMARC1; p=none")],
      [`TXT:${domain}`]: [txt(domain, "v=spf1 -all")],
      [`A:${domain}`]: [{ name: domain, type: "A", data: "192.0.2.10", ttl: 300 }],
      [`NS:${domain}`]: [{ name: domain, type: "NS", data: "ns1.example.net", ttl: 300 }],
      [`SOA:${domain}`]: [
        { name: domain, type: "SOA", data: "ns1.example.net hostmaster.example.net 1 3600 600 1209600 300" },
      ],
    };

    const result = await scanDomain(domain, new FakeResolver(records));
    const finding = result.findings.find((candidate) => candidate.id === "dns-single-nameserver");

    expect(result.checks.dns.status).toBe("warning");
    expect(result.checks.dns.records).toEqual(expect.arrayContaining([expect.objectContaining({ type: "A" })]));
    expect(finding?.remediation?.steps.length).toBeGreaterThan(1);
  });
});

async function scanWithDmarc(record: string) {
  const records: Record<string, DnsAnswer[]> = {
    "TXT:_dmarc.example.com": [txt("_dmarc.example.com", record)],
    "TXT:example.com": [txt("example.com", "v=spf1 -all")],
  };
  return scanDomain("example.com", new FakeResolver(records));
}

function txt(name: string, data: string): DnsAnswer {
  return { name, type: "TXT", data, ttl: 300 };
}
