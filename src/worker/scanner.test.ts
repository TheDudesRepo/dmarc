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
