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
});

function txt(name: string, data: string): DnsAnswer {
  return { name, type: "TXT", data, ttl: 300 };
}
