import { describe, expect, it } from "vitest";
import type { DnsLookupType } from "../shared/types";
import { type DnsAnswer, DnsQueryError, type DnsQueryType } from "./dns";
import {
  DNS_LOOKUP_TYPES,
  type LookupResolver,
  LookupUpstreamError,
  LookupValidationError,
  lookupDns,
  normalizeLookupRequest,
} from "./lookup";

class FakeResolver implements LookupResolver {
  readonly calls: Array<{ name: string; type: DnsQueryType }> = [];

  constructor(
    private readonly answers: DnsAnswer[] = [],
    private readonly failure?: Error,
  ) {}

  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    this.calls.push({ name, type });
    return this.failure ? Promise.reject(this.failure) : Promise.resolve(this.answers);
  }
}

describe("DNS lookup request validation", () => {
  it.each(DNS_LOOKUP_TYPES)("accepts the allowlisted uppercase type %s", (type) => {
    const name = type === "PTR" ? "192.0.2.8" : "example.com";
    expect(normalizeLookupRequest(name, type).type).toBe(type);
  });

  it.each(["txt", "Txt", " TXT ", "ANY", "AXFR", "", 16, null, undefined])(
    "rejects a non-allowlisted or non-uppercase type: %s",
    (type) => {
      expect(() => normalizeLookupRequest("example.com", type)).toThrow(LookupValidationError);
    },
  );

  it.each(["CERT", "DNSKEY", "DS", "IPSECKEY", "LOC", "NSEC", "NSEC3PARAM", "RRSIG", "TLSA"])(
    "rejects the non-native record type %s",
    (type) => {
      expect(() => normalizeLookupRequest("example.com", type)).toThrow(LookupValidationError);
    },
  );

  it("normalizes case, IDNs, a root dot, and service labels with underscores", () => {
    expect(normalizeLookupRequest("  _SIP._TCP.BÜCHER.Example.COM.  ", "SRV")).toEqual({
      input: "_sip._tcp.xn--bcher-kva.example.com",
      queryName: "_sip._tcp.xn--bcher-kva.example.com",
      type: "SRV",
    });
    expect(normalizeLookupRequest("Selector._DomainKey.Example.COM", "TXT").queryName).toBe(
      "selector._domainkey.example.com",
    );
  });

  it.each([
    "localhost",
    "printer",
    "service.local",
    "service.corp.internal",
    "https://example.com",
    "user@example.com",
    "example.com/path",
    "example.com:53",
    "*.example.com",
    "example..com",
    "-bad.example.com",
    "bad-.example.com",
    "example.123",
    "127.0.0.1",
    "2001:db8::1",
  ])("rejects a local, single-label, address, or malformed public owner: %s", (name) => {
    expect(() => normalizeLookupRequest(name, "TXT")).toThrow(LookupValidationError);
  });

  it("rejects oversized labels and non-string names", () => {
    expect(() => normalizeLookupRequest(`${"a".repeat(64)}.example.com`, "A")).toThrow(/label/iu);
    expect(() => normalizeLookupRequest({ name: "example.com" }, "A")).toThrow(/string/iu);
  });
});

describe("PTR normalization", () => {
  it("converts an IPv4 address to a complete in-addr.arpa owner", () => {
    expect(normalizeLookupRequest("192.0.2.45", "PTR")).toEqual({
      input: "192.0.2.45",
      queryName: "45.2.0.192.in-addr.arpa",
      type: "PTR",
    });
  });

  it("canonicalizes and expands IPv6 into all 32 reverse nibbles", () => {
    const normalized = normalizeLookupRequest("2001:0DB8::1", "PTR");
    expect(normalized.input).toBe("2001:db8::1");
    expect(normalized.queryName).toBe(
      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
    );
  });

  it("supports an IPv4-embedded IPv6 address", () => {
    const normalized = normalizeLookupRequest("::ffff:192.0.2.1", "PTR");
    expect(normalized.input).toBe("::ffff:c000:201");
    expect(normalized.queryName).toBe(
      "1.0.2.0.0.0.0.c.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
    );
    expect(normalized.queryName.split(".")).toHaveLength(34);
  });

  it("accepts and normalizes already-complete reverse owners", () => {
    expect(normalizeLookupRequest("45.2.0.192.IN-ADDR.ARPA.", "PTR").queryName).toBe(
      "45.2.0.192.in-addr.arpa",
    );
    expect(
      normalizeLookupRequest(
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.IP6.ARPA.",
        "PTR",
      ).queryName,
    ).toMatch(/\.ip6\.arpa$/u);
  });

  it.each([
    "example.com",
    "300.2.0.192.in-addr.arpa",
    "2.0.192.in-addr.arpa",
    "1.2.3.4.5.in-addr.arpa",
    "1.0.0.0.ip6.arpa",
    "2001:db8:::1",
    "192.168.001.1",
    "fe80::1%eth0",
  ])("rejects a malformed or incomplete PTR input: %s", (name) => {
    expect(() => normalizeLookupRequest(name, "PTR")).toThrow(LookupValidationError);
  });
});

describe("lookupDns", () => {
  it("returns record views, timing metadata, and a literal result count", async () => {
    const resolver = new FakeResolver([
      { name: "example.com", type: "MX", ttl: 300, data: "10 mail.example.com" },
      { name: "example.com", type: "MX", ttl: 600, data: "20 mail2.example.com" },
    ]);

    const result = await lookupDns("Example.COM.", "MX", resolver);

    expect(resolver.calls).toEqual([{ name: "example.com", type: "MX" }]);
    expect(result).toEqual(expect.objectContaining({
      input: "example.com",
      queryName: "example.com",
      type: "MX" satisfies DnsLookupType,
      durationMs: expect.any(Number),
      records: [
        { name: "example.com", type: "MX", value: "10 mail.example.com", ttl: 300 },
        { name: "example.com", type: "MX", value: "20 mail2.example.com", ttl: 600 },
      ],
      summary: "2 MX records returned for example.com.",
    }));
    expect(Number.isNaN(Date.parse(result.scannedAt))).toBe(false);
    expect(result.durationMs).toBeGreaterThanOrEqual(1);
  });

  it("treats an empty answer as a successful neutral result", async () => {
    const result = await lookupDns("_dmarc.example.com", "TXT", new FakeResolver());

    expect(result.records).toEqual([]);
    expect(result.summary).toBe("No TXT records were returned for _dmarc.example.com.");
    expect(result.summary).not.toMatch(/issue|error|broken|invalid/iu);
  });

  it("reports the canonical target even when its terminal answer is empty", async () => {
    const resolver: LookupResolver = {
      query: async () => [],
      queryFollowingCname: async () => ({
        answers: [],
        canonicalName: "target.example.net",
        aliases: [{ name: "alias.example.com", type: "CNAME", data: "target.example.net" }],
      }),
    };

    const result = await lookupDns("alias.example.com", "AAAA", resolver);

    expect(result.canonicalName).toBe("target.example.net");
    expect(result.records).toEqual([]);
    expect(result.summary).toMatch(/following alias\.example\.com to target\.example\.net/u);
  });

  it("maps resolver failures to a lookup upstream error", async () => {
    await expect(
      lookupDns("example.com", "A", new FakeResolver([], new DnsQueryError("SERVFAIL"))),
    ).rejects.toBeInstanceOf(LookupUpstreamError);
  });
});
