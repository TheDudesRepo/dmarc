import { describe, expect, it } from "vitest";
import type { DnsLookupType } from "../shared/types";
import {
  type DnsAnswer,
  DnsClient,
  DnsQueryError,
  type DnsQueryType,
  type NativeDnsResolver,
} from "./dns";
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

class RoutedResolver implements LookupResolver {
  readonly calls: Array<{ name: string; type: DnsQueryType }> = [];

  constructor(
    private readonly answers: Record<string, DnsAnswer[]> = {},
    private readonly failures = new Set<string>(),
  ) {}

  query(name: string, type: DnsQueryType): Promise<DnsAnswer[]> {
    this.calls.push({ name, type });
    const key = `${type}:${name}`;
    return this.failures.has(key)
      ? Promise.reject(new DnsQueryError("SERVFAIL"))
      : Promise.resolve(this.answers[key] ?? []);
  }
}

const MYAVISTA_SPF_WORKERD =
  'v=spf1 include:u1791881.wl.sendgrid.net include:spf.protection.outlook.com include:aspmx.pardot.com ip4:198.181.21.221 ip4:198.181.21.222 ip4:198.181.30.101 ip4:198.251.0.114 ip4:198.251.4.1 ip4:198.251.4.2 ip4:198.251.4.3 ip4:198.251.4.4 ip4:198.251.4.5 " "include:_spf.salesforce.com -all';
const MYAVISTA_SPF = MYAVISTA_SPF_WORKERD.replace('" "', "");

function txt(name: string, data: string, ttl?: number): DnsAnswer {
  return { name, type: "TXT", data, ...(ttl === undefined ? {} : { ttl }) };
}

function nativeResolver(overrides: Partial<NativeDnsResolver> = {}): NativeDnsResolver {
  return {
    resolve4: async () => [],
    resolve6: async () => [],
    resolveCaa: async () => [],
    resolveCname: async () => [],
    resolveMx: async () => [],
    resolveNs: async () => [],
    resolvePtr: async () => [],
    resolveSoa: async () => ({
      nsname: "ns1.example.com",
      hostmaster: "hostmaster.example.com",
      serial: 1,
      refresh: 7_200,
      retry: 3_600,
      expire: 1_209_600,
      minttl: 300,
    }),
    resolveSrv: async () => [],
    resolveTxt: async () => [],
    ...overrides,
  };
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
    expect(normalizeLookupRequest("  BÜCHER.Example.COM. ", "SPF")).toEqual({
      input: "xn--bcher-kva.example.com",
      queryName: "xn--bcher-kva.example.com",
      type: "SPF",
    });
  });

  it("accepts a normalized public SPF policy owner and still rejects IP literals", () => {
    expect(normalizeLookupRequest("_SPF.Example.COM.", "SPF")).toEqual({
      input: "_spf.example.com",
      queryName: "_spf.example.com",
      type: "SPF",
    });
    expect(() => normalizeLookupRequest("192.0.2.1", "SPF")).toThrow(LookupValidationError);
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

  it("returns only SPF TXT evidence and a neutral missing analysis when no policy exists", async () => {
    const resolver = new FakeResolver([
      txt("example.com", "google-site-verification=abc", 300),
      txt("example.com", "some unrelated TXT value", 600),
    ]);

    const result = await lookupDns("example.com", "SPF", resolver);

    expect(resolver.calls).toEqual([{ name: "example.com", type: "TXT" }]);
    expect(result.type).toBe("SPF");
    expect(result.records).toEqual([]);
    expect(result.summary).toMatch(/No SPF policy was found/u);
    expect(result.spfAnalysis).toEqual(expect.objectContaining({
      status: "missing",
      recordCount: 0,
      valid: false,
      syntaxValid: false,
      mechanisms: [],
      terminalPolicy: "none",
    }));
    expect(result.spfAnalysis?.correctionGuidance.steps).toHaveLength(3);
  });

  it("classifies multiple SPF policies as permerror and returns both raw records", async () => {
    const resolver = new FakeResolver([
      txt("example.com", "v=spf1 include:mail.example.net -all", 300),
      txt("example.com", "v=spf1 ip4:192.0.2.0/24 ~all", 600),
      txt("example.com", "verification=not-spf", 600),
    ]);

    const result = await lookupDns("example.com", "SPF", resolver);

    expect(result.records).toHaveLength(2);
    expect(result.records.every((record) => record.type === "TXT" && record.value.startsWith("v=spf1"))).toBe(true);
    expect(result.spfAnalysis).toEqual(expect.objectContaining({
      status: "multiple",
      recordCount: 2,
      valid: false,
      syntaxValid: false,
    }));
    expect(result.spfAnalysis?.errors.join(" ")).toMatch(/exactly one|multiple/iu);
  });

  it("reports parser errors, parsed mechanisms, and targeted repair guidance for an invalid policy", async () => {
    const result = await lookupDns("example.com", "SPF", new FakeResolver([
      txt("example.com", "v=spf1 ip4:not-an-address include:mail.example.net -all"),
    ]));

    expect(result.spfAnalysis).toEqual(expect.objectContaining({
      status: "invalid",
      recordCount: 1,
      valid: false,
      syntaxValid: false,
      terminalPolicy: "-all",
    }));
    expect(result.spfAnalysis?.errors.join(" ")).toMatch(/invalid IPv4/iu);
    expect(result.spfAnalysis?.mechanisms).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "include", domainSpec: "mail.example.net", causesDnsLookup: true }),
      expect.objectContaining({ name: "all", qualifier: "-", causesDnsLookup: false }),
    ]));
    expect(result.spfAnalysis?.correctionGuidance.summary).toMatch(/Repair the existing SPF/iu);
  });

  it("bounds parser messages and correction guidance for a large allowed TXT response", async () => {
    const oversizedToken = "x".repeat(20_000);
    const result = await lookupDns("example.com", "SPF", new FakeResolver([
      txt("example.com", `v=spf1 ${oversizedToken} ${oversizedToken}=value -all`),
    ]));
    const analysis = result.spfAnalysis;

    expect(analysis?.status).toBe("invalid");
    expect(analysis?.errors.every((message) => message.length <= 8_192)).toBe(true);
    expect(analysis?.warnings.every((message) => message.length <= 8_192)).toBe(true);
    expect(analysis?.correctionGuidance.steps.every((step) => step.length <= 8_192)).toBe(true);
    expect(analysis?.issues.join(" ")).toMatch(/Parser messages were limited/iu);
  });

  it("marks a syntactically valid policy invalid when its evaluation path exceeds ten lookups", async () => {
    const elevenLookups = Array.from({ length: 11 }, () => "a").join(" ");
    const result = await lookupDns("example.com", "SPF", new FakeResolver([
      txt("example.com", `v=spf1 ${elevenLookups} -all`),
    ]));

    expect(result.spfAnalysis).toEqual(expect.objectContaining({
      status: "invalid",
      valid: false,
      syntaxValid: true,
      terminalPolicy: "-all",
      lookupEstimate: expect.objectContaining({
        count: 11,
        exceedsLimit: true,
        truncated: false,
      }),
    }));
    expect(result.spfAnalysis?.issues.join(" ")).toMatch(/above the RFC limit of 10/iu);
    expect(result.spfAnalysis?.correctionGuidance.summary).toMatch(/ten DNS lookups or fewer/iu);
  });

  it("bounds structured SPF mechanism output without losing the terminal-policy conclusion", async () => {
    const manyIpMechanisms = Array.from({ length: 257 }, () => "ip4:192.0.2.1").join(" ");
    const result = await lookupDns("example.com", "SPF", new FakeResolver([
      txt("example.com", `v=spf1 ${manyIpMechanisms} -all`),
    ]));

    expect(result.spfAnalysis).toEqual(expect.objectContaining({
      status: "warning",
      valid: true,
      syntaxValid: true,
      terminalPolicy: "-all",
    }));
    expect(result.spfAnalysis?.mechanisms).toHaveLength(256);
    expect(result.spfAnalysis?.issues.join(" ")).toMatch(/limited to the first 256/iu);
  });

  it("repairs MyAvista split TXT presentation and calculates its six-lookup recursive path", async () => {
    const includeRecords: Record<string, string> = {
      "u1791881.wl.sendgrid.net": "v=spf1 ip4:167.89.0.0/17 -all",
      "spf.protection.outlook.com": "v=spf1 ip4:40.92.0.0/15 -all",
      "aspmx.pardot.com": "v=spf1 include:et._spf.pardot.com -all",
      "et._spf.pardot.com": "v=spf1 ip4:198.245.80.0/20 -all",
      "_spf.salesforce.com": "v=spf1 exists:%{i}._spf.mta.salesforce.com -all",
    };
    const resolver = nativeResolver({
      resolveTxt: async (name) => {
        if (name === "myavista.com") {
          return [[MYAVISTA_SPF_WORKERD], ["google-site-verification=not-spf"]];
        }
        const record = includeRecords[name];
        return record ? [[record]] : [];
      },
    });

    const result = await lookupDns("MyAvista.COM.", "SPF", new DnsClient({ resolver }));

    expect(result.records).toEqual([
      { name: "myavista.com", type: "TXT", value: MYAVISTA_SPF },
    ]);
    expect(result.records[0]?.value).not.toContain('" "');
    expect(result.spfAnalysis).toEqual(expect.objectContaining({
      status: "valid",
      recordCount: 1,
      valid: true,
      syntaxValid: true,
      terminalPolicy: "-all",
      lookupEstimate: expect.objectContaining({
        count: 6,
        exceedsLimit: false,
        truncated: false,
        expandedDomains: [
          "_spf.salesforce.com",
          "aspmx.pardot.com",
          "et._spf.pardot.com",
          "spf.protection.outlook.com",
          "u1791881.wl.sendgrid.net",
        ],
      }),
    }));
    expect(result.spfAnalysis?.errors).toEqual([]);
    expect(result.spfAnalysis?.issues).toEqual([]);
  });

  it("keeps an included-domain resolver failure explicit instead of treating the branch as absent", async () => {
    const resolver = new RoutedResolver(
      { "TXT:example.com": [txt("example.com", "v=spf1 include:unavailable.example.net -all")] },
      new Set(["TXT:unavailable.example.net"]),
    );

    const result = await lookupDns("example.com", "SPF", resolver);

    expect(result.spfAnalysis).toEqual(expect.objectContaining({
      status: "warning",
      valid: true,
      syntaxValid: true,
      lookupEstimate: expect.objectContaining({ count: 1, exceedsLimit: false }),
    }));
    expect(result.spfAnalysis?.issues.join(" ")).toMatch(/Could not resolve.*unavailable\.example\.net/iu);
    expect(result.spfAnalysis?.correctionGuidance.summary).toMatch(/incomplete SPF branches/iu);
  });

  it("maps a root SPF TXT resolver failure to a lookup upstream error", async () => {
    await expect(
      lookupDns("example.com", "SPF", new FakeResolver([], new DnsQueryError("SERVFAIL"))),
    ).rejects.toBeInstanceOf(LookupUpstreamError);
  });
});
