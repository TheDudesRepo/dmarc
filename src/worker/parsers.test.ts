import { describe, expect, it } from "vitest";
import { findDmarcRecords, parseDmarcRecord } from "./dmarc";
import { decodeDnsTxt } from "./dns";
import { estimateSpfLookups, findSpfRecords, parseSpfRecord } from "./spf";

describe("DNS TXT presentation decoding", () => {
  it("joins quoted character-string chunks without adding spaces", () => {
    expect(decodeDnsTxt('"v=DMARC1; p=quaran" "tine; rua=mailto:d@example.com"')).toBe(
      "v=DMARC1; p=quarantine; rua=mailto:d@example.com",
    );
  });

  it("decodes escaped quotes and decimal escapes", () => {
    expect(decodeDnsTxt('"a\\\"b\\032c"')).toBe('a"b c');
  });

  it("leaves malformed quoted data untouched", () => {
    expect(decodeDnsTxt('"unterminated')).toBe('"unterminated');
  });
});

describe("DMARC parser", () => {
  it("parses a valid enforcement policy", () => {
    const parsed = parseDmarcRecord(
      "v=DMARC1; p=quarantine; sp=reject; pct=50; adkim=s; aspf=r; rua=mailto:dmarc@example.com",
    );

    expect(parsed.valid).toBe(true);
    expect(parsed.policy).toBe("quarantine");
    expect(parsed.subdomainPolicy).toBe("reject");
    expect(parsed.legacyPercentage).toBe(50);
    expect(parsed.warnings.join(" ")).toMatch(/historic/u);
  });

  it("requires an exact, first version tag and a valid policy", () => {
    const parsed = parseDmarcRecord("p=reject; v=dmarc1");
    expect(parsed.valid).toBe(false);
    expect(parsed.errors).toEqual(expect.arrayContaining([expect.stringMatching(/must be first/u), expect.stringMatching(/exactly/u)]));
  });

  it("rejects duplicate active tags but treats pct as historic", () => {
    const parsed = parseDmarcRecord("v=DMARC1; p=reject; p=none; pct=101");
    expect(parsed.valid).toBe(false);
    expect(parsed.errors.join(" ")).toMatch(/Duplicate p/u);
    expect(parsed.errors.join(" ")).not.toMatch(/pct/u);
    expect(parsed.warnings.join(" ")).toMatch(/historic/u);
  });

  it("supports RFC 9989 policy defaults and test mode", () => {
    const defaulted = parseDmarcRecord("v=DMARC1; rua=mailto:dmarc@example.com");
    const testing = parseDmarcRecord("v=DMARC1; p=reject; t=y; np=quarantine; psd=n");

    expect(defaulted.valid).toBe(true);
    expect(defaulted.policy).toBe("none");
    expect(testing.valid).toBe(true);
    expect(testing.testing).toBe(true);
    expect(testing.nonexistentSubdomainPolicy).toBe("quarantine");
  });

  it("selects only versioned DMARC TXT resource records", () => {
    expect(findDmarcRecords(["google-site-verification=x", "v=DMARC1; p=none"])).toEqual(["v=DMARC1; p=none"]);
  });
});

describe("SPF parser", () => {
  it("parses mechanisms, qualifiers, CIDR, and direct lookup terms", () => {
    const parsed = parseSpfRecord("v=spf1 ip4:192.0.2.0/24 include:_spf.example.com mx -all");
    expect(parsed.valid).toBe(true);
    expect(parsed.terminalAll).toBe("-");
    expect(parsed.directLookupTerms).toBe(2);
    expect(parsed.mechanisms[0]?.cidr4).toBe(24);
  });

  it("flags unsafe +all", () => {
    const parsed = parseSpfRecord("v=spf1 +all");
    expect(parsed.valid).toBe(true);
    expect(parsed.terminalAll).toBe("+");
    expect(parsed.warnings.join(" ")).toMatch(/authorizes every sender/u);
  });

  it("rejects malformed IP mechanisms and duplicate modifiers", () => {
    const parsed = parseSpfRecord("v=spf1 ip4:999.1.1.1 redirect=a.example redirect=b.example");
    expect(parsed.valid).toBe(false);
    expect(parsed.errors.join(" ")).toMatch(/invalid IPv4/u);
    expect(parsed.errors.join(" ")).toMatch(/Duplicate redirect/u);
  });

  it("preserves TXT RR boundaries when selecting SPF records", () => {
    expect(findSpfRecords(["v=spf1 -all", "v=spf1 include:x.example -all", "unrelated=value"])).toHaveLength(2);
  });
});

describe("recursive SPF lookup estimate", () => {
  it("expands include chains and counts lookup-causing terms", async () => {
    const records: Record<string, string[]> = {
      "a.example": ["v=spf1 include:c.example a -all"],
      "b.example": ["v=spf1 exists:probe.example -all"],
      "c.example": ["v=spf1 mx -all"],
    };
    const root = parseSpfRecord("v=spf1 include:a.example include:b.example -all");
    const estimate = await estimateSpfLookups("root.example", root, async (domain) => records[domain] ?? []);

    expect(estimate.count).toBe(6);
    expect(estimate.exceedsLimit).toBe(false);
    expect(estimate.expandedDomains).toEqual(["a.example", "b.example", "c.example"]);
  });

  it("detects recursive include cycles", async () => {
    const root = parseSpfRecord("v=spf1 include:a.example -all");
    const estimate = await estimateSpfLookups("root.example", root, async (domain) =>
      domain === "a.example" ? ["v=spf1 include:root.example -all"] : [],
    );

    expect(estimate.count).toBe(2);
    expect(estimate.issues.join(" ")).toMatch(/cycle/u);
  });

  it("flags more than ten lookup terms without doing extra DNS work", async () => {
    const root = parseSpfRecord(`v=spf1 ${Array.from({ length: 11 }, () => "a").join(" ")} -all`);
    const estimate = await estimateSpfLookups("root.example", root, async () => []);

    expect(estimate.count).toBe(11);
    expect(estimate.exceedsLimit).toBe(true);
  });
});
