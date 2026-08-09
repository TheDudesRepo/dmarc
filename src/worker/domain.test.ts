import { describe, expect, it } from "vitest";
import { DomainValidationError, normalizeDomain } from "./domain";

describe("normalizeDomain", () => {
  it("normalizes case, surrounding space, and one DNS root dot", () => {
    expect(normalizeDomain("  Mail.Example.COM.  ")).toBe("mail.example.com");
  });

  it("converts an internationalized domain to ASCII", () => {
    expect(normalizeDomain("BÜCHER.example")).toBe("xn--bcher-kva.example");
  });

  it.each([
    "https://example.com",
    "user@example.com",
    "example.com/path",
    "example.com:443",
    "*.example.com",
    "_dmarc.example.com",
    "127.0.0.1",
    "localhost",
    "mail.example.local",
    "service.corp.internal",
    "example..com",
    "-bad.example",
    "bad-.example",
    "example.123",
  ])("rejects unsafe or non-public-domain input: %s", (value) => {
    expect(() => normalizeDomain(value)).toThrow(DomainValidationError);
  });

  it("rejects a label longer than 63 characters", () => {
    expect(() => normalizeDomain(`${"a".repeat(64)}.example`)).toThrow(/label/u);
  });

  it("rejects non-string values", () => {
    expect(() => normalizeDomain({ domain: "example.com" })).toThrow(/string/u);
  });
});
