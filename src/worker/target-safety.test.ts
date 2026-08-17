import { describe, expect, it } from "vitest";
import {
  canonicalPublicScanAddress,
  resolvePublicHost,
  ScanTargetResolutionError,
  selectDeepTlsEndpoints,
  UnsafeScanTargetError,
} from "./target-safety";

describe("security assessment target safety", () => {
  it("canonicalizes and de-duplicates an exclusively public DNS answer", async () => {
    await expect(resolvePublicHost("example.com", async () => [
      "8.8.8.8",
      "2606:4700:4700:0:0:0:0:1111",
      "2606:4700:4700::1111",
    ])).resolves.toEqual(["2606:4700:4700::1111", "8.8.8.8"]);
  });

  it.each([
    "127.0.0.1",
    "10.0.0.1",
    "169.254.169.254",
    "::1",
    "fc00::1",
    "::ffff:127.0.0.1",
    "64:ff9b::808:808",
    "2002:0808:0808::1",
    "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
  ])("rejects private, special, mapped, translation, and transition address %s", async (address) => {
    await expect(resolvePublicHost("example.com", async () => [address])).rejects.toBeInstanceOf(UnsafeScanTargetError);
    expect(() => canonicalPublicScanAddress(address)).toThrow(UnsafeScanTargetError);
  });

  it("rejects mixed public/private answers instead of selecting only the public member", async () => {
    await expect(resolvePublicHost("example.com", async () => ["8.8.8.8", "127.0.0.1"]))
      .rejects.toBeInstanceOf(UnsafeScanTargetError);
  });

  it("distinguishes an empty public DNS answer from an unsafe one", async () => {
    await expect(resolvePublicHost("example.com", async () => []))
      .rejects.toBeInstanceOf(ScanTargetResolutionError);
  });

  it("caps and balances selected deep endpoints across address families", () => {
    expect(selectDeepTlsEndpoints([
      "8.8.8.8",
      "1.1.1.1",
      "9.9.9.9",
      "2606:4700:4700::1111",
      "2001:4860:4860::8888",
      "2620:fe::fe",
    ])).toEqual([
      "1.1.1.1",
      "8.8.8.8",
      "2001:4860:4860::8888",
      "2606:4700:4700::1111",
    ]);
  });
});
