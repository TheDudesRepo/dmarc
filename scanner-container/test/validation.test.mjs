import assert from "node:assert/strict";
import { test } from "node:test";
import { assertPublicAddress } from "../src/ip-policy.mjs";
import { validateScanRequest } from "../src/validation.mjs";

test("accepts only the exact safe request schema", () => {
  const input = {
    hostname: "example.com",
    address: "93.184.216.34",
    profile: "safe",
    deadlineMs: 180_000,
  };
  const result = validateScanRequest(input);
  assert.equal(result.addressFamily, 4);
  for (const change of [
    { extra: true },
    { profile: "full" },
    { deadlineMs: 119_999 },
    { deadlineMs: 180_001 },
    { hostname: "https://example.com" },
    { hostname: "EXAMPLE.COM" },
    { hostname: "example.local" },
    { address: "127.0.0.1" },
  ]) {
    assert.throws(() => validateScanRequest({ ...input, ...change }), /request|profile|deadline|hostname|address/u);
  }
});

test("independently rejects special-use and transition addresses", () => {
  assert.equal(assertPublicAddress("8.8.8.8").family, 4);
  assert.equal(assertPublicAddress("192.0.0.9").family, 4);
  assert.equal(assertPublicAddress("2606:4700:4700::1111").family, 6);
  for (const address of [
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "169.254.1.1",
    "192.0.2.1",
    "198.18.0.1",
    "224.0.0.1",
    "::1",
    "fc00::1",
    "fe80::1",
    "ff02::1",
    "2001:db8::1",
    "64:ff9b::808:808",
    "2002:0808:0808::1",
    "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
    "::ffff:8.8.8.8",
  ]) assert.throws(() => assertPublicAddress(address), /address/u, address);
});
