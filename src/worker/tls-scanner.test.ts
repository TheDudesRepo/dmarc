import { describe, expect, it, vi } from "vitest";
import {
  scanTlsConfiguration,
  TlsProbeError,
  type TlsConnectionEvidence,
  type TlsConnector,
  type TlsConnectorInput,
} from "./tls-scanner";

const NOW = Date.parse("2026-08-16T12:00:00.000Z");

function trustedEvidence(overrides: Partial<TlsConnectionEvidence> = {}): TlsConnectionEvidence {
  return {
    authorized: true,
    hostnameValid: true,
    protocol: "TLSv1.3",
    cipher: {
      name: "TLS_AES_256_GCM_SHA384",
      standardName: "TLS_AES_256_GCM_SHA384",
      version: "TLSv1.3",
      bits: 256,
    },
    alpnProtocol: "h2",
    ephemeralKey: "ECDH · X25519 · 253 bits",
    certificate: {
      subject: "CN=example.com",
      issuer: "CN=Example CA",
      subjectAltNames: ["DNS:example.com"],
      validFrom: "2026-01-01T00:00:00.000Z",
      validTo: "2027-01-01T00:00:00.000Z",
      fingerprint256: "AA:BB",
      bits: 2048,
    },
    certificateChain: [{
      subject: "CN=example.com",
      issuer: "CN=Example CA",
      subjectAltNames: ["DNS:example.com"],
      validFrom: "2026-01-01T00:00:00.000Z",
      validTo: "2027-01-01T00:00:00.000Z",
    }],
    ...overrides,
  };
}

function modernConnector(calls: TlsConnectorInput[]): TlsConnector {
  return async (input) => {
    calls.push(input);
    if (input.weakCipherOnly || input.protocol === "TLSv1" || input.protocol === "TLSv1.1") {
      throw new TlsProbeError("rejected", "not negotiated");
    }
    return trustedEvidence({
      protocol: input.protocol ?? "TLSv1.3",
      cipher: input.protocol === "TLSv1.2"
        ? { name: "ECDHE-RSA-AES128-GCM-SHA256", version: "TLSv1.2", bits: 128 }
        : trustedEvidence().cipher,
    });
  };
}

describe("bounded TLS posture scanner", () => {
  it("uses an absolute handshake deadline even while a connector reports periodic activity", async () => {
    vi.useFakeTimers();
    let activityTicks = 0;
    try {
      const connector: TlsConnector = async (input) => new Promise<TlsConnectionEvidence>((_resolve, reject) => {
        const activity = setInterval(() => {
          activityTicks += 1;
        }, 250);
        input.signal?.addEventListener("abort", () => {
          clearInterval(activity);
          reject(input.signal?.reason);
        }, { once: true });
      });

      const scan = scanTlsConfiguration("example.com", ["93.184.216.34"], { connector });
      let settled = false;
      void scan.then(() => {
        settled = true;
      });

      await vi.advanceTimersByTimeAsync(3_499);
      expect(settled).toBe(false);
      expect(activityTicks).toBeGreaterThan(1);

      await vi.advanceTimersByTimeAsync(1);
      const result = await scan;
      expect(result.connectionCount).toBe(1);
      expect(result.assessment.status).toBe("unavailable");
      expect(result.assessment.grade).toBe("N/A");
      expect(result.assessment.endpoints[0]).toEqual(expect.objectContaining({ status: "unreachable" }));
    } finally {
      vi.useRealTimers();
    }
  });

  it("pins one representative address per family and grades modern fixed profiles", async () => {
    const calls: TlsConnectorInput[] = [];

    const result = await scanTlsConfiguration(
      "example.com",
      ["93.184.216.34", "93.184.216.35", "2606:2800:220:1:248:1893:25c8:1946"],
      { connector: modernConnector(calls), now: () => NOW },
    );

    expect(result.connectionCount).toBe(12);
    expect(calls).toHaveLength(12);
    expect(new Set(calls.map((call) => call.address))).toEqual(new Set([
      "93.184.216.34",
      "2606:2800:220:1:248:1893:25c8:1946",
    ]));
    expect(calls.every((call) => call.hostname === "example.com")).toBe(true);
    expect(result.assessment).toEqual(expect.objectContaining({
      status: "complete",
      grade: "A",
      endpointsTruncated: true,
      resolvedAddresses: ["93.184.216.34", "93.184.216.35", "2606:2800:220:1:248:1893:25c8:1946"],
    }));
    expect(result.assessment.endpoints[0]?.certificate?.daysRemaining).toBe(137);
    expect(result.assessment.reportUrl).toContain("ssllabs.com/ssltest/analyze.html");
    expect(result.assessment.limitations.join(" ")).toContain("not an SSL Labs-equivalent");
  });

  it("treats a platform socket restriction as unavailable evidence, never a TLS failure", async () => {
    const connector = vi.fn<TlsConnector>().mockRejectedValue(
      new TlsProbeError("platform-blocked", "Cloudflare destination blocked"),
    );

    const result = await scanTlsConfiguration("example.com", ["104.16.1.1"], { connector });

    expect(connector).toHaveBeenCalledOnce();
    expect(result.connectionCount).toBe(1);
    expect(result.assessment.status).toBe("unavailable");
    expect(result.assessment.grade).toBe("N/A");
    expect(result.assessment.endpoints[0]).toEqual(expect.objectContaining({ status: "platform-blocked" }));
    expect(result.assessment.endpoints[0]).not.toHaveProperty("authorized");
    expect(result.assessment.endpoints[0]).not.toHaveProperty("hostnameValid");
    expect(result.assessment.summary).toContain("No TLS failure was inferred");
  });

  it("marks incomplete version evidence partial and fails an untrusted certificate", async () => {
    const connector: TlsConnector = async (input) => {
      if (!input.protocol && !input.weakCipherOnly) {
        return trustedEvidence({
          authorized: false,
          authorizationError: "CERT_HAS_EXPIRED",
        });
      }
      if (input.protocol === "TLSv1.2") {
        throw new TlsProbeError("timeout", "timeout");
      }
      if (input.protocol === "TLSv1.3") return trustedEvidence();
      throw new TlsProbeError("rejected", "not negotiated");
    };

    const result = await scanTlsConfiguration("example.com", ["93.184.216.34"], { connector });

    expect(result.assessment.status).toBe("partial");
    expect(result.assessment.grade).toBe("F");
    expect(result.assessment.endpoints[0]?.protocols).toContainEqual(expect.objectContaining({
      version: "TLSv1.2",
      status: "unknown",
    }));
  });

  it("does not downgrade the TLS grade when fixed version probes are unknown", async () => {
    const connector: TlsConnector = async (input) => {
      if (!input.protocol && !input.weakCipherOnly) return trustedEvidence({ protocol: "TLSv1.3" });
      throw new TlsProbeError("timeout", "timeout");
    };

    const result = await scanTlsConfiguration("example.com", ["93.184.216.34"], { connector });

    expect(result.assessment.status).toBe("partial");
    expect(result.assessment.grade).toBe("A");
    expect(result.assessment.endpoints[0]?.protocols.every((protocol) => protocol.status === "unknown")).toBe(true);
  });
});
