import { describe, expect, it, vi } from "vitest";
import {
  DNS_TYPE_CODES,
  DnsClient,
  DnsQueryError,
  joinDnsTxtChunks,
  type DnsQueryType,
  type DnsTiming,
  type NativeDnsResolver,
} from "./dns";

const MYAVISTA_SPF_WORKERD =
  'v=spf1 include:u1791881.wl.sendgrid.net include:spf.protection.outlook.com include:aspmx.pardot.com ip4:198.181.21.221 ip4:198.181.21.222 ip4:198.181.30.101 ip4:198.251.0.114 ip4:198.251.4.1 ip4:198.251.4.2 ip4:198.251.4.3 ip4:198.251.4.4 ip4:198.251.4.5 " "include:_spf.salesforce.com -all';
const MYAVISTA_SPF = MYAVISTA_SPF_WORKERD.replace('" "', "");

const MYAVISTA_DKIM_WORKERD =
  'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp4ENNEyR6BISU0UPaRXz44n2tg77JdrU13T1VnMK+eEnPUzr4IRCO7vENNMEWUmBeDah2FInnxCQ5vro8cSjbAADlOcQSDj2M2F47H+SBn/EMZrOnHcT6I9KtiU6DboZGFkzVJt9IEW2TOmB/kMl2K7tJ2kCmwPeAO9L4TA3x+y2wSAu2WRv4onLxB0xNoR4n" "jeTiTgMalOLNi9xGVvPkCcrMG37XvCdZ/GqZfxLrkdgAhUWdoLwR5O+NDU9RWQnNOMFN1ysuDNQpkyxoU4J55PO61PdfKCYfs5cTk8eFt1Cc2tgY7QdzrrUAU5D3u6aE529Yy8I3paPGD0o8vxF1QIDAQAB;';
const MYAVISTA_DKIM = MYAVISTA_DKIM_WORKERD.replace('" "', "");

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
      refresh: 7200,
      retry: 3600,
      expire: 1_209_600,
      minttl: 300,
    }),
    resolveSrv: async () => [],
    resolveTxt: async () => [],
    ...overrides,
  };
}

function dnsError(code: string): Error & { code: string } {
  return Object.assign(new Error(code), { code });
}

async function flushMicrotasks(count = 4): Promise<void> {
  for (let index = 0; index < count; index += 1) await Promise.resolve();
}

function manualClock(): { timing: DnsTiming; advance: (milliseconds: number) => void } {
  let currentTime = 0;
  let nextHandle = 1;
  const timers = new Map<number, { due: number; callback: () => void }>();

  return {
    timing: {
      now: () => currentTime,
      setTimeout: (callback, delayMs) => {
        const handle = nextHandle;
        nextHandle += 1;
        timers.set(handle, { due: currentTime + delayMs, callback });
        return handle;
      },
      clearTimeout: (handle) => {
        if (typeof handle === "number") timers.delete(handle);
      },
    },
    advance: (milliseconds) => {
      currentTime += milliseconds;
      const due = [...timers.entries()]
        .filter(([, timer]) => timer.due <= currentTime)
        .sort((left, right) => left[1].due - right[1].due);
      for (const [handle, timer] of due) {
        timers.delete(handle);
        timer.callback();
      }
    },
  };
}

describe("Cloudflare native DNS resolver", () => {
  it("exposes exactly the ten RR types supported by Workerd's specific node:dns methods", () => {
    expect(DNS_TYPE_CODES).toEqual({
      A: 1,
      NS: 2,
      CNAME: 5,
      SOA: 6,
      PTR: 12,
      MX: 15,
      TXT: 16,
      AAAA: 28,
      SRV: 33,
      CAA: 257,
    });
  });

  it("dispatches native record types and formats their evidence consistently", async () => {
    const resolver = nativeResolver({
      resolve4: async () => [{ address: "192.0.2.10", ttl: 60 }],
      resolve6: async () => [{ address: "2001:db8::10", ttl: 120 }],
      resolveCaa: async () => [{ critical: 0, issue: "letsencrypt.org" }],
      resolveCname: async (name) => name === "alias.example.com" ? ["target.example.net."] : [],
      resolveMx: async () => [{ priority: 10, exchange: "mail.example.net." }],
      resolveNs: async () => ["ns1.example.net."],
      resolvePtr: async () => ["host.example.net."],
      resolveSoa: async () => ({
        nsname: "ns1.example.net.",
        hostmaster: "hostmaster.example.net.",
        serial: 2026081101,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minttl: 300,
      }),
      resolveSrv: async () => [{ priority: 10, weight: 5, port: 443, name: "service.example.net." }],
      resolveTxt: async () => [["v=spf1 ", "-all"]],
    });
    const client = new DnsClient({ resolver });

    await expect(client.query("Example.COM.", "A")).resolves.toEqual([
      { name: "example.com", type: "A", ttl: 60, data: "192.0.2.10" },
    ]);
    await expect(client.query("example.com", "AAAA")).resolves.toEqual([
      { name: "example.com", type: "AAAA", ttl: 120, data: "2001:db8::10" },
    ]);
    await expect(client.query("example.com", "CAA")).resolves.toEqual([
      { name: "example.com", type: "CAA", data: '0 issue "letsencrypt.org"' },
    ]);
    await expect(client.query("alias.example.com", "CNAME")).resolves.toEqual([
      { name: "alias.example.com", type: "CNAME", data: "target.example.net" },
    ]);
    await expect(client.query("example.com", "MX")).resolves.toEqual([
      { name: "example.com", type: "MX", data: "10 mail.example.net" },
    ]);
    await expect(client.query("example.com", "NS")).resolves.toEqual([
      { name: "example.com", type: "NS", data: "ns1.example.net" },
    ]);
    await expect(client.query("1.2.0.192.in-addr.arpa", "PTR")).resolves.toEqual([
      { name: "1.2.0.192.in-addr.arpa", type: "PTR", data: "host.example.net" },
    ]);
    await expect(client.query("example.com", "SOA")).resolves.toEqual([
      {
        name: "example.com",
        type: "SOA",
        data: "ns1.example.net hostmaster.example.net 2026081101 7200 3600 1209600 300",
      },
    ]);
    await expect(client.query("_https._tcp.example.com", "SRV")).resolves.toEqual([
      { name: "_https._tcp.example.com", type: "SRV", data: "10 5 443 service.example.net" },
    ]);
    await expect(client.query("example.com", "TXT")).resolves.toEqual([
      { name: "example.com", type: "TXT", data: "v=spf1 -all" },
    ]);
  });

  it("repairs the exact myavista.com SPF quote-boundary artifact", async () => {
    const client = new DnsClient({
      resolver: nativeResolver({ resolveTxt: async () => [[MYAVISTA_SPF_WORKERD]] }),
    });

    await expect(client.query("myavista.com", "TXT")).resolves.toEqual([
      { name: "myavista.com", type: "TXT", data: MYAVISTA_SPF },
    ]);
    expect(joinDnsTxtChunks([MYAVISTA_SPF.slice(0, -35), MYAVISTA_SPF.slice(-35)])).toBe(
      MYAVISTA_SPF,
    );
  });

  it("repairs the exact selector1 MyAvista DKIM quote-boundary artifact", async () => {
    const client = new DnsClient({
      resolver: nativeResolver({ resolveTxt: async () => [[MYAVISTA_DKIM_WORKERD]] }),
    });

    await expect(client.query("selector1._domainkey.myavista.com", "TXT")).resolves.toEqual([
      { name: "selector1._domainkey.myavista.com", type: "TXT", data: MYAVISTA_DKIM },
    ]);
  });

  it("repairs an adjacent Workerd quote boundary in structured email TXT data", () => {
    const flagged = MYAVISTA_DKIM.replace("R4n", 'R4n""');

    expect(joinDnsTxtChunks([flagged])).toBe(MYAVISTA_DKIM);
  });

  it("repairs DKIM records that put flags between the key type and public key", () => {
    const workerdValue = 'k=rsa; t=s; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" "MIIBCgKCAQEA';

    expect(joinDnsTxtChunks([workerdValue])).toBe(
      "k=rsa; t=s; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
    );
  });

  it("repairs DKIM chunk boundaries regardless of tag order when the owner is a DKIM selector", async () => {
    const client = new DnsClient({
      resolver: nativeResolver({
        resolveTxt: async () => [['h=sha256; k=rsa; n=rotation; p=MIIB""IjAN']],
      }),
    });

    await expect(client.query("selector._domainkey.example.com", "TXT")).resolves.toEqual([
      {
        name: "selector._domainkey.example.com",
        type: "TXT",
        data: "h=sha256; k=rsa; n=rotation; p=MIIBIjAN",
      },
    ]);
  });

  it("preserves legitimate quotes outside the DKIM public-key tag", () => {
    const value = 'v=DKIM1; n=Alice "" Bob; p=MIIB" "IjAN';

    expect(joinDnsTxtChunks([value], "selector._domainkey.example.com")).toBe(
      'v=DKIM1; n=Alice "" Bob; p=MIIBIjAN',
    );
  });

  it("normalizes Workerd's empty exchange for an RFC 7505 null MX", async () => {
    const client = new DnsClient({
      resolver: nativeResolver({ resolveMx: async () => [{ priority: 0, exchange: "" }] }),
    });

    await expect(client.query("example.com", "MX")).resolves.toEqual([
      { name: "example.com", type: "MX", data: "0 ." },
    ]);
  });

  it("follows a CNAME chain before resolving a terminal record type", async () => {
    const resolve4 = vi.fn<NativeDnsResolver["resolve4"]>(async (name) => {
      if (name !== "target.example.net") throw new Error(`unexpected A query for ${name}`);
      return [{ address: "192.0.2.25", ttl: 300 }];
    });
    const client = new DnsClient({
      resolver: nativeResolver({
        resolve4,
        resolveCname: async (name) => {
          if (name === "alias.example.com") return ["middle.example.net."];
          if (name === "middle.example.net") return ["target.example.net."];
          return [];
        },
      }),
    });

    await expect(client.queryFollowingCname("alias.example.com", "A")).resolves.toEqual({
      canonicalName: "target.example.net",
      aliases: [
        { name: "alias.example.com", type: "CNAME", data: "middle.example.net" },
        { name: "middle.example.net", type: "CNAME", data: "target.example.net" },
      ],
      answers: [
      { name: "target.example.net", type: "A", ttl: 300, data: "192.0.2.25" },
      ],
    });
    expect(resolve4).toHaveBeenCalledWith("target.example.net", { ttl: true });
  });

  it("rejects CNAME loops before querying the terminal record type", async () => {
    const resolve4 = vi.fn<NativeDnsResolver["resolve4"]>(async () => []);
    const client = new DnsClient({
      resolver: nativeResolver({
        resolve4,
        resolveCname: async (name) => [name === "a.example" ? "b.example" : "a.example"],
      }),
    });

    await expect(client.queryFollowingCname("a.example", "A")).rejects.toThrow(/CNAME loop/u);
    expect(resolve4).not.toHaveBeenCalled();
  });

  it("uses one deadline across a CNAME chain and its terminal query", async () => {
    const clock = manualClock();
    const resolve4 = vi.fn<NativeDnsResolver["resolve4"]>(async () => []);
    const resolveCname = vi.fn<NativeDnsResolver["resolveCname"]>(async (name) => {
      if (name === "a.example") {
        return new Promise<string[]>((resolve) => {
          clock.timing.setTimeout(() => resolve(["b.example"]), 60);
        });
      }
      return new Promise<string[]>(() => undefined);
    });
    const client = new DnsClient({
      resolver: nativeResolver({ resolve4, resolveCname }),
      timing: clock.timing,
      timeoutMs: 100,
    });
    const result = client.queryFollowingCname("a.example", "A").catch((error: unknown) => error);

    await flushMicrotasks(12);
    clock.advance(60);
    await flushMicrotasks(24);
    expect(resolveCname).toHaveBeenCalledTimes(2);
    clock.advance(40);
    const error = await result;

    expect(error).toBeInstanceOf(DnsQueryError);
    expect((error as Error).message).toMatch(/timed out/u);
    expect(resolve4).not.toHaveBeenCalled();
  });

  it("preserves separate TXT RRs and does not alter literal quotes in unrelated TXT data", async () => {
    const client = new DnsClient({
      resolver: nativeResolver({
        resolveTxt: async () => [
          ["v=spf1 ", "-all"],
          ['site-verification=literal" "value'],
        ],
      }),
    });

    await expect(client.query("example.com", "TXT")).resolves.toEqual([
      { name: "example.com", type: "TXT", data: "v=spf1 -all" },
      { name: "example.com", type: "TXT", data: 'site-verification=literal" "value' },
    ]);
  });

  it.each(["ENODATA", "ENOTFOUND", "NXDOMAIN"])(
    "maps %s to an absent RR set",
    async (code) => {
      const client = new DnsClient({
        resolver: nativeResolver({ resolveTxt: async () => Promise.reject(dnsError(code)) }),
      });
      await expect(client.query("missing.example", "TXT")).resolves.toEqual([]);
    },
  );

  it("retries a quick transient native resolver error once", async () => {
    const resolveTxt = vi
      .fn<NativeDnsResolver["resolveTxt"]>()
      .mockRejectedValueOnce(dnsError("ESERVFAIL"))
      .mockResolvedValueOnce([["v=spf1 -all"]]);
    const client = new DnsClient({ resolver: nativeResolver({ resolveTxt }) });

    await expect(client.query("example.com", "TXT")).resolves.toEqual([
      { name: "example.com", type: "TXT", data: "v=spf1 -all" },
    ]);
    expect(resolveTxt).toHaveBeenCalledTimes(2);
  });

  it("does not retry REFUSED and never converts it to absence", async () => {
    const resolveTxt = vi.fn<NativeDnsResolver["resolveTxt"]>(async () =>
      Promise.reject(dnsError("EREFUSED")),
    );
    const client = new DnsClient({ resolver: nativeResolver({ resolveTxt }) });

    await expect(client.query("example.com", "TXT")).rejects.toThrow(/REFUSED/u);
    expect(resolveTxt).toHaveBeenCalledTimes(1);
  });

  it("bounds a stalled native query to one overall deadline", async () => {
    const clock = manualClock();
    const resolveTxt = vi.fn<NativeDnsResolver["resolveTxt"]>(
      async () => new Promise<string[][]>(() => undefined),
    );
    const client = new DnsClient({
      resolver: nativeResolver({ resolveTxt }),
      timing: clock.timing,
      timeoutMs: 100,
    });
    const result = client.queryDirect("example.com", "TXT").catch((error: unknown) => error);

    await flushMicrotasks(12);
    expect(resolveTxt).toHaveBeenCalledTimes(1);
    clock.advance(100);
    const error = await result;
    expect(error).toBeInstanceOf(DnsQueryError);
    expect((error as Error).message).toMatch(/timed out/u);
    expect(resolveTxt).toHaveBeenCalledTimes(1);
  });

  it("caches normalized in-flight queries", async () => {
    const resolveTxt = vi.fn<NativeDnsResolver["resolveTxt"]>(async () => []);
    const client = new DnsClient({ resolver: nativeResolver({ resolveTxt }) });

    const first = client.query("Example.COM.", "TXT");
    const second = client.query("example.com", "TXT");
    expect(second).toBe(first);
    await first;
    expect(resolveTxt).toHaveBeenCalledTimes(1);
  });

  it("counts retries as native subrequests and never exceeds 48", async () => {
    const resolveCname = vi.fn<NativeDnsResolver["resolveCname"]>(async (name) => {
      if (name === "retry.example") throw dnsError("ESERVFAIL");
      return [];
    });
    const client = new DnsClient({ resolver: nativeResolver({ resolveCname }) });

    await Promise.all(Array.from({ length: 47 }, (_, index) => client.query(`host${index}.example`, "CNAME")));
    await expect(client.query("retry.example", "CNAME")).rejects.toThrow(/safety limit/u);
    await expect(client.query("blocked.example", "CNAME")).rejects.toThrow(/safety limit/u);
    expect(resolveCname).toHaveBeenCalledTimes(48);
  });

  it("queues native lookups above the six-connection Worker limit", async () => {
    let active = 0;
    let maximumActive = 0;
    const releases: Array<() => void> = [];
    const resolveCname = vi.fn<NativeDnsResolver["resolveCname"]>(
      async () =>
        new Promise<string[]>((resolve) => {
          active += 1;
          maximumActive = Math.max(maximumActive, active);
          releases.push(() => {
            active -= 1;
            resolve([]);
          });
        }),
    );
    const client = new DnsClient({ resolver: nativeResolver({ resolveCname }) });
    const lookups = Array.from({ length: 10 }, (_, index) => client.query(`host${index}.example`, "CNAME"));

    await flushMicrotasks();
    expect(resolveCname).toHaveBeenCalledTimes(6);
    expect(maximumActive).toBe(6);
    for (const release of releases.splice(0, 6)) release();
    await flushMicrotasks(12);
    expect(resolveCname).toHaveBeenCalledTimes(10);
    expect(maximumActive).toBe(6);
    for (const release of releases.splice(0)) release();
    await expect(Promise.all(lookups)).resolves.toHaveLength(10);
  });

  it("removes timed-out queued work without reusing slots held by stalled native calls", async () => {
    const clock = manualClock();
    const releases: Array<() => void> = [];
    const resolveCname = vi.fn<NativeDnsResolver["resolveCname"]>(
      async () => new Promise<string[]>((resolve) => releases.push(() => resolve([]))),
    );
    const client = new DnsClient({
      resolver: nativeResolver({ resolveCname }),
      timing: clock.timing,
      timeoutMs: 100,
    });
    const lookups = Array.from({ length: 7 }, (_, index) =>
      client.query(`stalled${index}.example`, "CNAME").catch((error: unknown) => error),
    );

    await flushMicrotasks(12);
    expect(resolveCname).toHaveBeenCalledTimes(6);
    clock.advance(100);
    const results = await Promise.all(lookups);
    expect(results.every((result) => result instanceof DnsQueryError)).toBe(true);

    for (const release of releases.splice(0)) release();
    await flushMicrotasks(20);
    expect(resolveCname).toHaveBeenCalledTimes(6);
  });

  it("rejects malformed or oversized native responses", async () => {
    const malformed = new DnsClient({
      resolver: nativeResolver({
        resolveMx: async () => [{ priority: -1, exchange: "mail.example" }],
      }),
    });
    const oversized = new DnsClient({
      resolver: nativeResolver({
        resolveTxt: async () => Array.from({ length: 257 }, () => ["value"]),
      }),
    });

    await expect(malformed.query("example.com", "MX")).rejects.toThrow(/malformed MX/u);
    await expect(oversized.query("example.com", "TXT")).rejects.toThrow(/malformed response data/u);
  });

  it("rejects invalid names, unsupported types, and timeout configuration before resolving", () => {
    const resolveTxt = vi.fn<NativeDnsResolver["resolveTxt"]>(async () => []);
    const client = new DnsClient({ resolver: nativeResolver({ resolveTxt }) });

    expect(() => client.query("https://example.com", "TXT")).toThrow(/invalid DNS query name/u);
    expect(() => client.query("-bad.example", "TXT")).toThrow(/invalid DNS query name/u);
    expect(() => client.query("example.com", "DNSKEY" as DnsQueryType)).toThrow(/unsupported DNS query type/u);
    expect(() => new DnsClient({ timeoutMs: 0 })).toThrow(/invalid DNS timeout/u);
    expect(resolveTxt).not.toHaveBeenCalled();
  });
});
