import { describe, expect, it, vi } from "vitest";
import {
  DNS_TYPE_CODES,
  DnsClient,
  DnsQueryError,
  type DnsFetch,
  type DnsQueryType,
  type DnsTiming,
} from "./dns";

function dnsJson(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/dns-json" },
  });
}

function flushMicrotasks(): Promise<void> {
  return new Promise((resolve) => queueMicrotask(() => queueMicrotask(resolve)));
}

async function flushMicrotasksRepeatedly(count = 8): Promise<void> {
  for (let index = 0; index < count; index += 1) await flushMicrotasks();
}

function manualClock(): {
  timing: DnsTiming;
  advance: (milliseconds: number) => void;
} {
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
      const dueTimers = [...timers.entries()]
        .filter(([, timer]) => timer.due <= currentTime)
        .sort((left, right) => left[1].due - right[1].due);
      for (const [handle, timer] of dueTimers) {
        timers.delete(handle);
        timer.callback();
      }
    },
  };
}

describe("Google DNS JSON resolver", () => {
  it("uses the fixed endpoint, a numeric validated type, and a normalized name", async () => {
    const fetchMock = vi.fn<DnsFetch>(async () => dnsJson({ Status: 0 }));
    const client = new DnsClient({ fetch: fetchMock });

    await client.query("Example.COM.", "TXT");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    const requestUrl = new URL(url ?? "");
    expect(requestUrl.origin + requestUrl.pathname).toBe("https://dns.google/resolve");
    expect(requestUrl.searchParams.get("name")).toBe("example.com");
    expect(requestUrl.searchParams.get("type")).toBe("16");
    expect(init).toMatchObject({
      method: "GET",
      redirect: "error",
      headers: { Accept: "application/dns-json" },
    });
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("supports the complete reusable query-type map", () => {
    expect(DNS_TYPE_CODES).toEqual({
      A: 1,
      NS: 2,
      CNAME: 5,
      SOA: 6,
      PTR: 12,
      MX: 15,
      TXT: 16,
      AAAA: 28,
      LOC: 29,
      SRV: 33,
      CERT: 37,
      DS: 43,
      IPSECKEY: 45,
      RRSIG: 46,
      NSEC: 47,
      DNSKEY: 48,
      NSEC3PARAM: 51,
      TLSA: 52,
      CAA: 257,
    });
  });

  it("preserves TXT RR boundaries and joins character-string chunks within each RR", async () => {
    const client = new DnsClient({
      fetch: async () =>
        dnsJson({
          Status: 0,
          Answer: [
            { name: "example.com.", type: 16, TTL: 300, data: '"first" "second"' },
            { name: "example.com.", type: 16, TTL: 120, data: '"third"' },
            { name: "example.com.", type: 5, TTL: 60, data: "alias.example.net." },
          ],
        }),
    });

    await expect(client.query("example.com", "TXT")).resolves.toEqual([
      { name: "example.com", type: "TXT", ttl: 300, data: "firstsecond" },
      { name: "example.com", type: "TXT", ttl: 120, data: "third" },
    ]);
  });

  it.each([
    ["MX", "10 mail.example.com.", "10 mail.example.com"],
    ["NS", "ns1.example.com.", "ns1.example.com"],
    ["CNAME", "target.example.com.", "target.example.com"],
    ["SOA", "ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300", "ns1.example.com hostmaster.example.com 1 7200 3600 1209600 300"],
    ["SRV", "10 5 443 service.example.com.", "10 5 443 service.example.com"],
    ["PTR", "host.example.com.", "host.example.com"],
    ["CAA", '0 issue "letsencrypt.org"', '0 issue "letsencrypt.org"'],
  ] satisfies Array<[DnsQueryType, string, string]>)
  ("formats %s data readably while retaining the owner and TTL", async (type, data, expected) => {
    const client = new DnsClient({
      fetch: async () =>
        dnsJson({
          Status: 0,
          Answer: [{ name: "Example.COM.", type: DNS_TYPE_CODES[type], TTL: 600, data }],
        }),
    });

    await expect(client.query("example.com", type)).resolves.toEqual([
      { name: "example.com", type, ttl: 600, data: expected },
    ]);
  });

  it("treats NOERROR without the requested RR and NXDOMAIN as absence", async () => {
    const noData = new DnsClient({
      fetch: async () =>
        dnsJson({
          Status: 0,
          Answer: [{ name: "example.com.", type: 5, TTL: 60, data: "alias.example.net." }],
        }),
    });
    const noDomain = new DnsClient({ fetch: async () => dnsJson({ Status: 3 }) });

    await expect(noData.query("example.com", "TXT")).resolves.toEqual([]);
    await expect(noDomain.query("missing.example", "TXT")).resolves.toEqual([]);
  });

  it("retries SERVFAIL once but never converts it to absence", async () => {
    const fetchMock = vi.fn<DnsFetch>(async () => dnsJson({ Status: 2 }));
    const client = new DnsClient({ fetch: fetchMock });

    await expect(client.query("example.com", "TXT")).rejects.toThrow(/SERVFAIL/u);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each([
    [5, "REFUSED"],
    [1, "DNS status 1"],
  ])("rejects DNS status %i without retrying", async (status, message) => {
    const fetchMock = vi.fn<DnsFetch>(async () => dnsJson({ Status: status }));
    const client = new DnsClient({ fetch: fetchMock });

    await expect(client.query("example.com", "TXT")).rejects.toThrow(message);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries a transient HTTP failure within the same query budget", async () => {
    const fetchMock = vi
      .fn<DnsFetch>()
      .mockResolvedValueOnce(dnsJson({ error: "temporary" }, 503))
      .mockResolvedValueOnce(dnsJson({ Status: 0 }));
    const client = new DnsClient({ fetch: fetchMock });

    await expect(client.query("example.com", "TXT")).resolves.toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("rejects non-transient HTTP failures without retrying", async () => {
    const fetchMock = vi.fn<DnsFetch>(async () => dnsJson({ error: "bad request" }, 400));
    const client = new DnsClient({ fetch: fetchMock });

    await expect(client.query("example.com", "TXT")).rejects.toThrow(/HTTP 400/u);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries malformed JSON once, then returns a typed resolver error", async () => {
    const fetchMock = vi.fn<DnsFetch>(async () => new Response("{", { status: 200 }));
    const client = new DnsClient({ fetch: fetchMock });

    const result = client.query("example.com", "TXT").catch((error: unknown) => error);
    expect(await result).toBeInstanceOf(DnsQueryError);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("rejects oversized DNS JSON before parsing or retrying", async () => {
    const fetchMock = vi.fn<DnsFetch>(async () =>
      new Response("{}", {
        status: 200,
        headers: { "content-length": "262145" },
      }),
    );
    const client = new DnsClient({ fetch: fetchMock });

    await expect(client.query("example.com", "TXT")).rejects.toThrow(/safety limit/u);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects implausibly large answer sets", async () => {
    const fetchMock = vi.fn<DnsFetch>(async () =>
      dnsJson({
        Status: 0,
        Answer: Array.from({ length: 257 }, () => ({
          name: "example.com.",
          type: 16,
          TTL: 60,
          data: '"value"',
        })),
      }),
    );
    const client = new DnsClient({ fetch: fetchMock });

    await expect(client.query("example.com", "TXT")).rejects.toThrow(/safety limit/u);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("bounds both timed-out attempts inside one injected overall deadline", async () => {
    const clock = manualClock();
    const signals: AbortSignal[] = [];
    const fetchMock = vi.fn<DnsFetch>(
      async (_url, init) =>
        new Promise<Response>(() => {
          if (init.signal) signals.push(init.signal);
        }),
    );
    const client = new DnsClient({ fetch: fetchMock, timing: clock.timing, timeoutMs: 100 });
    const result = client.query("example.com", "TXT").catch((error: unknown) => error);

    await flushMicrotasks();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    clock.advance(50);
    await flushMicrotasks();
    await flushMicrotasks();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(signals[0]?.aborted).toBe(true);

    clock.advance(50);
    const error = await result;
    expect(error).toBeInstanceOf(DnsQueryError);
    expect((error as Error).message).toMatch(/timed out/u);
    expect(signals[1]?.aborted).toBe(true);
  });

  it("caches each normalized name and type, including in-flight work", async () => {
    const fetchMock = vi.fn<DnsFetch>(async () => dnsJson({ Status: 0 }));
    const client = new DnsClient({ fetch: fetchMock });

    const first = client.query("Example.COM.", "TXT");
    const second = client.query("example.com", "TXT");

    expect(second).toBe(first);
    await expect(first).resolves.toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("counts retries as actual subrequests and never exceeds 48", async () => {
    const fetchMock = vi.fn<DnsFetch>(async (url) => {
      const name = new URL(url).searchParams.get("name");
      return dnsJson({ Status: name === "retry.example" ? 2 : 0 });
    });
    const client = new DnsClient({ fetch: fetchMock });

    await Promise.all(
      Array.from({ length: 47 }, (_, index) => client.query(`host${index}.example`, "TXT")),
    );
    await expect(client.query("retry.example", "TXT")).rejects.toThrow(/safety limit/u);
    await expect(client.query("blocked.example", "TXT")).rejects.toThrow(/safety limit/u);
    expect(fetchMock).toHaveBeenCalledTimes(48);
  });

  it("queues lookups above the Worker outbound-connection limit", async () => {
    let active = 0;
    let maximumActive = 0;
    const releases: Array<() => void> = [];
    const fetchMock = vi.fn<DnsFetch>(
      async () =>
        new Promise<Response>((resolve) => {
          active += 1;
          maximumActive = Math.max(maximumActive, active);
          releases.push(() => {
            active -= 1;
            resolve(dnsJson({ Status: 0 }));
          });
        }),
    );
    const client = new DnsClient({ fetch: fetchMock });
    const lookups = Array.from({ length: 10 }, (_, index) => client.query(`host${index}.example`, "TXT"));

    await flushMicrotasks();
    expect(fetchMock).toHaveBeenCalledTimes(6);
    expect(maximumActive).toBe(6);

    for (const release of releases.splice(0, 6)) release();
    await flushMicrotasksRepeatedly();
    expect(fetchMock).toHaveBeenCalledTimes(10);
    expect(maximumActive).toBe(6);

    for (const release of releases.splice(0)) release();
    await expect(Promise.all(lookups)).resolves.toHaveLength(10);
  });

  it("rejects invalid names, types, and timeout configuration before fetching", () => {
    const fetchMock = vi.fn<DnsFetch>(async () => dnsJson({ Status: 0 }));
    const client = new DnsClient({ fetch: fetchMock });

    expect(() => client.query("https://example.com", "TXT")).toThrow(/invalid DNS query name/u);
    expect(() => client.query("-bad.example", "TXT")).toThrow(/invalid DNS query name/u);
    expect(() => client.query("example.com", "ANY" as DnsQueryType)).toThrow(/invalid DNS query type/u);
    expect(() => new DnsClient({ timeoutMs: 0 })).toThrow(/invalid DNS timeout/u);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
