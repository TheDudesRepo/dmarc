import { describe, expect, it, vi } from "vitest";
import type { TlsAssessment, WebSecurityCheckId } from "../shared/types";
import {
  scanWebSecurity,
  WebSecurityTargetError,
  type WebSecurityFetcher,
  type WebSecurityResolver,
  type WebSecurityTlsScanner,
} from "./web-security";

const NOW = Date.parse("2026-08-16T12:00:00.000Z");
const PUBLIC_ADDRESS = "8.8.8.8";
const IDS: readonly WebSecurityCheckId[] = [
  "https-enforcement",
  "hsts",
  "content-security-policy",
  "frame-protection",
  "mime-sniffing",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-isolation",
  "cors-policy",
  "http-methods",
  "cookie-secure",
  "cookie-httponly",
  "cookie-samesite",
  "cookie-scope-prefix",
  "cache-control",
  "technology-disclosure",
  "error-handling",
  "mixed-content",
  "form-transport",
  "subresource-integrity",
] as const;

const unavailableTls: TlsAssessment = {
  status: "unavailable",
  grade: "N/A",
  summary: "TLS test stub",
  resolvedAddresses: [PUBLIC_ADDRESS],
  endpoints: [],
  endpointsTruncated: false,
  reportUrl: "https://www.ssllabs.com/ssltest/analyze.html?d=example.com",
  limitations: ["test stub"],
};

const tlsScanner: WebSecurityTlsScanner = async () => ({
  assessment: unavailableTls,
  connectionCount: 0,
});

const stableResolver: WebSecurityResolver = async () => [PUBLIC_ADDRESS];

function secureHeaders(extra: HeadersInit = {}): Headers {
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; script-src 'nonce-test123'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
    server: "example-edge",
  });
  const additions = new Headers(extra);
  additions.forEach((value, key) => headers.set(key, value));
  return headers;
}

function standardFetcher(
  calls: Array<{ url: string; method: string; target: readonly string[] }>,
  options: {
    mainHeaders?: Headers;
    mainHtml?: string;
    httpStatus?: number;
    httpLocation?: string;
    optionsStatus?: number;
    allow?: string;
    errorStatus?: number;
    errorBody?: string;
  } = {},
): WebSecurityFetcher {
  return async (input, init, target) => {
    const method = String(init.method ?? "GET");
    calls.push({ url: input, method, target: target.validatedAddresses });
    const url = new URL(input);
    if (url.protocol === "http:") {
      return new Response(null, {
        status: options.httpStatus ?? 308,
        headers: options.httpLocation === ""
          ? undefined
          : { location: options.httpLocation ?? "https://example.com/" },
      });
    }
    if (method === "OPTIONS") {
      return new Response(null, {
        status: options.optionsStatus ?? 204,
        headers: options.allow === "" ? undefined : { allow: options.allow ?? "GET, HEAD, OPTIONS" },
      });
    }
    if (url.pathname.startsWith("/.well-known/dmarc-ready-probe-")) {
      return new Response(options.errorBody ?? "Not found", {
        status: options.errorStatus ?? 404,
        headers: { "content-type": "text/plain" },
      });
    }
    return new Response(options.mainHtml ?? "<!doctype html><title>Safe</title>", {
      status: 200,
      headers: options.mainHeaders ?? secureHeaders(),
    });
  };
}

async function run(fetcher: WebSecurityFetcher) {
  return scanWebSecurity("example.com", {
    resolver: stableResolver,
    fetcher,
    tlsScanner,
    now: () => NOW,
    nonce: () => "fixed-nonce-1234",
  });
}

function check(result: Awaited<ReturnType<typeof run>>, id: WebSecurityCheckId) {
  const value = result.checks.find((candidate) => candidate.id === id);
  if (!value) throw new Error(`Missing check ${id}`);
  return value;
}

describe("bounded web security scan", () => {
  it("returns the fixed 20 OWASP-aligned checks and uses only four ordinary probes", async () => {
    const calls: Array<{ url: string; method: string; target: readonly string[] }> = [];
    const result = await run(standardFetcher(calls));

    expect(result.checks.map((candidate) => candidate.id)).toEqual(IDS);
    expect(result.checks).toHaveLength(20);
    expect(result.checks.every((candidate) =>
      candidate.owasp.top10.length > 0 && candidate.owasp.wstg.length > 0)).toBe(true);
    expect(result.grade).toBe("A");
    expect(result.score).toBe(100);
    expect(result.coverage).toEqual({ evaluated: 13, total: 20, unknown: 0, notApplicable: 7 });
    expect(result.requestBudget).toEqual({
      httpRequests: 4,
      tlsConnections: 0,
      maxResponseBytes: 131_072,
      redirectHopsFollowed: 0,
    });
    expect(calls.map((call) => call.method)).toEqual(["HEAD", "GET", "OPTIONS", "GET"]);
    expect(calls.at(-1)?.url).toBe("https://example.com/.well-known/dmarc-ready-probe-fixed-nonce-1234");
    expect(calls.every((call) => call.target.join() === PUBLIC_ADDRESS)).toBe(true);
  });

  it.each([
    ["HTTPS enforcement", "https-enforcement"],
    ["HSTS", "hsts"],
    ["CSP", "content-security-policy"],
  ] as const)("requires bounded critical %s evidence before assigning a letter grade", async (_label, criticalId) => {
    const headers = secureHeaders();
    const fetchOptions: Parameters<typeof standardFetcher>[1] = { mainHeaders: headers };
    if (criticalId === "https-enforcement") {
      fetchOptions.httpStatus = 405;
      fetchOptions.httpLocation = "";
    } else if (criticalId === "hsts") {
      headers.set("strict-transport-security", `max-age=31536000; includeSubDomains; x=${"a".repeat(8_192)}`);
    } else {
      headers.set(
        "content-security-policy",
        `${headers.get("content-security-policy")}; report-uri /${"a".repeat(8_192)}`,
      );
    }

    const result = await run(standardFetcher([], fetchOptions));
    expect(check(result, criticalId).status).toBe("unknown");
    expect(result.grade).toBe("N/A");
    expect(result.summary).toContain("requires bounded HTTPS enforcement, HSTS, and CSP evidence");
  });

  it("uses applicable check weight rather than check count for the 70% grade threshold", async () => {
    const headers = secureHeaders({ "cache-control": "no-store" });
    for (let index = 0; index < 33; index += 1) {
      headers.append(
        "set-cookie",
        `session${index}=value; Secure; HttpOnly; SameSite=Lax; Path=/`,
      );
    }
    const html = [
      '<meta name="generator" content="Example Framework">',
      '<form action="https://example.com/login" method="get"><input type="password"></form>',
      '<script src="https://cdn.example.net/app.js"></script>',
      "a".repeat(131_072),
    ].join("");

    const result = await run(standardFetcher([], {
      mainHeaders: headers,
      mainHtml: html,
      optionsStatus: 405,
      allow: "",
    }));

    expect(result.coverage).toEqual({ evaluated: 14, total: 20, unknown: 6, notApplicable: 0 });
    expect(check(result, "https-enforcement").status).toBe("pass");
    expect(check(result, "hsts").status).toBe("pass");
    expect(check(result, "content-security-policy").status).toBe("pass");
    expect(check(result, "mixed-content").status).toBe("unknown");
    expect(result.grade).toBe("N/A");
    expect(result.summary).toContain("Less than 70% of applicable check weight");
  });

  it("evaluates common session cookies but leaves ordinary analytics cookies not applicable", async () => {
    const sessionHeaders = secureHeaders({ "cache-control": "no-store" });
    sessionHeaders.append("set-cookie", "JSESSIONID=abc; Secure; HttpOnly; SameSite=Lax; Path=/");
    const sessionResult = await run(standardFetcher([], { mainHeaders: sessionHeaders }));

    expect(check(sessionResult, "cookie-secure").status).toBe("pass");
    expect(check(sessionResult, "cookie-httponly").status).toBe("pass");
    expect(check(sessionResult, "cookie-samesite").status).toBe("pass");
    expect(check(sessionResult, "cookie-scope-prefix").status).toBe("pass");
    expect(check(sessionResult, "cache-control").status).toBe("pass");

    const analyticsHeaders = secureHeaders();
    analyticsHeaders.append("set-cookie", "_ga=value; Path=/");
    const analyticsResult = await run(standardFetcher([], { mainHeaders: analyticsHeaders }));
    for (const id of ["cookie-secure", "cookie-httponly", "cookie-samesite", "cookie-scope-prefix"] as const) {
      expect(check(analyticsResult, id).status).toBe("not-applicable");
      expect(check(analyticsResult, id).summary).toContain("no session or security-prefixed cookie");
    }
  });

  it("detects unsafe CORS and declared TRACE without sending either exploit request", async () => {
    const headers = secureHeaders({
      "access-control-allow-origin": "*",
      "access-control-allow-credentials": "true",
    });
    const calls: Array<{ url: string; method: string; target: readonly string[] }> = [];
    const result = await run(standardFetcher(calls, { mainHeaders: headers, allow: "GET, HEAD, TRACE" }));

    expect(check(result, "cors-policy").status).toBe("fail");
    expect(check(result, "http-methods").status).toBe("fail");
    expect(calls.some((call) => call.method === "TRACE")).toBe(false);
  });

  it("treats an OPTIONS rejection as unknown rather than proof that dangerous methods are disabled", async () => {
    const result = await run(standardFetcher([], { optionsStatus: 405, allow: "" }));
    expect(check(result, "http-methods").status).toBe("unknown");
  });

  it("caps the grade at F for a confirmed cleartext HTTP content response", async () => {
    const result = await run(standardFetcher([], { httpStatus: 200, httpLocation: "" }));
    expect(check(result, "https-enforcement").status).toBe("fail");
    expect(result.score).toBeGreaterThanOrEqual(70);
    expect(result.grade).toBe("F");
  });

  it("does not follow a redirect to another public hostname and reports it for review", async () => {
    const calls: Array<{ url: string; method: string; target: readonly string[] }> = [];
    const result = await run(standardFetcher(calls, {
      httpStatus: 302,
      httpLocation: "https://elsewhere.net/path",
    }));

    expect(check(result, "https-enforcement").status).toBe("warning");
    expect(calls.some((call) => call.url.includes("elsewhere.net"))).toBe(false);
  });

  it("rejects an HTTPS redirect to an IP literal without making a request to it", async () => {
    const calls: string[] = [];
    const fetcher: WebSecurityFetcher = async (input, init) => {
      calls.push(input);
      if (String(init.method) === "HEAD") {
        return new Response(null, { status: 308, headers: { location: "https://example.com/" } });
      }
      return new Response(null, { status: 302, headers: { location: "https://127.0.0.1/admin" } });
    };

    const result = await run(fetcher);

    expect(check(result, "https-enforcement").status).toBe("fail");
    expect(result.grade).toBe("F");
    expect(calls).toEqual(["http://example.com/", "https://example.com/"]);
  });

  it("uses a generated-nonce 404 and flags bounded internal error detail", async () => {
    const result = await run(standardFetcher([], {
      errorStatus: 500,
      errorBody: "Traceback (most recent call last) /var/www/app/main.py",
    }));
    expect(check(result, "error-handling").status).toBe("fail");
  });

  it("marks body-derived checks unknown when the 128 KiB HTML cap is reached", async () => {
    const oversized = "a".repeat(131_072) + '<script src="http://late.example/script.js"></script>';
    const result = await run(standardFetcher([], { mainHtml: oversized }));

    expect(check(result, "mixed-content").status).toBe("unknown");
    expect(check(result, "form-transport").status).toBe("unknown");
    expect(result.requestBudget.maxResponseBytes).toBe(131_072);
  });

  it("stops HTTP work at the aggregate deadline after TLS consumes the budget", async () => {
    let clock = NOW;
    const fetcher = vi.fn<WebSecurityFetcher>();
    const slowTls: WebSecurityTlsScanner = async () => {
      clock += 29_000;
      return { assessment: unavailableTls, connectionCount: 1 };
    };
    const result = await scanWebSecurity("example.com", {
      resolver: stableResolver,
      fetcher,
      tlsScanner: slowTls,
      now: () => clock,
      nonce: () => "fixed-nonce-1234",
    });

    expect(fetcher).not.toHaveBeenCalled();
    expect(result.durationMs).toBe(29_000);
    expect(result.requestBudget.httpRequests).toBe(0);
    expect(result.grade).toBe("N/A");
  });

  it("rejects an overlong redirect rather than following a truncated Location value", async () => {
    const calls: string[] = [];
    const fetcher: WebSecurityFetcher = async (input, init) => {
      calls.push(input);
      if (String(init.method) === "HEAD") {
        return new Response(null, {
          status: 301,
          headers: { location: `https://example.com/${"a".repeat(5_000)}` },
        });
      }
      return new Response("<!doctype html>", { status: 200, headers: secureHeaders() });
    };
    const result = await run(fetcher);

    expect(check(result, "https-enforcement").status).toBe("fail");
    expect(calls.every((value) => value.length < 4_096)).toBe(true);
  });

  it("returns N/A instead of grading unavailable observations as failures", async () => {
    const fetcher = vi.fn<WebSecurityFetcher>().mockRejectedValue(new Error("timeout"));
    const result = await run(fetcher);

    expect(result.grade).toBe("N/A");
    expect(result.checks.filter((candidate) => candidate.status === "fail")).toHaveLength(0);
    expect(result.coverage.unknown).toBeGreaterThan(10);
  });
});

describe("SSRF and DNS rebinding defenses", () => {
  it.each(["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "64:ff9b::7f00:1"])(
    "rejects non-public or transition destination %s before HTTP",
    async (address) => {
      const fetcher = vi.fn<WebSecurityFetcher>();
      await expect(scanWebSecurity("example.com", {
        resolver: async () => [address],
        fetcher,
        tlsScanner,
        now: () => NOW,
      })).rejects.toBeInstanceOf(WebSecurityTargetError);
      expect(fetcher).not.toHaveBeenCalled();
    },
  );

  it("rejects private-address rebinding after the first request and cancels further probes", async () => {
    let resolutions = 0;
    const resolver: WebSecurityResolver = async () => {
      resolutions += 1;
      return resolutions < 3 ? [PUBLIC_ADDRESS] : ["127.0.0.1"];
    };
    const fetcher = vi.fn<WebSecurityFetcher>().mockResolvedValue(
      new Response(null, { status: 308, headers: { location: "https://example.com/" } }),
    );

    await expect(scanWebSecurity("example.com", {
      resolver,
      fetcher,
      tlsScanner,
      now: () => NOW,
    })).rejects.toThrow(/DNS|non-public|rebind/iu);
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("rejects a changed public address set rather than accepting time-of-check/time-of-use drift", async () => {
    let resolutions = 0;
    const resolver: WebSecurityResolver = async () => {
      resolutions += 1;
      return resolutions < 3 ? [PUBLIC_ADDRESS] : ["1.1.1.1"];
    };
    const fetcher = vi.fn<WebSecurityFetcher>().mockResolvedValue(
      new Response(null, { status: 308, headers: { location: "https://example.com/" } }),
    );

    await expect(scanWebSecurity("example.com", {
      resolver,
      fetcher,
      tlsScanner,
      now: () => NOW,
    })).rejects.toThrow(/changed during a request/iu);
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("rejects an oversized DNS answer set before TLS or HTTP work", async () => {
    const fetcher = vi.fn<WebSecurityFetcher>();
    const addresses = Array.from({ length: 17 }, (_, index) => `8.8.8.${index + 1}`);
    await expect(scanWebSecurity("example.com", {
      resolver: async () => addresses,
      fetcher,
      tlsScanner,
      now: () => NOW,
    })).rejects.toThrow(/too many addresses/iu);
    expect(fetcher).not.toHaveBeenCalled();
  });
});
