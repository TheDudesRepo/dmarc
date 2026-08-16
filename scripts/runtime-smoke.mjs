import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
import { Log, LogLevel, Miniflare } from "miniflare";

const TYPE_CODES = {
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
};

const TYPE_NAMES = Object.fromEntries(Object.entries(TYPE_CODES).map(([name, code]) => [String(code), name]));
const outboundQueries = [];
const wranglerConfig = JSON.parse(await readFile("wrangler.jsonc", "utf8"));

const bundle = await build({
  entryPoints: ["src/worker/index.ts"],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  external: ["node:dns", "node:tls"],
  logLevel: "silent",
  write: false,
});
const workerScript = bundle.outputFiles[0]?.text;
assert.ok(workerScript, "esbuild did not produce a Worker bundle");

const miniflare = new Miniflare({
  script: workerScript,
  modules: true,
  compatibilityDate: wranglerConfig.compatibility_date,
  compatibilityFlags: wranglerConfig.compatibility_flags,
  log: new Log(LogLevel.ERROR),
  outboundService: async (request) => dnsJsonResponse(request),
});

const directLookupCases = [
  { type: "A", name: "direct.example.com", expected: "192.0.2.10" },
  { type: "AAAA", name: "direct.example.com", expected: "2001:db8::10" },
  { type: "MX", name: "mail.example.com", expected: "10 mx.example.com" },
  { type: "NS", name: "zone.example.com", expected: "ns1.example.com" },
  { type: "TXT", name: "txt.example.com", expected: "v=spf1 -all" },
  { type: "CNAME", name: "www.alias.example.com", expected: "target.example.com" },
  { type: "SOA", name: "zone.example.com", expected: "ns1.example.com hostmaster.example.com 1 3600 600 1209600 300" },
  { type: "CAA", name: "zone.example.com", expected: '0 issue "pki.goog"' },
  { type: "SRV", name: "_sip._tcp.zone.example.com", expected: "10 5 5060 sip.example.com" },
  { type: "PTR", name: "8.8.8.8", expected: "dns.google" },
];

const myAvistaSpfPresentation =
  '"v=spf1 include:u1791881.wl.sendgrid.net include:spf.protection.outlook.com include:aspmx.pardot.com ip4:198.181.21.221 ip4:198.181.21.222 ip4:198.181.30.101 ip4:198.251.0.114 ip4:198.251.4.1 ip4:198.251.4.2 ip4:198.251.4.3 ip4:198.251.4.4 ip4:198.251.4.5 " "include:_spf.salesforce.com -all"';

async function requestJson(pathname, init = {}) {
  const response = await miniflare.dispatchFetch(`https://runtime.test${pathname}`, init);
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    assert.fail(`${pathname} returned non-JSON HTTP ${response.status}: ${text.slice(0, 300)}`);
  }
  return { response, body };
}

async function postJson(pathname, body) {
  return requestJson(pathname, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
  });
}

try {
  const health = await requestJson("/api/health");
  assert.equal(health.response.status, 200);
  assert.equal(health.body.status, "ok");
  assert.equal(health.body.version, "0.4.0");

  const webScanQueryStart = outboundQueries.length;
  const webScanWithoutRateLimitSetup = await postJson("/api/web-security", {
    hostname: "example.com",
    authorizedUse: true,
    disclaimerVersion: "2026-08-16",
  });
  assert.equal(webScanWithoutRateLimitSetup.response.status, 503);
  assert.equal(webScanWithoutRateLimitSetup.body.code, "SERVICE_UNAVAILABLE");
  assert.equal(outboundQueries.length - webScanQueryStart, 0, "failed rate-limit setup must not contact the target");

  for (const lookup of directLookupCases) {
    const result = await postJson("/api/lookup", lookup);
    assert.equal(result.response.status, 200, `${lookup.type} ${lookup.name}: ${JSON.stringify(result.body)}`);
    assert.equal(result.body.type, lookup.type);
    assert.ok(result.body.records.some((record) => record.value === lookup.expected));
    assert.ok(result.body.records.every((record) => record.type === lookup.type));
  }

  for (const type of ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]) {
    const result = await postJson("/api/lookup", { name: "www.alias.example.com", type });
    assert.equal(result.response.status, 200, `alias ${type}: ${JSON.stringify(result.body)}`);
    assert.equal(result.body.canonicalName, "target.example.com");
    assert.ok(result.body.records.every((record) => record.name === "target.example.com"));
    assert.ok(result.body.records.every((record) => record.value !== "target.example.com"));
  }

  const nullMx = await postJson("/api/lookup", { name: "null-mx.example.com", type: "MX" });
  assert.equal(nullMx.response.status, 200);
  assert.equal(nullMx.body.records[0]?.value, "0 .");

  const snapshotQueryStart = outboundQueries.length;
  const snapshot = await postJson("/api/dns-snapshot", { domain: "toolbox.example.com" });
  const snapshotQueryCount = outboundQueries.length - snapshotQueryStart;
  assert.equal(snapshot.response.status, 200, JSON.stringify(snapshot.body));
  assert.equal(snapshot.body.domain, "toolbox.example.com");
  assert.equal(snapshot.body.groups.length, 8);
  assert.equal(snapshot.body.groups.find(({ type }) => type === "A")?.status, "found");
  assert.equal(snapshot.body.groups.find(({ type }) => type === "TXT")?.records[0]?.value, "v=spf1 -all");
  assert.equal(snapshot.body.securityRecords.find(({ key }) => key === "dmarc")?.status, "found");
  assert.ok(snapshot.body.infrastructureHosts.some(({ hostname }) => hostname === "mx.toolbox.example.com"));
  assert.ok(snapshot.body.infrastructureHosts.some(({ hostname }) => hostname === "ns1.toolbox.example.com"));
  assert.ok(snapshotQueryCount > 0 && snapshotQueryCount < 48, `snapshot used ${snapshotQueryCount} DNS attempts`);

  const discoveryCases = [
    { profile: "core", expectedHost: "www.toolbox.example.com" },
    { profile: "extended", expectedHost: "status.toolbox.example.com" },
  ];
  const discoveryQueryCounts = [];
  for (const discoveryCase of discoveryCases) {
    const queryStart = outboundQueries.length;
    const discovery = await postJson("/api/host-discovery", {
      domain: "toolbox.example.com",
      profile: discoveryCase.profile,
    });
    const queryCount = outboundQueries.length - queryStart;
    discoveryQueryCounts.push(queryCount);
    assert.equal(discovery.response.status, 200, `${discoveryCase.profile}: ${JSON.stringify(discovery.body)}`);
    assert.equal(discovery.body.domain, "toolbox.example.com");
    assert.equal(discovery.body.profile, discoveryCase.profile);
    assert.equal(discovery.body.testedNames.length, 7);
    assert.ok(discovery.body.hosts.some(({ hostname }) => hostname === discoveryCase.expectedHost));
    assert.match(discovery.body.wildcardProbe.hostname, /^dmarc-ready-probe-[a-f0-9]{16}\.toolbox\.example\.com$/u);
    assert.equal(discovery.body.wildcardProbe.detected, false);
    assert.equal(discovery.body.wildcardProbe.unavailable, false);
    assert.ok(queryCount > 0 && queryCount < 48, `${discoveryCase.profile} discovery used ${queryCount} DNS attempts`);
  }

  const ipQueryStart = outboundQueries.length;
  const ipResult = await postJson("/api/ip-network", { input: "8.8.4.4" });
  const ipQueryCount = outboundQueries.length - ipQueryStart;
  assert.equal(ipResult.response.status, 200, JSON.stringify(ipResult.body));
  assert.equal(ipResult.body.canonical, "8.8.4.4/32");
  assert.equal(ipResult.body.classification.kind, "global");
  assert.deepEqual(ipResult.body.enrichment.ptr.names, ["dns.google"]);
  assert.equal(ipResult.body.enrichment.origin.record.asn, "15169");
  assert.equal(ipResult.body.enrichment.origin.record.prefix, "8.8.4.0/24");
  assert.equal(ipResult.body.enrichment.asName.name, "GOOGLE, US");
  assert.equal(ipResult.body.enrichment.queryCount, 3);
  assert.ok(ipQueryCount > 0 && ipQueryCount < 16, `IP enrichment used ${ipQueryCount} DNS attempts`);

  const subnetQueryStart = outboundQueries.length;
  const subnetResult = await postJson("/api/ip-network", { input: "192.168.7.42/255.255.255.0" });
  assert.equal(subnetResult.response.status, 200, JSON.stringify(subnetResult.body));
  assert.equal(subnetResult.body.networkCidr, "192.168.7.0/24");
  assert.equal(subnetResult.body.ipv4.netmask, "255.255.255.0");
  assert.equal(subnetResult.body.enrichment.status, "not-applicable");
  assert.equal(outboundQueries.length - subnetQueryStart, 0, "subnet calculation must not perform DNS queries");

  const myAvistaScan = await postJson("/api/scan", { domain: "myavista.com" });
  assert.equal(myAvistaScan.response.status, 200, JSON.stringify(myAvistaScan.body));
  assert.equal(myAvistaScan.body.domain, "myavista.com");
  assert.equal(myAvistaScan.body.checks.dmarc.status, "pass");
  assert.equal(myAvistaScan.body.checks.spf.status, "pass");
  assert.equal(myAvistaScan.body.checks.dkim.status, "pass");
  const lookupEstimate = myAvistaScan.body.checks.spf.details.find((detail) => detail.label === "Lookup estimate");
  assert.equal(lookupEstimate?.value, "6");
  const spfRecord = myAvistaScan.body.checks.spf.records.find((record) => record.value.startsWith("v=spf1"));
  assert.ok(spfRecord);
  assert.ok(!spfRecord.value.includes('" "'));
  assert.ok(!spfRecord.value.includes('""'));
  assert.ok(!myAvistaScan.body.findings.some((finding) => finding.id === "invalid-spf-record"));
  assert.ok(!myAvistaScan.body.findings.some((finding) => finding.id === "spf-lookup-limit"));

  const missing = await postJson("/api/lookup", { name: "missing.example.com", type: "A" });
  assert.equal(missing.response.status, 200);
  assert.deepEqual(missing.body.records, []);

  const invalidType = await postJson("/api/lookup", { name: "example.com", type: "ANY" });
  assert.equal(invalidType.response.status, 400);
  assert.equal(invalidType.body.code, "BAD_REQUEST");

  const invalidName = await postJson("/api/lookup", { name: "https://example.com", type: "A" });
  assert.equal(invalidName.response.status, 400);
  assert.equal(invalidName.body.code, "BAD_REQUEST");

  const invalidIp = await postJson("/api/ip-network", { input: "https://127.0.0.1/admin" });
  assert.equal(invalidIp.response.status, 400);
  assert.equal(invalidIp.body.code, "BAD_REQUEST");

  const wrongMethod = await requestJson("/api/lookup");
  assert.equal(wrongMethod.response.status, 405);
  assert.equal(wrongMethod.response.headers.get("allow"), "POST");

  assert.ok(
    !outboundQueries.some(({ name, type }) => name === "www.alias.example.com" && type !== "CNAME"),
    "terminal record queries must not be sent for the alias owner",
  );
  assert.ok(
    !outboundQueries.some(({ name, type }) => name === "_dmarc.myavista.com" && type === "TXT"),
    `DMARC TXT must be resolved at its canonical target: ${JSON.stringify(outboundQueries.filter(({ name }) => name === "_dmarc.myavista.com"))}`,
  );
  assert.ok(
    !outboundQueries.some(({ name, type }) => name === "selector1._domainkey.myavista.com" && type === "TXT"),
    "DKIM TXT must be resolved at its canonical target",
  );

  console.log(
    `Runtime smoke passed: ${directLookupCases.length} native DNS types, 7 alias paths, null MX, MyAvista SPF/DKIM/DMARC, DNS snapshot (${snapshotQueryCount} queries), core/extended discovery (${discoveryQueryCounts.join("/")} queries), IP enrichment (${ipQueryCount} queries), subnet arithmetic, fail-closed web-scan boundary, and API boundaries.`,
  );
} finally {
  await miniflare.dispose();
}

function dnsJsonResponse(request) {
  const url = new URL(request.url);
  assert.equal(url.hostname, "cloudflare-dns.com");
  const name = (url.searchParams.get("name") ?? "").toLowerCase().replace(/\.$/u, "");
  const rawType = (url.searchParams.get("type") ?? "").toUpperCase();
  const type = TYPE_NAMES[rawType] ?? rawType;
  outboundQueries.push({ name, type });

  const answers = fixtureAnswers(name, type);
  const body = {
    Status: 0,
    TC: false,
    RD: true,
    RA: true,
    AD: false,
    CD: false,
    Question: [{ name: `${name}.`, type: TYPE_CODES[type] ?? 0 }],
    ...(answers.length > 0 ? { Answer: answers } : {}),
  };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/dns-json" },
  });
}

function fixtureAnswers(name, type) {
  if (name === "www.alias.example.com" && type === "CNAME") {
    return [answer(name, "CNAME", "target.example.com.")];
  }
  if (name === "www.alias.example.com" && type !== "CNAME") {
    return [answer(name, "CNAME", "target.example.com."), ...fixtureAnswers("target.example.com", type)];
  }
  if (name === "_dmarc.myavista.com" && type === "CNAME") {
    return [answer(name, "CNAME", "_dmarc.mail-policy.example.net.")];
  }
  if (name === "_dmarc.myavista.com" && type !== "CNAME") {
    return [answer(name, "CNAME", "_dmarc.mail-policy.example.net."), ...fixtureAnswers("_dmarc.mail-policy.example.net", type)];
  }
  if (name === "selector1._domainkey.myavista.com" && type === "CNAME") {
    return [answer(name, "CNAME", "selector1-myavista._domainkey.mail-provider.example.net.")];
  }
  if (name === "selector1._domainkey.myavista.com" && type !== "CNAME") {
    return [
      answer(name, "CNAME", "selector1-myavista._domainkey.mail-provider.example.net."),
      ...fixtureAnswers("selector1-myavista._domainkey.mail-provider.example.net", type),
    ];
  }

  const fixtures = {
    "A:direct.example.com": [answer(name, "A", "192.0.2.10")],
    "AAAA:direct.example.com": [answer(name, "AAAA", "2001:db8::10")],
    "MX:mail.example.com": [answer(name, "MX", "10 mx.example.com.")],
    "NS:zone.example.com": [answer(name, "NS", "ns1.example.com.")],
    "TXT:txt.example.com": [answer(name, "TXT", '"v=spf1 -all"')],
    "SOA:zone.example.com": [answer(name, "SOA", "ns1.example.com. hostmaster.example.com. 1 3600 600 1209600 300")],
    "CAA:zone.example.com": [answer(name, "CAA", '0 issue "pki.goog"')],
    "SRV:_sip._tcp.zone.example.com": [answer(name, "SRV", "10 5 5060 sip.example.com.")],
    "PTR:8.8.8.8.in-addr.arpa": [answer(name, "PTR", "dns.google.")],
    "A:target.example.com": [answer(name, "A", "192.0.2.25")],
    "MX:target.example.com": [answer(name, "MX", "10 mx.target.example.com.")],
    "NS:target.example.com": [answer(name, "NS", "ns1.target.example.com.")],
    "TXT:target.example.com": [answer(name, "TXT", '"v=spf1 -all"')],
    "SOA:target.example.com": [answer(name, "SOA", "ns1.target.example.com. hostmaster.target.example.com. 2 3600 600 1209600 300")],
    "CAA:target.example.com": [answer(name, "CAA", '0 issue "letsencrypt.org"')],
    "MX:null-mx.example.com": [answer(name, "MX", "0 .")],
    "A:toolbox.example.com": [answer(name, "A", "192.0.2.20")],
    "AAAA:toolbox.example.com": [answer(name, "AAAA", "2001:db8::20")],
    "CAA:toolbox.example.com": [answer(name, "CAA", '0 issue "letsencrypt.org"')],
    "MX:toolbox.example.com": [answer(name, "MX", "10 mx.toolbox.example.com.")],
    "NS:toolbox.example.com": [answer(name, "NS", "ns1.toolbox.example.com.")],
    "SOA:toolbox.example.com": [
      answer(name, "SOA", "ns1.toolbox.example.com. hostmaster.toolbox.example.com. 2026081101 3600 600 1209600 300"),
    ],
    "TXT:toolbox.example.com": [answer(name, "TXT", '"v=spf1 -all"')],
    "TXT:_dmarc.toolbox.example.com": [
      answer(name, "TXT", '"v=DMARC1; p=quarantine; rua=mailto:dmarc@toolbox.example.com"'),
    ],
    "TXT:_mta-sts.toolbox.example.com": [answer(name, "TXT", '"v=STSv1; id=20260811"')],
    "TXT:_smtp._tls.toolbox.example.com": [
      answer(name, "TXT", '"v=TLSRPTv1; rua=mailto:tls@toolbox.example.com"'),
    ],
    "TXT:default._bimi.toolbox.example.com": [
      answer(name, "TXT", '"v=BIMI1; l=https://toolbox.example.com/logo.svg"'),
    ],
    "A:mx.toolbox.example.com": [answer(name, "A", "192.0.2.30")],
    "AAAA:mx.toolbox.example.com": [answer(name, "AAAA", "2001:db8::30")],
    "A:ns1.toolbox.example.com": [answer(name, "A", "192.0.2.53")],
    "A:www.toolbox.example.com": [answer(name, "A", "192.0.2.101")],
    "CNAME:mail.toolbox.example.com": [answer(name, "CNAME", "mail.discovery.example.net.")],
    "A:mail.discovery.example.net": [answer(name, "A", "192.0.2.102")],
    "AAAA:api.toolbox.example.com": [answer(name, "AAAA", "2001:db8::103")],
    "A:status.toolbox.example.com": [answer(name, "A", "192.0.2.104")],
    "PTR:101.2.0.192.in-addr.arpa": [answer(name, "PTR", "www-edge.toolbox.example.com.")],
    "PTR:102.2.0.192.in-addr.arpa": [answer(name, "PTR", "mail-edge.toolbox.example.com.")],
    "PTR:104.2.0.192.in-addr.arpa": [answer(name, "PTR", "status-edge.toolbox.example.com.")],
    "PTR:4.4.8.8.in-addr.arpa": [answer(name, "PTR", "dns.google.")],
    "TXT:4.4.8.8.origin.asn.cymru.com": [
      answer(name, "TXT", '"15169 | 8.8.4.0/24 | US | arin | 1992-12-01"'),
    ],
    "TXT:as15169.asn.cymru.com": [
      answer(name, "TXT", '"15169 | US | arin | 2000-03-30 | GOOGLE, US"'),
    ],
    "TXT:myavista.com": [answer(name, "TXT", myAvistaSpfPresentation)],
    "MX:myavista.com": [answer(name, "MX", "10 myavista-com.mail.protection.outlook.com.")],
    "NS:myavista.com": [
      answer(name, "NS", "ns1.example.net."),
      answer(name, "NS", "ns2.example.net."),
    ],
    "SOA:myavista.com": [answer(name, "SOA", "ns1.example.net. hostmaster.example.net. 1 3600 600 1209600 300")],
    "TXT:_dmarc.mail-policy.example.net": [answer(name, "TXT", '"v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@myavista.com"')],
    "TXT:u1791881.wl.sendgrid.net": [answer(name, "TXT", '"v=spf1 ip4:167.89.0.0/17 -all"')],
    "TXT:spf.protection.outlook.com": [answer(name, "TXT", '"v=spf1 ip4:40.92.0.0/15 -all"')],
    "TXT:aspmx.pardot.com": [answer(name, "TXT", '"v=spf1 include:et._spf.pardot.com -all"')],
    "TXT:et._spf.pardot.com": [answer(name, "TXT", '"v=spf1 ip4:198.245.80.0/20 -all"')],
    "TXT:_spf.salesforce.com": [answer(name, "TXT", '"v=spf1 exists:%{i}._spf.mta.salesforce.com -all"')],
    "TXT:selector1-myavista._domainkey.mail-provider.example.net": [
      answer(name, "TXT", '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" "MIIBCgKCAQEA"'),
    ],
  };
  return fixtures[`${type}:${name}`] ?? [];
}

function answer(name, type, data) {
  return { name: `${name}.`, type: TYPE_CODES[type], TTL: 300, data };
}
