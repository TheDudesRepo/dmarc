# Cresswell Security Lab

Cresswell Security Lab is a public, read-only security evidence toolbox organized into four families: **Email Security**, **DNS & OSINT**, **Network Intelligence**, and **Web & TLS**. The authorized Web & TLS assessment combines exactly 20 bounded OWASP-aligned HTTP observations with an isolated, endpoint-level TLS inventory powered by a fixed `testssl.sh` profile.

The current release is an intentionally focused MVP: no accounts, no mailbox access, no DNS writes, and no AI-generated enforcement decisions.

## What it does

- Parses and validates the published DMARC policy
- Distinguishes monitoring, quarantine, reject, missing, and invalid postures
- Checks aggregate-reporting configuration
- Provides first-class SPF analysis backed by TXT queries, including record conflicts, syntax, mechanisms, qualifiers, CIDRs, terminal policy, recursive domains, and an RFC lookup-budget estimate
- Displays MX and nameserver context
- Inventories A, AAAA, CNAME, TXT, MX, NS, SOA, and CAA answers in the main scan
- Takes an explicit apex snapshot of A, AAAA, CAA, CNAME, MX, NS, SOA, and TXT, plus TXT at the DMARC, MTA-STS, TLS-RPT, and default BIMI owner names
- Checks two documented seven-name host-discovery profiles and uses a random-label control to identify likely wildcard DNS answers
- Looks for MTA-STS, SMTP TLS reporting, and BIMI records
- Checks a small set of common DKIM selectors without claiming that non-discovery means DKIM is absent
- Provides direct lookup for ten common resource-record types plus the analyzed SPF mode
- Calculates IPv4/IPv6 networks, ranges, classifications, netmasks, and related values locally; a single global address can receive bounded PTR and Team Cymru DNS evidence
- Runs a version-pinned `testssl.sh` identity, cryptography, compatibility, client-simulation, and safe known-issue profile against as many as four representative public TLS endpoints
- Runs exactly 20 non-exploitative web checks covering HTTPS, response headers, CORS/method observations, cookie attributes, caching/disclosure, error handling, forms, mixed content, and subresource integrity, cross-referenced to relevant OWASP Top 10 (2025) and WSTG areas
- Produces deterministic, prioritized findings with raw DNS evidence and guided remediation
- Shows reviewable DNS record templates when a safe template is possible, with deployment cautions
- Distinguishes records that were found, names with an empty answer, and queries that were temporarily unavailable
- Clearly warns that public DNS alone cannot prove a domain is safe to move into enforcement

## Product principles

1. **Evidence before confidence.** Every result comes from observable public DNS and the raw records remain available.
2. **Configuration is not readiness.** Aggregate DMARC history is required before safely changing a production policy.
3. **No automatic DNS changes.** The scanner is read-only and does not ask for DNS credentials.
4. **Uncertainty is explicit.** Timeouts, undiscoverable DKIM selectors, and partial lookups are not converted into false failures.
5. **Deterministic core.** Protocol parsing, scoring, and safety gates are code—not LLM judgment.
6. **Authorized and bounded active work.** The web scan requires an explicit authorization attestation, validates public destinations, and enforces a server-side rolling quota before target traffic begins.

The four product families stay deliberately separate: Email Security evaluates published mail-authentication policy; DNS & OSINT collects bounded live-DNS evidence; Network Intelligence performs deterministic address/network analysis with limited DNS enrichment; Web & TLS is the only consent-gated active assessment.

## Stack

- React 19 and TypeScript
- Vite
- Cloudflare Workers Static Assets
- Cloudflare Workers' native `node:dns` resolver, backed by Cloudflare DNS at 1.1.1.1
- Cloudflare Workers Paid, Workflows, Containers, and Workers Static Assets
- A version-pinned `testssl.sh` container whose fixed-target CONNECT proxy pins scanner traffic to the revalidated IP:443 and hostname SNI
- SQLite-backed Durable Objects for the exact rolling quota, global scheduler, six-hour cache, and single-flight coordination
- Vitest
- Wrangler

The frontend and control-plane API deploy as one Cloudflare Worker. Static files are served from `dist`; a Workflow runs the bounded web phase and sequential deep-TLS endpoint phases; paid Containers isolate `testssl.sh`; and one global coordinator Durable Object enforces concurrency two, at most eight pending jobs, target single-flight, six-hour completed-result caching, and at most 256 retained job rows. Cache hits return the existing completed capability instead of copying its report. Each job/endpoint Container DO atomically records a scan-once claim before active probes, stores the first validated report for incomplete-step replay, and retains it until the Workflow has durably advanced. Cloudflare Containers require internet capability for opaque raw TCP; `allowedHosts` does not mediate that path. Safety therefore relies on fresh public-IP validation, a trusted fixed image with no caller-selected command or address, the container's exact-target CONNECT proxy, `testssl.sh --proxy`/`--nodns`, disabled phone-home behavior, fixed port 443, and strict budgets. Residual container network capability is an explicit trust boundary.

## Safe scope and completeness

Most tools remain DNS-only, passive-style reconnaissance. The deliberate exception is `POST /api/security-assessments`: after explicit deep-scan consent and server-side quota acceptance, it creates one asynchronous combined job. The web phase accepts no caller-selected URL, path, port, payload, credential, wordlist, or state-changing method. The TLS phase tests port 443 only, with exact IP+SNI, a fixed safe profile, strict process/connection/time/output limits, and selected cryptographic flaw probes. It does not crawl, authenticate, submit forms, change state, perform denial-of-service work, or run caller-selected probes.

The combined result is an independent point-in-time assessment, not an SSL Labs grade, penetration test, compliance certification, or proof of security. TLS methodology and grades are Cresswell-specific, and unknown evidence is never converted to a failure. Cresswell Security Lab does not call or proxy the Qualys SSL Labs API and requires no Qualys credentials.

All other active capabilities remain excluded: no general port scan, vulnerability exploitation, ping, traceroute, AXFR, banner grabbing, SMTP handshake, crawling, screenshots, or caller-defined network requests.

The DNS surface view is deliberately finite. An `ANY` response is not a zone listing and can be minimized by authoritative servers; it cannot enumerate owner names. Cresswell Security Lab therefore queries named RR types and a documented common-host list instead of implying that `ANY` means “all records.” The result is not exhaustive and is not equivalent to DNSDumpster or another product that combines certificate-transparency, historical/passive-DNS, search, or other third-party datasets. See [Toolbox scope](docs/TOOLBOX-SCOPE.md) for the capability boundary and future requirements for active tools.

## Local development

Requirements:

- Node.js 24 or newer
- npm
- a running Docker-compatible CLI and engine for local Container development and direct authenticated Wrangler deployment
- a Cloudflare Workers Paid account for Workflows and Containers when running the deep assessment

Install dependencies:

```bash
npm install
```

Run the API Worker in one terminal:

```bash
npm run dev:worker
```

Run Vite in another terminal:

```bash
npm run dev
```

Vite runs on `http://localhost:5173` and proxies `/api` to the local Worker on port `8787`.

## Verification

```bash
npm run check
npm test # Vitest plus the safety-critical scanner-container suite
npm run test:runtime
npm run build
```

These commands are intentionally CI-friendly. Add them to your preferred GitHub Actions workflow when the repository token or GitHub App has workflow-write permission.

## Cloudflare deployment

The repository is configured for [Cloudflare Workers Builds](https://developers.cloudflare.com/workers/ci-cd/builds/), which can deploy automatically from GitHub.

1. In Cloudflare, open **Workers & Pages**.
2. Select **Create application** and **Import a repository**.
3. Select this GitHub repository and the `main` branch.
4. Keep the legacy deployment identity `dmarc` unless intentionally migrating the connected Worker; the public product/service name is Cresswell Security Lab.
5. Set the build command to `npm run build`.
6. Keep the deploy command as `npx wrangler deploy`.
7. Save and deploy.

Cloudflare deploys the frontend, Worker API, Workflow, SQLite Durable Objects, and the container image built from `scanner-container/`. The route works without an additional secret by using a legacy-compatible domain-separated SHA-256 client-IP digest. For stronger pseudonymization of low-entropy IP addresses, add `WEB_SCAN_RATE_LIMIT_SECRET` as an encrypted Worker secret containing at least 32 unpredictable characters in the Cloudflare dashboard, or run:

```bash
npx wrangler secret put WEB_SCAN_RATE_LIMIT_SECRET
```

When the secret is configured, object names use HMAC-SHA-256 instead. The assessment route fails closed with `503 SERVICE_UNAVAILABLE` when required bindings, the trusted Cloudflare client-IP header, or a valid secret are unavailable. The DNS and local-calculation routes do not use this setting.

For a direct authenticated deployment:

Ensure the Docker-compatible CLI and engine are running locally so Wrangler can build and upload the scanner image. Cloudflare Workers Builds remains the repository-connected path when no local container engine is available.

```bash
npm run deploy
```

## API

### `POST /api/scan`

Request:

```json
{
  "domain": "example.com"
}
```

The endpoint accepts only a public domain name. It does not accept a resolver URL, arbitrary DNS query type, email address, IP address, or target URL.

### `GET /api/health`

Returns a basic service-health response, application version, and Cloudflare deployment identifier without performing DNS work.

### `POST /api/lookup`

Request:

```json
{
  "name": "_sip._tcp.example.com",
  "type": "SRV"
}
```

Direct lookup supports A, AAAA, CAA, CNAME, MX, NS, PTR, SOA, SRV, and TXT through Cloudflare's native DNS resolver. PTR accepts an IPv4 or IPv6 address and converts it to the corresponding reverse-DNS owner name. For non-CNAME lookups, the Worker follows a bounded CNAME chain before resolving the terminal type so alias data cannot be mislabeled as another record. The response reports the canonical target even when its terminal answer is empty. An empty answer is evidence that the requested record type was not returned; it is not automatically a configuration failure.

`SPF` is an analyzed lookup mode, not a query for obsolete SPF RR type 99. It accepts a validated public DNS owner (including provider policy owners such as `_spf.example.com`), queries TXT (following a bounded CNAME chain), preserves separate TXT resource-record boundaries, and returns only complete `v=spf1` records as evidence. The `spfAnalysis` object reports missing, multiple, invalid, warning, or valid status; syntax validity; mechanisms and qualifiers; the terminal `all` policy; a bounded recursive lookup estimate; incomplete branches; and corrective guidance. The estimate is static analysis, not an SPF result for a particular sender IP.

Example:

```json
{
  "name": "example.com",
  "type": "SPF"
}
```

### `POST /api/dns-snapshot`

Request:

```json
{
  "domain": "example.com"
}
```

The endpoint explicitly queries A, AAAA, CAA, CNAME, MX, NS, SOA, and TXT at the requested domain and security TXT owner names for DMARC, MTA-STS, TLS-RPT, and default BIMI. Each group is `found`, `empty`, or `unavailable`; partial resolver failures remain in a structured `200` response, while failure of every apex RRset group returns a sanitized `502` error. Up to two hostnames referenced by MX or NS answers receive bounded A/AAAA enrichment.

### `POST /api/host-discovery`

Request:

```json
{
  "domain": "example.com",
  "profile": "core"
}
```

`core` checks `www`, `mail`, `autodiscover`, `api`, `vpn`, `portal`, and `remote`. `extended` checks `smtp`, `webmail`, `admin`, `dev`, `staging`, `status`, and `ftp`. Each request also tests one unpredictable label. A matching CNAME/address fingerprint is tagged as a likely wildcard answer rather than silently treated as an independently discovered host. Query failures appear in `unavailableNames` and are not treated as proof of absence.

The snapshot and discovery endpoints accept only a normalized public domain, and discovery accepts only the two profiles above. They do not accept arbitrary labels, wordlists, URLs, resolvers, IP ranges, or query types.

### `POST /api/ip-network`

Request:

```json
{
  "input": "192.0.2.42/24"
}
```

This UI and API utility accepts one strict IPv4 or IPv6 address, CIDR, or contiguous dotted IPv4 netmask. It performs the network calculation locally and returns canonical address/prefix data, network and last address, total and conventional usable range, special-use classification, and IPv4 netmask/wildcard/broadcast fields. Classification describes the supplied address, not every address covered by its prefix.

DNS enrichment runs only when the input represents one globally routable address, including an explicit `/32` or `/128`. It uses at most four logical queries for native PTR evidence, Team Cymru origin-AS/prefix data, and up to two AS names. Multi-address CIDRs and non-global addresses make no enrichment queries. Enrichment is `complete`, `partial`, `indeterminate`, or `not-applicable`; a DNS failure never invalidates the deterministic network calculation. No address is pinged, connected to, scanned, or fetched over HTTP.

DNSSEC and specialist resource-record inspection are not exposed by this native lookup surface. Broader DNSSEC support and infrastructure-dependent checks such as SMTP handshakes, blocklists, worldwide propagation comparisons, port reachability, and other network probes remain future work rather than implied capabilities of these endpoints.

### `POST /api/security-assessments`

Request:

```json
{
  "hostname": "example.com",
  "authorizedUse": true,
  "disclaimerVersion": "2026-08-16-deep-v1"
}
```

The caller must certify ownership of or explicit permission to test the exact hostname and accept the versioned deep-scan notice. The notice discloses potentially hundreds of bounded TLS handshakes, selected cryptographic flaw probes, target-side logging, paid container execution, and the point-in-time/non-compliance boundary. This attestation is a legal/safety gate, not technical proof of ownership.

The Worker consumes one quota slot before DNS, HTTP, HTTPS, or TLS scan execution. It uses only Cloudflare's `CF-Connecting-IP` value, canonicalizes the address, derives either a domain-separated SHA-256 digest or a keyed HMAC-SHA-256 digest when the optional secret is set, and stores only rolling event timestamps in the corresponding SQLite Durable Object. Each client IP receives exactly five attempts in the preceding rolling hour; a sixth returns `429 RATE_LIMITED` with `quota`, `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` (relative delay seconds), and `Retry-After` (seconds). A scan that later produces a target or upstream error still consumes its slot.

An accepted request returns `202` with an unguessable job capability, progress resource, quota, and recommended poll interval. Poll `GET /api/security-assessments/:jobId`; responses are `Cache-Control: no-store`. Explicit cross-site browser requests are rejected before dispatch, and status/cancellation traffic is limited to 60 requests per rolling minute per trusted client IP before it can reach the global coordinator; responses include relative `RateLimit-*` metadata. The browser waits for up to two hours, which covers the bounded tail queue and sequential endpoint budget with margin; **Stop waiting** cancels only local polling. A creator-only cancellation token is returned only for newly created, unshared work and is required in `X-Assessment-Cancel-Token` for `DELETE`; the coordinator irrevocably clears that authority as soon as another request joins the same queued/running assessment, so neither creator nor joiner can disrupt shared work. The scheduler runs two jobs, holds no more than eight pending jobs, retains no more than 256 total job rows, and expires jobs/results after 24 hours. Since each combined result is already capped below 700 KiB, the row ceiling also bounds serialized report storage.

HTTP work remains capped at six requests, two HTTPS redirect hops, 2.5 seconds per request/body read, a 30-second phase deadline, and 131,072 bytes per inspected response. Deep TLS selects at most four representative public A/AAAA endpoints. Each endpoint is freshly resolved before use, must remain in the safe pre-job set, and receives a separate fixed-image container whose local CONNECT proxy permits only that exact address:443. Every one-shot container is stopped and its Durable Object configuration, schedules, and alarms are deleted after success, failure, cancellation, or stale recovery. The fixed three-phase profile has a 180-second deadline, three concurrent fixed testssl parent runners under a UID-wide 48-process ceiling, five concurrent connections, 128 total connections, 393,216 bytes of phase output, and a 163,840-byte response. Combined stored evidence is capped below 700 KiB. See [Scanner methodology](docs/SCANNER-METHODOLOGY.md).

`POST /api/web-security` remains a backward-compatible quick route, shares the same five-per-IP rolling quota, uses only the exact-IP socket HTTP adapter without a generic fetch fallback, and does not emit a supported native TLS grade. The user-facing interface uses the combined asynchronous route once.

## Repository layout

```text
src/
  client/       React user interface
  shared/       API contracts shared by the client and Worker
  worker/       Cloudflare Worker, DNS resolver, parsers, analysis, and tests
scanner-container/
                Isolated version-pinned deep TLS service and contract
docs/
  ARCHITECTURE.md
  SCANNER-METHODOLOGY.md
  TOOLBOX-SCOPE.md
```

## Standards note

The implementation is based on the current DMARC deployment model in [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html) and aggregate-reporting concepts in [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990.html), while recognizing that real-world receivers and records remain in a transition period from RFC 7489 behavior.

DMARC expresses a domain owner's requested handling policy. A receiver ultimately decides how it processes a message. A passing DMARC result authenticates use of a domain; it does not prove that a message is benign.

## Security and privacy

- DNS tools query public DNS records only. Query names and record types are resolved by Cloudflare's native DNS service; no user-selectable resolver is accepted.
- Snapshot and discovery work is capped by fixed RR types, fixed hostname profiles, a random wildcard control, per-request DNS budgets, bounded concurrency, and result-size limits.
- IP-network input is strictly parsed as one address/CIDR, calculations are local, and optional evidence is limited to PTR and explicitly attributed Team Cymru DNS queries for one global address.
- Web & TLS input is one hostname with versioned authorized-use consent. It is limited to root-page observations, one generated not-found path, safe redirects, the fixed container profile, and strict destination/time/output caps.
- One shared quota permits exactly five accepted combined or legacy quick starts per canonical `CF-Connecting-IP` in the preceding rolling hour. Every accepted POST consumes one slot, including cache hits and single-flight joins; target/upstream failures do not refund one.
- Assessment jobs/results are capability-addressed, returned with `no-store`, and retained for at most 24 hours; completed target evidence can be reused for six hours without duplicating its stored report. The global coordinator admits at most eight pending and 256 retained rows. Raw client IPs are not stored in job state.
- DNS answers are untrusted input and are rendered as text.
- No route fetches a caller-supplied URL; the web scanner constructs fixed root URLs and one unpredictable not-found URL from a validated hostname.
- Security headers are applied by the Worker.
- API requests have strict input and size limits.

See [SECURITY.md](SECURITY.md) for reporting guidance, [Architecture](docs/ARCHITECTURE.md) for trust boundaries, [Scanner methodology](docs/SCANNER-METHODOLOGY.md) for result semantics, and [Toolbox scope](docs/TOOLBOX-SCOPE.md) for the deliberate passive/active boundary.

## Roadmap

- DMARC aggregate-report ingestion with hardened XML parsing
- Historical sender inventory and change detection
- Verified ownership and multi-domain accounts
- Bulk-domain pricing and portfolio dashboards
- Provider-aware sender remediation and change-plan approvals
- Quarantine/reject change plans with explicit human approval
- Optional AI explanations using schema-constrained output
- Billing, RBAC, SSO, audit logs, and enterprise controls

## License

No open-source license has been selected yet. All rights are reserved until the project owner chooses a license.
