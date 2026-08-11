# DMARC Ready

DMARC Ready is a public, read-only email-authentication and DNS toolbox designed to make the path from monitoring to enforcement understandable. Enter a domain to inspect its published DMARC and SPF records, commonly discoverable DKIM selectors, mail routing, adjacent transport-security controls, explicit apex DNS RRsets, and a bounded set of common public hostnames. A built-in IP utility performs deterministic IPv4/IPv6 and CIDR calculations with limited DNS enrichment.

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

## Stack

- React 19 and TypeScript
- Vite
- Cloudflare Workers Static Assets
- Cloudflare Workers' native `node:dns` resolver, backed by Cloudflare DNS at 1.1.1.1
- Vitest
- Wrangler

The frontend and API Worker deploy as one Cloudflare Worker. Static files are served from the Vite `dist` directory and `/api/*` routes run through the Worker. DNS requests use the platform's fixed native resolver with bounded concurrency, per-request caching, timeouts, strict result limits, resolver-error handling, and a hard subrequest budget.

## Safe scope and completeness

This release performs DNS-only, passive-style reconnaissance: it sends bounded queries through the fixed recursive resolver but does not connect to discovered hosts or services. The IP calculator uses local arithmetic and, for one globally routable address, DNS-only PTR and Team Cymru IP-to-ASN lookups. It does not perform port or vulnerability scanning, ping, traceroute, zone transfer (AXFR), banner grabbing, or arbitrary HTTP requests.

The DNS surface view is deliberately finite. An `ANY` response is not a zone listing and can be minimized by authoritative servers; it cannot enumerate owner names. DMARC Ready therefore queries named RR types and a documented common-host list instead of implying that `ANY` means “all records.” The result is not exhaustive and is not equivalent to DNSDumpster or another product that combines certificate-transparency, historical/passive-DNS, search, or other third-party datasets. See [Toolbox scope](docs/TOOLBOX-SCOPE.md) for the capability boundary and future requirements for active tools.

## Local development

Requirements:

- Node.js 22 or newer
- npm

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
npm test
npm run test:runtime
npm run build
```

These commands are intentionally CI-friendly. Add them to your preferred GitHub Actions workflow when the repository token or GitHub App has workflow-write permission.

## Cloudflare deployment

The repository is configured for [Cloudflare Workers Builds](https://developers.cloudflare.com/workers/ci-cd/builds/), which can deploy automatically from GitHub.

1. In Cloudflare, open **Workers & Pages**.
2. Select **Create application** and **Import a repository**.
3. Select this GitHub repository and the `main` branch.
4. Keep the Worker name as `dmarc`; it must match `wrangler.jsonc` and the connected Cloudflare Worker.
5. Set the build command to `npm run build`.
6. Keep the deploy command as `npx wrangler deploy`.
7. Save and deploy.

Cloudflare will deploy the frontend and Worker API together. No environment variables or secrets are required for the basic scanner.

For a direct authenticated deployment:

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

## Repository layout

```text
src/
  client/       React user interface
  shared/       API contracts shared by the client and Worker
  worker/       Cloudflare Worker, DNS resolver, parsers, analysis, and tests
docs/
  ARCHITECTURE.md
  SCANNER-METHODOLOGY.md
  TOOLBOX-SCOPE.md
```

## Standards note

The implementation is based on the current DMARC deployment model in [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html) and aggregate-reporting concepts in [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990.html), while recognizing that real-world receivers and records remain in a transition period from RFC 7489 behavior.

DMARC expresses a domain owner's requested handling policy. A receiver ultimately decides how it processes a message. A passing DMARC result authenticates use of a domain; it does not prove that a message is benign.

## Security and privacy

- Scans query public DNS records only. Query names and record types are resolved by Cloudflare's native DNS service; no user-selectable resolver or target URL is accepted.
- Snapshot and discovery work is capped by fixed RR types, fixed hostname profiles, a random wildcard control, per-request DNS budgets, bounded concurrency, and result-size limits.
- IP-network input is strictly parsed as one address/CIDR, calculations are local, and optional evidence is limited to PTR and explicitly attributed Team Cymru DNS queries for one global address.
- The MVP does not persist scan history in an application database.
- DNS answers are untrusted input and are rendered as text.
- DNS lookups use the Worker's fixed native resolver and never fetch a user-supplied URL.
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
