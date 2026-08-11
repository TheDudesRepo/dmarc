# DMARC Ready

DMARC Ready is a public, read-only email-authentication and DNS scanner designed to make the path from monitoring to enforcement understandable. Enter a domain to inspect its published DMARC and SPF records, commonly discoverable DKIM selectors, mail routing, adjacent transport-security controls, and core DNS health.

The current release is an intentionally focused MVP: no accounts, no mailbox access, no DNS writes, and no AI-generated enforcement decisions.

## What it does

- Parses and validates the published DMARC policy
- Distinguishes monitoring, quarantine, reject, missing, and invalid postures
- Checks aggregate-reporting configuration
- Detects SPF record conflicts and estimates DNS-producing mechanisms within a strict lookup budget
- Displays MX and nameserver context
- Inventories A, AAAA, CNAME, TXT, MX, NS, SOA, and CAA answers in the main scan
- Looks for MTA-STS, SMTP TLS reporting, and BIMI records
- Checks a small set of common DKIM selectors without claiming that non-discovery means DKIM is absent
- Provides an advanced lookup for ten common record types supported by Cloudflare's native DNS resolver
- Produces deterministic, prioritized findings with raw DNS evidence and guided remediation
- Shows reviewable DNS record templates when a safe template is possible, with deployment cautions
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

The advanced lookup supports A, AAAA, CAA, CNAME, MX, NS, PTR, SOA, SRV, and TXT through Cloudflare's native DNS resolver. PTR accepts an IPv4 or IPv6 address and converts it to the corresponding reverse-DNS owner name. An empty answer is evidence that the requested record type was not returned; it is not automatically a configuration failure.

DNSSEC and specialist resource-record inspection is not exposed by this native lookup surface. Broader DNSSEC support and infrastructure-dependent checks such as SMTP handshakes, blocklists, worldwide propagation comparisons, port reachability, and other network probes remain future work rather than implied capabilities of this endpoint.

## Repository layout

```text
src/
  client/       React user interface
  shared/       API contracts shared by the client and Worker
  worker/       Cloudflare Worker, DNS resolver, parsers, analysis, and tests
docs/
  ARCHITECTURE.md
  SCANNER-METHODOLOGY.md
```

## Standards note

The implementation is based on the current DMARC deployment model in [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html) and aggregate-reporting concepts in [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990.html), while recognizing that real-world receivers and records remain in a transition period from RFC 7489 behavior.

DMARC expresses a domain owner's requested handling policy. A receiver ultimately decides how it processes a message. A passing DMARC result authenticates use of a domain; it does not prove that a message is benign.

## Security and privacy

- Scans query public DNS records only. Query names and record types are resolved by Cloudflare's native DNS service; no user-selectable resolver or target URL is accepted.
- The MVP does not persist scan history in an application database.
- DNS answers are untrusted input and are rendered as text.
- DNS lookups use the Worker's fixed native resolver and never fetch a user-supplied URL.
- Security headers are applied by the Worker.
- API requests have strict input and size limits.

See [SECURITY.md](SECURITY.md) for reporting guidance and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for trust boundaries.

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
