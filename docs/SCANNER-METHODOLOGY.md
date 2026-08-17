# Scanner methodology

## Scope

Cresswell Security Lab organizes evidence into Email Security, DNS & OSINT, Network Intelligence, and Web & TLS. The first three are DNS/local-analysis families; the explicitly authorized Web & TLS family combines 20 bounded HTTP controls with an asynchronous, container-isolated deep TLS profile. Results are point-in-time observations, not proof of security, vulnerability, ownership, or compliance.

The email, lookup, discovery, and IP tools are DNS-only and do not connect to discovered services. `POST /api/security-assessments` is the bounded active exception and requires the versioned deep-scan consent plus a server-enforced rolling quota before target work. The legacy quick `/api/web-security` path shares that quota and provides no supported native TLS grade.

## DMARC

The scanner looks for DMARC-version TXT records at `_dmarc.<domain>`, preserves individual TXT resource-record boundaries, parses tag/value pairs, and checks:

- Version placement and value
- Duplicate records and tags
- Requested policy
- Existing- and nonexistent-subdomain policy, including `sp`/`np` inheritance
- Aggregate-reporting destinations
- Alignment modes
- Testing and legacy rollout tags

The result is a configuration stage: missing, invalid, monitoring, quarantine, or reject. That primary stage follows the effective `p` policy, while headlines and findings explicitly qualify weaker `sp` or `np` coverage. The language says receivers are **asked** to apply a disposition because final message handling remains receiver policy.

## SPF

### Main-scan SPF check

The main scanner selects complete `v=spf1` TXT resource records, flags the permanent-error condition created by multiple policies, parses mechanisms and modifiers, and estimates DNS-producing mechanisms. Recursive traversal is bounded by query count, depth, cycles, time, and output size.

### First-class SPF lookup

The `SPF` lookup mode exposes the analysis directly. It is a semantic mode backed by TXT queries, not a query for obsolete DNS RR type 99. The input is a validated public DNS owner, including underscore-prefixed provider policy owners. The response contains only the selected SPF TXT records as raw evidence; unrelated TXT data is not relabeled as SPF.

For one SPF policy, the analysis reports:

- `missing`, `multiple`, `invalid`, `warning`, or `valid` status
- Syntax validity separately from overall validity
- Mechanisms, qualifiers, domain specifications, and IPv4/IPv6 CIDRs
- The terminal `all` posture, including a warning for `+all`
- A bounded worst-case recursive lookup estimate and whether it exceeds SPF's limit of ten
- Expanded domains and unresolved, invalid, cyclic, macro-dependent, depth-limited, or budget-limited branches
- Corrective steps and cautions designed to avoid inventing sender authorization

An estimate marked incomplete is not converted into a pass. The analysis is static linting: it does not evaluate SPF for a particular sender IP, expand runtime macros with SMTP context, prove that all real senders are represented, or demonstrate DMARC alignment.

## DKIM

DKIM has no universal selector-discovery mechanism. The scanner checks only a short list of common selectors. A match is useful evidence; no match is explicitly reported as inconclusive rather than as missing DKIM.

Reliable DKIM sender inventory requires known selectors or aggregate DMARC report data.

## Mail and transport context

The scanner checks:

- MX records and recognizable provider suffixes
- Nameservers
- `_mta-sts` TXT publication
- `_smtp._tls` TLS reporting
- `default._bimi` publication

These controls are reported separately from DMARC policy. Missing optional controls do not invalidate DMARC.

## Direct lookup

The direct lookup exposes Cloudflare-native A, AAAA, CAA, CNAME, MX, NS, PTR, SOA, SRV, and TXT queries one at a time. PTR accepts an IPv4 or IPv6 address and derives its standard reverse owner name; the other modes accept a validated public DNS owner name.

For a non-CNAME type, the resolver first follows a bounded CNAME chain and then asks for the requested type at the terminal owner. This prevents an alias from being formatted or labeled as an address, TXT record, NS value, or structured record. The response preserves the canonical target even when the terminal answer is empty. CNAME loops, excessive chains, and unavailable terminal queries remain errors.

DNS TXT records can consist of multiple character strings. Character strings are joined only within a single TXT resource record. Separate TXT records are never concatenated into one apparent DMARC or SPF policy.

## Explicit apex DNS snapshot

The snapshot uses a fixed query matrix:

| Owner | Types | Purpose |
| --- | --- | --- |
| Requested domain | A, AAAA, CAA, CNAME, MX, NS, SOA, TXT | Explicit apex/owner RRset evidence |
| `_dmarc.<domain>` | TXT | DMARC publication |
| `_mta-sts.<domain>` | TXT | MTA-STS policy signaling |
| `_smtp._tls.<domain>` | TXT | SMTP TLS reporting |
| `default._bimi.<domain>` | TXT | Default-selector BIMI publication |

The domain may be a hostname rather than a delegated zone apex. For that reason, no direct NS or SOA answer is described as something to review only if the input was intended to be an apex; it is not universally treated as broken delegation.

Snapshot results preserve raw records and an inferred canonical owner when resolution followed an alias. MX and NS data can contribute up to two infrastructure hostnames for bounded, direct A/AAAA enrichment. This enrichment is context only: it does not walk dependency graphs, perform reverse-DNS expansion, or connect to those addresses.

The snapshot also produces deterministic review findings for obvious apex/email-policy conflicts, such as multiple SPF records, an invalid or open SPF policy, a missing SPF policy alongside active MX, missing DMARC, or absent TLS-RPT. These are review prompts based on returned DNS, not proof that unobserved infrastructure is safe or unnecessary.

## Bounded common-host discovery

Host discovery accepts exactly two profiles:

| Profile | Labels |
| --- | --- |
| `core` | `www`, `mail`, `autodiscover`, `api`, `vpn`, `portal`, `remote` |
| `extended` | `smtp`, `webmail`, `admin`, `dev`, `staging`, `status`, `ftp` |

Each profile request checks its seven names plus one unpredictable `dmarc-ready-probe-…` label. Candidate resolution is intentionally narrow:

1. Query direct CNAME at the candidate.
2. If a CNAME exists, query direct A and AAAA at that one alias; otherwise query A and AAAA at the candidate.
3. Keep the observed alias and addresses with the original tested hostname.
4. Compare the candidate's alias plus sorted addresses with the random-label result.

An exact match to the random-label fingerprint is tagged `wildcardMatch`. Wildcard-tagged results remain visible because a legitimate explicitly configured name can share wildcard infrastructure; the tag asks the user to review the evidence rather than pretending the name was uniquely discovered. A failed wildcard probe means wildcard behavior is unknown, not absent.

The user cannot provide a wordlist or arbitrary label. The scanner does not brute-force, mutate, recurse, consult certificate-transparency or passive-DNS datasets, or derive more candidate names from returned content.

## IP and subnet utility

The IP/subnet UI uses `POST /api/ip-network`, a deterministic calculator. It accepts exactly one strict IPv4 or IPv6 address, an address with a numeric CIDR prefix, or IPv4 with a contiguous dotted netmask. It rejects URLs, lists, hyphenated ranges, scoped IPv6, whitespace, ambiguous leading-zero IPv4, and non-contiguous masks.

Local arithmetic returns:

- Canonical address and prefix, network CIDR, last address, and total-address count
- A conventional usable range (`/31` is treated as point-to-point and `/32` as one host)
- IPv6 address range conventions without inventing a broadcast address
- Classification of the supplied address as private, loopback, link-local, multicast, documentation, reserved, or global
- IPv4 netmask, wildcard mask, and broadcast address

Classification applies to the supplied address, not necessarily every address covered by a caller-provided prefix.

Enrichment is limited to an input that is both a single address (`/32` or `/128`) and globally routable. Within a ceiling of four logical DNS queries, the Worker requests PTR evidence, Team Cymru origin ASN/prefix TXT evidence, and AS names for at most two returned origin ASNs. Multiple-origin evidence is preserved. Parsed origin prefixes must contain the input address, and record owners, field formats, dates, ASN values, answer counts, and character volume are bounded and validated.

The response attributes Team Cymru data to [Team Cymru IP to ASN Mapping](https://www.team-cymru.com/ip-asn-mapping). DNS absence is `not-found`; malformed or failed evidence is `indeterminate`; mixed evidence is `partial`; and multi-address CIDRs or non-global inputs are `not-applicable` with zero DNS queries. An explicit `/32` or `/128` is still one address and can be enriched. Deterministic calculation remains available even when enrichment is unavailable. This endpoint does not ping, connect to, scan, or issue HTTP requests to the supplied address.

## Combined Web & TLS assessment workflow

The combined route accepts one normalized hostname plus exact `authorizedUse: true` and `disclaimerVersion: "2026-08-16-deep-v1"` values. The notice requires ownership or explicit permission and discloses potentially hundreds of bounded handshakes, selected cryptographic flaw probes, target logging, paid-container execution, prohibited disruption/crawling/credential activity, and point-in-time/non-compliance limits. The checkbox is not technical ownership proof.

Before any DNS or target traffic, the Worker consumes one of exactly five accepted starts available to the canonical `CF-Connecting-IP` during the preceding rolling hour. A sixth attempt returns `429`; accepted cache hits, single-flight joins, and later failures still consume their one slot. The global coordinator reuses the existing completed capability for six hours by hostname plus validated address set, joins concurrent identical targets, runs at most two jobs, holds at most eight pending jobs, retains at most 256 rows for up to 24 hours, and recovers a Workflow that reports no progress for 25 minutes. Cache hits do not duplicate report JSON; the row ceiling and sub-700-KiB result limit bound aggregate serialized evidence.

Target work is intentionally small:

1. Resolve A and AAAA; reject the entire target unless every returned address is a valid globally routable single address. Empty, private, loopback, link-local, reserved, transition/NAT64, malformed, or more than 16 addresses fail closed.
2. Make one non-following `HEAD` request to `http://<hostname>/` to observe cleartext behavior.
3. Attempt a manual `GET` redirect chain from `https://<hostname>/` with at most two redirects and inspect at most 131,072 bytes of the root response.
4. If a usable HTTPS root response exists, make a fixed `OPTIONS` observation and one `GET` to an unpredictable scanner-generated not-found path. The caller cannot choose this path.
5. Resolve immediately before each fetch and after its response; require the complete public address set to remain unchanged. Every redirect must stay on the exact hostname or its direct `www` counterpart, use a standard HTTP/HTTPS port, contain no credentials, avoid HTTPS downgrade, and pass the same address checks.
6. Stop at six total HTTP requests, enforce a 2.5-second timer on each fetch/body read and a 30-second whole-scan deadline, cap every inspected root/error body at 131,072 bytes, and bound URLs, headers, HTML tags, cookies, and displayed evidence.

The web transport first attempts a raw, exact-IP socket while retaining hostname Host/SNI and can retry one other validated address. Cloudflare blocks raw sockets to some Cloudflare-owned destinations; only then can the bounded platform fetch path be used, with fresh public-DNS validation before and after and an explicit report limitation. That fallback cannot be retroactively pinned if an answer changes only during Cloudflare's lookup, so the service does not claim perfect SSRF elimination.

### Exactly 20 passive/basic checks

The analyzer always returns these 20 check IDs in this order. Each check reports `pass`, `warning`, `fail`, `not-applicable`, or `unknown`, bounded evidence, remediation, and relevant OWASP Top 10 (2025) and Web Security Testing Guide references.

| # | Check ID | Observation |
| ---: | --- | --- |
| 1 | `https-enforcement` | Cleartext behavior, HTTPS reachability, redirect safety, and TLS validity context |
| 2 | `hsts` | Strict-Transport-Security presence and basic directive posture |
| 3 | `content-security-policy` | Enforced CSP presence and basic high-risk directive posture |
| 4 | `frame-protection` | CSP `frame-ancestors` and X-Frame-Options evidence |
| 5 | `mime-sniffing` | X-Content-Type-Options `nosniff` |
| 6 | `referrer-policy` | Referrer-Policy presence and basic posture |
| 7 | `permissions-policy` | Permissions-Policy presence |
| 8 | `cross-origin-isolation` | COOP, COEP, and CORP response-header evidence |
| 9 | `cors-policy` | Response to a fixed synthetic Origin and high-risk ACAO/credentials combinations |
| 10 | `http-methods` | Allow/public-method evidence from the fixed OPTIONS observation; no state-changing method is sent |
| 11 | `cookie-secure` | Secure on observed security-sensitive Set-Cookie values |
| 12 | `cookie-httponly` | HttpOnly on observed security-sensitive cookies |
| 13 | `cookie-samesite` | Explicit SameSite and the Secure requirement for SameSite=None |
| 14 | `cookie-scope-prefix` | Cookie Domain/Path scope and `__Host-`/`__Secure-` prefix consistency |
| 15 | `cache-control` | Public caching directives on the observed root response |
| 16 | `technology-disclosure` | Unnecessary response and HTML generator banners |
| 17 | `error-handling` | Status/body disclosure on one unpredictable generated not-found path |
| 18 | `mixed-content` | Cleartext active/resource URLs in the bounded root HTML |
| 19 | `form-transport` | Password/form action protocol and method evidence without submission |
| 20 | `subresource-integrity` | Integrity metadata on eligible third-party scripts/styles in bounded HTML |

The web score weights transport, CSP, CORS, and session controls more heavily than informational hardening. `unknown` evidence is never scored as a failure, and `not-applicable` weight is removed from the denominator. A letter grade is assigned only when at least 70% of applicable weight was evaluated and HTTPS enforcement, HSTS, and CSP all produced bounded evidence; a confirmed HTTPS-enforcement failure always caps the grade at `F`.

These are OWASP-aligned observations, not “the OWASP Top 20,” an official OWASP scanner, or complete coverage of the OWASP Top 10/WSTG. They do not test authentication or authorization decisions, injection, business logic, dependencies, APIs behind undiscovered paths, server internals, client-side runtime behavior, or exploitability. Header presence is not proof that a policy is correct for the application; root-page absence is not proof that a control is absent everywhere.

### Deep TLS profile

The Workflow deterministically selects at most four public endpoints, balancing IPv4 and IPv6. Before each one, it obtains a fresh DNS view and requires the exact pre-job address to remain public and present. Every endpoint receives its own container identity, original hostname SNI, fixed port 443, and a durable scan-once claim. The first validated report is retained until the Workflow step has durably advanced; an incomplete replay returns stored evidence or becomes unavailable rather than launching a duplicate profile. If DNS changes or the container fails validation, that endpoint becomes unavailable; it is not silently replaced with a new unapproved address.

The image pins `testssl.sh` 3.2.4 at commit `97763a411c525720a5f9bd9d2cded416b10f210a` and exposes one `safe-v1` profile. Its phases are:

1. **Identity:** certificate/chain, hostname, validity, revocation data available to the profile, and related features.
2. **Cryptography:** offered protocols/ciphers, server preference, key-exchange and forward-secrecy evidence.
3. **Compatibility:** bounded client simulations and explicit Heartbleed, CCS-injection, Ticketbleed, and ROBOT probes.

BREACH, live revocation guarantees, and cross-service DROWN remain `not-tested` when they cannot be established safely. No caller can add flags, change the port/address, supply a command, or request a denial-of-service probe. Per endpoint the hard envelope is 180 seconds, three concurrent fixed testssl parent runners under a UID-wide 48-process ceiling, five concurrent connections, 128 total connections, 393,216 bytes per phase, and 163,840 response bytes. Normalized displayed endpoint evidence is at most 128 KiB and all combined evidence stays below 700 KiB.

Opaque raw TCP requires container internet capability; Cloudflare `allowedHosts` does not constrain `net.connect`. Enforcement instead layers a trusted fixed image, independent Worker and container public-IP validation, the exact-target local CONNECT proxy, forced `testssl.sh --proxy`/`--nodns`, disabled phone-home behavior, port 443, and fixed process/connection/deadline/output budgets. This materially limits the profile but leaves residual trusted-image/container-network risk, which operators must monitor.

Each observation records `tested`, `inferred`, or `not-testable` evidence. Section and overall grades use the independent `cresswell-tls-v1` methodology. A grade requires at least 70% evaluated aggregate endpoint weight; unavailable/unknown evidence yields partial or `N/A`, never an invented failure. Confirmed critical protocol/known-issue evidence can cap the grade. This is not an SSL Labs grade or a compliance certification, and Cresswell Security Lab does not invoke or proxy the Qualys API.

## Found, empty, partial, and unavailable

The scanner keeps resolver absence separate from operational failure:

- `found`: at least one usable record was returned.
- `empty`: the resolver returned an absence condition for that name/type.
- `unavailable`: the query timed out, was refused, failed in transport, exceeded a safety bound, or was otherwise indeterminate.

Snapshot groups and security-owner records expose these states individually. A partially unavailable snapshot remains a successful structured result and includes an unavailable count; only an entirely unavailable set of eight apex queries becomes an upstream error. Host discovery returns successful hosts together with `unavailableNames`, and its wildcard control has its own unavailable flag.

The interface starts snapshot, core discovery, and extended discovery as three separate requests. It clears earlier results when the input changes or a new run starts, aborts superseded requests, and ignores late responses from an older run. Successful sections remain visible when another request fails, with the failure labeled as partial rather than converted into missing data.

## Why this is not “all DNS records”

DNS has no safe public operation that lists all owner names in an ordinary zone. An `ANY` query asks for records a server chooses to return at one already-known owner. It is not an enumeration primitive and can return deliberately minimized data as described in [RFC 8482](https://www.rfc-editor.org/rfc/rfc8482.html). Explicitly querying eight types provides clearer RRset evidence but still says nothing about unknown owner names or unsupported types.

DNSDumpster-style results can combine multiple sources such as certificate-transparency logs, historical/passive-DNS collections, search indexes, and other third-party datasets. Cresswell Security Lab uses none of those sources in this release. It also does not request AXFR. Its snapshot and fourteen-label discovery are therefore useful bounded observations, not an exhaustive zone inventory or DNSDumpster equivalent.

## Remediation guidance

Warnings and failures include ordered repair steps. When the intended value can be expressed safely, the result includes a DNS host, type, and value template. Templates are conditional: for example, `0 .` is only appropriate for a domain that must not receive mail. No generic SPF value is offered when the sender inventory is unknown. The user must confirm sender inventory, mailbox/report destinations, provider-specific host formatting, and change-control requirements before publishing.

## Configuration score

The score summarizes published configuration. It is not a security rating and is not enforcement approval. DMARC policy points use the weakest effective policy across `p`, inherited or explicit `sp`, and inherited or explicit `np`, so a strong organizational-domain policy cannot hide a weaker scoped exception. Policy stage always takes precedence over the number shown.

Aggregate-report history, sender ownership, business confirmation, and change monitoring are required before recommending quarantine or reject for an active production domain.

## Safe bounded boundary

Except for the documented combined assessment, this release does not connect to targets. The fixed TLS profile includes the selected bounded cryptographic flaw probes listed above, but no general port/exploit scanning, ping, traceroute, AXFR, arbitrary HTTP, crawling, login/form submission, credentials, denial-of-service work, or caller-configurable fingerprinting. Active work is never implied by DNS/IP output.

See [Toolbox scope](TOOLBOX-SCOPE.md) for the controls required before any active capability could be offered.

## Known limitations

- DNS caching may delay recently published changes.
- Receiver behavior varies during the transition between DMARC specifications.
- Public DNS cannot identify business ownership of a sender or host.
- Common-selector discovery cannot prove DKIM absence.
- Common-host discovery cannot prove another hostname does not exist.
- Wildcard fingerprints can be inconclusive when responses rotate or vary by location.
- A snapshot cannot detect intermittent sending systems.
- A DMARC pass authenticates domain use but does not prove message safety.
- The scanner uses one public recursive resolver and is not a multi-vantage DNS-propagation test.
- The native interface does not expose authoritative-server consistency, raw DNS response codes, or DNSSEC validation state, so the scanner does not claim those checks.
- The IP/CIDR utility's Team Cymru data is third-party DNS evidence, not routing authority or ownership proof.
- Web authorization is caller-attested rather than cryptographically verified, and shared hosting/CDNs can put third-party infrastructure behind an authorized name.
- Five attempts per IP per rolling hour can affect unrelated users behind NAT and can be distributed across changing IPv6 addresses or multiple clients; it is an abuse-reduction control, not identity.
- HTTP analysis observes only the root flow and one generated not-found path, and static HTML inspection does not execute JavaScript or discover application routes.
- The Cloudflare HTTP fallback is checked before and after fetches but cannot be pinned during the platform lookup; the disclosed residual timing limitation remains.
- Deep TLS samples at most four endpoints under one fixed network vantage and profile. Containers retain outbound network capability constrained by the trusted image/proxy rather than a platform raw-TCP allowlist.
- OWASP mappings identify related risk/testing areas; they do not make the 20 checks complete OWASP coverage or a certification.
