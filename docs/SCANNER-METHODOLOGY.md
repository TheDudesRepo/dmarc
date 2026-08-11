# Scanner methodology

## Scope

DMARC Ready evaluates a live snapshot of public DNS. It answers what the configured recursive resolver returned for a fixed set of owner names and record types at scan time. It does not prove that every legitimate sending system is aligned, enumerate every DNS owner, or authorize a change to production policy.

The scanner is DNS-only. It sends bounded DNS queries but does not connect to discovered web, mail, or other services. This is passive-style reconnaissance rather than a guarantee of zero interaction: authoritative DNS infrastructure can still observe recursive queries.

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

## Found, empty, partial, and unavailable

The scanner keeps resolver absence separate from operational failure:

- `found`: at least one usable record was returned.
- `empty`: the resolver returned an absence condition for that name/type.
- `unavailable`: the query timed out, was refused, failed in transport, exceeded a safety bound, or was otherwise indeterminate.

Snapshot groups and security-owner records expose these states individually. A partially unavailable snapshot remains a successful structured result and includes an unavailable count; only an entirely unavailable set of eight apex queries becomes an upstream error. Host discovery returns successful hosts together with `unavailableNames`, and its wildcard control has its own unavailable flag.

The interface starts snapshot, core discovery, and extended discovery as three separate requests. It clears earlier results when the input changes or a new run starts, aborts superseded requests, and ignores late responses from an older run. Successful sections remain visible when another request fails, with the failure labeled as partial rather than converted into missing data.

## Why this is not “all DNS records”

DNS has no safe public operation that lists all owner names in an ordinary zone. An `ANY` query asks for records a server chooses to return at one already-known owner. It is not an enumeration primitive and can return deliberately minimized data as described in [RFC 8482](https://www.rfc-editor.org/rfc/rfc8482.html). Explicitly querying eight types provides clearer RRset evidence but still says nothing about unknown owner names or unsupported types.

DNSDumpster-style results can combine multiple sources such as certificate-transparency logs, historical/passive-DNS collections, search indexes, and other third-party datasets. DMARC Ready uses none of those sources in this release. It also does not request AXFR. Its snapshot and fourteen-label discovery are therefore useful bounded observations, not an exhaustive zone inventory or DNSDumpster equivalent.

## Remediation guidance

Warnings and failures include ordered repair steps. When the intended value can be expressed safely, the result includes a DNS host, type, and value template. Templates are conditional: for example, `0 .` is only appropriate for a domain that must not receive mail. No generic SPF value is offered when the sender inventory is unknown. The user must confirm sender inventory, mailbox/report destinations, provider-specific host formatting, and change-control requirements before publishing.

## Configuration score

The score summarizes published configuration. It is not a security rating and is not enforcement approval. DMARC policy points use the weakest effective policy across `p`, inherited or explicit `sp`, and inherited or explicit `np`, so a strong organizational-domain policy cannot hide a weaker scoped exception. Policy stage always takes precedence over the number shown.

Aggregate-report history, sender ownership, business confirmation, and change monitoring are required before recommending quarantine or reject for an active production domain.

## Safe passive boundary

This release does not perform port or vulnerability scans, ping, traceroute, AXFR, banner grabbing, SMTP handshakes, arbitrary HTTP fetches, blocklist queries, or service fingerprinting. Those operations create direct target traffic and substantially different authorization and abuse risks. They are not hidden behind the DNS routes and are not implied by discovered host or address output.

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
