# Toolbox scope

## Release boundary

DMARC Ready is an email-authentication scanner plus a bounded public-DNS evidence toolbox. The supported release surface is defined by the API routes, not by experimental source files, tests, or the feature sets of third-party websites.

| Capability | Release status | Scope |
| --- | --- | --- |
| Email-authentication scan | Available | DMARC, SPF, limited DKIM selector evidence, MX/NS context, MTA-STS, TLS-RPT, BIMI, deterministic findings and score |
| First-class SPF analyzer | Available | TXT-backed policy selection, syntax/mechanisms, terminal policy, bounded recursive estimate, incomplete-state reporting, corrective guidance |
| Direct DNS lookup | Available | A, AAAA, CAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, plus analyzed `SPF` mode |
| Apex DNS snapshot | Available | Explicit A, AAAA, CAA, CNAME, MX, NS, SOA, TXT and four email-security TXT owner names |
| Common-host discovery | Available | Two fixed seven-label profiles, bounded CNAME/address resolution, one random wildcard control per profile |
| IP/CIDR utility | Available | UI and API for local IPv4/IPv6 network calculation; bounded PTR and Team Cymru DNS evidence only for one global address |
| Active network/security tools | Deliberately excluded | No ports, vulnerability probes, ping, traceroute, AXFR, banners, arbitrary HTTP, or service handshakes |

## What “DNS surface” means here

The surface view consists of three independently budgeted requests:

1. One explicit apex/security-owner snapshot.
2. One `core` common-host request.
3. One `extended` common-host request.

Each result remains tied to the exact owner name and query type used. `found`, `empty`, and `unavailable` are separate states. A random label is used to tag candidate answers that match likely wildcard DNS. Partial results remain visible, and an unavailable query does not become evidence that a record or hostname is missing.

“Passive” in this project means DNS-only and non-intrusive with respect to the discovered application services. The Worker still sends DNS queries through its fixed recursive resolver; DNS operators may observe those queries. The IP utility similarly performs local arithmetic and, for one global address, reverse and Team Cymru attribution DNS. It does not make connections to supplied or returned addresses or derive arbitrary network targets from records.

## IP/CIDR utility boundary

`POST /api/ip-network` accepts one strict IPv4/IPv6 address or CIDR (including a contiguous dotted IPv4 netmask). It calculates the network and range locally. It does not expand or iterate over the addresses in a CIDR.

Only a single globally routable address, bare or explicitly `/32` or `/128`, is eligible for DNS enrichment. The fixed enrichment path is PTR, Team Cymru IP-to-origin-AS/prefix TXT, and up to two Team Cymru AS-name TXT queries, capped at four logical queries. Multi-address CIDRs and special-use addresses make no enrichment queries. The UI and API keep `not-found`, `partial`, `indeterminate`, and `not-applicable` evidence distinct, and explicitly attribute Team Cymru. This is address metadata, not a reachability, ownership, reputation, or vulnerability claim.

## Why the result is not exhaustive

DNS is a mapping from already-known owner names to typed records. Ordinary public resolution provides no universal list of every owner in a zone.

- `ANY` is not “all zone records.” It asks for data at one known owner, and an authoritative server may return a deliberately minimal answer under [RFC 8482](https://www.rfc-editor.org/rfc/rfc8482.html).
- Explicit A/AAAA/CAA/CNAME/MX/NS/SOA/TXT queries are more truthful about which RRsets were tested, but cannot reveal unknown owners or unsupported record types.
- Fourteen common labels are a documented sample, not a brute-force dictionary.
- Wildcard detection explains repeated catch-all answers; it does not prove that every matching name is synthetic.
- No AXFR is attempted, even when a server might be misconfigured to allow it.

DNSDumpster-style inventory may combine live DNS with certificate-transparency records, historical/passive-DNS databases, search engines, reverse datasets, and other third-party sources. This release integrates none of those datasets. DMARC Ready must therefore be described as a bounded live DNS observation, never as a complete zone inventory or a DNSDumpster equivalent.

## Why HackerTarget-like active tools are excluded

Port scans, vulnerability scans, ping, traceroute, AXFR attempts, banner collection, and arbitrary HTTP requests create direct traffic to a caller-selected third party. On an anonymous public Worker they would introduce a different security product and threat model:

- The service could be used as a scan relay or SSRF proxy.
- A valid domain does not prove caller authorization, and a domain can resolve to shared or third-party infrastructure.
- Redirects and DNS changes can turn apparently public targets into private, link-local, metadata, or control-plane destinations.
- Target traffic, concurrency, long jobs, and large responses require abuse-aware scheduling and operations.
- Vulnerability labels can be misleading without version validation, context, and controlled evidence retention.
- Cloudflare Worker runtime/network behavior is not an authorization or isolation boundary for arbitrary probing.

For those reasons these capabilities are not implemented as anonymous convenience endpoints and are not simulated with misleading DNS-only substitutes.

## Gate for a future active-scanning plane

Any future active tool must be a separately reviewed and deployed system. Before release it would need:

1. Authenticated users, verified contact information, and auditable actions.
2. Fresh proof of ownership or explicit authorization for the exact target, with third-party/shared infrastructure excluded by default.
3. Fixed operations and ports rather than caller-defined URLs, commands, payloads, or wordlists.
4. Per-user, per-target, and global quotas; strict rate and concurrency limits; and abuse suspension.
5. Durable queues, cancellation, backpressure, bounded retries, job expiry, and predictable cost limits.
6. Isolated egress with destination validation both before and after DNS resolution and every redirect.
7. Deny rules for private, loopback, link-local, metadata, multicast, reserved, and control-plane ranges for both IPv4 and IPv6.
8. Bounded execution time, redirects, response bytes, output records, retention, and access to results.
9. Audit logs, operator monitoring, abuse reporting, incident response, and legal/policy review.

Until that gate is met, the safe public boundary remains normalized, allowlisted, bounded DNS resolution only.
