# Toolbox scope

## Release boundary

Cresswell Security Lab has four supported families: Email Security, DNS & OSINT, Network Intelligence, and Web & TLS. The first three remain DNS/local-analysis oriented; Web & TLS is the one consent-gated active family. The release surface is defined by the routes and fixed profiles below, not by third-party product feature lists.

| Capability | Release status | Scope |
| --- | --- | --- |
| Email-authentication scan | Available | DMARC, SPF, limited DKIM selector evidence, MX/NS context, MTA-STS, TLS-RPT, BIMI, deterministic findings and score |
| First-class SPF analyzer | Available | TXT-backed policy selection, syntax/mechanisms, terminal policy, bounded recursive estimate, incomplete-state reporting, corrective guidance |
| Direct DNS lookup | Available | A, AAAA, CAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, plus analyzed `SPF` mode |
| Apex DNS snapshot | Available | Explicit A, AAAA, CAA, CNAME, MX, NS, SOA, TXT and four email-security TXT owner names |
| Common-host discovery | Available | Two fixed seven-label profiles, bounded CNAME/address resolution, one random wildcard control per profile |
| IP/CIDR utility | Available | UI and API for local IPv4/IPv6 network calculation; bounded PTR and Team Cymru DNS evidence only for one global address |
| Combined Web & TLS assessment | Available with deep consent and quota | One hostname/job; exactly 20 OWASP-aligned web controls plus up to four endpoint-level fixed `testssl.sh` profiles on port 443 |
| General active network/security tools | Deliberately excluded | No arbitrary ports/URLs/paths/methods/payloads, denial-of-service work, ping, traceroute, AXFR, crawling, login, or SMTP handshakes |

## What “DNS surface” means here

The surface view consists of three independently budgeted requests:

1. One explicit apex/security-owner snapshot.
2. One `core` common-host request.
3. One `extended` common-host request.

Each result remains tied to the exact owner name and query type used. `found`, `empty`, and `unavailable` are separate states. A random label is used to tag candidate answers that match likely wildcard DNS. Partial results remain visible, and an unavailable query does not become evidence that a record or hostname is missing.

“Passive-style” describes the DNS surface, not the whole product. DNS operators may observe resolver queries. The IP utility does not connect to supplied addresses. The separately labeled combined assessment intentionally generates bounded HTTP and potentially hundreds of TLS handshakes, including selected cryptographic flaw probes, only after consent and quota enforcement.

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

DNSDumpster-style inventory may combine live DNS with certificate-transparency records, historical/passive-DNS databases, search engines, reverse datasets, and other third-party sources. This release integrates none of those datasets. Cresswell Security Lab must therefore be described as a bounded live DNS observation, never as a complete zone inventory or a DNSDumpster equivalent.

## Fixed Web & TLS active exception

`POST /api/security-assessments` accepts a hostname, `authorizedUse: true`, and disclaimer version `2026-08-16-deep-v1`; it never accepts a URL, address, path, port, credential, method, body, wordlist, scanner flag, or command. It returns one asynchronous combined job. HTTP work is capped at six requests, two redirects, 2.5 seconds per request/body read, 30 seconds overall, and 131,072 bytes per inspected response.

All A/AAAA answers must be public and are capped at 16. Web requests prefer exact-IP raw sockets; the disclosed Cloudflare-fetch fallback gets fresh public-DNS checks before and after but retains a rebinding timing limitation. Deep TLS selects at most four representative A/AAAA endpoints and revalidates each exact address immediately before its scan. A separate fixed-image container runs identity, cryptography, and compatibility phases with 180 seconds, three concurrent fixed testssl parent runners under a UID-wide 48-process ceiling, five concurrent/128 total connections, 393,216 phase-output bytes, and 163,840 response bytes per endpoint.

The web analyzer returns exactly 20 deterministic header, cookie, bounded-HTML, redirect, method, and error-response observations. OWASP references are contextual mappings, not official tooling or complete coverage. TLS uses a version-pinned safe `testssl.sh` profile with bounded Heartbleed, CCS-injection, Ticketbleed, and ROBOT probes plus client simulations. It is an independent Cresswell methodology, not an SSL Labs grade; no Qualys API is called.

One SQLite Durable Object per canonical Cloudflare client-IP digest enforces exactly five accepted combined-or-legacy starts in the preceding rolling hour. A global coordinator provides target single-flight, six-hour cache reuse without report copies, concurrency two, at most eight pending jobs, at most 256 retained rows, 25-minute stale-job recovery, creator-token cancellation, and 24-hour expiry. Every accepted POST consumes one quota slot even if it reuses cached/in-flight evidence. The attestation and quota reduce casual abuse but do not prove ownership or identity.

Cloudflare Containers require internet capability for opaque raw TCP; `allowedHosts` does not constrain `net.connect`. The trusted image therefore forces `testssl.sh` through a local proxy that dials only the freshly validated exact IP:443, disables its own DNS/phone-home behavior, and exposes no caller-selected command. This is a material control but leaves residual container network capability and fixed-image trust.

## Why broader HackerTarget-like active tools are excluded

Port scans, vulnerability scans, ping, traceroute, AXFR attempts, banner collection, and arbitrary HTTP requests create direct traffic to a caller-selected third party. On an anonymous public Worker they would introduce a different security product and threat model:

- The service could be used as a scan relay or SSRF proxy.
- A valid domain does not prove caller authorization, and a domain can resolve to shared or third-party infrastructure.
- Redirects and DNS changes can turn apparently public targets into private, link-local, metadata, or control-plane destinations.
- Target traffic, concurrency, long jobs, and large responses require abuse-aware scheduling and operations.
- Vulnerability labels can be misleading without version validation, context, and controlled evidence retention.
- Cloudflare Worker runtime/network behavior is not an authorization or isolation boundary for arbitrary probing.

For those reasons broader capabilities are not anonymous convenience endpoints. The fixed assessment does not authorize arbitrary or higher-impact probing.

## Gate for a broader active-scanning plane

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

Until that gate is met, the public boundary remains normalized DNS/IP tooling plus the one fixed, consent-gated, five-per-IP/hour combined assessment above.
