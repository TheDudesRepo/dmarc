# Scanner methodology

## Scope

The basic scanner evaluates a snapshot of public DNS. It answers what a domain currently publishes, not whether every legitimate sending system is correctly aligned in real traffic.

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

The scanner finds `v=spf1` TXT records, flags multiple-record conflicts, and identifies DNS-producing mechanisms. Recursive evaluation is bounded by a strict query count, depth, cycle detection, and timeout. It is a linting aid rather than a full simulation of SPF evaluation for a particular sender IP.

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

## Core DNS and advanced lookup

The main scan also resolves A, AAAA, CNAME, TXT, MX, NS, SOA, and CAA. It flags evidence-backed delegation and owner-name conflicts without treating optional records or an email-only domain as broken. Advanced lookup exposes Cloudflare-native A, AAAA, CAA, CNAME, MX, NS, PTR, SOA, SRV, and TXT queries one at a time. An empty advanced answer is not scored and is not automatically labeled an issue.

The Worker uses Cloudflare's native DNS resolver. Resolver-reported absence is returned as an empty result; transport errors and timeouts remain indeterminate failures. The native interface does not expose authoritative-server consistency, raw DNS response codes, or DNSSEC validation state, so the scanner does not claim those checks. TXT character-string chunks are joined only within one resource record, never across separate TXT records.

## Remediation guidance

Warnings and failures include ordered repair steps. When the intended value can be expressed safely, the result includes a DNS host, type, and value template. Templates are conditional: for example, `0 .` is only appropriate for a domain that must not receive mail. No generic SPF value is offered when the sender inventory is unknown. The user must confirm sender inventory, mailbox/report destinations, provider-specific host formatting, and change-control requirements before publishing.

## Configuration score

The score summarizes published configuration. It is not a security rating and is not enforcement approval. DMARC policy points use the weakest effective policy across `p`, inherited or explicit `sp`, and inherited or explicit `np`, so a strong organizational-domain policy cannot hide a weaker scoped exception. Policy stage always takes precedence over the number shown.

Aggregate-report history, sender ownership, business confirmation, and change monitoring are required before recommending quarantine or reject for an active production domain.

## Known limitations

- DNS caching may delay recently published changes.
- Receiver behavior varies during the transition between DMARC specifications.
- Public DNS cannot identify business ownership of a sender.
- Common-selector discovery cannot prove DKIM absence.
- A snapshot cannot detect intermittent sending systems.
- A DMARC pass authenticates domain use but does not prove message safety.
- The scanner uses one public recursive resolver and is not a multi-vantage DNS-propagation test.
- It does not provide SMTP probing, blacklist reputation, port scanning, ping, traceroute, inbox placement, or continuous mailflow monitoring.
