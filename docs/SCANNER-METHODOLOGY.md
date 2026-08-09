# Scanner methodology

## Scope

The basic scanner evaluates a snapshot of public DNS. It answers what a domain currently publishes, not whether every legitimate sending system is correctly aligned in real traffic.

## DMARC

The scanner looks for DMARC-version TXT records at `_dmarc.<domain>`, preserves individual TXT resource-record boundaries, parses tag/value pairs, and checks:

- Version placement and value
- Duplicate records and tags
- Requested policy
- Subdomain policy
- Aggregate-reporting destinations
- Alignment modes
- Testing and legacy rollout tags

The result is a configuration stage: missing, invalid, monitoring, quarantine, or reject. The language says receivers are **asked** to apply a disposition because final message handling remains receiver policy.

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

## Configuration score

The score summarizes published configuration. It is not a security rating and is not enforcement approval. Policy stage always takes precedence over the number shown.

Aggregate-report history, sender ownership, business confirmation, and change monitoring are required before recommending quarantine or reject for an active production domain.

## Known limitations

- DNS caching may delay recently published changes.
- Receiver behavior varies during the transition between DMARC specifications.
- Public DNS cannot identify business ownership of a sender.
- Common-selector discovery cannot prove DKIM absence.
- A snapshot cannot detect intermittent sending systems.
- A DMARC pass authenticates domain use but does not prove message safety.
