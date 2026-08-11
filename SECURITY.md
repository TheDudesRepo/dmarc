# Security policy

## Reporting a vulnerability

Please do not open a public GitHub issue for a suspected vulnerability. Until a dedicated security mailbox is configured, use GitHub's private vulnerability reporting feature for this repository.

Include:

- Affected route or component
- Reproduction steps
- Expected and observed behavior
- Impact assessment
- Any suggested mitigation

Do not include customer data, credentials, or destructive proof-of-concept payloads.

## Current security model

The MVP is a public, unauthenticated, read-only DNS scanner. It does not request DNS-provider credentials, mailbox access, or email content. DNS answers are considered attacker-controlled and must never be inserted as HTML.

The scanner intentionally limits:

- Request body size
- Accepted input shape
- Domain length and label length
- DNS query types and names
- Total lookup count and concurrent upstream connections
- Recursive SPF depth
- Upstream request duration
- Upstream response size and answer count

All DNS resolution uses a fixed Google Public DNS-over-HTTPS endpoint with redirects disabled. DNS response codes are handled explicitly so temporary resolver failures are not converted into absent records. The advanced lookup route accepts only an allowlisted record type and a validated public owner name; it cannot select an upstream host or fetch an arbitrary URL.

Future DMARC aggregate-report ingestion will require additional controls for compressed files, XML entities, expansion ratios, tenant mapping, deduplication, and report-email authentication before it is enabled in production.
