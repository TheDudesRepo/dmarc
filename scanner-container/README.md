# Cresswell bounded TLS scanner container

This internal service runs a fixed, versioned testssl.sh profile for one
Worker-validated public IP address. It is not intended to have a public route.

## API

- `GET /healthz`
- `POST /scan` with `Content-Type: application/json`

The scan body must contain exactly:

```json
{
  "hostname": "example.com",
  "address": "93.184.216.34",
  "profile": "safe",
  "deadlineMs": 180000
}
```

`hostname` is used only for SNI and must be a normalized public DNS hostname.
`address` must be a globally routable native IPv4 or IPv6 literal. Port 443 is
hardcoded. URLs, paths, ports, DNS resolution, testssl arguments, proxy
destinations, and output paths cannot be supplied by the caller.

The accepted deadline is 120–180 seconds. One instance runs one job at a time.
Three fixed concurrent testssl parent runners share a localhost CONNECT proxy
capped at five concurrent and 128 total outbound connections; the service UID
has a separate 48-process ceiling for all runner descendants. The proxy accepts only the
validated address on port 443 and always dials that literal. Every testssl
process inherits a 393,216-byte `RLIMIT_FSIZE`, and the runner independently
validates the JSON file size after exit. Log streams, process groups, requests,
connections, and normalized responses have separate hard bounds. The final
endpoint result is capped at 160 KiB so four TLS endpoint reports can fit with
the web assessment in the Workflow result limit.

The profile actively observes certificates and chain presentation, protocols,
cipher categories and server preference, forward secrecy, named groups,
signature algorithms, session behavior, SNI/no-SNI certificate defaults,
OCSP stapling, client simulations, secure renegotiation, Heartbleed, CCS
injection, Ticketbleed, ROBOT, CRIME, POODLE, fallback SCSV, SWEET32, BEAST,
LUCKY13, FREAK, LOGJAM, DROWN on the endpoint, and RC4. It does not query live
OCSP/CRL/AIA endpoints, run BREACH HTTP probes, or search other services for
certificate reuse; those appear as explicit `not-tested` observations.

The runner does not pass `--openssl`: the pinned upstream release selects its
bundled legacy-capable OpenSSL binary and can use system OpenSSL for modern
TLS 1.3 work according to its own fixed selection logic. The image build
asserts that the bundled binary for the target architecture is executable.

Cloudflare's Container allowlist intercepts HTTP(S), but testssl.sh must
observe the target's original opaque TLS handshakes. HTTPS interception would
terminate and replace the session being measured, while `enableInternet=false`
blocks the required raw socket path. The wrapper therefore uses
`enableInternet=true`; `allowedHosts` still limits incidental HTTP, but does
not constrain opaque TCP.

The raw-socket boundary is instead the trusted fixed image and its independent
controls: the request validator accepts only one public IP literal; the
in-container CONNECT proxy accepts and dials only that literal on port 443;
testssl.sh is forced through that proxy with `--nodns`; phone-home and live
revocation retrieval are disabled; and process, time, output, concurrency, and
connection budgets are fixed. The non-root image receives no secrets and the
caller cannot supply a URL, port, command, option, or proxy destination.

## Local tests

```sh
node --test --test-reporter=spec test/*.test.mjs
```

The parser, validator, proxy policy, runner arguments, grading, response bound,
and HTTP service tests require Node 24 but do not require Docker or network
access. See `THIRD_PARTY_NOTICES.md` before distributing the image.
